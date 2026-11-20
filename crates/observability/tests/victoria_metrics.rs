//! Metrics reach VictoriaMetrics over OTLP and can be queried back.
//!
//! One test only: telemetry installs process-wide globals.

use hodor_observability::{Config, LogFormat, Telemetry};
use opentelemetry::KeyValue;
use std::time::Duration;
use testcontainers::core::IntoContainerPort as _;
use testcontainers::runners::AsyncRunner as _;
use testcontainers::{GenericImage, ImageExt as _};

const VICTORIA_METRICS_PORT: u16 = 8428;

async fn wait_until_healthy(client: &reqwest::Client, base: &str) {
    for _ in 0..60 {
        if let Ok(response) = client.get(format!("{base}/health")).send().await
            && response.status().is_success()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("VictoriaMetrics did not become healthy");
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_are_exported_to_victoria_metrics() {
    let container = GenericImage::new("victoriametrics/victoria-metrics", "v1.156.0")
        .with_exposed_port(VICTORIA_METRICS_PORT.tcp())
        // Make freshly ingested samples visible to queries at once.
        .with_cmd(["-search.latencyOffset=0s"])
        .start()
        .await
        .expect("VictoriaMetrics container should start; is Docker running?");
    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(VICTORIA_METRICS_PORT)
        .await
        .expect("container port");
    let base = format!("http://{host}:{port}");
    let client = reqwest::Client::new();
    wait_until_healthy(&client, &base).await;

    let mut config = Config::new("hodor-observability-test", "0.0.0");
    config.log_format = LogFormat::Pretty;
    config.metrics_endpoint = Some(format!("{base}/opentelemetry/v1/metrics"));
    config.metrics_interval = Duration::from_secs(1);

    // The exporter uses a blocking HTTP client, so telemetry is driven from
    // a blocking thread, as a binary does from `main` before its runtime.
    let telemetry = tokio::task::spawn_blocking(move || {
        let telemetry = Telemetry::init(&config).expect("telemetry should start");
        let counter = opentelemetry::global::meter("hodor.test")
            .u64_counter("hodor_test_logins")
            .build();
        counter.add(3, &[KeyValue::new("outcome", "success")]);
        counter.add(1, &[KeyValue::new("outcome", "failure")]);
        telemetry.flush();
        telemetry
    })
    .await
    .expect("telemetry task");

    // Ask VictoriaMetrics to make buffered samples searchable, then query.
    let mut series = serde_json::Value::Null;
    for _ in 0..30 {
        client
            .get(format!("{base}/internal/force_flush"))
            .send()
            .await
            .expect("force flush");
        let body: serde_json::Value = client
            .get(format!("{base}/api/v1/query"))
            .query(&[("query", r#"{__name__=~"hodor_test_logins.*"}"#)])
            .send()
            .await
            .expect("query")
            .json()
            .await
            .expect("query response");
        series = body["data"]["result"].clone();
        if series.as_array().is_some_and(|s| s.len() == 2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let series = series.as_array().expect("query result").clone();
    assert_eq!(series.len(), 2, "one series per outcome: {series:?}");
    let value_of = |outcome: &str| -> String {
        series
            .iter()
            .find(|s| s["metric"]["outcome"] == outcome)
            .and_then(|s| s["value"][1].as_str())
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(value_of("success"), "3");
    assert_eq!(value_of("failure"), "1");
    // Resource attributes arrive as labels, so series can be told apart by
    // service.
    assert!(
        series.iter().all(|s| s["metric"]
            .as_object()
            .is_some_and(|labels| labels.values().any(|v| v == "hodor-observability-test"))),
        "service name label missing: {series:?}"
    );

    tokio::task::spawn_blocking(move || telemetry.shutdown())
        .await
        .expect("shutdown task");
}
