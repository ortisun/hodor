//! The capabilities file: what it removes, and that Open Policy Agent
//! refuses a policy that uses what it removed.

use serde_json::Value;
use std::time::Duration;
use testcontainers::core::WaitFor;
use testcontainers::core::wait::ExitWaitStrategy;
use testcontainers::runners::AsyncRunner as _;
use testcontainers::{GenericImage, ImageExt as _};

const CAPABILITIES: &str = include_str!("../../../deploy/open-policy-agent/capabilities.json");
const IMAGE: (&str, &str) = ("openpolicyagent/opa", "1.10.1");
const REMOVED: [&str; 4] = [
    "http.send",
    "net.lookup_ip_addr",
    "opa.runtime",
    "providers.aws.sign_req",
];

fn builtins() -> Vec<String> {
    let document: Value = serde_json::from_str(CAPABILITIES).expect("the file is JSON");
    document["builtins"]
        .as_array()
        .expect("a list of built-ins")
        .iter()
        .map(|builtin| builtin["name"].as_str().expect("a name").to_owned())
        .collect()
}

#[test]
fn the_file_removes_the_built_ins_with_side_effects_and_allows_no_network() {
    let names = builtins();
    for removed in REMOVED {
        assert!(!names.iter().any(|name| name == removed), "{removed}");
    }
    for kept in [
        "net.cidr_contains",
        "time.now_ns",
        "io.jwt.decode_verify",
        "count",
    ] {
        assert!(names.iter().any(|name| name == kept), "{kept}");
    }
    let document: Value = serde_json::from_str(CAPABILITIES).expect("JSON");
    assert_eq!(document["allow_net"], serde_json::json!([]));
}

/// Runs `opa check --capabilities` on `policy` and answers whether it
/// passed.
async fn checks(policy: &str, expected_exit: i64) {
    let (name, tag) = IMAGE;
    let container = GenericImage::new(name, tag)
        .with_wait_for(WaitFor::exit(
            ExitWaitStrategy::new()
                .with_exit_code(expected_exit)
                .with_poll_interval(Duration::from_millis(100)),
        ))
        .with_copy_to("/check/capabilities.json", CAPABILITIES.as_bytes().to_vec())
        .with_copy_to("/check/policy.rego", policy.as_bytes().to_vec())
        .with_cmd([
            "check",
            "--capabilities=/check/capabilities.json",
            "/check/policy.rego",
        ])
        .start()
        .await;
    assert!(
        container.is_ok(),
        "`opa check` should exit with {expected_exit} for:\n{policy}"
    );
}

#[tokio::test]
async fn a_policy_that_calls_out_is_refused_and_a_plain_one_passes() {
    checks(
        r#"package hodor.check

decision := {"allow": true} if input.action == "read"
"#,
        0,
    )
    .await;
    for call in [
        r#"http.send({"method": "GET", "url": "http://169.254.169.254/"})"#,
        r#"net.lookup_ip_addr("example.com")"#,
        "opa.runtime()",
    ] {
        checks(
            &format!(
                r#"package hodor.check

decision := {{"allow": true, "seen": {call}}}
"#
            ),
            1,
        )
        .await;
    }
}
