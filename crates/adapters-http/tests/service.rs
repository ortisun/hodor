//! The client for services the operator runs, against servers the test
//! runs on this machine.

use hodor_adapters_http::{OutboundPolicy, ServiceHttpClient};
use hodor_kernel::{HttpClient as _, HttpRequest};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

struct Server {
    port: u16,
    connections: Arc<AtomicUsize>,
}

async fn serve(answer: &'static [u8]) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let port = listener.local_addr().expect("address").port();
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = connections.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            seen.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                let _ = stream.write_all(answer).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Server { port, connections }
}

impl Server {
    fn seen(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

fn client(origins: &[String]) -> ServiceHttpClient {
    ServiceHttpClient::new(
        origins,
        OutboundPolicy {
            timeout: Duration::from_millis(600),
            connect_timeout: Duration::from_millis(600),
            max_response_bytes: 64,
            development_hosts: Vec::new(),
        },
    )
    .expect("client")
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
const REDIRECT: &[u8] = b"HTTP/1.1 307 Temporary Redirect\r\nlocation: http://169.254.169.254/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

#[tokio::test]
async fn a_configured_service_is_reached_at_a_private_address() {
    let server = serve(OK).await;
    let client = client(&[server.origin()]);

    let response = client
        .send(HttpRequest::post(
            format!("{}/v1/data/hodor/decision", server.origin()),
            "application/json",
            b"{}".to_vec(),
        ))
        .await
        .expect("response");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"{}");
    assert_eq!(server.seen(), 1);
}

#[tokio::test]
async fn any_other_address_is_refused_without_a_connection() {
    let configured = serve(OK).await;
    let other = serve(OK).await;
    let client = client(&[configured.origin()]);

    for url in [
        other.origin(),
        format!("https://127.0.0.1:{}/", configured.port),
        format!("http://localhost:{}/", configured.port),
        "http://169.254.169.254/latest/meta-data/".to_owned(),
        "https://example.com/".to_owned(),
    ] {
        let error = client
            .send(HttpRequest::get(&url))
            .await
            .expect_err("must be refused");
        assert_eq!(error.code(), "http.destination_not_configured", "{url}");
    }
    assert_eq!(other.seen(), 0);
    assert_eq!(configured.seen(), 0);

    let error = client
        .send(HttpRequest::get(format!(
            "http://user:password@127.0.0.1:{}/",
            configured.port
        )))
        .await
        .expect_err("a name and password");
    assert_eq!(error.code(), "http.url_invalid");
    assert_eq!(configured.seen(), 0);
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let server = serve(REDIRECT).await;
    let client = client(&[server.origin()]);

    let response = client
        .send(HttpRequest::get(server.origin()))
        .await
        .expect("the redirect itself");
    assert_eq!(response.status, 307);
    assert_eq!(server.seen(), 1);
}

#[tokio::test]
async fn an_origin_with_more_than_an_origin_is_refused() {
    let error = ServiceHttpClient::new(
        &["http://127.0.0.1:8181/v1/data".to_owned()],
        OutboundPolicy::default(),
    )
    .expect_err("a path");
    assert_eq!(error.code(), "http.origin_invalid");
    assert!(ServiceHttpClient::check_origin("http://127.0.0.1:8181").is_ok());
}
