//! The guarded client against servers the test runs on this machine.
//!
//! This machine's addresses are exactly what the client refuses, so the
//! servers are reached through the development exception, and the same
//! servers are used to show that without it they cannot be reached.

use hodor_adapters_http::{GuardedHttpClient, OutboundPolicy};
use hodor_kernel::{HttpClient as _, HttpRequest};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// A server that answers every connection with the same bytes and counts
/// the connections it got.
struct Server {
    port: u16,
    connections: Arc<AtomicUsize>,
}

async fn serve(answer: &'static [u8], delay: Duration) -> Server {
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
                tokio::time::sleep(delay).await;
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
}

fn client(development_hosts: &[String]) -> GuardedHttpClient {
    GuardedHttpClient::new(OutboundPolicy {
        timeout: Duration::from_millis(600),
        connect_timeout: Duration::from_millis(600),
        max_response_bytes: 64,
        development_hosts: development_hosts.to_vec(),
    })
    .expect("client")
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello";

#[tokio::test]
async fn a_development_host_is_reached_and_its_answer_read() {
    let server = serve(OK, Duration::ZERO).await;
    let client = client(&[format!("127.0.0.1:{}", server.port)]);

    let response = client
        .send(
            HttpRequest::get(format!("http://127.0.0.1:{}/keys", server.port))
                .header("accept", "text/plain"),
        )
        .await
        .expect("response");

    assert_eq!(response.status, 200);
    assert!(response.is_success());
    assert_eq!(response.body, b"hello");
    assert_eq!(response.header("Content-Type"), Some("text/plain"));
    assert_eq!(server.seen(), 1);
}

#[tokio::test]
async fn this_machine_is_not_reached_in_any_spelling() {
    let server = serve(OK, Duration::ZERO).await;
    let port = server.port;
    let client = client(&[]);

    for host in [
        "127.0.0.1",
        "localhost",
        "2130706433",
        "0x7f.0.0.1",
        "0177.0.0.1",
        "127.1",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "[::ffff:7f00:1]",
        "LOCALHOST",
        "localhost.",
    ] {
        for scheme in ["https", "http"] {
            let error = client
                .send(HttpRequest::get(format!("{scheme}://{host}:{port}/")))
                .await
                .expect_err("must be refused");
            let expected = if scheme == "https" {
                "http.destination_forbidden"
            } else {
                "http.url_invalid"
            };
            assert_eq!(error.code(), expected, "{scheme}://{host}");
            assert!(
                !format!("{error}").contains(host),
                "the address is not repeated"
            );
        }
    }
    assert_eq!(server.seen(), 0, "no connection was ever opened");
}

#[tokio::test]
async fn private_and_metadata_addresses_are_refused_before_any_connection() {
    let client = client(&[]);
    for host in [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "[fd00::1]",
        "[fe80::1]",
        "[64:ff9b::a9fe:a9fe]",
    ] {
        let started = std::time::Instant::now();
        let error = client
            .send(HttpRequest::get(format!(
                "https://{host}/latest/meta-data/"
            )))
            .await
            .expect_err("must be refused");
        assert_eq!(error.code(), "http.destination_forbidden", "{host}");
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "{host} was refused without waiting for a connection"
        );
    }
}

#[tokio::test]
async fn the_exception_is_for_one_host_and_port_only() {
    let allowed = serve(OK, Duration::ZERO).await;
    let other = serve(OK, Duration::ZERO).await;
    let client = client(&[format!("127.0.0.1:{}", allowed.port)]);

    let error = client
        .send(HttpRequest::get(format!(
            "http://127.0.0.1:{}/",
            other.port
        )))
        .await
        .expect_err("another port is not the development host");
    assert_eq!(error.code(), "http.url_invalid");
    // The same address under another name is another host.
    let error = client
        .send(HttpRequest::get(format!(
            "http://localhost:{}/",
            allowed.port
        )))
        .await
        .expect_err("another name is not the development host");
    assert_eq!(error.code(), "http.url_invalid");
    assert_eq!(other.seen() + allowed.seen(), 0);
}

#[tokio::test]
async fn a_redirect_is_handed_back_and_never_followed() {
    let target = serve(OK, Duration::ZERO).await;
    let answer: &'static [u8] = Box::leak(
        format!(
            "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:{}/secret\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            target.port
        )
        .into_bytes()
        .into_boxed_slice(),
    );
    let redirecting = serve(answer, Duration::ZERO).await;
    // Both are development hosts: even so the redirect is not followed.
    let client = client(&[
        format!("127.0.0.1:{}", redirecting.port),
        format!("127.0.0.1:{}", target.port),
    ]);

    let response = client
        .send(HttpRequest::get(format!(
            "http://127.0.0.1:{}/",
            redirecting.port
        )))
        .await
        .expect("the redirect itself is the response");

    assert_eq!(response.status, 302);
    assert!(response.header("location").is_some());
    assert_eq!(target.seen(), 0, "the place it pointed to was never called");
}

#[tokio::test]
async fn an_answer_larger_than_the_limit_is_cut() {
    // Announces 5 bytes and sends far more: the limit is on what arrives.
    const LYING: &[u8] = b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let server = serve(LYING, Duration::ZERO).await;
    let client = client(&[format!("127.0.0.1:{}", server.port)]);

    let error = client
        .send(HttpRequest::get(format!(
            "http://127.0.0.1:{}/",
            server.port
        )))
        .await
        .expect_err("too large");
    assert_eq!(error.code(), "http.response_too_large");
}

#[tokio::test]
async fn a_slow_answer_is_given_up_on() {
    let server = serve(OK, Duration::from_secs(5)).await;
    let client = client(&[format!("127.0.0.1:{}", server.port)]);

    let started = std::time::Instant::now();
    let error = client
        .send(HttpRequest::get(format!(
            "http://127.0.0.1:{}/",
            server.port
        )))
        .await
        .expect_err("too slow");
    assert_eq!(error.code(), "http.unreachable");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn addresses_that_are_not_plain_https_are_refused() {
    let client = client(&[]);
    for url in [
        "https://user:password@example.com/",
        "https://user@example.com/",
        "http://example.com/",
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "not an address",
        "https://",
        "",
    ] {
        let error = client
            .send(HttpRequest::get(url))
            .await
            .expect_err("must be refused");
        assert_eq!(error.code(), "http.url_invalid", "{url}");
    }
}

#[tokio::test]
async fn a_body_is_posted_with_its_content_type() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let port = listener.local_addr().expect("address").port();
    let received = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("connection");
        let mut request = vec![0_u8; 4096];
        let read = stream.read(&mut request).await.expect("request");
        stream.write_all(OK).await.expect("answer");
        String::from_utf8_lossy(&request[..read]).into_owned()
    });
    let client = client(&[format!("127.0.0.1:{port}")]);

    let response = client
        .send(HttpRequest::post(
            format!("http://127.0.0.1:{port}/token"),
            "application/x-www-form-urlencoded",
            b"grant_type=authorization_code".to_vec(),
        ))
        .await
        .expect("response");
    assert_eq!(response.status, 200);

    let request = received.await.expect("server");
    assert!(request.starts_with("POST /token HTTP/1.1"), "{request}");
    assert!(request.contains("content-type: application/x-www-form-urlencoded"));
    assert!(request.ends_with("grant_type=authorization_code"));
    assert!(request.contains("user-agent: hodor"));
}
