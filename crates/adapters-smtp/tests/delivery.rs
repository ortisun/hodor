//! Delivery to a real mail server, running in a container. What it
//! received is read back through its own interface.

use hodor_adapters_smtp::{ConfigurationError, SmtpSender};
use hodor_kernel::Secret;
use hodor_notification::api::{Email, EmailSender};
use std::time::Duration;
use testcontainers::core::IntoContainerPort as _;
use testcontainers::runners::AsyncRunner as _;
use testcontainers::{ContainerAsync, GenericImage};

struct MailServer {
    _container: ContainerAsync<GenericImage>,
    smtp_port: u16,
    api: String,
}

impl MailServer {
    async fn start() -> Self {
        let container = GenericImage::new("axllent/mailpit", "v1.27")
            .with_exposed_port(1025.tcp())
            .with_exposed_port(8025.tcp())
            .start()
            .await
            .expect("start the mail server");
        let smtp_port = container.get_host_port_ipv4(1025).await.expect("port");
        let api_port = container.get_host_port_ipv4(8025).await.expect("port");
        let server = Self {
            _container: container,
            smtp_port,
            api: format!("http://127.0.0.1:{api_port}/api/v1"),
        };
        for _ in 0..100 {
            if server.get("messages").await.is_some() {
                return server;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the mail server did not become ready");
    }

    async fn get(&self, path: &str) -> Option<serde_json::Value> {
        let response = reqwest::get(format!("{}/{path}", self.api)).await.ok()?;
        let text = response.error_for_status().ok()?.text().await.ok()?;
        serde_json::from_str(&text).ok()
    }

    fn sender(&self) -> SmtpSender {
        let url = Secret::from(format!("smtp://127.0.0.1:{}", self.smtp_port));
        SmtpSender::new(&url, "Hodor <no-reply@example.com>").expect("valid configuration")
    }

    /// The messages received, newest first, each in full.
    async fn received(&self) -> Vec<serde_json::Value> {
        let list = self.get("messages").await.expect("list");
        let mut received = Vec::new();
        for summary in list["messages"].as_array().expect("messages") {
            let id = summary["ID"].as_str().expect("identifier");
            received.push(self.get(&format!("message/{id}")).await.expect("message"));
        }
        received
    }
}

fn email() -> Email {
    Email {
        recipient: "pessoa@example.com".to_owned(),
        subject: "Confirme seu endereço de email em Padaria São João".to_owned(),
        body:
            "Olá,\n\nAbra este link:\n\nhttps://example.com/verify?token=0a1b2c&next=%2Finicio\n\n\
               O link funciona uma única vez.\n"
                .to_owned(),
    }
}

#[tokio::test]
async fn a_message_arrives_as_it_was_written() {
    let server = MailServer::start().await;

    server.sender().send(&email()).await.expect("accepted");

    let received = server.received().await;
    assert_eq!(received.len(), 1);
    let message = &received[0];
    assert_eq!(message["To"][0]["Address"], "pessoa@example.com");
    assert_eq!(message["From"]["Address"], "no-reply@example.com");
    assert_eq!(message["From"]["Name"], "Hodor");
    assert_eq!(message["Subject"], email().subject.as_str());
    let text = message["Text"]
        .as_str()
        .expect("text")
        .replace("\r\n", "\n");
    assert_eq!(text.trim_end(), email().body.trim_end());
    // Plain text only: there is no other version of the message.
    assert_eq!(message["HTML"], "");
    assert!(message["Attachments"].as_array().is_none_or(Vec::is_empty));
}

#[tokio::test]
async fn each_message_is_delivered_separately() {
    let server = MailServer::start().await;
    let sender = server.sender();

    for index in 0..3 {
        let mut message = email();
        message.recipient = format!("person{index}@example.com");
        sender.send(&message).await.expect("accepted");
    }

    assert_eq!(server.received().await.len(), 3);
}

#[tokio::test]
async fn a_mail_server_that_cannot_be_reached_is_an_error_to_retry() {
    // Nothing listens on this port: bind one, note it, and let it go.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("address").port();
    drop(listener);
    let url = Secret::from(format!("smtp://user:hunter2@127.0.0.1:{port}"));
    let sender = SmtpSender::new(&url, "no-reply@example.com").expect("valid configuration");

    let error = sender.send(&email()).await.expect_err("unreachable");

    assert_eq!(error.code(), "notification.delivery_failed");
    let shown = format!("{error} {:?} {sender:?}", error.detail());
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(!shown.contains("0a1b2c"), "{shown}");
}

#[test]
fn configuration_that_is_not_valid_is_refused_without_repeating_it() {
    let good = Secret::from("smtps://user:hunter2@mail.example.com:465".to_owned());
    for (url, from, expected) in [
        (
            "http://user:hunter2@mail.example.com",
            "no-reply@example.com",
            ConfigurationError::InvalidServerAddress,
        ),
        (
            "user:hunter2 at mail",
            "no-reply@example.com",
            ConfigurationError::InvalidServerAddress,
        ),
        (
            good.expose().as_str(),
            "not an address",
            ConfigurationError::InvalidSenderAddress,
        ),
    ] {
        let error = SmtpSender::new(&Secret::from(url.to_owned()), from).expect_err("refused");
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("hunter2"));
    }
    let sender = SmtpSender::new(&good, "Hodor <no-reply@example.com>").expect("valid");
    assert!(!format!("{sender:?}").contains("hunter2"));
}

#[tokio::test]
async fn a_recipient_that_cannot_be_addressed_is_an_error_not_to_retry() {
    let url = Secret::from("smtp://127.0.0.1:1".to_owned());
    let sender = SmtpSender::new(&url, "no-reply@example.com").expect("valid configuration");
    let mut message = email();
    message.recipient = "not an address".to_owned();

    let error = sender.send(&message).await.expect_err("refused");

    assert_eq!(error.kind(), hodor_kernel::ErrorKind::Invalid);
    assert_eq!(error.code(), "notification.recipient_refused");
}
