//! Mail adapter.
//!
//! Implements the notification context's [`EmailSender`] by speaking to a
//! mail server. A separate crate so that the mail library and what it
//! depends on stay out of every binary that sends no mail.
//!
//! See `docs/architecture/contexts/notification.md`, "Configuration".

use hodor_kernel::{DomainError, Secret};
use hodor_notification::api::{Email, EmailSender};
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::time::Duration;

/// How long the mail server is waited for before delivery gives up. The
/// message stays locked for this long at most.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Why a [`SmtpSender`] could not be set up. Never contains the mail
/// server's address, which may hold a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationError {
    /// The mail server's address is not one this adapter understands.
    InvalidServerAddress,
    /// The address messages are sent from is not an email address.
    InvalidSenderAddress,
}

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidServerAddress => {
                "the mail server address is not valid; expected, for example, \
                 smtps://user:password@mail.example.com:465"
            }
            Self::InvalidSenderAddress => {
                "the sender address is not valid; expected, for example, \
                 Hodor <no-reply@example.com>"
            }
        })
    }
}

impl std::error::Error for ConfigurationError {}

/// [`EmailSender`] over the Simple Mail Transfer Protocol.
pub struct SmtpSender {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl std::fmt::Debug for SmtpSender {
    /// The transport is left out: it holds the mail server's password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpSender")
            .field("from", &self.from.email.to_string())
            .finish_non_exhaustive()
    }
}

impl SmtpSender {
    /// Sets up delivery to the mail server at `url`, with every message
    /// sent from `from`.
    ///
    /// The address has the form `scheme://user:password@host:port`:
    /// `smtps` speaks over an encrypted connection from the start, `smtp`
    /// with `?tls=required` encrypts after connecting, and plain `smtp`
    /// does not encrypt at all and is for development only.
    ///
    /// Nothing is connected yet; the mail server is first spoken to when a
    /// message is sent.
    ///
    /// # Errors
    ///
    /// Returns an error if either address is not valid.
    pub fn new(url: &Secret<String>, from: &str) -> Result<Self, ConfigurationError> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(url.expose())
            .map_err(|_| ConfigurationError::InvalidServerAddress)?
            .timeout(Some(TIMEOUT))
            .build();
        let from = from
            .parse()
            .map_err(|_| ConfigurationError::InvalidSenderAddress)?;
        Ok(Self { transport, from })
    }
}

fn failed(detail: String) -> DomainError {
    DomainError::internal(
        "notification.delivery_failed",
        "the message could not be delivered",
    )
    .with_detail(detail)
}

#[async_trait::async_trait]
impl EmailSender for SmtpSender {
    async fn send(&self, email: &Email) -> Result<(), DomainError> {
        // Trying again would not help: the address will not change.
        let to: Mailbox = email.recipient.parse().map_err(|_| {
            DomainError::invalid(
                "notification.recipient_refused",
                "the recipient cannot be addressed",
            )
        })?;
        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(email.subject.as_str())
            .header(ContentType::TEXT_PLAIN)
            .body(email.body.clone())
            .map_err(|error| failed(format!("the message could not be built: {error}")))?;
        self.transport
            .send(message)
            .await
            .map_err(|error| failed(error.to_string()))?;
        Ok(())
    }
}
