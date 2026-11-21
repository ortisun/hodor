//! A message: what is to be sent to whom, and what became of it.

use crate::domain::event::NotificationEvent;
use crate::domain::template::{Email, Template};
use hodor_kernel::{DomainError, Timestamp};
use std::collections::BTreeMap;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a message.
    MessageId
);

/// How many times delivery of a message is tried.
pub const MAX_ATTEMPTS: u32 = 8;
/// The wait after the first failed delivery. Each later wait is twice the
/// one before.
const FIRST_RETRY_DELAY: Duration = Duration::seconds(30);
/// The longest wait between two tries.
const LONGEST_RETRY_DELAY: Duration = Duration::minutes(30);
/// The longest email address accepted.
const MAX_RECIPIENT_LENGTH: usize = 254;
/// The longest value of a variable.
const MAX_VALUE_LENGTH: usize = 2_000;
/// The longest text kept from a failed delivery.
const MAX_ERROR_LENGTH: usize = 500;

/// The language a message is written in, as a tag such as `en` or `pt-BR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locale(String);

impl Locale {
    /// Accepts a language tag.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the tag is empty, too long or has characters
    /// other than letters, digits and hyphens.
    pub fn parse(tag: &str) -> Result<Self, DomainError> {
        let acceptable = !tag.is_empty()
            && tag.len() <= 35
            && tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if acceptable {
            Ok(Self(tag.to_owned()))
        } else {
            Err(DomainError::invalid(
                "notification.invalid_locale",
                "the language is not a valid language tag",
            ))
        }
    }

    /// English, the language every template exists in.
    #[must_use]
    pub fn english() -> Self {
        Self("en".to_owned())
    }

    /// The tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What became of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageStatus {
    /// Waiting to be delivered.
    Pending,
    /// The mail server accepted it.
    Sent,
    /// Delivery failed too many times, or the message could not be written.
    Failed,
    /// It was not delivered before it expired.
    Expired,
}

impl MessageStatus {
    /// The name the status is stored and reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sent => "sent",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    /// Reads a stored status.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if there is no such status.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        [Self::Pending, Self::Sent, Self::Failed, Self::Expired]
            .into_iter()
            .find(|status| status.as_str() == value)
            .ok_or_else(|| {
                DomainError::invalid(
                    "notification.unknown_status",
                    "there is no such message status",
                )
            })
    }
}

/// Everything stored about a message.
#[derive(Clone, PartialEq, Eq)]
pub struct MessageSnapshot {
    /// The message.
    pub id: MessageId,
    /// The email address to send to.
    pub recipient: String,
    /// Which message this is.
    pub template: Template,
    /// The language to write it in.
    pub locale: Locale,
    /// The values the template needs. Empty once the message is no longer
    /// pending.
    pub variables: BTreeMap<String, String>,
    /// What became of it.
    pub status: MessageStatus,
    /// How many times delivery was tried.
    pub attempts: u32,
    /// When to try next.
    pub next_attempt_at: Timestamp,
    /// After this moment the message is no longer worth sending.
    pub expires_at: Timestamp,
    /// What went wrong the last time, for operators.
    pub last_error: Option<String>,
    /// When it was put in the queue.
    pub created_at: Timestamp,
    /// When the mail server accepted it.
    pub sent_at: Option<Timestamp>,
}

impl std::fmt::Debug for MessageSnapshot {
    /// The variables are left out: a link in them is as good as a token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageSnapshot")
            .field("id", &self.id)
            .field("template", &self.template)
            .field("status", &self.status)
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}

/// A message in the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    state: MessageSnapshot,
}

impl Message {
    /// Creates a message that is waiting to be delivered.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the recipient is not an email address, if the
    /// variables are not exactly the ones the template needs, if a value
    /// has a line break or other control character, or if the message
    /// would already be expired.
    pub fn enqueue(
        recipient: &str,
        template: Template,
        locale: Locale,
        variables: BTreeMap<String, String>,
        expires_at: Timestamp,
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        check_recipient(recipient)?;
        check_variables(template, &variables)?;
        if expires_at <= now {
            return Err(DomainError::invalid(
                "notification.already_expired",
                "the message would expire before it could be sent",
            ));
        }
        Ok(Self {
            state: MessageSnapshot {
                id: MessageId::generate(),
                recipient: recipient.to_owned(),
                template,
                locale,
                variables,
                status: MessageStatus::Pending,
                attempts: 0,
                next_attempt_at: now,
                expires_at,
                last_error: None,
                created_at: now,
                sent_at: None,
            },
        })
    }

    /// Rebuilds a message from storage.
    #[must_use]
    pub const fn from_snapshot(state: MessageSnapshot) -> Self {
        Self { state }
    }

    /// The message's identifier.
    #[must_use]
    pub const fn id(&self) -> MessageId {
        self.state.id
    }

    /// Everything stored about the message.
    #[must_use]
    pub const fn snapshot(&self) -> &MessageSnapshot {
        &self.state
    }

    /// Whether the message is still waiting to be delivered.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.state.status == MessageStatus::Pending
    }

    /// Whether the message is no longer worth sending at `now`.
    #[must_use]
    pub fn is_expired_at(&self, now: Timestamp) -> bool {
        now >= self.state.expires_at
    }

    /// Writes the message in the recipient's language.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if a variable the template needs is missing.
    pub fn render(&self) -> Result<Email, DomainError> {
        self.state.template.render(
            &self.state.recipient,
            self.state.locale.as_str(),
            &self.state.variables,
        )
    }

    /// Records that the mail server accepted the message.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the message is not pending.
    pub fn mark_sent(&mut self, now: Timestamp) -> Result<NotificationEvent, DomainError> {
        self.require_pending()?;
        self.state.attempts += 1;
        self.state.sent_at = Some(now);
        self.state.last_error = None;
        self.finish(MessageStatus::Sent);
        Ok(NotificationEvent::MessageSent {
            message_id: self.state.id,
            template: self.state.template.key(),
        })
    }

    /// Records that the message was not delivered before it expired.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the message is not pending.
    pub fn expire(&mut self) -> Result<NotificationEvent, DomainError> {
        self.require_pending()?;
        self.finish(MessageStatus::Expired);
        Ok(self.failed_event())
    }

    /// Records a failed delivery. The message waits and is tried again,
    /// unless this was the last try: then it fails for good and the event
    /// that says so is returned.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the message is not pending.
    pub fn record_failure(
        &mut self,
        now: Timestamp,
        error: &str,
    ) -> Result<Option<NotificationEvent>, DomainError> {
        self.require_pending()?;
        self.state.attempts += 1;
        self.state.last_error = Some(shortened(error));
        if self.state.attempts >= MAX_ATTEMPTS {
            self.finish(MessageStatus::Failed);
            return Ok(Some(self.failed_event()));
        }
        self.state.next_attempt_at = now + retry_delay(self.state.attempts);
        Ok(None)
    }

    /// Records that the message can never be delivered, so trying again
    /// would not help.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` if the message is not pending.
    pub fn fail_for_good(&mut self, error: &str) -> Result<NotificationEvent, DomainError> {
        self.require_pending()?;
        self.state.last_error = Some(shortened(error));
        self.finish(MessageStatus::Failed);
        Ok(self.failed_event())
    }

    fn require_pending(&self) -> Result<(), DomainError> {
        if self.is_pending() {
            Ok(())
        } else {
            Err(DomainError::conflict(
                "notification.not_pending",
                "the message is no longer waiting to be delivered",
            ))
        }
    }

    /// Leaves the pending state and erases what the message contained.
    fn finish(&mut self, status: MessageStatus) {
        self.state.status = status;
        self.state.variables.clear();
    }

    fn failed_event(&self) -> NotificationEvent {
        NotificationEvent::MessageFailed {
            message_id: self.state.id,
            template: self.state.template.key(),
            status: self.state.status.as_str(),
        }
    }
}

/// The wait after the given number of failed tries: 30 seconds, then twice
/// as long each time, up to 30 minutes.
fn retry_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    (FIRST_RETRY_DELAY * 2_i32.pow(doublings)).min(LONGEST_RETRY_DELAY)
}

fn shortened(error: &str) -> String {
    let mut end = error.len().min(MAX_ERROR_LENGTH);
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    error[..end].to_owned()
}

fn check_recipient(recipient: &str) -> Result<(), DomainError> {
    let invalid = || {
        DomainError::invalid(
            "notification.invalid_recipient",
            "the recipient is not an email address",
        )
    };
    if recipient.len() > MAX_RECIPIENT_LENGTH
        || recipient
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '<' | '>' | ',' | ';'))
    {
        return Err(invalid());
    }
    match recipient.split_once('@') {
        Some((local, domain))
            if !local.is_empty() && !domain.is_empty() && !domain.contains('@') =>
        {
            Ok(())
        }
        _ => Err(invalid()),
    }
}

fn check_variables(
    template: Template,
    variables: &BTreeMap<String, String>,
) -> Result<(), DomainError> {
    let needed = template.variables();
    for name in needed {
        if !variables.contains_key(*name) {
            return Err(DomainError::invalid(
                "notification.missing_variable",
                "the message is missing a value it needs",
            )
            .with_detail(format!("variable `{name}` was not given")));
        }
    }
    for (name, value) in variables {
        if !needed.contains(&name.as_str()) {
            return Err(DomainError::invalid(
                "notification.unknown_variable",
                "the message was given a value it has no place for",
            )
            .with_detail(format!("variable `{name}` is not used by the template")));
        }
        if value.is_empty() || value.len() > MAX_VALUE_LENGTH || value.chars().any(char::is_control)
        {
            return Err(DomainError::invalid(
                "notification.invalid_variable",
                "a value of the message is empty, too long or has a line break",
            )
            .with_detail(format!("variable `{name}` is not acceptable")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn variables() -> BTreeMap<String, String> {
        [
            ("link", "https://example.com/verify?token=abc"),
            ("tenant_name", "Example"),
            ("expires_in", "24 hours"),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
    }

    fn message() -> Message {
        Message::enqueue(
            "person@example.com",
            Template::EmailVerification,
            Locale::english(),
            variables(),
            NOW + Duration::hours(24),
            NOW,
        )
        .expect("valid")
    }

    fn code(result: Result<Message, DomainError>) -> String {
        result.expect_err("refused").code().to_owned()
    }

    #[test]
    fn a_new_message_is_pending_and_due_at_once() {
        let message = message();
        let state = message.snapshot();
        assert_eq!(state.status, MessageStatus::Pending);
        assert_eq!(state.attempts, 0);
        assert_eq!(state.next_attempt_at, NOW);
        assert!(
            message
                .render()
                .expect("renders")
                .body
                .contains("token=abc")
        );
    }

    #[test]
    fn recipients_that_are_not_addresses_are_refused() {
        for recipient in [
            "",
            "person",
            "@example.com",
            "person@",
            "a@b@c",
            "person @example.com",
            "person@example.com\nBcc: other@example.com",
            "Person <person@example.com>",
            "a@example.com,b@example.com",
        ] {
            let result = Message::enqueue(
                recipient,
                Template::PasswordChanged,
                Locale::english(),
                [("tenant_name".to_owned(), "Example".to_owned())].into(),
                NOW + Duration::hours(1),
                NOW,
            );
            assert_eq!(
                code(result),
                "notification.invalid_recipient",
                "{recipient:?}"
            );
        }
    }

    #[test]
    fn the_variables_must_be_exactly_the_ones_the_template_needs() {
        let enqueue = |variables| {
            Message::enqueue(
                "person@example.com",
                Template::EmailVerification,
                Locale::english(),
                variables,
                NOW + Duration::hours(1),
                NOW,
            )
        };
        let mut missing = variables();
        missing.remove("link");
        assert_eq!(code(enqueue(missing)), "notification.missing_variable");

        let mut extra = variables();
        extra.insert("other".to_owned(), "value".to_owned());
        assert_eq!(code(enqueue(extra)), "notification.unknown_variable");

        let mut broken = variables();
        broken.insert(
            "tenant_name".to_owned(),
            "Example\nSubject: other".to_owned(),
        );
        assert_eq!(code(enqueue(broken)), "notification.invalid_variable");

        let mut empty = variables();
        empty.insert("tenant_name".to_owned(), String::new());
        assert_eq!(code(enqueue(empty)), "notification.invalid_variable");
    }

    #[test]
    fn a_message_that_would_already_be_expired_is_refused() {
        let result = Message::enqueue(
            "person@example.com",
            Template::EmailVerification,
            Locale::english(),
            variables(),
            NOW,
            NOW,
        );
        assert_eq!(code(result), "notification.already_expired");
    }

    #[test]
    fn sending_erases_the_contents_and_keeps_the_record() {
        let mut message = message();
        let event = message.mark_sent(NOW + Duration::seconds(5)).expect("sent");
        let state = message.snapshot();
        assert_eq!(state.status, MessageStatus::Sent);
        assert_eq!(state.attempts, 1);
        assert_eq!(state.sent_at, Some(NOW + Duration::seconds(5)));
        assert!(state.variables.is_empty());
        assert_eq!(state.recipient, "person@example.com");
        assert!(matches!(event, NotificationEvent::MessageSent { .. }));
        assert!(message.mark_sent(NOW).is_err());
        assert!(message.expire().is_err());
        assert!(message.record_failure(NOW, "late").is_err());
    }

    #[test]
    fn failures_wait_twice_as_long_each_time_and_then_fail_for_good() {
        let mut message = message();
        let mut waits = Vec::new();
        for attempt in 1..MAX_ATTEMPTS {
            let event = message
                .record_failure(NOW, "connection refused")
                .expect("pending");
            assert_eq!(event, None, "attempt {attempt}");
            assert!(!message.snapshot().variables.is_empty());
            waits.push((message.snapshot().next_attempt_at - NOW).whole_seconds());
        }
        assert_eq!(waits, [30, 60, 120, 240, 480, 960, 1800]);

        let event = message
            .record_failure(NOW, "connection refused")
            .expect("pending");
        assert!(matches!(
            event,
            Some(NotificationEvent::MessageFailed {
                status: "failed",
                ..
            })
        ));
        let state = message.snapshot();
        assert_eq!(state.status, MessageStatus::Failed);
        assert_eq!(state.attempts, MAX_ATTEMPTS);
        assert!(state.variables.is_empty());
        assert_eq!(state.last_error.as_deref(), Some("connection refused"));
    }

    #[test]
    fn expiring_erases_the_contents() {
        let mut message = message();
        assert!(!message.is_expired_at(NOW + Duration::hours(24) - Duration::seconds(1)));
        assert!(message.is_expired_at(NOW + Duration::hours(24)));
        let event = message.expire().expect("pending");
        assert!(matches!(
            event,
            NotificationEvent::MessageFailed {
                status: "expired",
                ..
            }
        ));
        assert_eq!(message.snapshot().status, MessageStatus::Expired);
        assert!(message.snapshot().variables.is_empty());
    }

    #[test]
    fn failing_for_good_does_not_count_as_a_try() {
        let mut message = message();
        message.fail_for_good("no such variable").expect("pending");
        assert_eq!(message.snapshot().status, MessageStatus::Failed);
        assert_eq!(message.snapshot().attempts, 0);
        assert!(message.snapshot().variables.is_empty());
    }

    #[test]
    fn debug_output_never_shows_the_variables() {
        let shown = format!("{:?}", message());
        assert!(!shown.contains("token=abc"), "{shown}");
        assert!(!shown.contains("person@example.com"), "{shown}");
    }

    #[test]
    fn locales_are_language_tags() {
        assert!(Locale::parse("en").is_ok());
        assert!(Locale::parse("pt-BR").is_ok());
        assert!(Locale::parse("").is_err());
        assert!(Locale::parse("en US").is_err());
        assert!(Locale::parse("en\n").is_err());
        assert!(Locale::parse(&"a".repeat(36)).is_err());
    }

    #[test]
    fn stored_statuses_round_trip() {
        for status in [
            MessageStatus::Pending,
            MessageStatus::Sent,
            MessageStatus::Failed,
            MessageStatus::Expired,
        ] {
            assert_eq!(
                MessageStatus::from_stored(status.as_str()).ok(),
                Some(status)
            );
        }
        assert!(MessageStatus::from_stored("nope").is_err());
    }

    proptest! {
        #[test]
        fn a_long_error_is_shortened_without_breaking_a_character(error in "\\PC{0,900}") {
            let mut message = message();
            message.record_failure(NOW, &error).expect("pending");
            let kept = message.snapshot().last_error.clone().expect("kept");
            prop_assert!(kept.len() <= MAX_ERROR_LENGTH);
            prop_assert!(error.starts_with(&kept));
        }

        #[test]
        fn the_wait_never_exceeds_the_longest_one(failures in 0u32..10_000) {
            let wait = retry_delay(failures);
            prop_assert!(wait >= FIRST_RETRY_DELAY);
            prop_assert!(wait <= LONGEST_RETRY_DELAY);
        }

        #[test]
        fn a_value_with_a_control_character_is_always_refused(
            before in "[a-z]{0,10}", control in "[\\x00-\\x1f\\x7f]", after in "[a-z]{0,10}"
        ) {
            let result = Message::enqueue(
                "person@example.com",
                Template::PasswordChanged,
                Locale::english(),
                [("tenant_name".to_owned(), format!("{before}{control}{after}"))].into(),
                NOW + Duration::hours(1),
                NOW,
            );
            prop_assert!(result.is_err());
        }
    }
}
