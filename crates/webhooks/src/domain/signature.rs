//! What is sent: the envelope of an event, and its signature as Standard
//! Webhooks writes it. See `docs/architecture/contexts/webhooks.md`, "What
//! is sent" and "How it is signed".

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_kernel::{Actor, EventEnvelope, EventId, TenantId};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;

/// Version 1 of the envelope. Fields may be added, never removed or
/// renamed.
#[derive(Serialize)]
struct Envelope<'a> {
    id: EventId,
    #[serde(rename = "type")]
    event_type: &'a str,
    timestamp: String,
    tenant_id: TenantId,
    actor: &'a Actor,
    data: &'a serde_json::Value,
}

/// The body sent for an event: its identifier, type, moment, tenant and
/// actor, and its own fields as the outbox holds them.
#[must_use]
pub fn envelope(event: &EventEnvelope) -> String {
    let metadata = &event.metadata;
    let body = Envelope {
        id: metadata.event_id,
        event_type: &event.event_type,
        timestamp: metadata.occurred_at.format(&Rfc3339).unwrap_or_default(),
        tenant_id: metadata.tenant_id,
        actor: &metadata.actor,
        data: &event.payload,
    };
    // Every field is a string, an identifier or JSON already: writing it
    // cannot fail.
    serde_json::to_string(&body).unwrap_or_default()
}

/// What is signed: `{webhook-id}.{webhook-timestamp}.{body}`.
#[must_use]
pub fn signed_content(webhook_id: &str, timestamp: i64, body: &str) -> Vec<u8> {
    format!("{webhook_id}.{timestamp}.{body}").into_bytes()
}

/// The value of `webhook-signature`: `v1,` and the Base64 of each
/// signature, separated by spaces.
#[must_use]
pub fn signature_header(signatures: &[[u8; 32]]) -> String {
    signatures
        .iter()
        .map(|signature| format!("v1,{}", STANDARD.encode(signature)))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::clock::testing::FixedClock;
    use hodor_kernel::{CorrelationId, EventMetadata, Timestamp, UserId};

    #[test]
    fn the_envelope_holds_the_events_fields_and_its_metadata() {
        let user = UserId::generate();
        let metadata = EventMetadata::new(
            TenantId::generate(),
            Actor::User(user),
            CorrelationId::generate(),
            &FixedClock::at(Timestamp::UNIX_EPOCH),
        );
        let event = EventEnvelope {
            metadata: metadata.clone(),
            event_type: "session.started".to_owned(),
            payload: serde_json::json!({ "session_id": "s", "methods": ["pwd"] }),
        };
        let body: serde_json::Value = serde_json::from_str(&envelope(&event)).expect("JSON");
        assert_eq!(
            body,
            serde_json::json!({
                "id": metadata.event_id.to_string(),
                "type": "session.started",
                "timestamp": "1970-01-01T00:00:00Z",
                "tenant_id": metadata.tenant_id.to_string(),
                "actor": { "kind": "user", "id": user.to_string() },
                "data": { "session_id": "s", "methods": ["pwd"] },
            })
        );
    }

    #[test]
    fn the_header_carries_one_value_per_signature() {
        assert_eq!(signature_header(&[]), "");
        assert_eq!(
            signature_header(&[[0; 32], [255; 32]]),
            "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
             v1,//////////////////////////////////////////8="
        );
        assert_eq!(signed_content("msg", 7, "{}"), b"msg.7.{}");
    }
}
