//! The signature of a webhook, made by Hodor and checked by the
//! `standardwebhooks` crate, an implementation of Standard Webhooks that
//! shares no code with Hodor's: its HMAC is `hmac-sha256`, not
//! `aws-lc-rs`. See `docs/architecture/contexts/webhooks.md`, "How it is
//! signed".

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_adapters_crypto::AwsLcHmacSha256;
use hodor_webhooks::api::{HmacSha256, signature_header, signed_content};
use http::{HeaderMap, HeaderValue};
use standardwebhooks::Webhook;

const BODY: &str = r#"{"id":"0193f2c4-7d1e-7a3b-9c55-2f0e8a1b4c6d","type":"session.started","data":{"user_id":"…"}}"#;
const ID: &str = "0193f2c4-7d1e-7a3b-9c55-2f0e8a1b4c6d";
const TIMESTAMP: i64 = 1_795_000_000;

fn headers(signature: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("webhook-id", HeaderValue::from_static(ID));
    headers.insert(
        "webhook-timestamp",
        HeaderValue::from_str(&TIMESTAMP.to_string()).expect("header"),
    );
    headers.insert(
        "webhook-signature",
        HeaderValue::from_str(signature).expect("header"),
    );
    headers
}

fn sign(keys: &[&[u8]]) -> String {
    let content = signed_content(ID, TIMESTAMP, BODY);
    let signatures: Vec<[u8; 32]> = keys
        .iter()
        .map(|key| AwsLcHmacSha256.mac(key, &content))
        .collect();
    signature_header(&signatures)
}

fn receiver(key: &[u8]) -> Webhook {
    // What an administrator copies from the answer that showed the secret.
    Webhook::new(&format!("whsec_{}", STANDARD.encode(key))).expect("secret")
}

#[test]
fn a_signature_hodor_makes_checks_with_another_implementation() {
    let key = [7_u8; 32];
    let headers = headers(&sign(&[&key]));
    receiver(&key)
        .verify_with_timestamp(BODY.as_bytes(), &headers, TIMESTAMP + 30)
        .expect("the signature checks");
    // The library makes the very same header value.
    assert_eq!(
        receiver(&key)
            .sign(ID, TIMESTAMP, BODY.as_bytes())
            .expect("signed"),
        sign(&[&key])
    );
}

#[test]
fn during_a_rotation_either_secret_checks() {
    let (new, old) = ([1_u8; 32], [2_u8; 32]);
    let headers = headers(&sign(&[&new, &old]));
    for key in [new, old] {
        receiver(&key)
            .verify_with_timestamp(BODY.as_bytes(), &headers, TIMESTAMP)
            .expect("checks with either");
    }
    assert!(
        receiver(&[3_u8; 32])
            .verify_with_timestamp(BODY.as_bytes(), &headers, TIMESTAMP)
            .is_err()
    );
}

#[test]
fn a_changed_body_another_secret_or_an_old_timestamp_does_not_check() {
    let key = [7_u8; 32];
    let headers = headers(&sign(&[&key]));
    let changed = BODY.replace("session.started", "session.revoked");
    assert!(
        receiver(&key)
            .verify_with_timestamp(changed.as_bytes(), &headers, TIMESTAMP)
            .is_err()
    );
    assert!(
        receiver(&[8_u8; 32])
            .verify_with_timestamp(BODY.as_bytes(), &headers, TIMESTAMP)
            .is_err()
    );
    // A request replayed an hour later is refused by the receiver's clock.
    assert!(
        receiver(&key)
            .verify_with_timestamp(BODY.as_bytes(), &headers, TIMESTAMP + 3_600)
            .is_err()
    );
}
