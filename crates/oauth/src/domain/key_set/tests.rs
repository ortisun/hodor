use super::*;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

const NOW: Timestamp = Timestamp::UNIX_EPOCH;
const ADDRESS: &str = "https://payroll.example.com/jwks";

fn encoded(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn p256(kid: Option<&str>) -> Value {
    let mut key =
        json!({"kty": "EC", "crv": "P-256", "x": encoded(&[1; 32]), "y": encoded(&[2; 32])});
    if let Some(kid) = kid {
        key["kid"] = json!(kid);
    }
    key
}

fn keys(set: &Value) -> Vec<ClientKey> {
    published_keys(set.to_string().as_bytes(), NOW).expect("a set")
}

/// A token whose header is `header`; nothing else of it is read.
fn signed(header: &Value) -> String {
    format!(
        "{}.e30.c2lnbmF0dXJl",
        encoded(header.to_string().as_bytes())
    )
}

#[test]
fn an_address_has_the_form_of_a_back_channel_logout_address() {
    for good in [
        ADDRESS,
        "https://payroll.example.com:8443/.well-known/jwks.json?v=2",
        "http://127.0.0.1:9/jwks",
    ] {
        assert!(check_jwks_uri(good).is_ok(), "{good}");
    }
    let long = format!("https://payroll.example.com/{}", "k".repeat(2000));
    for bad in [
        "",
        "payroll.example.com/jwks",
        "ftp://payroll.example.com/jwks",
        "https://name:password@payroll.example.com/jwks",
        "https://payroll.example.com/jwks#current",
        "https://payroll.example.com/my keys",
        long.as_str(),
    ] {
        assert_eq!(
            check_jwks_uri(bad).expect_err(bad).code(),
            "oauth.client_jwks_uri_invalid"
        );
    }
}

#[test]
fn a_set_keeps_the_signature_keys_hodor_accepts_and_leaves_out_the_rest() {
    let mut private = p256(Some("private"));
    private["d"] = json!(encoded(&[3; 32]));
    let mut encryption = p256(Some("encryption"));
    encryption["use"] = json!("enc");
    let set = json!({"keys": [
        p256(Some("one")),
        private,
        encryption,
        {"kty": "oct", "kid": "shared", "k": "c2VjcmV0"},
        "not a key",
        p256(None),
    ]});
    let kept = keys(&set);
    let ids: Vec<&str> = kept.iter().map(|key| key.key_id.as_str()).collect();
    assert_eq!(
        ids,
        ["one", ""],
        "a key without a `kid` is kept without one"
    );
    assert!(kept.iter().all(|key| !key.jwk.contains("\"d\"")));
}

#[test]
fn a_set_is_read_up_to_twenty_keys_and_an_answer_that_is_no_set_is_none() {
    let many: Vec<Value> = (0..30).map(|n| p256(Some(&format!("key-{n}")))).collect();
    let kept = keys(&json!({ "keys": many }));
    assert_eq!(kept.len(), MAX_PUBLISHED_KEYS);
    assert_eq!(kept[19].key_id, "key-19");
    assert!(keys(&json!({"keys": []})).is_empty(), "a set of no keys");
    for not_a_set in [
        b"not json".as_slice(),
        b"[]",
        b"{\"keys\": {}}",
        b"{\"other\": []}",
    ] {
        assert!(published_keys(not_a_set, NOW).is_none());
    }
    let padded = format!(
        "{{\"keys\": [], \"padding\": \"{}\"}}",
        " ".repeat(MAX_KEY_SET_BYTES)
    );
    assert!(published_keys(padded.as_bytes(), NOW).is_none(), "too long");
}

#[test]
fn a_header_names_an_unknown_key_only_when_no_kept_key_could_have_signed() {
    let kept = keys(&json!({"keys": [p256(Some("one"))]}));
    let es256 = |kid: Option<&str>| {
        let mut header = json!({"alg": "ES256"});
        if let Some(kid) = kid {
            header["kid"] = json!(kid);
        }
        signed(&header)
    };
    assert!(!names_unknown_key(&es256(Some("one")), &kept));
    assert!(names_unknown_key(&es256(Some("two")), &kept));
    assert!(!names_unknown_key(&es256(None), &kept), "the one key fits");
    assert!(
        names_unknown_key(&signed(&json!({"alg": "RS256"})), &kept),
        "no kept key fits the algorithm"
    );
    assert!(names_unknown_key(&es256(Some("one")), &[]), "nothing kept");
    // Headers that would be refused anyway name no key to fetch for.
    for refused in [
        signed(&json!({"alg": "none", "kid": "two"})),
        signed(&json!({"alg": "HS256", "kid": "two"})),
        signed(&json!({"alg": "ES256", "kid": 7})),
        "not a token".to_owned(),
        format!("{}.e30.", "A".repeat(MAX_REQUEST_OBJECT_BYTES)),
    ] {
        assert!(!names_unknown_key(&refused, &[]), "{refused}");
    }
}

#[test]
fn a_key_without_a_kid_is_never_the_one_a_kid_names() {
    let kept = keys(&json!({"keys": [p256(None)]}));
    assert!(names_unknown_key(
        &signed(&json!({"alg": "ES256", "kid": ""})),
        &kept
    ));
    assert!(!names_unknown_key(&signed(&json!({"alg": "ES256"})), &kept));
}

fn fetched(at: Timestamp, asked_at: Timestamp) -> KeptSet {
    KeptSet {
        address: ADDRESS.to_owned(),
        keys: keys(&json!({"keys": [p256(Some("one"))]})),
        fetched_at: Some(at),
        asked_at,
    }
}

#[test]
fn a_set_is_used_for_an_hour_and_fetched_again_for_an_unknown_key_once_a_minute() {
    let known = signed(&json!({"alg": "ES256", "kid": "one"}));
    let unknown = signed(&json!({"alg": "ES256", "kid": "two"}));
    assert_eq!(
        next_step(None, ADDRESS, Some(&known), NOW),
        KeySetStep::Fetch,
        "nothing kept"
    );
    let kept = fetched(NOW, NOW);
    let later = |by: Duration| NOW + by;
    assert!(matches!(
        next_step(Some(&kept), ADDRESS, Some(&known), later(Duration::minutes(59))),
        KeySetStep::Use(keys) if keys.len() == 1
    ));
    assert!(matches!(
        next_step(Some(&kept), ADDRESS, None, later(Duration::minutes(59))),
        KeySetStep::Use(keys) if keys.len() == 1
    ));
    // An unknown key within the minute of the last fetch is checked against
    // what is kept; after it, the address is fetched.
    assert!(matches!(
        next_step(Some(&kept), ADDRESS, Some(&unknown), later(Duration::seconds(59))),
        KeySetStep::Use(keys) if keys.len() == 1
    ));
    assert_eq!(
        next_step(
            Some(&kept),
            ADDRESS,
            Some(&unknown),
            later(Duration::minutes(1))
        ),
        KeySetStep::Fetch
    );
    // After the hour, the set is fetched again, and never used.
    assert_eq!(
        next_step(
            Some(&kept),
            ADDRESS,
            Some(&known),
            later(Duration::hours(1))
        ),
        KeySetStep::Fetch
    );
    let asked_after_the_hour = fetched(NOW, later(Duration::hours(1)));
    assert_eq!(
        next_step(
            Some(&asked_after_the_hour),
            ADDRESS,
            Some(&known),
            later(Duration::hours(1) + Duration::seconds(30))
        ),
        KeySetStep::Use(Vec::new()),
        "an old set is never used, even when no fetch may be made"
    );
    // A set kept for another address is no set of this one.
    assert_eq!(
        next_step(
            Some(&kept),
            "https://payroll.example.com/other",
            Some(&known),
            NOW
        ),
        KeySetStep::Fetch
    );
}

#[test]
fn a_fetch_that_has_not_answered_counts_for_its_minute() {
    let asking = KeptSet::asked(ADDRESS.to_owned(), NOW);
    let known = signed(&json!({"alg": "ES256", "kid": "one"}));
    assert_eq!(
        next_step(
            Some(&asking),
            ADDRESS,
            Some(&known),
            NOW + Duration::seconds(3)
        ),
        KeySetStep::Use(Vec::new())
    );
    assert_eq!(
        next_step(
            Some(&asking),
            ADDRESS,
            Some(&known),
            NOW + Duration::minutes(1)
        ),
        KeySetStep::Fetch
    );
}
