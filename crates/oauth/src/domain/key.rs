//! Public keys of clients that prove who they are with `private_key_jwt`
//! (RFC 7523), kept as JSON Web Keys.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{DomainError, PublicKey, SignatureAlgorithm, Timestamp};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// The most keys a client may have.
pub const MAX_KEYS: usize = 5;
/// The longest key, written as JSON.
const MAX_KEY_BYTES: usize = 8192;
/// The longest key identifier.
const MAX_KEY_ID_LENGTH: usize = 128;
/// The shortest RSA modulus accepted, in bits.
const SHORTEST_RSA_MODULUS: usize = 2048;
/// Members that only a private or a symmetric key has.
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// A public key of a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKey {
    /// The `kid` of the key, unique among the client's keys.
    pub key_id: String,
    /// The key, written as compact JSON with its members in order.
    pub jwk: String,
    /// When it was added.
    pub added_at: Timestamp,
}

fn key_invalid(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_key_invalid",
        "a client key is a public JSON Web Key with a `kid`: EC on P-256 or P-384, RSA of at \
         least 2048 bits, or Ed25519",
    )
    .with_detail(reason)
}

fn decoded_length(key: &Map<String, Value>, member: &str) -> Result<Vec<u8>, DomainError> {
    let value = key
        .get(member)
        .and_then(Value::as_str)
        .ok_or_else(|| key_invalid("a required member is missing"))?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| key_invalid("a member is not base64url"))
}

fn rsa_modulus_bits(modulus: &[u8]) -> usize {
    let mut significant = modulus.iter().skip_while(|byte| **byte == 0);
    match significant.next() {
        None => 0,
        Some(first) => {
            let rest = significant.count();
            rest * 8 + (8 - first.leading_zeros() as usize)
        }
    }
}

/// The algorithms each kind of key may be used with.
fn algorithms_for(kind: &str, curve: Option<&str>) -> &'static [&'static str] {
    match (kind, curve) {
        ("EC", Some("P-256")) => &["ES256"],
        ("EC", Some("P-384")) => &["ES384"],
        ("RSA", _) => &["RS256", "PS256"],
        ("OKP", Some("Ed25519")) => &["EdDSA"],
        _ => &[],
    }
}

impl ClientKey {
    /// Reads a key as an administrator gives it.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_key_invalid` for anything that is not a
    /// public key of an accepted kind with a usable `kid`, and in
    /// particular for any key with a private part.
    pub fn parse(text: &str, now: Timestamp) -> Result<Self, DomainError> {
        if text.len() > MAX_KEY_BYTES {
            return Err(key_invalid("the key is too long"));
        }
        let value: Value =
            serde_json::from_str(text).map_err(|_| key_invalid("the key is not JSON"))?;
        let Value::Object(key) = value else {
            return Err(key_invalid("the key is not a JSON object"));
        };
        if PRIVATE_MEMBERS
            .iter()
            .any(|member| key.contains_key(*member))
        {
            return Err(key_invalid("the key has a private part"));
        }
        let key_id = key
            .get("kid")
            .and_then(Value::as_str)
            .filter(|kid| {
                !kid.is_empty()
                    && kid.chars().count() <= MAX_KEY_ID_LENGTH
                    && kid.bytes().all(|b| b.is_ascii_graphic())
            })
            .ok_or_else(|| key_invalid("the `kid` is missing or unusable"))?
            .to_owned();
        let kind = key
            .get("kty")
            .and_then(Value::as_str)
            .ok_or_else(|| key_invalid("the `kty` is missing"))?;
        let curve = key.get("crv").and_then(Value::as_str);
        match (kind, curve) {
            ("EC", Some(curve @ ("P-256" | "P-384"))) => {
                let length = if curve == "P-256" { 32 } else { 48 };
                for member in ["x", "y"] {
                    if decoded_length(&key, member)?.len() != length {
                        return Err(key_invalid("a coordinate has the wrong length"));
                    }
                }
            }
            ("RSA", _) => {
                if rsa_modulus_bits(&decoded_length(&key, "n")?) < SHORTEST_RSA_MODULUS {
                    return Err(key_invalid("the RSA modulus is shorter than 2048 bits"));
                }
                if decoded_length(&key, "e")?.is_empty() {
                    return Err(key_invalid("the RSA exponent is empty"));
                }
            }
            ("OKP", Some("Ed25519")) => {
                if decoded_length(&key, "x")?.len() != 32 {
                    return Err(key_invalid("an Ed25519 key is 32 bytes"));
                }
            }
            _ => return Err(key_invalid("the kind of key is not accepted")),
        }
        if key
            .get("use")
            .is_some_and(|usage| usage.as_str() != Some("sig"))
        {
            return Err(key_invalid("the key is not for signatures"));
        }
        if let Some(algorithm) = key.get("alg") {
            let fits = algorithm
                .as_str()
                .is_some_and(|name| algorithms_for(kind, curve).contains(&name));
            if !fits {
                return Err(key_invalid("the `alg` does not fit the key"));
            }
        }
        // Written with its members in order, so that the same key is always
        // the same text, however it was given or stored.
        let ordered: BTreeMap<String, Value> = key.into_iter().collect();
        let jwk = serde_json::to_string(&ordered)
            .map_err(|_| key_invalid("the key cannot be written as JSON"))?;
        Ok(Self {
            key_id,
            jwk,
            added_at: now,
        })
    }
}

impl ClientKey {
    /// The key, as the kernel's signature checking reads it, when it can
    /// have made a signature of `algorithm`: of the kind the algorithm
    /// needs, and of the key's own `alg` when it has one. Keys on P-384 and
    /// Ed25519 are kept but fit no algorithm Hodor checks yet.
    #[must_use]
    pub fn verifying_key(&self, algorithm: SignatureAlgorithm) -> Option<PublicKey> {
        let key: Map<String, Value> = serde_json::from_str(&self.jwk).ok()?;
        let member = |name: &str| {
            key.get(name)
                .and_then(Value::as_str)
                .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
        };
        let named = match algorithm {
            SignatureAlgorithm::Es256 => "ES256",
            SignatureAlgorithm::Rs256 => "RS256",
            SignatureAlgorithm::Ps256 => "PS256",
        };
        if key
            .get("alg")
            .is_some_and(|given| given.as_str() != Some(named))
        {
            return None;
        }
        let public = match (
            key.get("kty").and_then(Value::as_str),
            key.get("crv").and_then(Value::as_str),
        ) {
            (Some("EC"), Some("P-256")) => PublicKey::P256 {
                x: member("x")?,
                y: member("y")?,
            },
            (Some("RSA"), _) => PublicKey::Rsa {
                modulus: member("n")?,
                exponent: member("e")?,
            },
            _ => return None,
        };
        algorithm.fits(&public).then_some(public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn encoded(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn p256() -> Value {
        json!({"kty": "EC", "crv": "P-256", "kid": "one", "x": encoded(&[1; 32]), "y": encoded(&[2; 32])})
    }

    fn rsa(bits: usize) -> Value {
        let mut modulus = vec![0xff_u8; bits / 8];
        modulus.insert(0, 0);
        json!({"kty": "RSA", "kid": "rsa", "n": encoded(&modulus), "e": "AQAB"})
    }

    fn parse(value: &Value) -> Result<ClientKey, DomainError> {
        ClientKey::parse(&value.to_string(), NOW)
    }

    #[test]
    fn the_accepted_kinds_of_public_key_are_kept() {
        let ed25519 = json!({"kty": "OKP", "crv": "Ed25519", "kid": "ed", "x": encoded(&[3; 32]), "alg": "EdDSA", "use": "sig"});
        let p384 = json!({"kty": "EC", "crv": "P-384", "kid": "p384", "x": encoded(&[1; 48]), "y": encoded(&[2; 48]), "alg": "ES384"});
        for key in [p256(), rsa(2048), rsa(4096), ed25519, p384] {
            let parsed = parse(&key).expect("accepted");
            assert_eq!(Some(parsed.key_id.as_str()), key["kid"].as_str());
            let stored: Value = serde_json::from_str(&parsed.jwk).expect("json");
            assert_eq!(stored, key);
        }
    }

    #[test]
    fn a_key_with_a_private_part_is_never_kept() {
        for member in PRIVATE_MEMBERS {
            let mut key = p256();
            key[member] = json!(encoded(&[4; 32]));
            let error = parse(&key).expect_err(member);
            assert_eq!(error.code(), "oauth.client_key_invalid");
            assert_eq!(error.detail(), Some("the key has a private part"));
        }
    }

    #[test]
    fn a_key_that_breaks_a_rule_is_refused() {
        let mut cases = Vec::new();
        cases.push(rsa(1024));
        cases.push(rsa(2040));
        let mut no_kid = p256();
        no_kid.as_object_mut().expect("object").remove("kid");
        cases.push(no_kid);
        let mut empty_kid = p256();
        empty_kid["kid"] = json!("");
        cases.push(empty_kid);
        let mut long_kid = p256();
        long_kid["kid"] = json!("k".repeat(129));
        cases.push(long_kid);
        let mut short_coordinate = p256();
        short_coordinate["x"] = json!(encoded(&[1; 31]));
        cases.push(short_coordinate);
        let mut wrong_curve = p256();
        wrong_curve["crv"] = json!("P-521");
        cases.push(wrong_curve);
        let mut for_encryption = p256();
        for_encryption["use"] = json!("enc");
        cases.push(for_encryption);
        let mut wrong_algorithm = p256();
        wrong_algorithm["alg"] = json!("RS256");
        cases.push(wrong_algorithm);
        let mut none_algorithm = rsa(2048);
        none_algorithm["alg"] = json!("none");
        cases.push(none_algorithm);
        cases.push(json!({"kty": "oct", "kid": "symmetric"}));
        cases.push(json!(["not", "an", "object"]));
        let mut not_base64 = p256();
        not_base64["y"] = json!("***");
        cases.push(not_base64);
        for key in cases {
            let error = parse(&key).expect_err(&key.to_string());
            assert_eq!(error.code(), "oauth.client_key_invalid", "{key}");
        }
        assert!(ClientKey::parse("not json", NOW).is_err());
        assert!(ClientKey::parse(&" ".repeat(MAX_KEY_BYTES + 1), NOW).is_err());
    }

    #[test]
    fn a_key_verifies_only_the_algorithms_it_fits() {
        let p256 = parse(&p256()).expect("accepted");
        assert!(matches!(
            p256.verifying_key(SignatureAlgorithm::Es256),
            Some(PublicKey::P256 { .. })
        ));
        assert!(p256.verifying_key(SignatureAlgorithm::Rs256).is_none());
        let rsa_key = parse(&rsa(2048)).expect("accepted");
        assert!(rsa_key.verifying_key(SignatureAlgorithm::Rs256).is_some());
        assert!(rsa_key.verifying_key(SignatureAlgorithm::Ps256).is_some());
        assert!(rsa_key.verifying_key(SignatureAlgorithm::Es256).is_none());
        let mut only_pss = rsa(2048);
        only_pss["alg"] = json!("PS256");
        let only_pss = parse(&only_pss).expect("accepted");
        assert!(only_pss.verifying_key(SignatureAlgorithm::Rs256).is_none());
        assert!(only_pss.verifying_key(SignatureAlgorithm::Ps256).is_some());
        let ed25519 =
            parse(&json!({"kty": "OKP", "crv": "Ed25519", "kid": "ed", "x": encoded(&[3; 32])}))
                .expect("accepted");
        for algorithm in [
            SignatureAlgorithm::Es256,
            SignatureAlgorithm::Rs256,
            SignatureAlgorithm::Ps256,
        ] {
            assert!(ed25519.verifying_key(algorithm).is_none());
        }
    }

    #[test]
    fn the_modulus_is_measured_without_its_leading_zeros() {
        assert_eq!(rsa_modulus_bits(&[0, 0, 0x80, 0]), 16);
        assert_eq!(rsa_modulus_bits(&[0x01]), 1);
        assert_eq!(rsa_modulus_bits(&[0, 0]), 0);
    }
}
