//! The client's key, and the assertions it signs for `private_key_jwt`.
//!
//! Specified in `docs/operations/hodor-cert-manager-issuer.md`, "How it
//! proves who it is to Hodor". An assertion is signed with ES256: `iss`
//! and `sub` the client, `aud` the tenant's issuer, a lifetime of one
//! minute and a `jti` of 16 random bytes.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::fmt;

/// How long an assertion lives, in seconds.
const ASSERTION_SECONDS: i64 = 60;

/// Why a key cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(String);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the client's key cannot be used: {}", self.0)
    }
}

impl std::error::Error for KeyError {}

/// The client's ECDSA P-256 key, which signs its assertions.
pub struct ClientKey {
    pair: EcdsaKeyPair,
    key_id: Option<String>,
    random: SystemRandom,
}

impl fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl ClientKey {
    /// Reads a key in PEM: PKCS#8 (`PRIVATE KEY`), as `openssl genpkey`
    /// writes it, or SEC 1 (`EC PRIVATE KEY`). It must be on P-256.
    ///
    /// # Errors
    ///
    /// Returns a [`KeyError`] when the text holds no such key.
    pub fn from_pem(pem: &str, key_id: Option<String>) -> Result<Self, KeyError> {
        let (label, der) = pem_block(pem).ok_or_else(|| {
            KeyError("it is not one key in PEM, `PRIVATE KEY` or `EC PRIVATE KEY`".to_owned())
        })?;
        let pair = match label.as_str() {
            "PRIVATE KEY" => EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der),
            "EC PRIVATE KEY" => {
                EcdsaKeyPair::from_private_key_der(&ECDSA_P256_SHA256_FIXED_SIGNING, &der)
            }
            _ => {
                return Err(KeyError(format!(
                    "a PEM block `{label}` is not a private key"
                )));
            }
        }
        .map_err(|_| KeyError("it is not an ECDSA key on P-256".to_owned()))?;
        Ok(Self {
            pair,
            key_id,
            random: SystemRandom::new(),
        })
    }

    /// The public part, as the JSON Web Key Hodor keeps for the client.
    #[must_use]
    pub fn jwk(&self) -> Value {
        // The public key is the uncompressed point: 0x04, x, then y.
        let point = self.pair.public_key().as_ref();
        let x = point.get(1..33).unwrap_or_default();
        let y = point.get(33..65).unwrap_or_default();
        let mut jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
            "use": "sig",
            "alg": "ES256",
        });
        if let (Some(kid), Some(object)) = (&self.key_id, jwk.as_object_mut()) {
            object.insert("kid".to_owned(), Value::String(kid.clone()));
        }
        jwk
    }

    /// An assertion for `client_id`, to the tenant's issuer `audience`,
    /// issued at `now`, in seconds since 1970.
    ///
    /// # Errors
    ///
    /// Returns a [`KeyError`] if no random bytes or no signature could be
    /// had.
    pub fn assertion(&self, client_id: &str, audience: &str, now: i64) -> Result<String, KeyError> {
        let mut jti = [0_u8; 16];
        self.random
            .fill(&mut jti)
            .map_err(|_| KeyError("no random bytes for the assertion".to_owned()))?;
        let mut header = json!({ "alg": "ES256", "typ": "JWT" });
        if let (Some(kid), Some(object)) = (&self.key_id, header.as_object_mut()) {
            object.insert("kid".to_owned(), Value::String(kid.clone()));
        }
        let claims = json!({
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "iat": now,
            "exp": now + ASSERTION_SECONDS,
            "jti": jti.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        });
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = self
            .pair
            .sign(&self.random, signed.as_bytes())
            .map_err(|_| KeyError("the assertion could not be signed".to_owned()))?;
        Ok(format!(
            "{signed}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }
}

/// The label and the bytes of the one PEM block of `text`.
fn pem_block(text: &str) -> Option<(String, Vec<u8>)> {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let label = lines
        .next()?
        .strip_prefix("-----BEGIN ")?
        .strip_suffix("-----")?
        .to_owned();
    let end = format!("-----END {label}-----");
    let mut body = String::new();
    for line in lines.by_ref() {
        if line == end {
            let der = STANDARD.decode(body).ok()?;
            // Nothing may follow but blank lines.
            return lines.next().is_none().then_some((label, der));
        }
        body.push_str(line);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::ClientKey;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, UnparsedPublicKey,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use serde_json::Value;

    fn pem(label: &str, der: &[u8]) -> String {
        let body = STANDARD.encode(der);
        let lines: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).expect("ASCII"))
            .collect();
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            lines.join("\n")
        )
    }

    fn new_key() -> String {
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .expect("a key");
        pem("PRIVATE KEY", document.as_ref())
    }

    fn part(token: &str, index: usize) -> Value {
        let part = token.split('.').nth(index).expect("a part");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("JSON")
    }

    #[test]
    fn an_assertion_is_signed_by_the_key_its_public_part_names() {
        let key = ClientKey::from_pem(&new_key(), Some("issuer-2026".to_owned())).expect("a key");
        let jwk = key.jwk();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["kid"], "issuer-2026");
        assert!(jwk.get("d").is_none(), "no private part");

        let assertion = key
            .assertion(
                "client-1",
                "https://login.example.com/t/acme",
                1_800_000_000,
            )
            .expect("an assertion");
        let header = part(&assertion, 0);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "issuer-2026");
        let claims = part(&assertion, 1);
        assert_eq!(claims["iss"], "client-1");
        assert_eq!(claims["sub"], "client-1");
        assert_eq!(claims["aud"], "https://login.example.com/t/acme");
        assert_eq!(claims["iat"], 1_800_000_000);
        assert_eq!(claims["exp"], 1_800_000_060);
        assert_eq!(claims["jti"].as_str().expect("jti").len(), 32);

        let mut point = vec![4_u8];
        for coordinate in ["x", "y"] {
            point.extend(
                URL_SAFE_NO_PAD
                    .decode(jwk[coordinate].as_str().expect("coordinate"))
                    .expect("base64url"),
            );
        }
        let (signed, signature) = assertion.rsplit_once('.').expect("three parts");
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(
                signed.as_bytes(),
                &URL_SAFE_NO_PAD.decode(signature).expect("base64url"),
            )
            .expect("the signature checks with the public part");

        let again = key
            .assertion(
                "client-1",
                "https://login.example.com/t/acme",
                1_800_000_000,
            )
            .expect("an assertion");
        assert_ne!(
            part(&again, 1)["jti"],
            claims["jti"],
            "a fresh jti each time"
        );
    }

    #[test]
    fn without_an_identifier_the_key_names_none() {
        let key = ClientKey::from_pem(&new_key(), None).expect("a key");
        assert!(key.jwk().get("kid").is_none());
        let assertion = key.assertion("c", "a", 0).expect("an assertion");
        assert!(part(&assertion, 0).get("kid").is_none());
    }

    #[test]
    fn what_is_not_a_p256_key_is_refused() {
        let other = EcdsaKeyPair::generate_pkcs8(
            &aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            &SystemRandom::new(),
        )
        .expect("a key");
        for text in [
            String::new(),
            "not a key".to_owned(),
            pem("CERTIFICATE", b"\x30\x00"),
            pem("PRIVATE KEY", b"\x30\x00"),
            pem("PRIVATE KEY", other.as_ref()),
            format!("{}{}", new_key(), new_key()),
        ] {
            assert!(ClientKey::from_pem(&text, None).is_err(), "{text}");
        }
    }
}
