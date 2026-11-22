//! A WebAuthn authenticator in software, for tests: it makes a real P-256
//! key, answers registrations and challenges as a security key would, and
//! signs with the key. Never use outside tests.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use std::sync::Mutex;

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_ATTESTED_CREDENTIAL: u8 = 0x40;

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    digest.as_ref().try_into().unwrap_or([0; 32])
}

fn cbor_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = if value.len() < 24 {
        vec![0x40 | u8::try_from(value.len()).unwrap_or(0)]
    } else if value.len() < 256 {
        vec![0x58, u8::try_from(value.len()).unwrap_or(0)]
    } else {
        let length = u16::try_from(value.len()).unwrap_or(0).to_be_bytes();
        vec![0x59, length[0], length[1]]
    };
    out.extend_from_slice(value);
    out
}

fn cbor_text(value: &str) -> Vec<u8> {
    let mut out = vec![0x60 | u8::try_from(value.len()).unwrap_or(0)];
    out.extend_from_slice(value.as_bytes());
    out
}

/// A security key in software, holding one credential.
pub struct SoftwareAuthenticator {
    document: Vec<u8>,
    key: EcdsaKeyPair,
    credential_id: Vec<u8>,
    origin: String,
    counter: Mutex<u32>,
}

impl std::fmt::Debug for SoftwareAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareAuthenticator")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl SoftwareAuthenticator {
    /// A new authenticator, for pages served from `origin`, such as
    /// `https://id.example.com`. Its counter starts at zero and grows by one
    /// for every answer.
    ///
    /// # Panics
    ///
    /// Panics if a key cannot be made.
    #[must_use]
    pub fn new(origin: &str) -> Self {
        let random = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
            .expect("a P-256 key");
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref())
            .expect("the key just made");
        let mut credential_id = vec![0_u8; 32];
        aws_lc_rs::rand::fill(&mut credential_id).expect("random bytes");
        Self {
            document: document.as_ref().to_vec(),
            key,
            credential_id,
            origin: origin.to_owned(),
            counter: Mutex::new(0),
        }
    }

    /// The same key and credential, used by a page of another origin, as
    /// a key would be on a site that imitates Hodor's.
    ///
    /// # Panics
    ///
    /// Panics if the key cannot be read again.
    #[must_use]
    pub fn at_origin(&self, origin: &str) -> Self {
        Self {
            document: self.document.clone(),
            key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.document)
                .expect("the same key"),
            credential_id: self.credential_id.clone(),
            origin: origin.to_owned(),
            counter: Mutex::new(*self.counter.lock().expect("counter") + 100),
        }
    }

    /// The identifier of its credential, in base64url.
    #[must_use]
    pub fn credential_id(&self) -> String {
        encode(&self.credential_id)
    }

    /// Makes the counter report `value` next, as a copy of the key would.
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned.
    pub fn set_counter(&self, value: u32) {
        *self.counter.lock().expect("counter") = value;
    }

    fn next_counter(&self) -> u32 {
        let mut counter = self.counter.lock().expect("counter");
        let value = *counter;
        *counter = value.saturating_add(1);
        value
    }

    fn cose_key(&self) -> Vec<u8> {
        // An uncompressed point: 0x04, then x, then y.
        let point = self.key.public_key().as_ref();
        let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
        key.extend(cbor_bytes(&point[1..33]));
        key.push(0x22);
        key.extend(cbor_bytes(&point[33..65]));
        key
    }

    fn authenticator_data(&self, rp_id: &str, attested: bool) -> Vec<u8> {
        let mut data = sha256(rp_id.as_bytes()).to_vec();
        data.push(
            FLAG_USER_PRESENT
                | if attested {
                    FLAG_ATTESTED_CREDENTIAL
                } else {
                    0
                },
        );
        data.extend_from_slice(&self.next_counter().to_be_bytes());
        if attested {
            data.extend_from_slice(&[0; 16]);
            data.extend_from_slice(
                &u16::try_from(self.credential_id.len())
                    .unwrap_or(0)
                    .to_be_bytes(),
            );
            data.extend_from_slice(&self.credential_id);
            data.extend(self.cose_key());
        }
        data
    }

    fn client_data(&self, kind: &str, challenge: &str) -> Vec<u8> {
        json!({ "type": kind, "challenge": challenge, "origin": self.origin, "crossOrigin": false })
            .to_string()
            .into_bytes()
    }

    /// What the browser sends to finish a registration, for the creation
    /// options of the interaction interface (`public_key`), as the body of
    /// the finishing request.
    ///
    /// # Panics
    ///
    /// Panics if the options lack a challenge or a relying party.
    #[must_use]
    pub fn register(&self, options: &Value) -> Value {
        let challenge = options["challenge"].as_str().expect("a challenge");
        let rp_id = options["rp"]["id"].as_str().expect("a relying party");
        let mut object = vec![0xa3];
        object.extend(cbor_text("fmt"));
        object.extend(cbor_text("none"));
        object.extend(cbor_text("attStmt"));
        object.push(0xa0);
        object.extend(cbor_text("authData"));
        object.extend(cbor_bytes(&self.authenticator_data(rp_id, true)));
        json!({
            "client_data": encode(&self.client_data("webauthn.create", challenge)),
            "attestation_object": encode(&object),
            "transports": ["usb"],
            "discoverable": false,
            "name": "Software key",
        })
    }

    /// What the browser sends as the answer to the request options of the
    /// interaction interface (`public_key`), as the body of the step.
    ///
    /// # Panics
    ///
    /// Panics if the options lack a challenge or a relying party.
    #[must_use]
    pub fn answer(&self, options: &Value) -> Value {
        let challenge = options["challenge"].as_str().expect("a challenge");
        let rp_id = options["rpId"].as_str().expect("a relying party");
        let client_data = self.client_data("webauthn.get", challenge);
        let authenticator_data = self.authenticator_data(rp_id, false);
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&sha256(&client_data));
        let signature = self
            .key
            .sign(&SystemRandom::new(), &message)
            .expect("a signature");
        json!({
            "credential_id": encode(&self.credential_id),
            "client_data": encode(&client_data),
            "authenticator_data": encode(&authenticator_data),
            "signature": encode(signature.as_ref()),
            "user_handle": null,
        })
    }
}
