//! Each check of registration and of an answer, shown to refuse what
//! breaks it. Signatures are made and checked by stand-ins; the real
//! cryptography is tested in `hodor-adapters-crypto`.

use super::*;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{PublicKey, SignatureAlgorithm, SignatureVerifier};

const NOW: Timestamp = Timestamp::UNIX_EPOCH;

fn relying_party() -> RelyingParty {
    RelyingParty::from_public_address("https://id.example.com").expect("valid")
}

/// A stand-in signature: two digests of the message.
fn fake_signature(message: &[u8]) -> Vec<u8> {
    let first = FakeDigest.sha256(message);
    let mut signature = first.to_vec();
    signature.extend_from_slice(&FakeDigest.sha256(&first));
    signature
}

struct FakeVerifier;

impl SignatureVerifier for FakeVerifier {
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        algorithm.fits(key) && signature == fake_signature(message)
    }
}

fn der_integer(value: &[u8]) -> Vec<u8> {
    let first = value
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(value.len() - 1);
    let mut body = value[first..].to_vec();
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    let mut out = vec![0x02, u8::try_from(body.len()).expect("short")];
    out.extend(body);
    out
}

fn der(fixed: &[u8]) -> Vec<u8> {
    let mut body = der_integer(&fixed[..32]);
    body.extend(der_integer(&fixed[32..]));
    let mut out = vec![0x30, u8::try_from(body.len()).expect("short")];
    out.extend(body);
    out
}

fn text(value: &str) -> Vec<u8> {
    let mut out = vec![0x60 | u8::try_from(value.len()).expect("short")];
    out.extend_from_slice(value.as_bytes());
    out
}

fn bytes(value: &[u8]) -> Vec<u8> {
    let mut out = if value.len() < 24 {
        vec![0x40 | u8::try_from(value.len()).expect("short")]
    } else if value.len() < 256 {
        vec![0x58, u8::try_from(value.len()).expect("short")]
    } else {
        let length = u16::try_from(value.len()).expect("short");
        vec![0x59, (length >> 8) as u8, (length & 0xff) as u8]
    };
    out.extend_from_slice(value);
    out
}

/// A P-256 COSE key with fixed coordinates.
fn es256_key() -> Vec<u8> {
    let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
    key.extend(bytes(&[7; 32]));
    key.push(0x22);
    key.extend(bytes(&[9; 32]));
    key
}

/// A simulated authenticator holding one credential.
struct Authenticator {
    credential_id: Vec<u8>,
    key: Vec<u8>,
    flags: u8,
    count: u32,
    origin: String,
    rp_id: String,
}

impl Authenticator {
    fn new() -> Self {
        Self {
            credential_id: vec![0xc1; 16],
            key: es256_key(),
            flags: FLAG_USER_PRESENT,
            count: 0,
            origin: "https://id.example.com".to_owned(),
            rp_id: "id.example.com".to_owned(),
        }
    }

    fn client_data(&self, kind: &str, challenge: &Challenge) -> Vec<u8> {
        format!(
            r#"{{"type":"{kind}","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            challenge.encoded(),
            self.origin
        )
        .into_bytes()
    }

    fn authenticator_data(&self, attested: bool) -> Vec<u8> {
        let mut data = FakeDigest.sha256(self.rp_id.as_bytes()).to_vec();
        data.push(
            self.flags
                | if attested {
                    FLAG_ATTESTED_CREDENTIAL
                } else {
                    0
                },
        );
        data.extend_from_slice(&self.count.to_be_bytes());
        if attested {
            data.extend_from_slice(&[0; 16]);
            data.extend_from_slice(
                &u16::try_from(self.credential_id.len())
                    .expect("short")
                    .to_be_bytes(),
            );
            data.extend_from_slice(&self.credential_id);
            data.extend_from_slice(&self.key);
        }
        data
    }

    fn attestation_object(&self, authenticator_data: &[u8]) -> Vec<u8> {
        let mut object = vec![0xa3];
        object.extend(text("fmt"));
        object.extend(text("none"));
        object.extend(text("attStmt"));
        object.push(0xa0);
        object.extend(text("authData"));
        object.extend(bytes(authenticator_data));
        object
    }

    fn register(&self, pending: &PendingRegistration) -> RegistrationResponse {
        RegistrationResponse {
            client_data: self.client_data("webauthn.create", &pending.snapshot().challenge),
            attestation_object: self.attestation_object(&self.authenticator_data(true)),
            transports: vec![
                "usb".to_owned(),
                "carrier-pigeon".to_owned(),
                "usb".to_owned(),
            ],
            discoverable: Some(true),
            name: Some("  Blue key  ".to_owned()),
        }
    }

    fn answer(&self, challenge: &Challenge, user: Option<UserId>) -> AssertionResponse {
        let client_data = self.client_data("webauthn.get", challenge);
        let authenticator_data = self.authenticator_data(false);
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&FakeDigest.sha256(&client_data));
        AssertionResponse {
            credential_id: self.credential_id.clone(),
            client_data,
            authenticator_data,
            signature: der(&fake_signature(&message)),
            user_handle: user.map(user_handle),
        }
    }
}

fn pending() -> PendingRegistration {
    PendingRegistration::begin(UserId::generate(), false, &FakeRandom, NOW)
}

fn pending_passkey() -> PendingRegistration {
    PendingRegistration::begin(UserId::generate(), true, &FakeRandom, NOW)
}

struct FakeRandom;

impl RandomSource for FakeRandom {
    fn fill(&self, buffer: &mut [u8]) {
        for (byte, value) in buffer.iter_mut().zip(1_u8..) {
            *byte = value;
        }
    }
}

fn registered(authenticator: &Authenticator) -> WebAuthnCredential {
    let pending = pending();
    check_registration(
        &relying_party(),
        &pending,
        authenticator.register(&pending),
        &FakeDigest,
        NOW,
    )
    .expect("registered")
}

fn answer_check(
    credential: &WebAuthnCredential,
    response: &AssertionResponse,
    challenge: &Challenge,
) -> AssertionCheck {
    check_assertion(
        &relying_party(),
        challenge,
        credential,
        response,
        AssertionKind::SecondFactor,
        &FakeDigest,
        &FakeVerifier,
    )
}

fn passkey_check(
    credential: &WebAuthnCredential,
    response: &AssertionResponse,
    challenge: &Challenge,
) -> AssertionCheck {
    check_assertion(
        &relying_party(),
        challenge,
        credential,
        response,
        AssertionKind::Passkey,
        &FakeDigest,
        &FakeVerifier,
    )
}

const CHALLENGE: Challenge = Challenge([5; 32]);

#[test]
fn the_relying_party_is_the_host_of_the_public_address() {
    let party =
        RelyingParty::from_public_address("https://ID.example.com/some/path").expect("valid");
    assert_eq!(party.id(), "id.example.com");
    assert_eq!(party.origin(), "https://id.example.com");
    let local = RelyingParty::from_public_address("http://localhost:8080").expect("valid");
    assert_eq!(local.id(), "localhost");
    assert_eq!(local.origin(), "http://localhost:8080");
    for address in [
        "ftp://id.example.com",
        "id.example.com",
        "https://192.0.2.1",
        "https://[2001:db8::1]",
        "https://user@id.example.com",
        "https://",
        "https://bad..example.com",
    ] {
        assert!(
            RelyingParty::from_public_address(address).is_err(),
            "{address}"
        );
    }
}

#[test]
fn a_registration_makes_the_credential_the_authenticator_sent() {
    let authenticator = Authenticator::new();
    let credential = registered(&authenticator);
    let stored = credential.snapshot();
    assert_eq!(stored.credential_id, authenticator.credential_id);
    assert_eq!(stored.public_key, authenticator.key);
    assert_eq!(stored.algorithm, CoseAlgorithm::Es256);
    assert_eq!(stored.transports, vec!["usb".to_owned()]);
    assert_eq!(stored.discoverable, Some(true));
    assert_eq!(stored.name, "Blue key");
    assert!(!stored.backup_eligible);
}

#[test]
fn a_registration_is_refused_for_each_check_it_breaks() {
    let pending = pending();
    let check = |response: RegistrationResponse| {
        check_registration(&relying_party(), &pending, response, &FakeDigest, NOW)
            .map(|_| ())
            .expect_err("refused")
    };
    let good = Authenticator::new();

    let mut response = good.register(&pending);
    response.client_data = good.client_data("webauthn.get", &pending.snapshot().challenge);
    assert_eq!(check(response), Refusal::WrongType);

    let mut response = good.register(&pending);
    response.client_data = good.client_data("webauthn.create", &CHALLENGE);
    assert_eq!(check(response), Refusal::WrongChallenge);

    let mut other_site = Authenticator::new();
    other_site.origin = "https://evil.example.net".to_owned();
    assert_eq!(check(other_site.register(&pending)), Refusal::WrongOrigin);

    let mut response = good.register(&pending);
    response.client_data = String::from_utf8(response.client_data)
        .expect("text")
        .replace("\"crossOrigin\":false", "\"crossOrigin\":true")
        .into_bytes();
    assert_eq!(check(response), Refusal::CrossOrigin);

    let mut response = good.register(&pending);
    response.client_data = b"not json".to_vec();
    assert_eq!(check(response), Refusal::ClientDataUnreadable);

    let mut response = good.register(&pending);
    response.attestation_object = vec![0xa0];
    assert_eq!(check(response), Refusal::AttestationUnreadable);

    let mut other_party = Authenticator::new();
    other_party.rp_id = "evil.example.net".to_owned();
    assert_eq!(
        check(other_party.register(&pending)),
        Refusal::WrongRelyingParty
    );

    let mut absent = Authenticator::new();
    absent.flags = 0;
    assert_eq!(check(absent.register(&pending)), Refusal::UserNotPresent);

    let mut inconsistent = Authenticator::new();
    inconsistent.flags = FLAG_USER_PRESENT | FLAG_BACKED_UP;
    assert_eq!(
        check(inconsistent.register(&pending)),
        Refusal::BackupFlagsInconsistent
    );

    let mut long_identifier = Authenticator::new();
    long_identifier.credential_id = vec![1; 1024];
    assert_eq!(
        check(long_identifier.register(&pending)),
        Refusal::CredentialIdTooLong
    );

    let mut response = good.register(&pending);
    response.attestation_object = good.attestation_object(&good.authenticator_data(false));
    assert_eq!(check(response), Refusal::CredentialDataMisplaced);

    let mut response = good.register(&pending);
    let mut data = good.authenticator_data(true);
    data.push(0);
    response.attestation_object = good.attestation_object(&data);
    assert_eq!(check(response), Refusal::AuthenticatorDataUnreadable);

    // EdDSA, which Hodor does not accept.
    let mut eddsa = Authenticator::new();
    eddsa.key = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21];
    eddsa.key.extend(bytes(&[7; 32]));
    assert_eq!(check(eddsa.register(&pending)), Refusal::UnacceptableKey);

    // A P-256 key with a short coordinate.
    let mut short = Authenticator::new();
    short.key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
    short.key.extend(bytes(&[7; 31]));
    short.key.push(0x22);
    short.key.extend(bytes(&[9; 32]));
    assert_eq!(check(short.register(&pending)), Refusal::UnacceptableKey);

    // An RSA key of 1,024 bits.
    let mut weak = Authenticator::new();
    weak.key = vec![0xa4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20];
    weak.key.extend(bytes(&[0xab; 128]));
    weak.key.push(0x21);
    weak.key.extend(bytes(&[1, 0, 1]));
    assert_eq!(check(weak.register(&pending)), Refusal::UnacceptableKey);
}

#[test]
fn an_rsa_key_of_2048_bits_is_accepted() {
    let pending = pending();
    let mut authenticator = Authenticator::new();
    authenticator.key = vec![0xa4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20];
    authenticator.key.extend(bytes(&[0xab; 256]));
    authenticator.key.push(0x21);
    authenticator.key.extend(bytes(&[1, 0, 1]));
    let credential = check_registration(
        &relying_party(),
        &pending,
        authenticator.register(&pending),
        &FakeDigest,
        NOW,
    )
    .expect("accepted");
    assert_eq!(credential.snapshot().algorithm, CoseAlgorithm::Rs256);
}

#[test]
fn an_answer_by_the_credential_to_its_challenge_is_verified() {
    let mut authenticator = Authenticator::new();
    let credential = registered(&authenticator);
    authenticator.count = 1;
    let user = credential.user_id();
    assert_eq!(
        answer_check(
            &credential,
            &authenticator.answer(&CHALLENGE, Some(user)),
            &CHALLENGE
        ),
        AssertionCheck::Verified {
            sign_count: 1,
            backed_up: false
        }
    );
    assert_eq!(
        answer_check(
            &credential,
            &authenticator.answer(&CHALLENGE, None),
            &CHALLENGE
        ),
        AssertionCheck::Verified {
            sign_count: 1,
            backed_up: false
        }
    );
}

#[test]
fn an_answer_is_refused_for_each_check_it_breaks() {
    let good = Authenticator::new();
    let credential = registered(&good);
    let refused =
        |response: &AssertionResponse| match answer_check(&credential, response, &CHALLENGE) {
            AssertionCheck::Refused(refusal) => refusal,
            other => panic!("{other:?}"),
        };

    assert_eq!(
        refused(&good.answer(&Challenge([6; 32]), None)),
        Refusal::WrongChallenge
    );

    let mut response = good.answer(&CHALLENGE, None);
    response.credential_id = vec![0xc2; 16];
    assert_eq!(refused(&response), Refusal::UnknownCredential);

    assert_eq!(
        refused(&good.answer(&CHALLENGE, Some(UserId::generate()))),
        Refusal::WrongUser
    );

    let mut other_site = Authenticator::new();
    other_site.origin = "https://id.example.com.evil.example.net".to_owned();
    assert_eq!(
        refused(&other_site.answer(&CHALLENGE, None)),
        Refusal::WrongOrigin
    );

    let mut response = good.answer(&CHALLENGE, None);
    response.client_data = good.client_data("webauthn.create", &CHALLENGE);
    assert_eq!(refused(&response), Refusal::WrongType);

    let mut other_party = Authenticator::new();
    other_party.rp_id = "example.com".to_owned();
    assert_eq!(
        refused(&other_party.answer(&CHALLENGE, None)),
        Refusal::WrongRelyingParty
    );

    let mut absent = Authenticator::new();
    absent.flags = 0;
    assert_eq!(
        refused(&absent.answer(&CHALLENGE, None)),
        Refusal::UserNotPresent
    );

    let mut now_eligible = Authenticator::new();
    now_eligible.flags = FLAG_USER_PRESENT | FLAG_BACKUP_ELIGIBLE;
    assert_eq!(
        refused(&now_eligible.answer(&CHALLENGE, None)),
        Refusal::BackupFlagsInconsistent
    );

    let mut response = good.answer(&CHALLENGE, None);
    response.authenticator_data = vec![0; 36];
    assert_eq!(refused(&response), Refusal::AuthenticatorDataUnreadable);

    let mut response = good.answer(&CHALLENGE, None);
    response.signature[10] ^= 1;
    assert_eq!(refused(&response), Refusal::BadSignature);

    // A signature for other client data: the answer was changed on the way.
    let mut response = good.answer(&CHALLENGE, None);
    response.client_data = String::from_utf8(response.client_data)
        .expect("text")
        .replace("\"crossOrigin\":false", "\"crossOrigin\":false ")
        .into_bytes();
    assert_eq!(refused(&response), Refusal::BadSignature);

    let mut response = good.answer(&CHALLENGE, None);
    response.signature = fake_signature(b"anything");
    assert_eq!(refused(&response), Refusal::BadSignature);
}

#[test]
fn a_counter_that_does_not_grow_means_a_copied_credential() {
    let mut authenticator = Authenticator::new();
    authenticator.count = 7;
    let mut credential = registered(&authenticator);
    assert_eq!(credential.snapshot().sign_count, 7);

    for count in [7, 6, 0] {
        authenticator.count = count;
        assert_eq!(
            answer_check(
                &credential,
                &authenticator.answer(&CHALLENGE, None),
                &CHALLENGE
            ),
            AssertionCheck::CounterNotIncreased,
            "{count}"
        );
    }
    authenticator.count = 8;
    let AssertionCheck::Verified {
        sign_count,
        backed_up,
    } = answer_check(
        &credential,
        &authenticator.answer(&CHALLENGE, None),
        &CHALLENGE,
    )
    else {
        panic!("verified");
    };
    credential.record_use(sign_count, backed_up, NOW);
    authenticator.count = 8;
    assert_eq!(
        answer_check(
            &credential,
            &authenticator.answer(&CHALLENGE, None),
            &CHALLENGE
        ),
        AssertionCheck::CounterNotIncreased
    );
}

#[test]
fn an_authenticator_without_a_counter_is_accepted() {
    let authenticator = Authenticator::new();
    let credential = registered(&authenticator);
    for _ in 0..3 {
        assert!(matches!(
            answer_check(
                &credential,
                &authenticator.answer(&CHALLENGE, None),
                &CHALLENGE
            ),
            AssertionCheck::Verified { sign_count: 0, .. }
        ));
    }
}

#[test]
fn only_strict_der_signatures_are_read() {
    let fixed: Vec<u8> = (1..=64).collect();
    assert_eq!(der_to_fixed(&der(&fixed)), Some(fixed.clone()));
    let high: Vec<u8> = (0..64)
        .map(|i| if i % 32 == 0 { 0x80 } else { 1 })
        .collect();
    assert_eq!(der_to_fixed(&der(&high)), Some(high.clone()));
    let good = der(&fixed);
    // A padding zero that is not needed.
    let mut padded = vec![0x30, good[1] + 1, 0x02, 33, 0];
    padded.extend_from_slice(&good[4..]);
    for bad in [
        vec![],
        fixed.clone(),
        padded,
        [&good[..], &[0]].concat(),
        {
            let mut wrong_tag = good.clone();
            wrong_tag[0] = 0x31;
            wrong_tag
        },
        {
            let mut negative = good.clone();
            negative[4] = 0x81;
            negative
        },
        vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x00],
    ] {
        assert_eq!(der_to_fixed(&bad), None, "{bad:02x?}");
    }
}

#[test]
fn values_in_base64url_are_read() {
    let response =
        AssertionResponse::from_base64url("AQI", "AwQ", "BQY", "Bwg", Some("CQo")).expect("read");
    assert_eq!(response.credential_id, vec![1, 2]);
    assert_eq!(response.user_handle, Some(vec![9, 10]));
    assert!(AssertionResponse::from_base64url("AQI", "AwQ", "BQY", "Bwg", None).is_some());
    assert!(AssertionResponse::from_base64url("AQI", "AwQ", "BQY", "Bwg", Some("")).is_some());
    assert!(AssertionResponse::from_base64url("AQI=", "AwQ", "BQY", "Bwg", None).is_none());
    assert!(AssertionResponse::from_base64url("A+I", "AwQ", "BQY", "Bwg", None).is_none());
}

#[test]
fn the_options_are_shaped_as_the_specification_says() {
    let authenticator = Authenticator::new();
    let credential = registered(&authenticator);
    let pending = pending();
    let creation = serde_json::to_value(creation_options(
        &relying_party(),
        &pending,
        "ana@example.com",
        "Ana",
        std::slice::from_ref(&credential),
    ))
    .expect("json");
    assert_eq!(creation["rp"]["id"], "id.example.com");
    assert_eq!(creation["user"]["name"], "ana@example.com");
    assert_eq!(creation["user"]["displayName"], "Ana");
    assert_eq!(creation["pubKeyCredParams"][0]["alg"], -7);
    assert_eq!(creation["pubKeyCredParams"][1]["alg"], -257);
    assert_eq!(creation["timeout"], 300_000);
    assert_eq!(creation["attestation"], "none");
    assert_eq!(creation["extensions"]["credProps"], true);
    assert_eq!(
        creation["excludeCredentials"][0]["id"],
        "wcHBwcHBwcHBwcHBwcHBwQ"
    );
    assert_eq!(
        creation["user"]["id"],
        encode(&user_handle(pending.snapshot().user_id))
    );

    let request = serde_json::to_value(request_options(
        &relying_party(),
        &CHALLENGE,
        std::slice::from_ref(&credential),
    ))
    .expect("json");
    assert_eq!(request["rpId"], "id.example.com");
    assert_eq!(request["challenge"], CHALLENGE.encoded());
    assert_eq!(request["allowCredentials"][0]["type"], "public-key");
    assert_eq!(request["allowCredentials"][0]["transports"][0], "usb");
    assert_eq!(request["userVerification"], "discouraged");
}

#[test]
fn a_pending_registration_is_good_for_its_user_for_five_minutes() {
    let pending = pending();
    let user = pending.snapshot().user_id;
    assert!(pending.is_good_for(user, NOW));
    assert!(pending.is_good_for(user, NOW + Duration::seconds(299)));
    assert!(!pending.is_good_for(user, NOW + Duration::minutes(5)));
    assert!(!pending.is_good_for(UserId::generate(), NOW));
}

#[test]
fn a_passkey_is_asked_for_as_discoverable_and_verified() {
    let creation = serde_json::to_value(creation_options(
        &relying_party(),
        &pending_passkey(),
        "ana@example.com",
        "Ana (Acme)",
        &[],
    ))
    .expect("json");
    assert_eq!(
        creation["authenticatorSelection"],
        serde_json::json!({ "residentKey": "required", "userVerification": "required" })
    );
    let security_key = serde_json::to_value(creation_options(
        &relying_party(),
        &pending(),
        "ana@example.com",
        "Ana",
        &[],
    ))
    .expect("json");
    assert_eq!(
        security_key["authenticatorSelection"],
        serde_json::json!({ "residentKey": "preferred", "userVerification": "discouraged" })
    );
    let request =
        serde_json::to_value(passkey_request_options(&relying_party(), &CHALLENGE)).expect("json");
    assert_eq!(request["allowCredentials"], serde_json::json!([]));
    assert_eq!(request["userVerification"], "required");
    assert_eq!(request["rpId"], "id.example.com");
}

#[test]
fn a_passkey_registration_needs_the_person_verified_and_a_discoverable_credential() {
    let pending = pending_passkey();
    let unverified = Authenticator::new();
    assert_eq!(
        check_registration(
            &relying_party(),
            &pending,
            unverified.register(&pending),
            &FakeDigest,
            NOW,
        ),
        Err(Refusal::UserNotVerified)
    );
    let mut verified = Authenticator::new();
    verified.flags |= FLAG_USER_VERIFIED;
    let mut not_kept = verified.register(&pending);
    not_kept.discoverable = Some(false);
    assert_eq!(
        check_registration(&relying_party(), &pending, not_kept, &FakeDigest, NOW),
        Err(Refusal::NotDiscoverable)
    );
    // A browser that does not say is trusted to have honoured the
    // requirement: it may not make a credential that is not discoverable.
    let mut unsaid = verified.register(&pending);
    unsaid.discoverable = None;
    let credential = check_registration(&relying_party(), &pending, unsaid, &FakeDigest, NOW)
        .expect("registered");
    assert_eq!(credential.snapshot().discoverable, Some(true));
    // A security key needs neither.
    let pending = self::pending();
    let mut key = unverified.register(&pending);
    key.discoverable = Some(false);
    let credential =
        check_registration(&relying_party(), &pending, key, &FakeDigest, NOW).expect("a key");
    assert_eq!(credential.snapshot().discoverable, Some(false));
}

#[test]
fn a_passkey_answer_needs_the_user_handle_and_the_person_verified() {
    let mut authenticator = Authenticator::new();
    authenticator.flags |= FLAG_USER_VERIFIED;
    let credential = registered(&authenticator);
    let user = credential.user_id();
    authenticator.count = 1;
    let accepted = authenticator.answer(&CHALLENGE, Some(user));
    assert!(matches!(
        passkey_check(&credential, &accepted, &CHALLENGE),
        AssertionCheck::Verified { sign_count: 1, .. }
    ));
    assert_eq!(
        passkey_check(
            &credential,
            &authenticator.answer(&CHALLENGE, None),
            &CHALLENGE
        ),
        AssertionCheck::Refused(Refusal::WrongUser)
    );
    assert_eq!(
        passkey_check(
            &credential,
            &authenticator.answer(&CHALLENGE, Some(UserId::generate())),
            &CHALLENGE
        ),
        AssertionCheck::Refused(Refusal::WrongUser)
    );
    authenticator.flags = FLAG_USER_PRESENT;
    let unverified = authenticator.answer(&CHALLENGE, Some(user));
    assert_eq!(
        passkey_check(&credential, &unverified, &CHALLENGE),
        AssertionCheck::Refused(Refusal::UserNotVerified)
    );
    // As a second factor, the same answer is enough: the person was
    // identified before, and the key is what is proved.
    assert!(matches!(
        answer_check(&credential, &unverified, &CHALLENGE),
        AssertionCheck::Verified { .. }
    ));
}
