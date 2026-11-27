//! What the OpenBao provider sends and how it reads what comes back,
//! against a scripted client: signing in with Kubernetes authentication,
//! which needs a cluster to try for real, keeping and replacing the token,
//! and every failure of OpenBao turned into a failure to sign.

use hodor_adapters_kms::{OpenBaoKeyProvider, OpenBaoLogin, OpenBaoSettings};
use hodor_kernel::{
    DomainError, ErrorKind, HttpClient, HttpMethod, HttpRequest, HttpResponse, PublicKey,
    TenantContext, TenantId, Timestamp,
};
use hodor_keys::api::{
    GeneratedKey, KeyAlgorithm, KeyMaterial, KeyProvider as _, KeyVersion, KeyVersionId,
    SignatureEncoding,
};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ADDRESS: &str = "https://openbao.internal:8200";

enum Step {
    Answer(u16, Value),
    Fail(&'static str),
}

struct Scripted {
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<HttpRequest>>,
}

impl Scripted {
    fn new(steps: Vec<Step>) -> Arc<Self> {
        Arc::new(Self {
            steps: Mutex::new(steps.into()),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<HttpRequest> {
        self.seen.lock().expect("seen").clone()
    }
}

#[async_trait::async_trait]
impl HttpClient for Scripted {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        self.seen.lock().expect("seen").push(request);
        match self.steps.lock().expect("steps").pop_front() {
            Some(Step::Answer(status, body)) => Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: body.to_string().into_bytes(),
            }),
            Some(Step::Fail(code)) => Err(DomainError::new(ErrorKind::Unavailable, code, "failed")),
            None => panic!("nothing scripted"),
        }
    }
}

fn settings(login: OpenBaoLogin) -> OpenBaoSettings {
    OpenBaoSettings {
        address: ADDRESS.to_owned(),
        transit_mount: "teams/hodor-transit".to_owned(),
        login,
        time_limit: Duration::from_millis(1500),
        certificate_authorities: None,
    }
}

fn approle() -> OpenBaoLogin {
    OpenBaoLogin::AppRole {
        mount: "approle".to_owned(),
        role_id: "role".to_owned(),
        secret_id: hodor_kernel::Secret::new("secret".to_owned()),
    }
}

fn signed_in(token: &str, lease: u64) -> Step {
    Step::Answer(
        200,
        json!({"auth": {"client_token": token, "lease_duration": lease}}),
    )
}

fn signature() -> Step {
    // 64 bytes in base64url: the JWS marshaling of a P-256 signature.
    Step::Answer(
        200,
        json!({"data": {"signature": format!("vault:v1:{}", "A".repeat(86)), "key_version": 1}}),
    )
}

/// A version as the provider would have made it, without OpenBao.
fn version(tenant: &TenantContext) -> KeyVersion {
    let id = KeyVersionId::generate();
    let name = OpenBaoKeyProvider::key_name(tenant, id);
    KeyVersion::create(
        id,
        KeyAlgorithm::Es256,
        "openbao",
        GeneratedKey {
            public_key: Some(PublicKey::P256 {
                x: vec![1; 32],
                y: vec![2; 32],
            }),
            material: KeyMaterial::from_stored(format!("openbao:1:{name}:ES256").into_bytes()),
        },
        Timestamp::UNIX_EPOCH,
    )
    .expect("version")
    .0
}

fn body(request: &HttpRequest) -> Value {
    serde_json::from_slice(request.body.as_deref().expect("a body")).expect("JSON")
}

fn token_of(request: &HttpRequest) -> Option<&str> {
    request
        .headers
        .iter()
        .find(|(name, _)| name == "x-vault-token")
        .map(|(_, value)| value.as_str())
}

#[tokio::test]
async fn kubernetes_authentication_sends_the_role_and_the_service_accounts_token() {
    let directory = std::env::temp_dir().join(format!("hodor-kms-{}", TenantId::generate()));
    std::fs::create_dir_all(&directory).expect("directory");
    let token_file: PathBuf = directory.join("token");
    std::fs::write(&token_file, "first.service.account.token\n").expect("token");
    let http = Scripted::new(vec![signed_in("t1", 0), signature(), signature()]);
    let provider = OpenBaoKeyProvider::new(
        http.clone(),
        &settings(OpenBaoLogin::Kubernetes {
            mount: "cluster-one".to_owned(),
            role: "hodor".to_owned(),
            token_file: token_file.clone(),
        }),
    );
    let tenant = TenantContext::assume(TenantId::generate());
    let version = version(&tenant);
    for _ in 0..2 {
        provider
            .sign(&tenant, &version, b"m", SignatureEncoding::Jose)
            .await
            .expect("signed");
    }
    std::fs::remove_dir_all(&directory).expect("cleaned up");

    let seen = http.seen();
    assert_eq!(seen.len(), 3, "signed in once for two signatures");
    let login = &seen[0];
    assert_eq!(login.method, HttpMethod::Post);
    assert_eq!(login.url, format!("{ADDRESS}/v1/auth/cluster-one/login"));
    assert_eq!(
        body(login),
        json!({"role": "hodor", "jwt": "first.service.account.token"})
    );
    assert_eq!(token_of(login), None);
    let name = OpenBaoKeyProvider::key_name(&tenant, version.id());
    for sign in &seen[1..] {
        assert_eq!(
            sign.url,
            format!("{ADDRESS}/v1/teams/hodor-transit/sign/{name}")
        );
        assert_eq!(token_of(sign), Some("t1"));
        assert_eq!(sign.time_limit, Some(Duration::from_millis(1500)));
        assert_eq!(
            body(sign),
            json!({
                "input": "bQ==",
                "hash_algorithm": "sha2-256",
                "key_version": 1,
                "marshaling_algorithm": "jws",
            })
        );
    }
}

#[tokio::test]
async fn a_missing_service_account_token_signs_nothing_in() {
    let http = Scripted::new(Vec::new());
    let provider = OpenBaoKeyProvider::new(
        http.clone(),
        &settings(OpenBaoLogin::Kubernetes {
            mount: "kubernetes".to_owned(),
            role: "hodor".to_owned(),
            token_file: PathBuf::from("/nonexistent/hodor/token"),
        }),
    );
    let tenant = TenantContext::assume(TenantId::generate());
    let error = provider
        .sign(&tenant, &version(&tenant), b"m", SignatureEncoding::Jose)
        .await
        .expect_err("no token");
    assert_eq!(error.code(), "keys.provider_failed");
    assert!(http.seen().is_empty(), "nothing sent");
}

#[tokio::test]
async fn a_refused_token_is_replaced_once_and_the_request_sent_again() {
    let http = Scripted::new(vec![
        signed_in("old", 3600),
        Step::Answer(403, json!({"errors": ["permission denied"]})),
        signed_in("new", 3600),
        signature(),
    ]);
    let provider = OpenBaoKeyProvider::new(http.clone(), &settings(approle()));
    let tenant = TenantContext::assume(TenantId::generate());
    provider
        .sign(&tenant, &version(&tenant), b"m", SignatureEncoding::Jose)
        .await
        .expect("signed with the new token");
    let seen = http.seen();
    assert_eq!(
        body(&seen[0]),
        json!({"role_id": "role", "secret_id": "secret"})
    );
    assert_eq!(seen[0].url, format!("{ADDRESS}/v1/auth/approle/login"));
    assert_eq!(token_of(&seen[1]), Some("old"));
    assert_eq!(token_of(&seen[3]), Some("new"));

    // Refused again with a new token: the policy refuses it, and that is
    // said, without a third try.
    let http = Scripted::new(vec![
        signed_in("old", 3600),
        Step::Answer(403, json!({"errors": ["permission denied"]})),
        signed_in("new", 3600),
        Step::Answer(403, json!({"errors": ["permission denied"]})),
    ]);
    let provider = OpenBaoKeyProvider::new(http.clone(), &settings(approle()));
    let error = provider
        .sign(&tenant, &version(&tenant), b"m", SignatureEncoding::Jose)
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "keys.provider_refused");
    assert_eq!(http.seen().len(), 4);
}

#[tokio::test]
async fn every_failure_of_openbao_is_a_failure_to_sign() {
    let tenant = TenantContext::assume(TenantId::generate());
    let cases = [
        (
            vec![Step::Fail("http.unreachable")],
            "keys.provider_unavailable",
        ),
        (
            vec![Step::Answer(503, json!({"errors": ["Vault is sealed"]}))],
            "keys.provider_unavailable",
        ),
        (
            vec![Step::Answer(
                400,
                json!({"errors": ["invalid role or secret ID"]}),
            )],
            "keys.provider_sign_in_refused",
        ),
        (
            vec![signed_in("t", 60), Step::Fail("http.timed_out")],
            "keys.provider_unavailable",
        ),
        (
            vec![
                signed_in("t", 60),
                Step::Answer(400, json!({"errors": ["signing key not found"]})),
            ],
            "keys.provider_failed",
        ),
        (
            vec![
                signed_in("t", 60),
                Step::Answer(200, json!({"data": {"signature": "vault:v2:AAAA"}})),
            ],
            "keys.provider_failed",
        ),
        (
            vec![
                signed_in("t", 60),
                Step::Answer(200, json!({"data": {"signature": "vault:v1:AAAA"}})),
            ],
            "keys.provider_failed",
        ),
    ];
    for (steps, code) in cases {
        let provider = OpenBaoKeyProvider::new(Scripted::new(steps), &settings(approle()));
        let error = provider
            .sign(&tenant, &version(&tenant), b"m", SignatureEncoding::Jose)
            .await
            .expect_err(code);
        assert_eq!(error.code(), code);
    }
}

#[tokio::test]
async fn material_of_another_tenant_version_or_provider_is_refused_before_anything_is_sent() {
    let http = Scripted::new(Vec::new());
    let provider = OpenBaoKeyProvider::new(http.clone(), &settings(approle()));
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let version = version(&tenant);
    let error = provider
        .sign(&elsewhere, &version, b"m", SignatureEncoding::Jose)
        .await
        .expect_err("another tenant");
    assert_eq!(error.code(), "keys.unusable");
    let mut snapshot = version.snapshot().clone();
    snapshot.id = KeyVersionId::generate();
    let error = provider
        .sign(
            &tenant,
            &KeyVersion::from_snapshot(snapshot),
            b"m",
            SignatureEncoding::Der,
        )
        .await
        .expect_err("another version");
    assert_eq!(error.code(), "keys.unusable");
    let mut snapshot = version.snapshot().clone();
    snapshot.provider = "local".to_owned();
    let error = provider
        .sign(
            &tenant,
            &KeyVersion::from_snapshot(snapshot),
            b"m",
            SignatureEncoding::Jose,
        )
        .await
        .expect_err("another provider");
    assert_eq!(error.code(), "keys.unusable");
    assert!(http.seen().is_empty());
}

#[tokio::test]
async fn a_new_token_is_asked_for_once_two_thirds_of_its_life_have_passed() {
    let http = Scripted::new(vec![
        signed_in("short", 1),
        signature(),
        signed_in("next", 3600),
        signature(),
    ]);
    let provider = OpenBaoKeyProvider::new(http.clone(), &settings(approle()));
    let tenant = TenantContext::assume(TenantId::generate());
    let version = version(&tenant);
    provider
        .sign(&tenant, &version, b"m", SignatureEncoding::Jose)
        .await
        .expect("signed");
    tokio::time::sleep(Duration::from_millis(700)).await;
    provider
        .sign(&tenant, &version, b"m", SignatureEncoding::Jose)
        .await
        .expect("signed");
    let seen = http.seen();
    assert_eq!(token_of(&seen[1]), Some("short"));
    assert_eq!(seen[2].url, format!("{ADDRESS}/v1/auth/approle/login"));
    assert_eq!(token_of(&seen[3]), Some("next"));
}

#[tokio::test]
async fn an_eddsa_signature_names_no_hash_and_is_the_same_in_both_encodings() {
    let tenant = TenantContext::assume(TenantId::generate());
    let id = KeyVersionId::generate();
    let name = OpenBaoKeyProvider::key_name(&tenant, id);
    let version = KeyVersion::create(
        id,
        KeyAlgorithm::EdDsa,
        "openbao",
        GeneratedKey {
            public_key: Some(PublicKey::Ed25519 { x: vec![3; 32] }),
            material: KeyMaterial::from_stored(format!("openbao:1:{name}:EdDSA").into_bytes()),
        },
        Timestamp::UNIX_EPOCH,
    )
    .expect("version")
    .0;
    // 64 bytes in base64, as OpenBao writes every signature but the JWS
    // marshaling of ECDSA.
    let ed25519 = || {
        Step::Answer(
            200,
            json!({"data": {"signature": format!("vault:v1:{}==", "A".repeat(86)), "key_version": 1}}),
        )
    };
    let http = Scripted::new(vec![signed_in("t", 3600), ed25519(), ed25519()]);
    let provider = OpenBaoKeyProvider::new(http.clone(), &settings(approle()));
    let jose = provider
        .sign(&tenant, &version, b"m", SignatureEncoding::Jose)
        .await
        .expect("signed");
    let der = provider
        .sign(&tenant, &version, b"m", SignatureEncoding::Der)
        .await
        .expect("signed");
    assert_eq!(jose.len(), 64);
    assert_eq!(jose, der);
    for sign in &http.seen()[1..] {
        assert_eq!(
            sign.url,
            format!("{ADDRESS}/v1/teams/hodor-transit/sign/{name}")
        );
        // The message itself is signed: no hash, no marshaling.
        assert_eq!(body(sign), json!({"input": "bQ==", "key_version": 1}));
    }

    // A signature of another size is not an Ed25519 signature.
    let http = Scripted::new(vec![
        signed_in("t", 3600),
        Step::Answer(
            200,
            json!({"data": {"signature": format!("vault:v1:{}", "A".repeat(84)), "key_version": 1}}),
        ),
    ]);
    let provider = OpenBaoKeyProvider::new(http, &settings(approle()));
    let error = provider
        .sign(&tenant, &version, b"m", SignatureEncoding::Jose)
        .await
        .expect_err("63 bytes");
    assert_eq!(error.code(), "keys.provider_failed");
}
