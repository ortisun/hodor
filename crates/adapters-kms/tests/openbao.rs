//! The OpenBao provider against a real OpenBao in a container, prepared
//! as an operator prepares theirs: Transit mounted at `hodor-transit`, the
//! policy Hodor ships (`deploy/openbao/hodor-policy.hcl`) and an AppRole
//! that gives it. Hodor signs in with that AppRole, as it would anywhere.

use hodor_adapters_crypto::{AwsLcVerifier, LocalKeyProvider, OsRandom, SecretKeys};
use hodor_adapters_http::{OutboundPolicy, ServiceHttpClient};
use hodor_adapters_kms::{OpenBaoKeyProvider, OpenBaoLogin, OpenBaoSettings};
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, Secret, SignatureVerifier as _, SystemClock, TenantContext, TenantId,
};
use hodor_keys::api::{
    KeyAlgorithm, KeyProvider, KeyProviders, KeyService, KeyUse, KeyVersionId, SignatureEncoding,
};
use hodor_keys::testing::{
    InMemoryKeys, ProviderPorts, der_to_jose, made_by, run_provider_contract,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use testcontainers::core::{IntoContainerPort as _, WaitFor};
use testcontainers::{ContainerAsync, GenericImage, ImageExt as _};
use x509_parser::prelude::FromDer as _;

/// Pinned, like every image a test starts.
const IMAGE: (&str, &str) = ("openbao/openbao", "2.7.2");
const ROOT: &str = "test-root-token";
const ROLE_ID: &str = "test-hodor-role";
const SECRET_ID: &str = "test-hodor-secret";
/// The policy Hodor ships, exactly.
const POLICY: &str = include_str!("../../../deploy/openbao/hodor-policy.hcl");

struct OpenBao {
    container: ContainerAsync<GenericImage>,
    address: String,
    administrator: reqwest::Client,
}

impl OpenBao {
    /// An OpenBao in development mode, over plain HTTP or, with `tls`,
    /// over HTTPS with a certificate of its own authority.
    async fn start(tls: bool) -> Self {
        let (name, tag) = IMAGE;
        let mut command = vec![
            "server",
            "-dev",
            "-dev-listen-address=0.0.0.0:8200",
            "-dev-no-store-token",
        ];
        if tls {
            command.extend(["-dev-tls", "-dev-tls-cert-dir=/openbao/logs"]);
        }
        let container = hodor_test_containers::start(
            "OpenBao",
            || {
                GenericImage::new(name, tag)
                    .with_exposed_port(8200.tcp())
                    .with_wait_for(WaitFor::message_on_either_std(
                        "Development mode should NOT be used",
                    ))
                    .with_env_var("BAO_DEV_ROOT_TOKEN_ID", ROOT)
                    .with_cmd(command.clone())
            },
            &[8200.tcp()],
        )
        .await;
        let port = container.port(8200);
        let container = container.into_container();
        let mut administrator = reqwest::Client::builder().no_proxy();
        let scheme = if tls {
            let authority = container
                .copy_file_from("/openbao/logs/vault-ca.pem", Vec::new())
                .await
                .expect("the development authority");
            administrator = administrator.tls_certs_only(
                reqwest::Certificate::from_pem_bundle(&authority).expect("certificates"),
            );
            "https"
        } else {
            "http"
        };
        let bao = Self {
            container,
            address: format!("{scheme}://localhost:{port}"),
            administrator: administrator.build().expect("client"),
        };
        bao.prepare().await;
        bao
    }

    /// What an operator does once, with the root token.
    async fn prepare(&self) {
        self.root(
            "POST",
            "sys/mounts/hodor-transit",
            json!({"type": "transit"}),
        )
        .await;
        self.root("POST", "sys/policies/acl/hodor", json!({"policy": POLICY}))
            .await;
        self.root("POST", "sys/auth/approle", json!({"type": "approle"}))
            .await;
        self.root(
            "POST",
            "auth/approle/role/hodor",
            json!({"token_policies": ["hodor"], "token_ttl": "1h"}),
        )
        .await;
        self.root(
            "POST",
            "auth/approle/role/hodor/role-id",
            json!({"role_id": ROLE_ID}),
        )
        .await;
        self.root(
            "POST",
            "auth/approle/role/hodor/custom-secret-id",
            json!({"secret_id": SECRET_ID}),
        )
        .await;
    }

    async fn request(
        &self,
        token: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let method = reqwest::Method::from_bytes(method.as_bytes()).expect("method");
        let mut request = self
            .administrator
            .request(method, format!("{}/v1/{path}", self.address))
            .header("x-vault-token", token);
        if let Some(body) = body {
            request = request.body(body.to_string());
        }
        let response = request.send().await.expect("OpenBao answers");
        let status = response.status().as_u16();
        let text = response.text().await.expect("body");
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn root(&self, method: &str, path: &str, body: Value) -> Value {
        let (status, answer) = self.request(ROOT, method, path, Some(body)).await;
        assert!((200..300).contains(&status), "{path}: {status} {answer}");
        answer
    }

    async fn root_read(&self, path: &str) -> (u16, Value) {
        self.request(ROOT, "GET", path, None).await
    }

    /// A token as Hodor gets one: the AppRole's.
    async fn hodor_token(&self) -> String {
        let (status, answer) = self
            .request(
                "",
                "POST",
                "auth/approle/login",
                Some(json!({"role_id": ROLE_ID, "secret_id": SECRET_ID})),
            )
            .await;
        assert_eq!(status, 200, "{answer}");
        answer["auth"]["client_token"]
            .as_str()
            .expect("a token")
            .to_owned()
    }

    fn settings(&self) -> OpenBaoSettings {
        OpenBaoSettings {
            address: self.address.clone(),
            transit_mount: "hodor-transit".to_owned(),
            login: OpenBaoLogin::AppRole {
                mount: "approle".to_owned(),
                role_id: ROLE_ID.to_owned(),
                secret_id: Secret::new(SECRET_ID.to_owned()),
            },
            time_limit: Duration::from_secs(10),
            certificate_authorities: None,
        }
    }

    /// The provider as the server builds it: through a client that calls
    /// this address and nothing else.
    fn provider(&self) -> OpenBaoKeyProvider {
        let http = ServiceHttpClient::new(
            std::slice::from_ref(&self.address),
            OutboundPolicy::default(),
        )
        .expect("client");
        OpenBaoKeyProvider::new(Arc::new(http), &self.settings())
    }
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

fn local() -> Arc<LocalKeyProvider> {
    let key = SecretKeys::generate(&OsRandom);
    Arc::new(LocalKeyProvider::new(Arc::new(
        SecretKeys::parse(&Secret::new(format!("root:{}", key.expose()))).expect("root keys"),
    )))
}

#[tokio::test]
async fn the_openbao_provider_passes_the_contract_of_a_key_provider() {
    let bao = OpenBao::start(false).await;
    let provider = bao.provider();
    run_provider_contract(ProviderPorts {
        provider: &provider,
        verifier: &AwsLcVerifier,
        signing: &[
            KeyAlgorithm::Es256,
            KeyAlgorithm::Rs256,
            KeyAlgorithm::Ps256,
        ],
        data: false,
    })
    .await;
}

#[tokio::test]
async fn a_key_is_made_in_transit_named_for_its_tenant_and_version_and_never_exportable() {
    let bao = OpenBao::start(false).await;
    let provider = bao.provider();
    let tenant = tenant();
    for (algorithm, kind) in [
        (KeyAlgorithm::Es256, "ecdsa-p256"),
        (KeyAlgorithm::Rs256, "rsa-2048"),
    ] {
        let version = made_by(&provider, &tenant, algorithm).await;
        assert_eq!(version.snapshot().provider, "openbao");
        let name = OpenBaoKeyProvider::key_name(&tenant, version.id());
        assert_eq!(
            name,
            format!("tenant-{}-version-{}", tenant.tenant_id(), version.id())
        );
        // The material is the key's name and nothing secret.
        assert_eq!(
            version.material().as_bytes(),
            format!("openbao:1:{name}:{}", algorithm.as_str()).as_bytes()
        );
        let (status, key) = bao.root_read(&format!("hodor-transit/keys/{name}")).await;
        assert_eq!(status, 200);
        let data = &key["data"];
        assert_eq!(data["type"], kind);
        assert_eq!(data["exportable"], false);
        assert_eq!(data["allow_plaintext_backup"], false);
        assert_eq!(data["latest_version"], 1);
    }
}

#[tokio::test]
async fn hodors_policy_never_lets_the_private_part_of_a_key_out() {
    let bao = OpenBao::start(false).await;
    let provider = bao.provider();
    let tenant = tenant();
    let version = made_by(&provider, &tenant, KeyAlgorithm::Es256).await;
    let name = OpenBaoKeyProvider::key_name(&tenant, version.id());
    let token = bao.hodor_token().await;

    // What Hodor's policy allows answers no private key.
    let (status, read) = bao
        .request(&token, "GET", &format!("hodor-transit/keys/{name}"), None)
        .await;
    assert_eq!(status, 200);
    assert!(!read.to_string().contains("PRIVATE"), "{read}");

    let other = OpenBaoKeyProvider::key_name(&tenant, KeyVersionId::generate());
    let refused: Vec<(&str, String, Option<Value>)> = vec![
        (
            "GET",
            format!("hodor-transit/export/signing-key/{name}"),
            None,
        ),
        (
            "GET",
            format!("hodor-transit/export/signing-key/{name}/1"),
            None,
        ),
        ("GET", format!("hodor-transit/backup/{name}"), None),
        (
            "POST",
            format!("hodor-transit/keys/{name}/config"),
            Some(json!({"exportable": true, "allow_plaintext_backup": true})),
        ),
        (
            "POST",
            format!("hodor-transit/keys/{name}/rotate"),
            Some(json!({})),
        ),
        ("DELETE", format!("hodor-transit/keys/{name}"), None),
        ("LIST", "hodor-transit/keys".to_owned(), None),
        (
            "POST",
            format!("hodor-transit/keys/{other}"),
            Some(json!({"type": "ecdsa-p256", "exportable": true})),
        ),
        (
            "POST",
            format!("hodor-transit/keys/{other}"),
            Some(json!({"type": "ecdsa-p256", "allow_plaintext_backup": true})),
        ),
        (
            "POST",
            format!("hodor-transit/keys/{other}"),
            Some(json!({"type": "aes256-gcm96"})),
        ),
        (
            "POST",
            format!("hodor-transit/encrypt/{name}"),
            Some(json!({"plaintext": "aGVsbG8="})),
        ),
        (
            "POST",
            "hodor-transit/restore".to_owned(),
            Some(json!({"backup": "x"})),
        ),
        ("GET", "sys/mounts".to_owned(), None),
        (
            "POST",
            "sys/policies/acl/hodor".to_owned(),
            Some(json!({"policy": "path \"*\" { capabilities = [\"sudo\"] }"})),
        ),
        (
            "POST",
            "auth/approle/role/hodor/secret-id".to_owned(),
            Some(json!({})),
        ),
    ];
    for (method, path, body) in refused {
        let (status, answer) = bao.request(&token, method, &path, body).await;
        assert_eq!(status, 403, "{method} {path}: {answer}");
    }

    // Even a key an administrator made exportable stays inside for Hodor:
    // the policy, not the key's setting, is what keeps it there.
    bao.root(
        "POST",
        &format!("hodor-transit/keys/{name}/config"),
        json!({"exportable": true}),
    )
    .await;
    let (status, answer) = bao
        .request(
            &token,
            "GET",
            &format!("hodor-transit/export/signing-key/{name}"),
            None,
        )
        .await;
    assert_eq!(status, 403, "{answer}");
    // And the provider no longer signs with it: it is not a key Hodor
    // makes.
    let error = provider
        .generate(&tenant, version.id(), KeyAlgorithm::Es256)
        .await
        .expect_err("an exportable key is refused");
    assert_eq!(error.code(), "keys.provider_failed");
}

#[tokio::test]
async fn a_key_under_the_name_that_hodor_would_not_have_made_is_refused() {
    let bao = OpenBao::start(false).await;
    let provider = bao.provider();
    let tenant = tenant();
    let cases = [
        ("of another type", json!({"type": "rsa-2048"})),
        (
            "exportable",
            json!({"type": "ecdsa-p256", "exportable": true}),
        ),
        (
            "backed up in plaintext",
            json!({"type": "ecdsa-p256", "exportable": true, "allow_plaintext_backup": true}),
        ),
    ];
    for (case, body) in cases {
        let version = KeyVersionId::generate();
        let name = OpenBaoKeyProvider::key_name(&tenant, version);
        bao.root("POST", &format!("hodor-transit/keys/{name}"), body)
            .await;
        let error = provider
            .generate(&tenant, version, KeyAlgorithm::Es256)
            .await
            .expect_err(case);
        assert_eq!(error.code(), "keys.provider_failed", "{case}");
    }
    let rotated = KeyVersionId::generate();
    let name = OpenBaoKeyProvider::key_name(&tenant, rotated);
    bao.root(
        "POST",
        &format!("hodor-transit/keys/{name}"),
        json!({"type": "ecdsa-p256"}),
    )
    .await;
    bao.root(
        "POST",
        &format!("hodor-transit/keys/{name}/rotate"),
        json!({}),
    )
    .await;
    assert!(
        provider
            .generate(&tenant, rotated, KeyAlgorithm::Es256)
            .await
            .is_err(),
        "rotated in OpenBao"
    );
    // A data key is not made in OpenBao at all.
    let error = provider
        .generate(&tenant, KeyVersionId::generate(), KeyAlgorithm::A256Gcm)
        .await
        .expect_err("no data key");
    assert_eq!(error.code(), "keys.algorithm_unsupported");
}

#[tokio::test]
async fn a_token_openbao_no_longer_accepts_is_replaced_by_signing_in_again() {
    let bao = OpenBao::start(false).await;
    let provider = bao.provider();
    let tenant = tenant();
    let version = made_by(&provider, &tenant, KeyAlgorithm::Es256).await;
    // Every token the AppRole gave, Hodor's included, is revoked.
    bao.root(
        "POST",
        "sys/leases/revoke-prefix/auth/approle/login",
        json!({}),
    )
    .await;
    let signature = provider
        .sign(&tenant, &version, b"after", SignatureEncoding::Jose)
        .await
        .expect("signed after signing in again");
    assert!(AwsLcVerifier.verify(
        hodor_kernel::SignatureAlgorithm::Es256,
        version.public_key().expect("public"),
        b"after",
        &signature
    ));
}

#[tokio::test]
async fn the_tenants_token_signing_keys_can_live_in_openbao() {
    let bao = OpenBao::start(false).await;
    let providers = KeyProviders::new(Arc::new(bao.provider()), local());
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let keys = KeyService::new(
        Arc::new(units_of_work),
        Arc::new(InMemoryKeys::default()),
        Arc::new(providers),
        Arc::new(SystemClock),
    );
    let tenant = tenant();
    for algorithm in [KeyAlgorithm::Es256, KeyAlgorithm::Rs256] {
        let active = keys
            .ensure_active(&tenant, algorithm, Caller::system())
            .await
            .expect("a first key, made in OpenBao");
        assert_eq!(active.snapshot().provider, "openbao");
        let (signed, signature) = keys
            .sign_naming_key(&tenant, algorithm, |kid| {
                format!("header naming {kid}.claims").into_bytes()
            })
            .await
            .expect("signed in OpenBao");
        assert_eq!(signature.key_version_id, active.id());
        assert!(AwsLcVerifier.verify(
            algorithm.signature().expect("signing"),
            active.public_key().expect("public"),
            &signed,
            &signature.bytes
        ));
    }
    let set = keys
        .key_set(&tenant, KeyUse::Signing)
        .await
        .expect("key set");
    assert!(
        set.versions()
            .iter()
            .all(|version| version.snapshot().provider == "openbao")
    );
}

#[tokio::test]
async fn with_openbao_down_nothing_signs_and_nothing_falls_back_to_the_local_provider() {
    let bao = OpenBao::start(false).await;
    let local = local();
    let providers = KeyProviders::new(Arc::new(bao.provider()), local.clone());
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryKeys::default();
    let keys = KeyService::new(
        Arc::new(units_of_work),
        Arc::new(store),
        Arc::new(providers.clone()),
        Arc::new(SystemClock),
    );
    let tenant = tenant();
    let active = keys
        .ensure_active(&tenant, KeyAlgorithm::Es256, Caller::system())
        .await
        .expect("made in OpenBao");
    let data = made_by(&providers, &tenant, KeyAlgorithm::A256Gcm).await;
    assert_eq!(data.snapshot().provider, "local");

    bao.container.stop().await.expect("stopped");

    for encoding in [SignatureEncoding::Jose, SignatureEncoding::Der] {
        let error = providers
            .sign(&tenant, &active, b"m", encoding)
            .await
            .expect_err("nothing signs");
        assert_eq!(error.code(), "keys.provider_unavailable");
    }
    let error = keys
        .sign_naming_key(&tenant, KeyAlgorithm::Es256, |_| b"m".to_vec())
        .await
        .expect_err("no token is signed");
    assert_eq!(error.code(), "keys.provider_unavailable");
    let error = keys
        .ensure_active(&tenant, KeyAlgorithm::Rs256, Caller::system())
        .await
        .expect_err("no first key is made elsewhere");
    assert_eq!(error.code(), "keys.provider_unavailable");
    // The local provider was there all along, and signed nothing: the key
    // set holds the one version made in OpenBao.
    let set = keys
        .key_set(&tenant, KeyUse::Signing)
        .await
        .expect("key set");
    assert_eq!(set.versions().len(), 1);
    assert_eq!(set.versions()[0].snapshot().provider, "openbao");
    // Data keys stay with the local provider, and still work.
    let secret = Secret::new(b"s".to_vec());
    assert!(
        providers
            .encrypt(&tenant, &data, b"x", &secret)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn openbao_is_reached_over_https_with_an_authority_of_the_operators_own() {
    let bao = OpenBao::start(true).await;
    let authority = bao
        .container
        .copy_file_from("/openbao/logs/vault-ca.pem", Vec::new())
        .await
        .expect("the development authority");
    let origins = [bao.address.clone()];
    let trusting =
        ServiceHttpClient::trusting_only(&origins, OutboundPolicy::default(), &authority)
            .expect("client");
    let provider = OpenBaoKeyProvider::new(Arc::new(trusting), &bao.settings());
    let tenant = tenant();
    let version = made_by(&provider, &tenant, KeyAlgorithm::Es256).await;
    let der = provider
        .sign(&tenant, &version, b"over https", SignatureEncoding::Der)
        .await
        .expect("signed");
    assert!(AwsLcVerifier.verify(
        hodor_kernel::SignatureAlgorithm::Es256,
        version.public_key().expect("public"),
        b"over https",
        &der_to_jose(&der, 32).expect("DER")
    ));

    // Without the authority, the system's authorities do not know
    // OpenBao's certificate: nothing is made.
    let untrusting = ServiceHttpClient::new(&origins, OutboundPolicy::default()).expect("client");
    let provider = OpenBaoKeyProvider::new(Arc::new(untrusting), &bao.settings());
    let error = provider
        .generate(&tenant, KeyVersionId::generate(), KeyAlgorithm::Es256)
        .await
        .expect_err("an unknown authority");
    assert_eq!(error.code(), "keys.provider_unavailable");
}

/// The certificate authority of a tenant on OpenBao, as an installation
/// with the authority `on` builds it: the key made by OpenBao for the
/// authority's own identifier, and signed there.
fn authority_on(bao: &OpenBao) -> (hodor_keys::api::AuthorityService, InMemoryUnitOfWorkFactory) {
    let openbao: Arc<dyn KeyProvider> = Arc::new(bao.provider());
    let providers = KeyProviders::new(local(), local()).with_authorities(openbao);
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let service = hodor_keys::api::AuthorityService::new(
        hodor_keys::api::AuthorityPorts {
            units_of_work: Arc::new(units_of_work.clone()),
            store: Arc::new(hodor_keys::testing::InMemoryAuthorities::default()),
            trust_domains: Arc::new(hodor_keys::testing::InMemoryTrustDomains::default()),
            maker: providers.authorities(),
            signer: Arc::new(providers),
            certificates: Arc::new(hodor_adapters_crypto::X509Certificates),
            digest: Arc::new(hodor_adapters_crypto::Sha256Digest),
            clock: Arc::new(SystemClock),
        },
        false,
    );
    (service, units_of_work)
}

#[tokio::test]
async fn an_authoritys_root_is_made_and_signed_in_openbao_and_its_key_never_comes_out() {
    let bao = OpenBao::start(false).await;
    let (service, units_of_work) = authority_on(&bao);
    let tenant = tenant();
    let authority = service
        .create(
            &tenant,
            hodor_keys::api::NewAuthority {
                kind: "root".to_owned(),
                trust_domains: vec!["prod.example.com".to_owned()],
                ..hodor_keys::api::NewAuthority::default()
            },
            Caller::system(),
        )
        .await
        .expect("a root, on a provider that signs inside itself");
    let key = authority.key();
    assert_eq!(key.provider, "openbao");
    assert!(!authority.snapshot().for_development);
    let name = OpenBaoKeyProvider::key_name(&tenant, key.id);

    // The key is OpenBao's, made not exportable, and its certificate is
    // signed by it: the signature checks with the public key OpenBao
    // answers, independently of Hodor.
    let (status, read) = bao.root_read(&format!("hodor-transit/keys/{name}")).await;
    assert_eq!(status, 200);
    assert_eq!(read["data"]["type"], "ecdsa-p256");
    assert_eq!(read["data"]["exportable"], false);
    assert_eq!(read["data"]["allow_plaintext_backup"], false);
    let certificate = &authority.certificate().expect("a certificate").der;
    let (_, parsed) =
        x509_parser::certificate::X509Certificate::from_der(certificate).expect("reads");
    let jose = der_to_jose(&parsed.signature_value.data, 32).expect("an ECDSA signature");
    assert!(AwsLcVerifier.verify(
        hodor_kernel::SignatureAlgorithm::Es256,
        &key.public_key,
        parsed.tbs_certificate.as_ref(),
        &jose,
    ));
    let pem = read["data"]["keys"]["1"]["public_key"]
        .as_str()
        .expect("OpenBao's public key");
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("PEM");
    let (_, spki) =
        x509_parser::x509::SubjectPublicKeyInfo::from_der(&block.contents).expect("a public key");
    assert_eq!(
        spki.subject_public_key.data.as_ref(),
        parsed.public_key().subject_public_key.data.as_ref()
    );

    // Hodor's own token cannot take the private key out, in any way its
    // policy might be asked.
    let token = bao.hodor_token().await;
    let (status, answer) = bao
        .request(&token, "GET", &format!("hodor-transit/keys/{name}"), None)
        .await;
    assert_eq!(status, 200);
    assert!(!answer.to_string().contains("PRIVATE"), "{answer}");
    for (method, path, body) in [
        (
            "GET",
            format!("hodor-transit/export/signing-key/{name}"),
            None,
        ),
        (
            "GET",
            format!("hodor-transit/export/signing-key/{name}/1"),
            None,
        ),
        ("GET", format!("hodor-transit/backup/{name}"), None),
        (
            "POST",
            format!("hodor-transit/keys/{name}/config"),
            Some(json!({"exportable": true, "allow_plaintext_backup": true})),
        ),
        ("DELETE", format!("hodor-transit/keys/{name}"), None),
    ] {
        let (status, answer) = bao.request(&token, method, &path, body).await;
        assert_eq!(status, 403, "{method} {path}: {answer}");
    }

    // The key signs for its tenant alone.
    let other = TenantContext::assume(TenantId::generate());
    let refused = bao
        .provider()
        .sign(
            &other,
            &key.version(SystemClock.now()),
            b"anything",
            SignatureEncoding::Der,
        )
        .await
        .expect_err("refused for another tenant");
    assert_eq!(refused.code(), "keys.unusable");
    assert_eq!(
        units_of_work.committed_event_types()[..3],
        [
            "keys.authority_created",
            "keys.authority_signed",
            "keys.authority_activated",
        ]
    );
}
