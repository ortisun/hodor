//! The certificate authority of a tenant with real certificates and the
//! local key provider: what it writes, what it signs, and what Hodor's own
//! chain checking and OpenSSL make of certificates below it.

use hodor_adapters_crypto::{
    LocalKeyProvider, OsRandom, SecretKeys, Sha256Digest, X509Certificates, check_path,
};
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock as _, Secret, SystemClock, TenantContext, TenantId};
use hodor_keys::api::{
    AuthorityPorts, AuthorityService, AuthorityState, CertificateAuthority, CertificateWriter as _,
    KeyProvider, NewAuthority, SignatureEncoding, TrustDomainPorts, TrustDomainService,
    TrustSource, TrustSourceRequest, to_pem,
};
use hodor_keys::testing::{FakeBundleEndpoints, InMemoryAuthorities, InMemoryTrustDomains};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints, RemoteKeyPair, SanType,
};
use std::process::Command;
use std::sync::{Arc, Mutex};
use x509_parser::prelude::{FromDer as _, GeneralName, ParsedExtension, X509Certificate};

const PROD: &str = "prod.example.com";
const EDGE: &str = "edge.example.com";

struct World {
    service: AuthorityService,
    trust_domains: TrustDomainService,
    provider: Arc<LocalKeyProvider>,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
}

fn world(for_development: bool) -> World {
    let root = SecretKeys::generate(&OsRandom);
    let keys = SecretKeys::parse(&Secret::new(format!("root:{}", root.expose()))).expect("keys");
    let provider = Arc::new(LocalKeyProvider::new(Arc::new(keys)));
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryTrustDomains::default();
    let endpoints = FakeBundleEndpoints::default();
    let service = AuthorityService::new(
        AuthorityPorts {
            units_of_work: Arc::new(units_of_work.clone()),
            store: Arc::new(InMemoryAuthorities::default()),
            trust_domains: Arc::new(store.clone()),
            maker: provider.clone(),
            signer: provider.clone(),
            certificates: Arc::new(X509Certificates),
            digest: Arc::new(Sha256Digest),
            clock: Arc::new(SystemClock),
        },
        for_development,
    );
    let trust_domains = TrustDomainService::new(TrustDomainPorts {
        units_of_work: Arc::new(units_of_work.clone()),
        store: Arc::new(store),
        destinations: Arc::new(endpoints.clone()),
        http: Arc::new(endpoints),
        digest: Arc::new(Sha256Digest),
        clock: Arc::new(SystemClock),
    });
    World {
        service,
        trust_domains,
        provider,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn asked(kind: &str, names: &[&str]) -> NewAuthority {
    NewAuthority {
        kind: kind.to_owned(),
        trust_domains: names.iter().map(|name| (*name).to_owned()).collect(),
        ..NewAuthority::default()
    }
}

async fn root(world: &World) -> CertificateAuthority {
    world
        .service
        .create(
            &world.tenant,
            asked("root", &[PROD, EDGE]),
            Caller::system(),
        )
        .await
        .expect("a root")
}

/// A key that remembers what it is asked to sign: the authority's key is
/// in the provider, which signs what this remembers.
struct Remembers {
    public_key: Vec<u8>,
    asked: Arc<Mutex<Option<Vec<u8>>>>,
}

impl RemoteKeyPair for Remembers {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        *self.asked.lock().expect("lock") = Some(message.to_vec());
        Ok(vec![0; 8])
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

fn point(key: &hodor_kernel::PublicKey) -> Vec<u8> {
    let hodor_kernel::PublicKey::P256 { x, y } = key else {
        panic!("a P-256 key")
    };
    [&[0x04][..], x, y].concat()
}

fn remembering(key: &hodor_kernel::PublicKey) -> (KeyPair, Arc<Mutex<Option<Vec<u8>>>>) {
    let asked = Arc::new(Mutex::new(None));
    let pair = KeyPair::from_remote(Box::new(Remembers {
        public_key: point(key),
        asked: asked.clone(),
    }))
    .expect("key");
    (pair, asked)
}

fn subject(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, "Hodor");
    name.push(DnType::CommonName, common_name);
    name
}

/// What a certificate signed by the authority's key needs: the authority
/// as `rcgen` names an issuer, and the key that remembers.
async fn signed_by_authority(
    world: &World,
    authority: &CertificateAuthority,
    params: CertificateParams,
    subject_key: &KeyPair,
) -> (Vec<u8>, rcgen::Certificate) {
    let public_key = &authority.key().public_key;
    let mut issuer = CertificateParams::default();
    issuer.distinguished_name = subject(&authority.snapshot().common_name);
    issuer.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    let (issuer_key, _) = remembering(public_key);
    let issuer = issuer.self_signed(&issuer_key).expect("issuer");
    let (key, asked) = remembering(public_key);
    let written = params
        .signed_by(subject_key, &issuer, &key)
        .expect("written");
    let tbs = asked.lock().expect("lock").take().expect("asked");
    let signature = world
        .provider
        .sign(
            &world.tenant,
            &authority.key().version(SystemClock.now()),
            &tbs,
            SignatureEncoding::Der,
        )
        .await
        .expect("signed");
    (X509Certificates.signed(&tbs, &signature), written)
}

fn leaf(names: Vec<SanType>) -> (CertificateParams, KeyPair) {
    let mut params = CertificateParams::default();
    params.distinguished_name = subject("workload");
    params.subject_alt_names = names;
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    (params, KeyPair::generate().expect("key"))
}

fn uri(value: &str) -> SanType {
    SanType::URI(value.try_into().expect("an IA5 string"))
}

fn dns(value: &str) -> SanType {
    SanType::DnsName(value.try_into().expect("an IA5 string"))
}

/// What OpenSSL says of a path, if it is installed: `Some(true)` when it
/// verifies.
fn openssl_verifies(anchor: &[u8], intermediates: &[Vec<u8>], leaf: &[u8]) -> Option<bool> {
    let directory = std::env::temp_dir().join(format!("hodor-authority-{}", uuid()));
    std::fs::create_dir_all(&directory).ok()?;
    let write = |name: &str, ders: &[&[u8]]| {
        let path = directory.join(name);
        let pem: String = ders.iter().map(|der| to_pem("CERTIFICATE", der)).collect();
        std::fs::write(&path, pem).expect("written");
        path
    };
    let anchor_file = write("anchor.pem", &[anchor]);
    let leaf_file = write("leaf.pem", &[leaf]);
    let mut command = Command::new("openssl");
    command.arg("verify").arg("-CAfile").arg(&anchor_file);
    if !intermediates.is_empty() {
        let refs: Vec<&[u8]> = intermediates.iter().map(Vec::as_slice).collect();
        command
            .arg("-untrusted")
            .arg(write("intermediates.pem", &refs));
    }
    let output = command.arg(&leaf_file).output().ok();
    let _ = std::fs::remove_dir_all(&directory);
    let output = output?;
    Some(output.status.success())
}

fn uuid() -> String {
    TenantId::generate().to_string()
}

#[tokio::test]
async fn the_local_provider_is_refused_unless_the_installation_is_for_development() {
    let world = world(false);
    let refused = world
        .service
        .create(&world.tenant, asked("root", &[PROD]), Caller::system())
        .await
        .expect_err("refused");
    assert_eq!(refused.code(), "keys.authority_provider_unsuitable");
    assert!(world.units_of_work.committed_event_types().is_empty());
    assert_eq!(
        world
            .service
            .get(&world.tenant)
            .await
            .expect_err("none")
            .code(),
        "keys.authority_not_found"
    );
}

#[tokio::test]
async fn a_root_is_signed_by_its_own_key_with_its_constraints_and_trusted_at_once() {
    let world = world(true);
    let authority = root(&world).await;
    assert_eq!(authority.state(), AuthorityState::Active);
    let certificate = authority.certificate().expect("a certificate");
    let (rest, parsed) = X509Certificate::from_der(&certificate.der).expect("reads");
    assert!(rest.is_empty());

    // Its own key signed it.
    let public = aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        point(&authority.key().public_key),
    );
    public
        .verify(
            parsed.tbs_certificate.as_ref(),
            &parsed.signature_value.data,
        )
        .expect("the signature checks with the authority's public key");
    assert_eq!(parsed.subject(), parsed.issuer());
    assert_eq!(
        parsed.subject().to_string(),
        "O=Hodor, CN=Hodor certificate authority (development)"
    );
    assert_eq!(
        hodor_keys::api::hexadecimal(parsed.raw_serial()),
        certificate.serial_number
    );

    // An authority of path length one, signing certificates, constrained
    // to its trust domains.
    let basic = parsed.basic_constraints().expect("once").expect("present");
    assert!(basic.critical && basic.value.ca);
    assert_eq!(basic.value.path_len_constraint, Some(1));
    let usage = parsed.key_usage().expect("once").expect("present");
    assert!(usage.critical && usage.value.key_cert_sign() && usage.value.crl_sign());
    let constraints = parsed
        .extensions()
        .iter()
        .find(|extension| {
            matches!(
                extension.parsed_extension(),
                ParsedExtension::NameConstraints(_)
            )
        })
        .expect("name constraints");
    assert!(constraints.critical);
    let ParsedExtension::NameConstraints(constraints) = constraints.parsed_extension() else {
        unreachable!()
    };
    let permitted: Vec<String> = constraints
        .permitted_subtrees
        .iter()
        .flatten()
        .map(|subtree| format!("{:?}", subtree.base))
        .collect();
    assert_eq!(
        permitted,
        [
            format!("{:?}", GeneralName::URI(PROD)),
            format!("{:?}", GeneralName::URI(EDGE)),
            format!("{:?}", GeneralName::DNSName(PROD)),
            format!("{:?}", GeneralName::DNSName(EDGE)),
        ]
    );
    let excluded: Vec<String> = constraints
        .excluded_subtrees
        .iter()
        .flatten()
        .map(|subtree| format!("{:?}", subtree.base))
        .collect();
    assert_eq!(
        excluded,
        [
            format!("{:?}", GeneralName::IPAddress(&[0; 8])),
            format!("{:?}", GeneralName::IPAddress(&[0; 32])),
        ]
    );

    // Its trust domains hold its bundle, and say where it comes from.
    let bundle = authority.bundle().expect("reads").expect("a bundle");
    for name in [PROD, EDGE] {
        let domain = world
            .trust_domains
            .find_by_name(&world.tenant, name)
            .await
            .expect("read")
            .expect("added");
        assert_eq!(domain.source(), TrustSource::Authority);
        assert_eq!(domain.bundle(), Some(&bundle));
    }
    assert_eq!(
        world.units_of_work.committed_event_types(),
        [
            "keys.authority_created",
            "keys.authority_signed",
            "keys.authority_activated",
            "keys.trust_domain_added",
            "keys.trust_domain_added",
        ]
    );
    let signed = &world.units_of_work.committed_events()[1].payload;
    assert_eq!(signed["signed"], "certificate");
    assert_eq!(signed["serial_number"], certificate.serial_number.as_str());
    assert_eq!(signed["trust_domains"], serde_json::json!([PROD, EDGE]));
    assert_eq!(
        signed["signed_sha256"],
        hodor_keys::api::hexadecimal(&<Sha256Digest as hodor_kernel::Digest>::sha256(
            &Sha256Digest,
            parsed.tbs_certificate.as_ref()
        ))
    );
}

#[tokio::test]
async fn a_certificate_below_it_for_a_name_outside_its_trust_domains_fails_verification() {
    let world = world(true);
    let authority = root(&world).await;
    let anchor = authority.certificate().expect("certificate").der.clone();
    let now = SystemClock.now();

    // A mesh's intermediate, constrained to one trust domain by DNS name
    // and to none by URI, as Issue-117 will sign them.
    let mut mesh = CertificateParams::default();
    mesh.distinguished_name = subject("mesh intermediate");
    mesh.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    mesh.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    mesh.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName(PROD.to_owned())],
        excluded_subtrees: Vec::new(),
    });
    let mesh_key = KeyPair::generate().expect("key");
    let (mesh_der, mesh_issuer) = signed_by_authority(&world, &authority, mesh, &mesh_key).await;
    let intermediates = vec![mesh_der];

    let under_mesh = |names: Vec<SanType>| {
        let (params, key) = leaf(names);
        params
            .signed_by(&key, &mesh_issuer, &mesh_key)
            .expect("signed")
            .der()
            .to_vec()
    };
    let within = [
        under_mesh(vec![uri("spiffe://prod.example.com/ns/payments/sa/api")]),
        under_mesh(vec![dns(
            "api.payments.serviceaccount.identity.linkerd.prod.example.com",
        )]),
    ];
    for certificate in &within {
        assert_eq!(
            check_path(
                certificate,
                &intermediates,
                std::slice::from_ref(&anchor),
                now
            )
            .ok(),
            Some(0)
        );
        if let Some(verified) = openssl_verifies(&anchor, &intermediates, certificate) {
            assert!(
                verified,
                "OpenSSL accepts a certificate within the trust domains"
            );
        }
    }
    let outside = [
        under_mesh(vec![uri("spiffe://other.example.com/ns/a/sa/b")]),
        under_mesh(vec![uri("spiffe://sub.prod.example.com/x")]),
        under_mesh(vec![dns("api.other.example.com")]),
        under_mesh(vec![SanType::IpAddress(
            "10.0.0.7".parse().expect("address"),
        )]),
    ];
    for certificate in &outside {
        let refused = check_path(
            certificate,
            &intermediates,
            std::slice::from_ref(&anchor),
            now,
        )
        .expect_err("refused by Hodor's chain checking");
        assert_eq!(refused.code(), "certificate.path_refused");
        if let Some(verified) = openssl_verifies(&anchor, &intermediates, certificate) {
            assert!(
                !verified,
                "OpenSSL refuses a certificate outside the trust domains"
            );
        }
    }

    // The check of a forwarded certificate goes through the same path,
    // with the authority's bundle element as its authority.
    {
        use hodor_oauth::api::CertificateCheck as _;
        let bundle = authority.bundle().expect("reads").expect("a bundle");
        let element = bundle.keys()[0].jwk.as_str();
        for certificate in &within {
            assert!(hodor_adapters_crypto::X509CertificateCheck.chains_to(
                certificate,
                &intermediates,
                &[element],
                now
            ));
        }
        for certificate in &outside {
            assert!(!hodor_adapters_crypto::X509CertificateCheck.chains_to(
                certificate,
                &intermediates,
                &[element],
                now
            ));
        }
    }

    // Directly below the root, the same holds.
    let (params, key) = leaf(vec![uri("spiffe://edge.example.com/x")]);
    let (direct, _) = signed_by_authority(&world, &authority, params, &key).await;
    assert!(check_path(&direct, &[], std::slice::from_ref(&anchor), now).is_ok());
    let (params, key) = leaf(vec![uri("spiffe://elsewhere.example/x")]);
    let (direct, _) = signed_by_authority(&world, &authority, params, &key).await;
    assert!(check_path(&direct, &[], std::slice::from_ref(&anchor), now).is_err());

    // `rustls-webpki` given the anchor as it is refuses even a URI within
    // the trust domains: why Hodor reads the URI constraints itself.
    let anchor_der = rustls_pki_types::CertificateDer::from(anchor.as_slice());
    let whole = [webpki::anchor_from_trusted_cert(&anchor_der).expect("anchor")];
    let leaf_der = rustls_pki_types::CertificateDer::from(within[0].as_slice());
    let end_entity = webpki::EndEntityCert::try_from(&leaf_der).expect("reads");
    let intermediate_ders: Vec<_> = intermediates
        .iter()
        .map(|der| rustls_pki_types::CertificateDer::from(der.as_slice()))
        .collect();
    let seconds = u64::try_from(now.unix_timestamp()).expect("after 1970");
    let unread = end_entity.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &whole,
        &intermediate_ders,
        rustls_pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(seconds)),
        webpki::KeyUsage::client_auth(),
        None,
        None,
    );
    assert!(unread.is_err());
    drop(unread);
}

#[tokio::test]
async fn an_intermediate_asks_for_its_certificate_and_takes_only_one_that_fits() {
    let world = world(true);
    let authority = world
        .service
        .create(
            &world.tenant,
            NewAuthority {
                common_name: Some("Example meshes".to_owned()),
                ..asked("intermediate", &[PROD])
            },
            Caller::system(),
        )
        .await
        .expect("an intermediate");
    assert_eq!(authority.state(), AuthorityState::AwaitingCertificate);
    assert_eq!(authority.bundle().expect("reads"), None);
    assert!(
        world
            .trust_domains
            .find_by_name(&world.tenant, PROD)
            .await
            .expect("read")
            .is_none(),
        "nothing is trusted before it is active"
    );

    // The request is signed by the authority's key and asks for an
    // authority constrained to its trust domains.
    let request_der = authority
        .snapshot()
        .certificate_signing_request
        .clone()
        .expect("a request");
    let (_, request) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&request_der)
            .expect("a request");
    let public = aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        point(&authority.key().public_key),
    );
    public
        .verify(
            request.certification_request_info.raw,
            &request.signature_value.data,
        )
        .expect("the request's signature checks");
    let requested: Vec<String> = request
        .requested_extensions()
        .into_iter()
        .flatten()
        .map(|extension| format!("{extension:?}"))
        .collect();
    assert!(
        requested.iter().any(|e| e.contains("BasicConstraints")),
        "{requested:?}"
    );
    assert!(
        requested.iter().any(|e| e.contains("NameConstraints")),
        "{requested:?}"
    );
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["keys.authority_created", "keys.authority_signed"]
    );

    // The tenant's own root signs it, outside Hodor.
    let mut tenant_root = CertificateParams::default();
    tenant_root.distinguished_name = subject("Example root");
    tenant_root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let tenant_root_key = KeyPair::generate().expect("key");
    let tenant_root = tenant_root.self_signed(&tenant_root_key).expect("root");
    let (holds, _) = remembering(&authority.key().public_key);
    let common_name = authority.snapshot().common_name.clone();
    assert_eq!(common_name, "Example meshes (development)");
    let issue = |constraints: Option<NameConstraints>, is_ca: bool, key: &KeyPair| {
        let mut params = CertificateParams::default();
        params.distinguished_name = subject(&common_name);
        if is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        }
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.name_constraints = constraints;
        params
            .signed_by(key, &tenant_root, &tenant_root_key)
            .expect("signed")
            .pem()
    };
    let constraints = |dns_names: &[&str]| {
        Some(NameConstraints {
            permitted_subtrees: dns_names
                .iter()
                .map(|name| GeneralSubtree::DnsName((*name).to_owned()))
                .collect(),
            excluded_subtrees: Vec::new(),
        })
    };
    // rcgen writes no URI subtrees, so each refused certificate is refused
    // before its URIs are looked at, and the one that fits is written with
    // a URI subtree by Hodor's own writer below.
    let other_key = KeyPair::generate().expect("key");
    for (pem, reason) in [
        (issue(constraints(&[PROD]), true, &other_key), "key"),
        (issue(constraints(&[PROD]), false, &holds), "authority"),
        (issue(None, true, &holds), "no name constraints"),
    ] {
        let refused = world
            .service
            .install(&world.tenant, &pem, &[], Caller::system())
            .await
            .expect_err("refused");
        assert_eq!(refused.code(), "keys.authority_certificate_unsuitable");
        assert!(
            refused.detail().unwrap_or_default().contains(reason),
            "{refused:?}"
        );
    }
    let no_uri = issue(constraints(&[PROD]), true, &holds);
    let refused = world
        .service
        .install(&world.tenant, &no_uri, &[], Caller::system())
        .await
        .expect_err("refused");
    assert!(refused.detail().unwrap_or_default().contains("URIs"));

    // What the tenant's root signs when it keeps the request's
    // extensions: the request's own name constraints.
    let mut fitting = CertificateParams::default();
    fitting.distinguished_name = subject(&common_name);
    fitting.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    fitting.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let name_constraints = request
        .requested_extensions()
        .into_iter()
        .flatten()
        .find_map(|extension| match extension {
            x509_parser::extensions::ParsedExtension::NameConstraints(_) => Some(()),
            _ => None,
        });
    assert!(name_constraints.is_some());
    let raw_constraints = raw_requested_name_constraints(&request_der);
    let mut extension = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 30], raw_constraints);
    extension.set_criticality(true);
    fitting.custom_extensions = vec![extension];
    let fitting = fitting
        .signed_by(&holds, &tenant_root, &tenant_root_key)
        .expect("signed")
        .pem();
    let installed = world
        .service
        .install(
            &world.tenant,
            &fitting,
            &[tenant_root.pem()],
            Caller::system(),
        )
        .await
        .expect("installed");
    assert_eq!(installed.state(), AuthorityState::Active);
    assert_eq!(installed.snapshot().chain, [tenant_root.der().to_vec()]);
    let domain = world
        .trust_domains
        .find_by_name(&world.tenant, PROD)
        .await
        .expect("read")
        .expect("trusted once active");
    assert_eq!(domain.source(), TrustSource::Authority);
    assert_eq!(
        world
            .service
            .install(&world.tenant, &fitting, &[], Caller::system())
            .await
            .expect_err("once")
            .code(),
        "keys.authority_not_awaiting_certificate"
    );

    // A workload below it is checked against it as its anchor.
    let (params, key) = leaf(vec![uri("spiffe://prod.example.com/x")]);
    let (below, _) = signed_by_authority(&world, &installed, params, &key).await;
    let anchor = installed.certificate().expect("certificate").der.clone();
    assert!(check_path(&below, &[], &[anchor], SystemClock.now()).is_ok());
}

/// The name constraints a request asks for, as the content of the
/// extension, read with `x509-parser` from the request's attributes.
fn raw_requested_name_constraints(request_der: &[u8]) -> Vec<u8> {
    let (_, request) =
        x509_parser::certification_request::X509CertificationRequest::from_der(request_der)
            .expect("a request");
    for attribute in request.certification_request_info.iter_attributes() {
        if let x509_parser::cri_attributes::ParsedCriAttribute::ExtensionRequest(extensions) =
            attribute.parsed_attribute()
        {
            for extension in &extensions.extensions {
                if extension.oid == x509_parser::oid_registry::OID_X509_EXT_NAME_CONSTRAINTS {
                    return extension.value.to_vec();
                }
            }
        }
    }
    panic!("the request asks for name constraints")
}

#[tokio::test]
async fn one_authority_per_tenant_its_trust_domains_kept_apart_and_removed_with_it() {
    let world = world(true);
    // A trust domain the tenant trusts from another source is refused.
    world
        .trust_domains
        .add(
            &world.tenant,
            EDGE,
            TrustSourceRequest::Mesh,
            Caller::system(),
        )
        .await
        .expect("added");
    let taken = world
        .service
        .create(
            &world.tenant,
            asked("root", &[PROD, EDGE]),
            Caller::system(),
        )
        .await
        .expect_err("taken");
    assert_eq!(taken.code(), "keys.authority_trust_domain_taken");
    let edge = world
        .trust_domains
        .find_by_name(&world.tenant, EDGE)
        .await
        .expect("read")
        .expect("kept");
    world
        .trust_domains
        .remove(&world.tenant, edge.id(), Caller::system())
        .await
        .expect("removed");

    let authority = root(&world).await;
    let again = world
        .service
        .create(
            &world.tenant,
            asked("root", &["other.example"]),
            Caller::system(),
        )
        .await
        .expect_err("one per tenant");
    assert_eq!(again.code(), "keys.authority_exists");

    // Its trust domains are not replaced through the trust domains'
    // operations, and cannot be added there.
    let prod = world
        .trust_domains
        .find_by_name(&world.tenant, PROD)
        .await
        .expect("read")
        .expect("added");
    let replaced = world
        .trust_domains
        .replace(
            &world.tenant,
            prod.id(),
            TrustSourceRequest::Mesh,
            Caller::system(),
        )
        .await
        .expect_err("refused");
    assert_eq!(replaced.code(), "keys.trust_domain_of_authority");
    assert!(TrustSourceRequest::from_parts("authority", Some(b"{}".to_vec()), None).is_err());

    // Another tenant has none of it.
    let other = TenantContext::assume(TenantId::generate());
    assert_eq!(
        world.service.get(&other).await.expect_err("none").code(),
        "keys.authority_not_found"
    );
    assert_eq!(world.service.bundle(&other).await.expect("read"), None);
    assert!(
        world
            .trust_domains
            .find_by_name(&other, PROD)
            .await
            .expect("read")
            .is_none()
    );
    assert_eq!(
        world
            .service
            .remove(&other, Caller::system())
            .await
            .expect_err("none")
            .code(),
        "keys.authority_not_found"
    );
    // The key of one tenant's authority does not sign for another.
    let foreign = world
        .provider
        .sign(
            &other,
            &authority.key().version(SystemClock.now()),
            b"anything",
            SignatureEncoding::Der,
        )
        .await
        .expect_err("refused");
    assert_eq!(foreign.code(), "keys.unusable");

    // Removing it removes the trust domains it added, and nothing else.
    world
        .trust_domains
        .add(
            &world.tenant,
            "mesh.example",
            TrustSourceRequest::Mesh,
            Caller::system(),
        )
        .await
        .expect("added");
    world
        .service
        .remove(&world.tenant, Caller::system())
        .await
        .expect("removed");
    for name in [PROD, EDGE] {
        assert!(
            world
                .trust_domains
                .find_by_name(&world.tenant, name)
                .await
                .expect("read")
                .is_none()
        );
    }
    assert!(
        world
            .trust_domains
            .find_by_name(&world.tenant, "mesh.example")
            .await
            .expect("read")
            .is_some()
    );
    let events = world.units_of_work.committed_event_types();
    assert_eq!(
        &events[events.len() - 3..],
        [
            "keys.trust_domain_removed",
            "keys.trust_domain_removed",
            "keys.authority_removed"
        ]
    );
    assert_eq!(
        world.service.bundle(&world.tenant).await.expect("read"),
        None
    );
}
