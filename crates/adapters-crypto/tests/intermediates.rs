//! Signing the intermediates of a tenant's meshes with real certificates
//! and the local key provider: each refusal with its reason, what Hodor
//! writes, the signature checked by `x509-parser` and OpenSSL, and
//! withdrawal through Hodor's own chain checking.

use hodor_adapters_crypto::testing::certificates::{Leaf, MeshIntermediate, MeshKey, MeshRequest};
use hodor_adapters_crypto::{
    LocalKeyProvider, OsRandom, SecretKeys, Sha256Digest, X509CertificateCheck, X509Certificates,
    check_path,
};
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock as _, PageRequest, Secret, SystemClock, TenantContext, TenantId};
use hodor_keys::api::{
    AuthorityPorts, AuthorityService, CertificateAuthority, IntermediateState, NewAuthority,
    TrustDomainPorts, TrustDomainService, hexadecimal, to_pem,
};
use hodor_keys::testing::{
    FakeBundleEndpoints, InMemoryAuthorities, InMemoryIntermediates, InMemoryTrustDomains,
};
use hodor_oauth::api::CertificateCheck as _;
use std::process::Command;
use std::sync::Arc;
use x509_parser::prelude::{FromDer as _, GeneralName, ParsedExtension, X509Certificate};

const CLUSTER: &str = "cluster.local";
const PROD: &str = "prod.example.com";
const LINKERD: &str = "identity.linkerd.cluster.local";

struct World {
    service: AuthorityService,
    trust_domains: TrustDomainService,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
}

fn world() -> World {
    let root = SecretKeys::generate(&OsRandom);
    let keys = SecretKeys::parse(&Secret::new(format!("root:{}", root.expose()))).expect("keys");
    let provider = Arc::new(LocalKeyProvider::new(Arc::new(keys)));
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryTrustDomains::default();
    let intermediates = Arc::new(InMemoryIntermediates::default());
    let endpoints = FakeBundleEndpoints::default();
    let service = AuthorityService::new(
        AuthorityPorts {
            units_of_work: Arc::new(units_of_work.clone()),
            store: Arc::new(InMemoryAuthorities::default()),
            trust_domains: Arc::new(store.clone()),
            intermediates: intermediates.clone(),
            maker: provider.clone(),
            signer: provider,
            certificates: Arc::new(X509Certificates),
            digest: Arc::new(Sha256Digest),
            clock: Arc::new(SystemClock),
        },
        true,
    );
    let trust_domains = TrustDomainService::new(TrustDomainPorts {
        units_of_work: Arc::new(units_of_work.clone()),
        store: Arc::new(store),
        destinations: Arc::new(endpoints.clone()),
        http: Arc::new(endpoints),
        digest: Arc::new(Sha256Digest),
        clock: Arc::new(SystemClock),
    })
    .with_intermediates(intermediates);
    World {
        service,
        trust_domains,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

async fn root(world: &World, kind: &str) -> CertificateAuthority {
    world
        .service
        .create(
            &world.tenant,
            NewAuthority {
                kind: kind.to_owned(),
                trust_domains: vec![CLUSTER.to_owned(), PROD.to_owned()],
                ..NewAuthority::default()
            },
            Caller::system(),
        )
        .await
        .expect("an authority")
}

fn linkerd_issuer() -> MeshRequest {
    MeshRequest {
        dns_names: vec![LINKERD.to_owned()],
        ..MeshRequest::authority(LINKERD)
    }
}

/// What OpenSSL says of a path, if it is installed: `Some(true)` when it
/// verifies.
fn openssl_verifies(anchor: &[u8], intermediates: &[Vec<u8>], leaf: &[u8]) -> Option<bool> {
    let directory =
        std::env::temp_dir().join(format!("hodor-intermediate-{}", TenantId::generate()));
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
    Some(output?.status.success())
}

fn extension<'a>(
    parsed: &'a X509Certificate<'a>,
    found: impl Fn(&ParsedExtension<'_>) -> bool,
) -> &'a x509_parser::extensions::X509Extension<'a> {
    parsed
        .extensions()
        .iter()
        .find(|extension| found(extension.parsed_extension()))
        .expect("the extension")
}

#[tokio::test]
async fn an_intermediate_is_written_by_hodor_signed_by_the_authority_and_checks_with_independent_libraries()
 {
    let world = world();
    let authority = root(&world, "root").await;
    let anchor = authority.certificate().expect("active").der.clone();
    let mesh = MeshIntermediate::new(&linkerd_issuer());
    let signed = world
        .service
        .sign(&world.tenant, mesh.request(), None, Caller::system())
        .await
        .expect("signed");
    let state = signed.intermediate.snapshot();
    assert_eq!(state.state, IntermediateState::Active);
    assert_eq!(state.authority_id, authority.id());
    assert_eq!(state.dns_names, [LINKERD]);
    assert_eq!(state.subject, format!("CN={LINKERD}"));
    assert_eq!(state.constraints.permitted_dns_names, [CLUSTER, PROD]);
    assert_eq!(state.constraints.excluded_ip_ranges, ["0.0.0.0/0", "::/0"]);
    assert_eq!(signed.chain, std::slice::from_ref(&anchor));
    assert_eq!(
        (state.not_after - state.not_before).whole_minutes(),
        30 * 24 * 60 + 1
    );

    // What it says, read with `x509-parser`.
    let (rest, parsed) = X509Certificate::from_der(&state.certificate).expect("reads");
    assert!(rest.is_empty());
    let (_, issuer) = X509Certificate::from_der(&anchor).expect("the authority");
    assert_eq!(parsed.issuer().as_raw(), issuer.subject().as_raw());
    assert_eq!(parsed.subject().to_string(), format!("CN={LINKERD}"));
    assert_eq!(hexadecimal(parsed.raw_serial()), state.serial_number);
    let basic = parsed.basic_constraints().expect("once").expect("present");
    assert!(basic.critical && basic.value.ca);
    assert_eq!(basic.value.path_len_constraint, Some(0));
    let usage = parsed.key_usage().expect("once").expect("present");
    assert!(usage.critical && usage.value.key_cert_sign() && usage.value.crl_sign());
    assert!(!usage.value.digital_signature());
    let names = parsed
        .subject_alternative_name()
        .expect("once")
        .expect("present");
    assert_eq!(
        format!("{:?}", names.value.general_names),
        format!("{:?}", [GeneralName::DNSName(LINKERD)])
    );
    let constraints = extension(&parsed, |found| {
        matches!(found, ParsedExtension::NameConstraints(_))
    });
    assert!(constraints.critical);
    let ParsedExtension::NameConstraints(constraints) = constraints.parsed_extension() else {
        unreachable!()
    };
    let subtrees = |subtrees: &Option<Vec<x509_parser::extensions::GeneralSubtree<'_>>>| {
        subtrees
            .iter()
            .flatten()
            .map(|subtree| format!("{:?}", subtree.base))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        subtrees(&constraints.permitted_subtrees),
        [
            format!("{:?}", GeneralName::DNSName(CLUSTER)),
            format!("{:?}", GeneralName::DNSName(PROD)),
        ],
        "DNS names only: no URI constraint in an intermediate"
    );
    assert_eq!(
        subtrees(&constraints.excluded_subtrees),
        [
            format!("{:?}", GeneralName::IPAddress(&[0; 8])),
            format!("{:?}", GeneralName::IPAddress(&[0; 32])),
        ]
    );
    let ParsedExtension::SubjectKeyIdentifier(subject_key) = extension(&parsed, |found| {
        matches!(found, ParsedExtension::SubjectKeyIdentifier(_))
    })
    .parsed_extension() else {
        unreachable!()
    };
    assert_eq!(hexadecimal(subject_key.0), state.public_key_sha256[..40]);
    let ParsedExtension::AuthorityKeyIdentifier(authority_key) = extension(&parsed, |found| {
        matches!(found, ParsedExtension::AuthorityKeyIdentifier(_))
    })
    .parsed_extension() else {
        unreachable!()
    };
    let ParsedExtension::SubjectKeyIdentifier(issuer_key) = extension(&issuer, |found| {
        matches!(found, ParsedExtension::SubjectKeyIdentifier(_))
    })
    .parsed_extension() else {
        unreachable!()
    };
    assert_eq!(
        authority_key.key_identifier.as_ref().map(|key| key.0),
        Some(issuer_key.0)
    );

    // The signature checks with the authority's public key, through
    // `x509-parser` (on `aws-lc-rs`), and through OpenSSL when it is here.
    parsed
        .verify_signature(Some(issuer.public_key()))
        .expect("the authority's key signed it");
    let within = mesh.issue(&Leaf {
        uris: vec!["spiffe://cluster.local/ns/shop/sa/web".to_owned()],
        dns_names: vec!["web.shop.serviceaccount.identity.linkerd.cluster.local".to_owned()],
        ..Leaf::default()
    });
    let outside = mesh.issue(&Leaf::uri("spiffe://elsewhere.example/ns/shop/sa/web"));
    let chain = [state.certificate.clone()];
    if let Some(verified) = openssl_verifies(&anchor, &[], &state.certificate) {
        assert!(
            verified,
            "OpenSSL checks the intermediate against the authority"
        );
        assert_eq!(openssl_verifies(&anchor, &chain, &within), Some(true));
        assert_eq!(
            openssl_verifies(&anchor, &chain, &outside),
            Some(false),
            "the authority's URI constraints bind below the intermediate"
        );
    }

    // Hodor's own chain checking: a workload within its names is accepted,
    // one outside refused by the authority's URI constraints.
    let now = SystemClock.now();
    assert!(check_path(&within, &chain, std::slice::from_ref(&anchor), &[], now).is_ok());
    assert!(check_path(&outside, &chain, std::slice::from_ref(&anchor), &[], now).is_err());

    // The signature is audited, with the request's hash.
    let events = world.units_of_work.committed_events();
    let signed_event = &events.last().expect("an event").payload;
    assert_eq!(
        world
            .units_of_work
            .committed_event_types()
            .last()
            .map(String::as_str),
        Some("keys.authority_signed")
    );
    assert_eq!(signed_event["signed"], "intermediate_certificate");
    assert_eq!(signed_event["serial_number"], state.serial_number.as_str());
    assert_eq!(signed_event["intermediate_id"], state.id.to_string());
    assert_eq!(
        signed_event["request_sha256"],
        state.request_sha256.as_str()
    );
    assert_eq!(
        signed_event["trust_domains"],
        serde_json::json!([CLUSTER, PROD])
    );
    let tbs_hash = hexadecimal(&<Sha256Digest as hodor_kernel::Digest>::sha256(
        &Sha256Digest,
        parsed.tbs_certificate.as_ref(),
    ));
    assert_eq!(signed_event["signed_sha256"], tbs_hash);
    assert!(!signed_event.to_string().contains("BEGIN"));
}

#[tokio::test]
async fn each_refused_request_names_its_reason_and_nothing_is_signed() {
    let world = world();
    root(&world, "root").await;
    let before = world.units_of_work.committed_event_types().len();
    let tampered = {
        let pem = MeshIntermediate::new(&linkerd_issuer())
            .request()
            .to_owned();
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        use base64::Engine as _;
        let engine = base64::engine::general_purpose::STANDARD;
        let mut der = engine.decode(body).expect("base64");
        let last = der.len() - 1;
        der[last] ^= 0x01;
        to_pem("CERTIFICATE REQUEST", &der)
    };
    let request = |change: &dyn Fn(&mut MeshRequest)| {
        let mut asked = linkerd_issuer();
        change(&mut asked);
        MeshIntermediate::new(&asked).request().to_owned()
    };
    let cases: Vec<(&str, String, Option<u32>, &str)> = vec![
        (
            "not a request",
            "hello".to_owned(),
            None,
            "keys.intermediate_request_invalid",
        ),
        (
            "a signature that does not check",
            tampered,
            None,
            "keys.intermediate_request_invalid",
        ),
        (
            "no basic constraints",
            request(&|asked| asked.authority = None),
            None,
            "keys.intermediate_not_an_authority",
        ),
        (
            "not an authority",
            request(&|asked| asked.authority = Some(false)),
            None,
            "keys.intermediate_not_an_authority",
        ),
        (
            "a path length of one",
            request(&|asked| asked.path_length = Some(1)),
            None,
            "keys.intermediate_path_length_invalid",
        ),
        (
            "a URI of another trust domain",
            request(&|asked| asked.uris = vec!["spiffe://elsewhere.example/x".to_owned()]),
            None,
            "keys.intermediate_name_outside_trust_domains",
        ),
        (
            "a DNS name outside",
            request(&|asked| asked.dns_names = vec!["identity.linkerd.evil.example".to_owned()]),
            None,
            "keys.intermediate_name_outside_trust_domains",
        ),
        (
            "an address",
            request(&|asked| asked.address = true),
            None,
            "keys.intermediate_name_outside_trust_domains",
        ),
        (
            "a permitted DNS name outside",
            request(&|asked| asked.permitted_dns_names = vec!["example.com".to_owned()]),
            None,
            "keys.intermediate_constraints_widened",
        ),
        (
            "permitted addresses",
            request(&|asked| asked.permitted_addresses = true),
            None,
            "keys.intermediate_constraints_widened",
        ),
        (
            "a URI constraint",
            request(&|asked| asked.permitted_uris = vec![CLUSTER.to_owned()]),
            None,
            "keys.intermediate_constraints_unsupported",
        ),
        (
            "an RSA key of 2048 bits",
            request(&|asked| asked.key = MeshKey::Rsa2048),
            None,
            "keys.intermediate_key_unsuitable",
        ),
        (
            "an Ed25519 key",
            request(&|asked| asked.key = MeshKey::Ed25519),
            None,
            "keys.intermediate_key_unsuitable",
        ),
        (
            "past the bound",
            request(&|_| {}),
            Some(31),
            "keys.intermediate_lifetime_invalid",
        ),
        (
            "no lifetime",
            request(&|_| {}),
            Some(0),
            "keys.intermediate_lifetime_invalid",
        ),
    ];
    for (case, pem, lifetime, code) in cases {
        let refused = world
            .service
            .sign(&world.tenant, &pem, lifetime, Caller::system())
            .await
            .expect_err(case);
        assert_eq!(refused.code(), code, "{case}");
        assert!(
            refused.detail().is_some_and(|detail| !detail.is_empty()),
            "{case} names its reason"
        );
    }
    assert_eq!(
        world.units_of_work.committed_event_types().len(),
        before,
        "nothing was signed"
    );
    let (page, _) = world
        .service
        .intermediates(&world.tenant, &PageRequest::default())
        .await
        .expect("listed");
    assert!(page.items.is_empty());
}

#[tokio::test]
async fn a_narrowed_request_is_signed_narrowed_and_other_keys_are_signed_too() {
    let world = world();
    let authority = root(&world, "root").await;
    let anchor = authority.certificate().expect("active").der.clone();
    let narrowed = MeshIntermediate::new(&MeshRequest {
        permitted_dns_names: vec!["linkerd.cluster.local".to_owned()],
        excluded_dns_names: vec!["admin.linkerd.cluster.local".to_owned()],
        path_length: Some(0),
        ..linkerd_issuer()
    });
    let signed = world
        .service
        .sign(&world.tenant, narrowed.request(), Some(2), Caller::system())
        .await
        .expect("signed");
    let state = signed.intermediate.snapshot();
    assert_eq!(
        state.constraints.permitted_dns_names,
        ["linkerd.cluster.local"]
    );
    assert_eq!(
        state.constraints.excluded_dns_names,
        ["admin.linkerd.cluster.local"]
    );
    assert_eq!(
        (state.not_after - state.not_before).whole_minutes(),
        2 * 24 * 60 + 1
    );
    let chain = [state.certificate.clone()];
    let now = SystemClock.now();
    let within = narrowed.issue(&Leaf::dns("web.shop.identity.linkerd.cluster.local"));
    let excluded = narrowed.issue(&Leaf::dns("web.admin.linkerd.cluster.local"));
    let beside = narrowed.issue(&Leaf::dns("web.istio.cluster.local"));
    assert!(check_path(&within, &chain, std::slice::from_ref(&anchor), &[], now).is_ok());
    for refused in [&excluded, &beside] {
        assert!(check_path(refused, &chain, std::slice::from_ref(&anchor), &[], now).is_err());
        if let Some(verified) = openssl_verifies(&anchor, &chain, refused) {
            assert!(
                !verified,
                "OpenSSL reads the intermediate's DNS constraints"
            );
        }
    }
    if let Some(verified) = openssl_verifies(&anchor, &chain, &within) {
        assert!(verified);
    }

    // Keys of the other kinds Hodor signs, each checking with OpenSSL.
    for key in [MeshKey::P384, MeshKey::Rsa3072] {
        let mesh = MeshIntermediate::new(&MeshRequest {
            key,
            ..MeshRequest::authority("istio-ca")
        });
        let signed = world
            .service
            .sign(&world.tenant, mesh.request(), None, Caller::system())
            .await
            .expect("signed");
        let chain = [signed.intermediate.snapshot().certificate.clone()];
        let workload = mesh.issue(&Leaf::uri("spiffe://prod.example.com/ns/a/sa/b"));
        assert!(
            check_path(&workload, &chain, std::slice::from_ref(&anchor), &[], now).is_ok(),
            "{key:?}"
        );
        if let Some(verified) = openssl_verifies(&anchor, &chain, &workload) {
            assert!(verified, "{key:?}");
        }
    }
}

#[tokio::test]
async fn withdrawing_an_intermediate_refuses_its_key_at_once_and_for_good() {
    let world = world();
    let authority = root(&world, "root").await;
    let bundle = authority.bundle().expect("reads").expect("a bundle");
    let element = bundle.keys()[0].jwk.clone();
    let mesh = MeshIntermediate::new(&linkerd_issuer());
    let other = MeshIntermediate::new(&MeshRequest::authority("istio-ca"));
    let sign = |pem: String| {
        let world = &world;
        async move {
            world
                .service
                .sign(&world.tenant, &pem, None, Caller::system())
                .await
        }
    };
    // The same key signed twice, as on a renewal, and another key.
    let first = sign(mesh.request().to_owned()).await.expect("signed");
    let renewed = sign(mesh.request().to_owned()).await.expect("signed again");
    let kept = sign(other.request().to_owned()).await.expect("signed");
    let workload = mesh.issue(&Leaf::uri("spiffe://cluster.local/ns/shop/sa/web"));
    let elsewhere = other.issue(&Leaf::uri("spiffe://cluster.local/ns/shop/sa/web"));
    let accepted = |certificate: &[u8], chain: &[Vec<u8>], withdrawn: &[String]| {
        X509CertificateCheck.chains_to(
            certificate,
            chain,
            &[element.as_str()],
            withdrawn,
            SystemClock.now(),
        )
    };
    let renewed_chain = [renewed.intermediate.snapshot().certificate.clone()];
    let kept_chain = [kept.intermediate.snapshot().certificate.clone()];
    assert!(accepted(&workload, &renewed_chain, &[]));
    assert!(
        world
            .trust_domains
            .withdrawn_keys(&world.tenant)
            .await
            .expect("read")
            .is_empty()
    );

    // Withdrawing the first withdraws the renewed one too: the key is out.
    let (withdrawn, _) = world
        .service
        .withdraw(
            &world.tenant,
            first.intermediate.id(),
            "the cluster was rebuilt",
            Caller::system(),
        )
        .await
        .expect("withdrawn");
    let ids: Vec<_> = withdrawn.iter().map(|row| row.id()).collect();
    assert_eq!(ids, [first.intermediate.id(), renewed.intermediate.id()]);
    assert!(withdrawn.iter().all(|row| {
        row.snapshot().withdrawal_reason.as_deref() == Some("the cluster was rebuilt")
    }));
    let keys = world
        .trust_domains
        .withdrawn_keys(&world.tenant)
        .await
        .expect("read");
    assert_eq!(
        keys,
        [first.intermediate.snapshot().public_key_sha256.clone()]
    );

    // Every path through the key is refused, whichever certificate of it
    // comes along; the other intermediate is untouched.
    let first_chain = [first.intermediate.snapshot().certificate.clone()];
    let both = [
        first.intermediate.snapshot().certificate.clone(),
        renewed.intermediate.snapshot().certificate.clone(),
    ];
    for chain in [&first_chain[..], &renewed_chain[..], &both[..]] {
        assert!(!accepted(&workload, chain, &keys));
    }
    let refused = check_path(
        &workload,
        &renewed_chain,
        &[authority.certificate().expect("active").der.clone()],
        &keys,
        SystemClock.now(),
    )
    .expect_err("withdrawn");
    assert!(
        refused
            .detail()
            .is_some_and(|detail| detail.contains("withdrawn")),
        "{refused:?}"
    );
    assert!(accepted(&elsewhere, &kept_chain, &keys));

    // The key is never signed again; a withdrawal is not repeated.
    assert_eq!(
        sign(mesh.request().to_owned())
            .await
            .expect_err("withdrawn key")
            .code(),
        "keys.intermediate_key_withdrawn"
    );
    assert_eq!(
        world
            .service
            .withdraw(
                &world.tenant,
                renewed.intermediate.id(),
                "again",
                Caller::system()
            )
            .await
            .expect_err("once")
            .code(),
        "keys.intermediate_withdrawn"
    );
    let types = world.units_of_work.committed_event_types();
    assert_eq!(
        types
            .iter()
            .filter(|kind| *kind == "keys.intermediate_withdrawn")
            .count(),
        2
    );

    // Listed newest first, the withdrawn ones with their state.
    let (page, chain) = world
        .service
        .intermediates(&world.tenant, &PageRequest::new(Some(2), None))
        .await
        .expect("listed");
    assert_eq!(
        chain,
        [authority.certificate().expect("active").der.clone()]
    );
    let listed: Vec<_> = page.items.iter().map(|row| row.id()).collect();
    assert_eq!(listed, [kept.intermediate.id(), renewed.intermediate.id()]);
    let cursor = page.next_cursor.expect("more");
    let (rest, _) = world
        .service
        .intermediates(&world.tenant, &PageRequest::new(Some(2), Some(cursor)))
        .await
        .expect("listed");
    assert_eq!(rest.items.len(), 1);
    assert!(rest.items[0].is_withdrawn());
    assert!(rest.next_cursor.is_none());
}

#[tokio::test]
async fn an_authority_signs_nothing_until_it_is_active_and_another_tenant_has_none() {
    let world = world();
    let mesh = MeshIntermediate::new(&linkerd_issuer());
    let refused = world
        .service
        .sign(&world.tenant, mesh.request(), None, Caller::system())
        .await
        .expect_err("no authority");
    assert_eq!(refused.code(), "keys.authority_not_found");
    root(&world, "intermediate").await;
    let refused = world
        .service
        .sign(&world.tenant, mesh.request(), None, Caller::system())
        .await
        .expect_err("awaiting its certificate");
    assert_eq!(refused.code(), "keys.authority_not_active");
}
