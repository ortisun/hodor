//! The federation use cases, run against the in-memory stores.

use hodor_federation::api::{
    ChangeProvider, CreateProvider, FederationService, ProviderKind, ProviderSettings,
    ProviderStatus, SamlSettings, Subject,
};
use hodor_federation::testing::{InMemoryFederation, Ports, run_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Secret, TenantContext, TenantId, Timestamp, UnitOfWorkFactory as _, UserId,
};
use hodor_saml::testing::{TestIdentityProvider, certificate_with_short_rsa_key};
use std::sync::Arc;

const SECRET: &str = "the-client-secret-of-the-provider";

struct World {
    service: FederationService,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
}

fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryFederation::default();
    World {
        service: FederationService::new(
            Arc::new(units_of_work.clone()),
            Arc::new(stores.clone()),
            Arc::new(stores),
            Arc::new(FakeSecretBox),
            Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
        ),
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn settings() -> ProviderSettings {
    ProviderSettings {
        saml: None,
        display_name: "Example".to_owned(),
        issuer: "https://accounts.example.com".to_owned(),
        client_id: "hodor".to_owned(),
        scopes: ProviderSettings::default_scopes(),
        creates_users: true,
        trusts_email: false,
        directory: None,
    }
}

fn create(alias: &str) -> CreateProvider {
    CreateProvider {
        alias: alias.to_owned(),
        kind: ProviderKind::OpenIdConnect,
        settings: settings(),
        client_secret: Secret::from(SECRET.to_owned()),
    }
}

fn subject(value: &str) -> Subject {
    Subject::parse(value).expect("subject")
}

#[tokio::test]
async fn the_in_memory_stores_pass_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryFederation::default();
    run_contract(Ports {
        units_of_work: &units_of_work,
        providers: &stores,
        links: &stores,
        pending: &stores,
    })
    .await;
}

#[tokio::test]
async fn a_provider_is_created_enabled_and_its_secret_is_nowhere_in_sight() {
    let world = world();
    let provider = world
        .service
        .create_provider(&world.tenant, create("example"), Caller::system())
        .await
        .expect("create");

    assert!(provider.is_enabled());
    assert_eq!(provider.alias().as_str(), "example");
    assert_eq!(
        world.units_of_work.committed_event_types(),
        ["federation.provider_created"]
    );

    // Not in what is read back, not in what is printed, not in the event.
    let read = world
        .service
        .provider(&world.tenant, provider.id())
        .await
        .expect("read");
    let stored = String::from_utf8_lossy(read.snapshot().client_secret.as_bytes()).into_owned();
    assert!(!stored.contains(SECRET), "stored sealed, not in the clear");
    assert!(!format!("{read:?}").contains(SECRET));
    let events = format!("{:?}", world.units_of_work.committed_events());
    assert!(!events.contains(SECRET));

    // The code that talks to the provider gets it back whole.
    let opened = world
        .service
        .client_secret(&world.tenant, &read)
        .await
        .expect("open");
    assert_eq!(opened.expose(), SECRET);
}

#[tokio::test]
async fn a_secret_sealed_for_one_tenant_does_not_open_in_another() {
    let world = world();
    let provider = world
        .service
        .create_provider(&world.tenant, create("example"), Caller::system())
        .await
        .expect("create");
    let elsewhere = TenantContext::assume(TenantId::generate());
    let error = world
        .service
        .client_secret(&elsewhere, &provider)
        .await
        .expect_err("another tenant");
    assert_eq!(error.code(), "secret.unreadable");
}

#[tokio::test]
async fn what_breaks_a_rule_is_refused_before_anything_is_stored() {
    let world = world();
    let mut bad_alias = create("Not An Alias");
    bad_alias.settings = settings();
    let mut bad_issuer = create("example");
    bad_issuer.settings.issuer = "http://plain.example.com".to_owned();
    let mut no_secret = create("example");
    no_secret.client_secret = Secret::from(String::new());
    let mut huge_secret = create("example");
    huge_secret.client_secret = Secret::from("x".repeat(4097));

    for (command, code) in [
        (bad_alias, "federation.alias_invalid"),
        (bad_issuer, "federation.issuer_invalid"),
        (no_secret, "federation.client_secret_invalid"),
        (huge_secret, "federation.client_secret_invalid"),
    ] {
        let error = world
            .service
            .create_provider(&world.tenant, command, Caller::system())
            .await
            .expect_err(code);
        assert_eq!(error.code(), code);
    }
    assert!(
        world
            .service
            .providers(&world.tenant)
            .await
            .expect("list")
            .is_empty()
    );
    assert!(world.units_of_work.committed_events().is_empty());
}

#[tokio::test]
async fn an_alias_is_used_once_in_a_tenant_and_a_tenant_has_a_limit() {
    let world = world();
    world
        .service
        .create_provider(&world.tenant, create("example"), Caller::system())
        .await
        .expect("create");
    let error = world
        .service
        .create_provider(&world.tenant, create("example"), Caller::system())
        .await
        .expect_err("taken");
    assert_eq!(error.code(), "federation.alias_taken");

    for number in 1..20 {
        world
            .service
            .create_provider(
                &world.tenant,
                create(&format!("provider-{number}")),
                Caller::system(),
            )
            .await
            .expect("create");
    }
    let error = world
        .service
        .create_provider(&world.tenant, create("one-too-many"), Caller::system())
        .await
        .expect_err("limit");
    assert_eq!(error.code(), "federation.too_many_providers");
    assert_eq!(
        world
            .service
            .providers(&world.tenant)
            .await
            .expect("list")
            .len(),
        20
    );

    // The limit is the tenant's own.
    let elsewhere = TenantContext::assume(TenantId::generate());
    world
        .service
        .create_provider(&elsewhere, create("example"), Caller::system())
        .await
        .expect("another tenant has room, and may use the alias");
}

#[tokio::test]
async fn changes_are_stored_and_announced_only_when_something_changed() {
    let world = world();
    let provider = world
        .service
        .create_provider(&world.tenant, create("example"), Caller::system())
        .await
        .expect("create");
    let id = provider.id();

    // The same settings: nothing happens.
    world
        .service
        .change_provider(
            &world.tenant,
            ChangeProvider {
                id,
                settings: settings(),
            },
            Caller::system(),
        )
        .await
        .expect("no change");
    assert_eq!(world.units_of_work.committed_event_types().len(), 1);

    let mut renamed = settings();
    renamed.display_name = "Another name".to_owned();
    renamed.creates_users = false;
    let changed = world
        .service
        .change_provider(
            &world.tenant,
            ChangeProvider {
                id,
                settings: renamed,
            },
            Caller::system(),
        )
        .await
        .expect("change");
    assert_eq!(changed.snapshot().settings.display_name, "Another name");
    assert!(!changed.snapshot().settings.creates_users);
    assert_eq!(
        changed.alias().as_str(),
        "example",
        "the alias never changes"
    );

    world
        .service
        .set_provider_status(
            &world.tenant,
            id,
            ProviderStatus::Disabled,
            Caller::system(),
        )
        .await
        .expect("disable");
    world
        .service
        .set_provider_status(
            &world.tenant,
            id,
            ProviderStatus::Disabled,
            Caller::system(),
        )
        .await
        .expect("disable again");
    world
        .service
        .set_provider_status(&world.tenant, id, ProviderStatus::Enabled, Caller::system())
        .await
        .expect("enable");

    let new_secret = Secret::from("a brand new secret".to_owned());
    world
        .service
        .change_provider_secret(&world.tenant, id, &new_secret, Caller::system())
        .await
        .expect("secret");
    let read = world
        .service
        .provider(&world.tenant, id)
        .await
        .expect("read");
    assert_eq!(
        world
            .service
            .client_secret(&world.tenant, &read)
            .await
            .expect("open")
            .expose(),
        "a brand new secret"
    );

    assert_eq!(
        world.units_of_work.committed_event_types(),
        [
            "federation.provider_created",
            "federation.provider_changed",
            "federation.provider_disabled",
            "federation.provider_enabled",
            "federation.provider_secret_changed",
        ]
    );
    assert!(!format!("{:?}", world.units_of_work.committed_events()).contains("brand new"));
}

#[tokio::test]
async fn a_provider_of_another_tenant_does_not_exist() {
    let world = world();
    let provider = world
        .service
        .create_provider(&world.tenant, create("example"), Caller::system())
        .await
        .expect("create");
    let elsewhere = TenantContext::assume(TenantId::generate());

    let by_id = world
        .service
        .provider(&elsewhere, provider.id())
        .await
        .expect_err("id");
    let by_alias = world
        .service
        .provider_by_alias(&elsewhere, "example")
        .await
        .expect_err("alias");
    let change = world
        .service
        .set_provider_status(
            &elsewhere,
            provider.id(),
            ProviderStatus::Disabled,
            Caller::system(),
        )
        .await
        .expect_err("change");
    for error in [by_id, by_alias, change] {
        assert_eq!(error.code(), "federation.provider_not_found");
    }
    // And an alias that could not be one is answered the same way.
    let error = world
        .service
        .provider_by_alias(&world.tenant, "../../etc/passwd")
        .await
        .expect_err("not an alias");
    assert_eq!(error.code(), "federation.provider_not_found");
    assert!(
        world
            .service
            .provider(&world.tenant, provider.id())
            .await
            .expect("own")
            .is_enabled()
    );
}

#[tokio::test]
async fn an_external_identity_is_linked_to_one_user_and_found_by_its_subject_alone() {
    let world = world();
    let provider = world
        .service
        .create_provider(&world.tenant, create("example"), Caller::system())
        .await
        .expect("create");
    let (ana, bia) = (UserId::generate(), UserId::generate());

    let mut uow = world
        .units_of_work
        .begin(&world.tenant)
        .await
        .expect("begin");
    assert_eq!(
        world
            .service
            .find_user(uow.as_mut(), provider.id(), &subject("subject-of-ana"))
            .await
            .expect("find"),
        None
    );
    world
        .service
        .link(
            uow.as_mut(),
            provider.id(),
            subject("subject-of-ana"),
            ana,
            Caller::system(),
        )
        .await
        .expect("link");
    uow.commit().await.expect("commit");

    let mut uow = world
        .units_of_work
        .begin(&world.tenant)
        .await
        .expect("begin");
    assert_eq!(
        world
            .service
            .find_user(uow.as_mut(), provider.id(), &subject("subject-of-ana"))
            .await
            .expect("find"),
        Some(ana)
    );
    // Linked once: not again to another user, not again to the same one.
    for user in [bia, ana] {
        let error = world
            .service
            .link(
                uow.as_mut(),
                provider.id(),
                subject("subject-of-ana"),
                user,
                Caller::system(),
            )
            .await
            .expect_err("already linked");
        assert_eq!(error.code(), "federation.identity_already_linked");
    }
    world
        .service
        .mark_used(uow.as_mut(), provider.id(), &subject("subject-of-ana"))
        .await
        .expect("used");
    let error = world
        .service
        .mark_used(uow.as_mut(), provider.id(), &subject("nobody"))
        .await
        .expect_err("no such link");
    assert_eq!(error.code(), "federation.link_not_found");
    drop(uow);

    assert_eq!(
        world
            .service
            .links_of(&world.tenant, ana)
            .await
            .expect("links")
            .len(),
        1
    );
    assert!(
        world
            .service
            .links_of(&world.tenant, bia)
            .await
            .expect("links")
            .is_empty()
    );

    world
        .service
        .unlink(
            &world.tenant,
            provider.id(),
            &subject("subject-of-ana"),
            Caller::system(),
        )
        .await
        .expect("unlink");
    let error = world
        .service
        .unlink(
            &world.tenant,
            provider.id(),
            &subject("subject-of-ana"),
            Caller::system(),
        )
        .await
        .expect_err("gone");
    assert_eq!(error.code(), "federation.link_not_found");

    // What was announced names the provider and the user, never the subject.
    let events = world.units_of_work.committed_events();
    let said = format!("{events:?}");
    assert!(said.contains("federation.identity_linked"));
    assert!(said.contains("federation.identity_unlinked"));
    // The subject is not hexadecimal, so no identifier can contain it by chance.
    assert!(!said.contains("subject-of-ana"), "{said}");
}

#[tokio::test]
async fn a_link_that_is_not_committed_is_not_made() {
    let world = world();
    let provider = world
        .service
        .create_provider(&world.tenant, create("example"), Caller::system())
        .await
        .expect("create");
    let before = world.units_of_work.committed_events().len();

    let mut uow = world
        .units_of_work
        .begin(&world.tenant)
        .await
        .expect("begin");
    world
        .service
        .link(
            uow.as_mut(),
            provider.id(),
            subject("abc"),
            UserId::generate(),
            Caller::system(),
        )
        .await
        .expect("link");
    drop(uow);

    // The event belongs to the unit of work that was abandoned.
    assert_eq!(world.units_of_work.committed_events().len(), before);
}

fn saml(certificate: &str, secret: &str) -> CreateProvider {
    CreateProvider {
        alias: "corp".to_owned(),
        kind: ProviderKind::Saml,
        settings: ProviderSettings {
            display_name: "Corp".to_owned(),
            issuer: "http://www.okta.com/exk1a2b3c4".to_owned(),
            client_id: String::new(),
            scopes: Vec::new(),
            creates_users: true,
            trusts_email: false,
            directory: None,
            saml: Some(SamlSettings::new(
                "https://corp.okta.com/app/sso/saml",
                certificate,
            )),
        },
        client_secret: Secret::from(secret.to_owned()),
    }
}

#[tokio::test]
async fn a_saml_provider_has_a_certificate_and_no_secret() {
    let world = world();
    let identity_provider = TestIdentityProvider::rsa("http://www.okta.com/exk1a2b3c4");
    let certificate = identity_provider.certificate_pem();

    let error = world
        .service
        .create_provider(
            &world.tenant,
            saml(certificate, "a secret"),
            Caller::system(),
        )
        .await
        .expect_err("a secret");
    assert_eq!(error.code(), "federation.client_secret_invalid");

    let error = world
        .service
        .create_provider(
            &world.tenant,
            saml(&certificate_with_short_rsa_key(), ""),
            Caller::system(),
        )
        .await
        .expect_err("a short key");
    assert_eq!(error.code(), "federation.saml_invalid");
    assert_eq!(error.detail(), Some("key_too_short"));

    let created = world
        .service
        .create_provider(&world.tenant, saml(certificate, ""), Caller::system())
        .await
        .expect("a SAML provider");
    assert_eq!(created.snapshot().kind, ProviderKind::Saml);
    let error = world
        .service
        .change_provider_secret(
            &world.tenant,
            created.id(),
            &Secret::from("a secret".to_owned()),
            Caller::system(),
        )
        .await
        .expect_err("no secret to change");
    assert_eq!(error.code(), "federation.client_secret_invalid");
}
