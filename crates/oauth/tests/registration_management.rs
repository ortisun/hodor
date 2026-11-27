//! Managing a registration, on the in-memory stores: a registered client
//! reads, changes and removes itself with its registration access token,
//! which is replaced at every change; every way a token fails is one
//! refusal; a change is checked as a registration and against the policy,
//! and calls only the addresses it makes new.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Managing a
//! registration".

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, DestinationCheck, DomainError, ErrorKind, TenantContext, TenantId,
    Timestamp, UnitOfWorkFactory as _,
};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings, AuthenticationMethod,
    ChangeRegistration, Client, ClientId, ClientRegistrationService, ClientSettings,
    ClientStore as _, ClientType, CreateClient, GrantType, MOST_REGISTRATIONS_PER_ADDRESS,
    ManageRegistration, RegisterClient, RegisteredClient, RegistrationSettings, RegistrationWay,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeDestinations, InMemoryClients, InMemoryStores, client_registration_service,
};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use time::Duration;

/// A destination check that counts how often it is asked and, when told
/// to, changes a client as an administrator would while it is asked.
#[derive(Default)]
struct Destinations {
    asked: AtomicUsize,
    interfere: Mutex<
        Option<(
            InMemoryUnitOfWorkFactory,
            InMemoryClients,
            TenantContext,
            ClientId,
        )>,
    >,
}

impl Destinations {
    fn asked(&self) -> usize {
        self.asked.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl DestinationCheck for Destinations {
    async fn check(&self, url: &str) -> Result<(), DomainError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let interfering = self
            .interfere
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some((units, clients, tenant, id)) = interfering {
            let mut uow = units.begin(&tenant).await.expect("begin");
            let client = clients
                .get(uow.as_mut(), id)
                .await
                .expect("get")
                .expect("there");
            clients
                .update(uow.as_mut(), &client)
                .await
                .expect("changed");
            uow.commit().await.expect("commit");
        }
        FakeDestinations.check(url).await
    }
}

struct World {
    units: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    clients: InMemoryClients,
    applications: ApplicationService,
    registration: ClientRegistrationService,
    destinations: Arc<Destinations>,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let registration = client_registration_service(Arc::new(units.clone()), &stores, clock.clone());
    let destinations = Arc::new(Destinations::default());
    let clients = stores.clients.clone();
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications),
        clients: Arc::new(stores.clients),
        resource_servers: Arc::new(stores.resource_servers),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    })
    .with_destinations(destinations.clone());
    World {
        units,
        clock,
        clients,
        applications,
        registration,
        destinations,
    }
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

const CALLBACK: &str = "https://portal.partner.example/callback";

fn body() -> Value {
    json!({ "redirect_uris": [CALLBACK], "client_name": "Partner portal" })
}

/// The body of a change of `client`: what it registered with, its
/// `client_id`, and `change` applied.
fn change_of(client: &Client, change: impl FnOnce(&mut Value)) -> Value {
    let mut body = body();
    body["client_id"] = json!(client.id().to_string());
    change(&mut body);
    body
}

fn manage(client: ClientId, token: &str) -> ManageRegistration {
    ManageRegistration {
        client_id: Some(client),
        access_token: Some(token.to_owned()),
    }
}

impl World {
    async fn turned_on_with(
        &self,
        tenant: &TenantContext,
        change: impl FnOnce(&mut RegistrationSettings),
    ) -> ApplicationId {
        let application = self
            .applications
            .create_application(
                tenant,
                ApplicationSettings {
                    name: "Partners".to_owned(),
                    first_party: false,
                },
                Caller::system(),
            )
            .await
            .expect("application")
            .id();
        let mut settings = RegistrationSettings {
            enabled: true,
            application_id: Some(application),
            ways: vec![RegistrationWay::Open],
            ..RegistrationSettings::default()
        };
        change(&mut settings);
        self.registration
            .replace(tenant, settings, Caller::system())
            .await
            .expect("on");
        application
    }

    async fn turned_on(&self, tenant: &TenantContext) -> ApplicationId {
        self.turned_on_with(tenant, |_| {}).await
    }

    async fn register_from(
        &self,
        tenant: &TenantContext,
        body: Value,
        address: [u8; 32],
    ) -> RegisteredClient {
        self.applications
            .register_client(
                &self.registration,
                tenant,
                RegisterClient {
                    body,
                    initial_access_token: None,
                    address_hash: Some(address),
                },
                Caller::system(),
            )
            .await
            .expect("registered")
    }

    async fn register(&self, tenant: &TenantContext, body: Value) -> RegisteredClient {
        self.register_from(tenant, body, [7; 32]).await
    }

    async fn read(
        &self,
        tenant: &TenantContext,
        request: &ManageRegistration,
    ) -> Result<Client, DomainError> {
        self.applications
            .read_registration(&self.registration, tenant, request)
            .await
    }

    async fn change(
        &self,
        tenant: &TenantContext,
        request: ManageRegistration,
        body: Value,
    ) -> Result<hodor_oauth::api::ChangedRegistration, DomainError> {
        self.applications
            .change_registration(
                &self.registration,
                tenant,
                ChangeRegistration {
                    registration: request,
                    body,
                },
                Caller::system(),
            )
            .await
    }

    async fn remove(
        &self,
        tenant: &TenantContext,
        request: &ManageRegistration,
    ) -> Result<(), DomainError> {
        self.applications
            .remove_registration(&self.registration, tenant, request, Caller::system())
            .await
    }
}

fn refused_as_a_token(result: Result<impl std::fmt::Debug, DomainError>, what: &str) {
    let error = result.expect_err(what);
    assert_eq!(error.kind(), ErrorKind::Unauthenticated, "{what}");
    assert_eq!(
        error.code(),
        "oauth.registration_access_token_invalid",
        "{what}"
    );
}

#[tokio::test]
async fn a_registered_client_reads_its_registration_with_its_token() {
    let world = world();
    let acme = tenant();
    world.turned_on(&acme).await;
    let registered = world.register(&acme, body()).await;
    let token = registered.access_token.expose().to_owned();
    assert!(token.starts_with("hodor_rat_"));
    let id = registered.client.id();

    let read = world.read(&acme, &manage(id, &token)).await.expect("read");
    assert_eq!(read, registered.client);
    // A read replaces nothing: the same token reads again.
    world
        .read(&acme, &manage(id, &token))
        .await
        .expect("read again");
    let events = world.units.committed_event_types();
    assert!(
        !events
            .iter()
            .any(|kind| kind.starts_with("oauth.registered_client"))
    );
}

#[tokio::test]
async fn every_way_a_token_fails_is_one_refusal() {
    let world = world();
    let acme = tenant();
    let application = world.turned_on(&acme).await;
    let one = world.register(&acme, body()).await;
    let other = world.register(&acme, body()).await;
    let token = one.access_token.expose().to_owned();
    let (by_hand, _) = world
        .applications
        .create_client(
            &acme,
            CreateClient {
                application_id: application,
                client_type: ClientType::Confidential,
                settings: ClientSettings::new(
                    "Made by hand",
                    ClientType::Confidential,
                    vec![GrantType::AuthorizationCode],
                    vec![CALLBACK.to_owned()],
                ),
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("made by an administrator");

    let without = world
        .read(
            &acme,
            &ManageRegistration {
                client_id: Some(one.client.id()),
                access_token: None,
            },
        )
        .await
        .expect_err("no token");
    assert_eq!(without.kind(), ErrorKind::Unauthenticated);
    assert_eq!(without.code(), "oauth.registration_access_token_required");

    for (request, what) in [
        (
            manage(one.client.id(), other.access_token.expose()),
            "another client's token",
        ),
        (
            manage(other.client.id(), &token),
            "at another client's address",
        ),
        (manage(by_hand.id(), &token), "a client made by hand"),
        (manage(ClientId::generate(), &token), "an unknown client"),
        (manage(one.client.id(), "hodor_rat_short"), "no shape"),
        (manage(one.client.id(), ""), "not a bearer token"),
        (
            ManageRegistration {
                client_id: None,
                access_token: Some(token.clone()),
            },
            "an address that names no client",
        ),
    ] {
        refused_as_a_token(world.read(&acme, &request).await, what);
        refused_as_a_token(
            world
                .change(&acme, request.clone(), change_of(&one.client, |_| {}))
                .await,
            what,
        );
        refused_as_a_token(world.remove(&acme, &request).await, what);
    }
    // Another tenant does not know the client.
    let globex = tenant();
    world.turned_on(&globex).await;
    refused_as_a_token(
        world.read(&globex, &manage(one.client.id(), &token)).await,
        "another tenant",
    );
    // Nothing was changed or removed by any of them.
    world
        .read(&acme, &manage(one.client.id(), &token))
        .await
        .expect("still good");
}

#[tokio::test]
async fn a_change_replaces_the_token_and_the_old_one_is_refused() {
    let world = world();
    let acme = tenant();
    let application = world.turned_on(&acme).await;
    let registered = world
        .register(
            &acme,
            json!({
                "redirect_uris": [CALLBACK],
                "client_name": "Partner portal",
                "initiate_login_uri": "https://portal.partner.example/start"
            }),
        )
        .await;
    let id = registered.client.id();
    let old = registered.access_token.expose().to_owned();

    let changed = world
        .change(
            &acme,
            manage(id, &old),
            change_of(&registered.client, |body| {
                body["client_name"] = json!("Partner portal, renamed");
                body["initiate_login_uri"] = json!("https://portal.partner.example/begin");
            }),
        )
        .await
        .expect("changed");
    assert!(changed.secret.is_none(), "it still has its secret");
    let new = changed.access_token.expose().to_owned();
    assert_ne!(new, old);
    let settings = &changed.client.snapshot().settings;
    assert_eq!(settings.name, "Partner portal, renamed");
    assert_eq!(
        settings.initiate_login_uri.as_deref(),
        Some("https://portal.partner.example/begin")
    );
    assert!(changed.client.is_registered());
    assert_eq!(changed.client.application_id(), application);

    refused_as_a_token(world.read(&acme, &manage(id, &old)).await, "old, read");
    refused_as_a_token(
        world
            .change(&acme, manage(id, &old), change_of(&changed.client, |_| {}))
            .await,
        "old, change",
    );
    refused_as_a_token(world.remove(&acme, &manage(id, &old)).await, "old, remove");
    let read = world.read(&acme, &manage(id, &new)).await.expect("new");
    assert_eq!(read.snapshot().settings.name, "Partner portal, renamed");

    // A change that changes nothing else still replaces the token.
    let again = world
        .change(
            &acme,
            manage(id, &new),
            change_of(&changed.client, |body| {
                body["client_name"] = json!("Partner portal, renamed");
                body["initiate_login_uri"] = json!("https://portal.partner.example/begin");
            }),
        )
        .await
        .expect("the same");
    refused_as_a_token(world.read(&acme, &manage(id, &new)).await, "replaced");
    world
        .read(&acme, &manage(id, again.access_token.expose()))
        .await
        .expect("newest");

    let changes: Vec<_> = world
        .units
        .committed_events()
        .into_iter()
        .filter(|event| event.event_type == "oauth.registered_client_changed")
        .collect();
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0].payload["client_id"], id.to_string());
    assert_eq!(
        changes[0].payload["application_id"],
        application.to_string()
    );
    assert!(
        !changes[0].payload.to_string().contains("hodor_rat_"),
        "never a token"
    );
    assert!(
        world
            .units
            .committed_event_types()
            .iter()
            .any(|kind| kind == "oauth.client_changed")
    );
}

#[tokio::test]
async fn a_change_is_checked_as_a_registration_and_against_the_policy() {
    let world = world();
    let acme = tenant();
    world.turned_on(&acme).await;
    let registered = world.register(&acme, body()).await;
    let id = registered.client.id();
    let token = registered.access_token.expose().to_owned();
    let secret = registered.secret.expect("a secret").expose().to_owned();
    let client = registered.client;

    for (body, code) in [
        (
            {
                let mut body = body();
                body["client_name"] = json!("Elsewhere");
                body
            },
            "oauth.registration_client_id_mismatch",
        ),
        (
            change_of(&client, |body| {
                body["client_id"] = json!(ClientId::generate().to_string())
            }),
            "oauth.registration_client_id_mismatch",
        ),
        (
            change_of(&client, |body| {
                body["client_secret"] = json!("hodor_cs_not_it")
            }),
            "oauth.registration_client_secret_mismatch",
        ),
        (
            change_of(&client, |body| body["software_statement"] = json!("eyJ")),
            "oauth.software_statement_unapproved",
        ),
        (
            change_of(&client, |body| {
                body["grant_types"] = json!(["authorization_code", "refresh_token"]);
            }),
            "oauth.registration_grant_not_allowed",
        ),
        (
            change_of(&client, |body| {
                body["redirect_uris"] = json!(["https://portal.partner.example/cb#here"]);
            }),
            "oauth.client_redirect_uri_invalid",
        ),
        (
            change_of(&client, |body| {
                body["initiate_login_uri"] = json!("http://portal.partner.example/start");
            }),
            "oauth.client_initiate_login_uri_invalid",
        ),
        // The type never changes: a confidential client cannot name `none`.
        (
            change_of(&client, |body| {
                body["token_endpoint_auth_method"] = json!("none")
            }),
            "oauth.client_authentication_method_invalid",
        ),
        (
            json!(["not", "an", "object"]),
            "oauth.client_metadata_invalid",
        ),
    ] {
        let refused = world
            .change(&acme, manage(id, &token), body.clone())
            .await
            .expect_err(code);
        assert_eq!(refused.code(), code, "{body}");
    }
    // Refused, nothing changed: the token still works and the client is as
    // it was.
    let read = world.read(&acme, &manage(id, &token)).await.expect("same");
    assert_eq!(read, client);

    // Its own secret, sent with the change, is accepted.
    world
        .change(
            &acme,
            manage(id, &token),
            change_of(&client, |body| body["client_secret"] = json!(secret)),
        )
        .await
        .expect("its own secret");
}

#[tokio::test]
async fn the_policy_hosts_bound_every_address_of_a_change() {
    let world = world();
    let acme = tenant();
    world
        .turned_on_with(&acme, |settings| {
            settings.policy.hosts = Some(vec!["portal.partner.example".to_owned()]);
        })
        .await;
    let registered = world.register(&acme, body()).await;
    let request = manage(registered.client.id(), registered.access_token.expose());
    for (member, value, code) in [
        (
            "initiate_login_uri",
            json!("https://elsewhere.example/start"),
            "oauth.registration_host_not_allowed",
        ),
        (
            "redirect_uris",
            json!(["https://elsewhere.example/callback"]),
            "oauth.registration_redirect_host_not_allowed",
        ),
    ] {
        let refused = world
            .change(
                &acme,
                request.clone(),
                change_of(&registered.client, |body| body[member] = value),
            )
            .await
            .expect_err(member);
        assert_eq!(refused.code(), code, "{member}");
    }
    world
        .change(
            &acme,
            request,
            change_of(&registered.client, |body| {
                body["initiate_login_uri"] = json!("https://portal.partner.example/start");
            }),
        )
        .await
        .expect("an allowed host");
}

#[tokio::test]
async fn only_the_addresses_a_change_makes_new_are_called_and_only_with_a_good_token() {
    let world = world();
    let acme = tenant();
    world.turned_on(&acme).await;
    let registered = world
        .register(
            &acme,
            json!({
                "redirect_uris": [CALLBACK],
                "backchannel_logout_uri": "https://portal.partner.example/logout"
            }),
        )
        .await;
    let id = registered.client.id();
    let token = registered.access_token.expose().to_owned();
    let asked = world.destinations.asked();
    assert_eq!(asked, 1, "checked when it registered");

    // Nothing is called for a token that is not good.
    let elsewhere = change_of(&registered.client, |body| {
        body["backchannel_logout_uri"] = json!("https://portal.partner.example/other");
    });
    refused_as_a_token(
        world
            .change(&acme, manage(id, "hodor_rat_nothing"), elsewhere.clone())
            .await,
        "no good token",
    );
    assert_eq!(world.destinations.asked(), asked);

    // The address it had already is not checked again.
    let changed = world
        .change(
            &acme,
            manage(id, &token),
            change_of(&registered.client, |body| {
                body["backchannel_logout_uri"] = json!("https://portal.partner.example/logout");
                body["client_name"] = json!("Renamed");
            }),
        )
        .await
        .expect("renamed");
    assert_eq!(world.destinations.asked(), asked);

    // A new one is, and one Hodor may not call is refused.
    let changed = world
        .change(
            &acme,
            manage(id, changed.access_token.expose()),
            elsewhere.clone(),
        )
        .await
        .expect("a new address");
    assert_eq!(world.destinations.asked(), asked + 1);
    let refused = world
        .change(
            &acme,
            manage(id, changed.access_token.expose()),
            change_of(&registered.client, |body| {
                body["backchannel_logout_uri"] = json!("https://localhost/logout");
            }),
        )
        .await
        .expect_err("not public");
    assert_eq!(
        refused.code(),
        "oauth.client_backchannel_logout_uri_forbidden"
    );
}

#[tokio::test]
async fn a_change_by_an_administrator_in_between_is_not_overwritten() {
    let world = world();
    let acme = tenant();
    world.turned_on(&acme).await;
    let registered = world.register(&acme, body()).await;
    let id = registered.client.id();
    let token = registered.access_token.expose().to_owned();
    // While the new address is checked, the client is changed elsewhere.
    *world
        .destinations
        .interfere
        .lock()
        .unwrap_or_else(|e| e.into_inner()) =
        Some((world.units.clone(), world.clients.clone(), acme.clone(), id));
    let refused = world
        .change(
            &acme,
            manage(id, &token),
            change_of(&registered.client, |body| {
                body["backchannel_logout_uri"] = json!("https://portal.partner.example/logout");
            }),
        )
        .await
        .expect_err("changed in between");
    assert_eq!(refused.code(), "oauth.client_modified_concurrently");
    assert_eq!(refused.kind(), ErrorKind::Conflict);
    // The token was not replaced.
    world
        .read(&acme, &manage(id, &token))
        .await
        .expect("still good");
}

#[tokio::test]
async fn keys_and_secrets_follow_the_method_a_change_names() {
    let world = world();
    let acme = tenant();
    world.turned_on(&acme).await;
    let key = |kid: &str| {
        json!({
            "kty": "EC", "crv": "P-256", "kid": kid,
            "x": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "y": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
        })
    };
    let registered = world
        .register(
            &acme,
            json!({
                "redirect_uris": [CALLBACK],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": { "keys": [key("one")] }
            }),
        )
        .await;
    assert!(registered.secret.is_none());
    let id = registered.client.id();

    // The keys sent replace the client's.
    let changed = world
        .change(
            &acme,
            manage(id, registered.access_token.expose()),
            change_of(&registered.client, |body| {
                body["token_endpoint_auth_method"] = json!("private_key_jwt");
                body["jwks"] = json!({ "keys": [key("two")] });
            }),
        )
        .await
        .expect("keys replaced");
    let kids: Vec<_> = changed
        .client
        .snapshot()
        .keys
        .iter()
        .map(|key| key.key_id.clone())
        .collect();
    assert_eq!(kids, ["two"]);

    // A secret method: the keys go, and a first secret comes, once.
    let changed = world
        .change(
            &acme,
            manage(id, changed.access_token.expose()),
            change_of(&registered.client, |_| {}),
        )
        .await
        .expect("a secret method");
    let secret = changed.secret.expect("a first secret");
    assert!(changed.client.snapshot().keys.is_empty());
    assert_eq!(
        changed.client.snapshot().settings.authentication_method,
        AuthenticationMethod::ClientSecretBasic
    );
    assert!(
        changed
            .client
            .accepts_secret(secret.expose(), &FakeDigest, world.clock.now())
    );
    let again = world
        .change(
            &acme,
            manage(id, changed.access_token.expose()),
            change_of(&registered.client, |_| {}),
        )
        .await
        .expect("again");
    assert!(again.secret.is_none(), "its secret works");
}

#[tokio::test]
async fn what_a_registration_never_sets_stays_as_it_is() {
    let world = world();
    let acme = tenant();
    world.turned_on(&acme).await;
    let registered = world.register(&acme, body()).await;
    let id = registered.client.id();
    // An administrator lets the client redeem a code without PKCE.
    let mut settings = registered.client.snapshot().settings.clone();
    settings.require_pkce = false;
    world
        .applications
        .change_client(&acme, id, settings, Caller::system())
        .await
        .expect("administrator");
    let changed = world
        .change(
            &acme,
            manage(id, registered.access_token.expose()),
            change_of(&registered.client, |body| {
                body["client_name"] = json!("Renamed")
            }),
        )
        .await
        .expect("changed");
    assert!(!changed.client.snapshot().settings.require_pkce);
}

#[tokio::test]
async fn removing_a_registration_deletes_the_client_and_frees_its_place() {
    let world = world();
    let acme = tenant();
    let application = world.turned_on(&acme).await;
    let mut registered = Vec::new();
    for _ in 0..MOST_REGISTRATIONS_PER_ADDRESS {
        registered.push(world.register(&acme, body()).await);
    }
    let eleventh = world
        .applications
        .register_client(
            &world.registration,
            &acme,
            RegisterClient {
                body: body(),
                initial_access_token: None,
                address_hash: Some([7; 32]),
            },
            Caller::system(),
        )
        .await
        .expect_err("the eleventh of the minute");
    assert_eq!(eleventh.code(), "oauth.too_many_registrations");

    let gone = registered.remove(0);
    let request = manage(gone.client.id(), gone.access_token.expose());
    world.remove(&acme, &request).await.expect("removed");
    assert!(
        world
            .applications
            .client(&acme, gone.client.id())
            .await
            .is_err()
    );
    assert_eq!(
        world
            .applications
            .clients(&acme, application)
            .await
            .expect("clients")
            .len(),
        MOST_REGISTRATIONS_PER_ADDRESS - 1
    );
    // The token goes with it, and removing again is an unknown client.
    refused_as_a_token(world.read(&acme, &request).await, "read after");
    refused_as_a_token(world.remove(&acme, &request).await, "removed again");
    // Its place in the count of its address is free.
    world.register(&acme, body()).await;

    let removed = world
        .units
        .committed_events()
        .into_iter()
        .find(|event| event.event_type == "oauth.registered_client_removed")
        .expect("recorded");
    assert_eq!(removed.payload["client_id"], gone.client.id().to_string());
    assert_eq!(removed.payload["application_id"], application.to_string());
}

#[tokio::test]
async fn while_registration_is_off_no_registration_is_managed() {
    let world = world();
    let acme = tenant();
    let application = world.turned_on(&acme).await;
    let registered = world.register(&acme, body()).await;
    let request = manage(registered.client.id(), registered.access_token.expose());
    world
        .registration
        .replace(
            &acme,
            RegistrationSettings {
                enabled: false,
                application_id: Some(application),
                ways: vec![RegistrationWay::Open],
                ..RegistrationSettings::default()
            },
            Caller::system(),
        )
        .await
        .expect("off");
    for error in [
        world
            .read(&acme, &request)
            .await
            .map(|_| ())
            .expect_err("read"),
        world
            .change(
                &acme,
                request.clone(),
                change_of(&registered.client, |_| {}),
            )
            .await
            .map(|_| ())
            .expect_err("change"),
        world.remove(&acme, &request).await.expect_err("remove"),
    ] {
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert_eq!(error.code(), "oauth.client_registration_off");
    }
    // On again, the token works again.
    world
        .registration
        .replace(
            &acme,
            RegistrationSettings {
                enabled: true,
                application_id: Some(application),
                ways: vec![RegistrationWay::Open],
                ..RegistrationSettings::default()
            },
            Caller::system(),
        )
        .await
        .expect("on");
    world.read(&acme, &request).await.expect("good again");
}
