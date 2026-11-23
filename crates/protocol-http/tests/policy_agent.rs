//! The service interface of Open Policy Agent: Hodor serves signed
//! bundles, and a real instance in a container pulls them, answers with
//! their revision, reports its status and uploads its decisions. Then
//! the rules of who may pull what, over HTTP.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use hodor_adapters_crypto::{BundleSigningKey, OsRandom, Sha256Digest};
use hodor_adapters_http::{OutboundPolicy, ServiceHttpClient};
use hodor_authorization::api::{
    Action, Attributes, AuthorizationEngine as _, AuthorizationRequest, Effect, EvaluationContext,
    EvaluationInput, Namespace, Resource, Subject, SubjectKind,
};
use hodor_authorization_opa::api::{
    Author, BundleFile, BundleService, BundleStore as _, Instances, OpenPolicyAgentEngine,
    PublishedBundle, bundle_name, decision_path, gzip,
};
use hodor_authorization_opa::testing::{
    FakeSigner, InMemoryBundles, InMemoryInstances, InMemoryStatuses, InMemoryUploadedDecisions,
    pack, unpack,
};
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Digest as _, SystemClock, TenantContext, TenantId, UnitOfWorkFactory as _,
};
use hodor_protocol_http::policy_agent_routes;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use testcontainers::core::{Host, IntoContainerPort as _, WaitFor};
use testcontainers::runners::AsyncRunner as _;
use testcontainers::{GenericImage, ImageExt as _};
use tower::ServiceExt as _;

/// Pinned, like every image a test starts: the version of the capabilities file.
const IMAGE: (&str, &str) = ("openpolicyagent/opa", "1.10.1");
const DOCUMENTS: &str = "https://documents.example.com";

struct World {
    service: BundleService,
    bundles: Arc<InMemoryBundles>,
    units: Arc<InMemoryUnitOfWorkFactory>,
}

fn world() -> World {
    let bundles = Arc::new(InMemoryBundles::default());
    let units = Arc::new(InMemoryUnitOfWorkFactory::default());
    let service = BundleService::new(
        Arc::new(InMemoryInstances::default()),
        bundles.clone(),
        Arc::new(InMemoryStatuses::default()),
        Arc::new(InMemoryUploadedDecisions::default()),
        units.clone(),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    );
    World {
        service,
        bundles,
        units,
    }
}

/// The package of the `decision` rule for `namespace` in `tenant`.
fn package(tenant: &TenantContext, namespace: &str) -> String {
    decision_path(
        tenant,
        &Namespace::parse(namespace).expect("namespace"),
        &Sha256Digest,
    )
    .trim_start_matches("/v1/data/")
    .trim_end_matches("/decision")
    .replace('/', ".")
}

/// A policy that lets everyone read, or no one, with a reason that names
/// the revision's intent; and data with characters JSON escapes.
fn files(tenant: &TenantContext, reading: bool) -> Vec<BundleFile> {
    let package = package(tenant, DOCUMENTS);
    // The package below the tenant's tree, as directories.
    let directory = package.split('.').skip(3).collect::<Vec<_>>().join("/");
    let policy = format!(
        "package {package}\n\ndecision := {{\"allow\": {reading}, \"reason\": data.{package}.reason}} if input.action == \"read\"\n"
    );
    let data = json!({"reason": if reading { "everyone_reads" } else { "nobody_reads" }, "note": "<a & b>\u{e9}\n\"quoted\""});
    vec![
        BundleFile {
            path: format!("{directory}/policy.rego"),
            contents: policy.into_bytes(),
        },
        BundleFile {
            path: format!("{directory}/data.json"),
            contents: data.to_string().into_bytes(),
        },
    ]
}

fn read_input() -> EvaluationInput {
    EvaluationInput {
        request: AuthorizationRequest {
            namespace: Namespace::parse(DOCUMENTS).expect("namespace"),
            subject: Subject::new(SubjectKind::User, "ana").expect("subject"),
            asserted: Attributes::none(),
            resource: Resource::new("document", Some("1"), Attributes::none()).expect("resource"),
            action: Action::parse("read").expect("action"),
            context: EvaluationContext::default(),
        },
        subject_attributes: Attributes::none(),
        time_limit: Duration::from_millis(2000),
    }
}

/// Waits up to a minute for `check` to give something.
async fn eventually<T, F, Fut>(what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    for _ in 0..120 {
        if let Some(found) = check().await {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Stores a bundle as given, bypassing publication: what a tampered store
/// would serve.
async fn store_as_is(world: &World, tenant: &TenantContext, revision: u64, archive: Vec<u8>) {
    let bundle = PublishedBundle {
        revision,
        author: Author::Tenant,
        digest: Sha256Digest.sha256(&archive),
        archive,
        published_at: time::OffsetDateTime::now_utc(),
    };
    let mut uow = world.units.begin(tenant).await.expect("begin");
    world
        .bundles
        .append(uow.as_mut(), &bundle)
        .await
        .expect("append");
    uow.commit().await.expect("commit");
}

#[tokio::test]
async fn an_instance_runs_only_bundles_hodor_signed_and_reports_what_it_runs() {
    let world = world();
    let tenant = TenantContext::assume(TenantId::generate());
    let (private, public) = BundleSigningKey::generate().expect("key");
    let signer = BundleSigningKey::from_pem(&private, "hodor").expect("signer");
    let (instance, credential) = world
        .service
        .register("own", Some(tenant.tenant_id()))
        .await
        .expect("register");

    // Hodor's service interface, where the container can reach it.
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .expect("listener");
    let port = listener.local_addr().expect("address").port();
    let router = policy_agent_routes(world.service.clone());
    tokio::spawn(async move { axum::serve(listener, router).await });

    world
        .service
        .publish(
            &tenant,
            Author::Tenant,
            &files(&tenant, true),
            &signer,
            Caller::system(),
        )
        .await
        .expect("first revision");

    let name = bundle_name(tenant.tenant_id());
    let indented: String = public
        .lines()
        .map(|line| format!("      {line}\n"))
        .collect();
    let configuration = format!(
        "services:
  hodor:
    url: http://host.docker.internal:{port}/opa
    credentials:
      bearer:
        token: {credential}
bundles:
  {name}:
    service: hodor
    resource: bundles/{name}
    polling:
      min_delay_seconds: 1
      max_delay_seconds: 1
    signing:
      keyid: hodor
keys:
  hodor:
    algorithm: ES256
    key: |
{indented}status:
  service: hodor
decision_logs:
  service: hodor
  reporting:
    min_delay_seconds: 1
    max_delay_seconds: 1
",
        credential = credential.expose()
    );
    let (image, tag) = IMAGE;
    let container = GenericImage::new(image, tag)
        .with_exposed_port(8181.tcp())
        .with_wait_for(WaitFor::message_on_either_std("Initializing server"))
        .with_host("host.docker.internal", Host::HostGateway)
        .with_copy_to("/configuration.yaml", configuration.into_bytes())
        .with_cmd([
            "run",
            "--server",
            "--addr=0.0.0.0:8181",
            "--config-file=/configuration.yaml",
            "--log-level=debug",
        ])
        .start()
        .await
        .expect("Open Policy Agent starts; is Docker running?");
    let origin = format!(
        "http://127.0.0.1:{}",
        container.get_host_port_ipv4(8181).await.expect("port")
    );
    let engine = OpenPolicyAgentEngine::new(
        Arc::new(
            ServiceHttpClient::new(std::slice::from_ref(&origin), OutboundPolicy::default())
                .expect("client"),
        ),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
        Instances::parse(None, &format!("{}={origin}", tenant.tenant_id())).expect("instances"),
    );
    let answer = |wanted: &'static str| {
        let engine = &engine;
        let tenant = &tenant;
        move || async move {
            let answer = engine
                .evaluate(tenant, &read_input())
                .await
                .expect("answer");
            (answer.policy_version.as_ref().map(|r| r.as_str()) == Some(wanted)).then_some(answer)
        }
    };

    // The signed bundle is activated, and decisions carry its revision.
    let first = eventually("revision 1 to answer", answer("1")).await;
    assert_eq!(first.effect, Effect::Allow);
    assert_eq!(first.reason.as_str(), "everyone_reads");

    // The instance says it runs revision 1, and its decisions arrive.
    let status = eventually("the status of revision 1", || async {
        world
            .service
            .statuses(&tenant)
            .await
            .expect("statuses")
            .into_iter()
            .find(|status| status.active_revision.as_deref() == Some("1"))
    })
    .await;
    assert_eq!(status.instance, instance.id());
    assert_eq!(status.error, None);
    let logged = eventually("a decision of revision 1", || async {
        world
            .service
            .uploaded_decisions(&tenant, 10)
            .await
            .expect("decisions")
            .into_iter()
            .find(|decision| decision.revision.as_deref() == Some("1"))
    })
    .await;
    assert_eq!(logged.allowed, Some(true));
    assert!(logged.path.contains(&name), "{}", logged.path);

    // A second revision replaces it.
    world
        .service
        .publish(
            &tenant,
            Author::Tenant,
            &files(&tenant, false),
            &signer,
            Caller::system(),
        )
        .await
        .expect("second revision");
    let second = eventually("revision 2 to answer", answer("2")).await;
    assert_eq!(second.effect, Effect::Deny);
    assert_eq!(second.reason.as_str(), "nobody_reads");

    // A bundle changed after it was signed is refused: the instance keeps
    // revision 2 and reports the error.
    let mut changed = unpack(&world.bundles_archive(&tenant).await);
    let policy = changed
        .iter_mut()
        .find(|(path, _)| path.ends_with("policy.rego"))
        .expect("policy");
    policy.1 = String::from_utf8(policy.1.clone())
        .expect("text")
        .replace("false", "true")
        .into_bytes();
    store_as_is(&world, &tenant, 3, pack(&changed)).await;
    let refused = eventually("the changed bundle to be refused", || async {
        world
            .service
            .statuses(&tenant)
            .await
            .expect("statuses")
            .into_iter()
            .find(|status| status.error.is_some())
    })
    .await;
    assert_eq!(refused.active_revision.as_deref(), Some("2"), "{refused:?}");
    let still = engine
        .evaluate(&tenant, &read_input())
        .await
        .expect("answer");
    assert_eq!(still.effect, Effect::Deny, "the changed policy never ran");
    assert_eq!(still.policy_version.as_ref().map(|r| r.as_str()), Some("2"));

    // A bundle without its signature is refused as well.
    let unsigned: Vec<(String, Vec<u8>)> = unpack(&world.bundles_archive(&tenant).await)
        .into_iter()
        .filter(|(path, _)| path != ".signatures.json")
        .collect();
    let first_error = refused.error.clone();
    store_as_is(&world, &tenant, 4, pack(&unsigned)).await;
    let refused_again = eventually("the unsigned bundle to be refused", || async {
        world
            .service
            .statuses(&tenant)
            .await
            .expect("statuses")
            .into_iter()
            .find(|status| status.error.is_some() && status.error != first_error)
    })
    .await;
    assert_eq!(
        refused_again.active_revision.as_deref(),
        Some("2"),
        "{refused_again:?}"
    );
    let still = engine
        .evaluate(&tenant, &read_input())
        .await
        .expect("answer");
    assert_eq!(still.policy_version.as_ref().map(|r| r.as_str()), Some("2"));

    // And one signed by another key under the same name.
    let (forger, _) = BundleSigningKey::generate().expect("key");
    let forger = BundleSigningKey::from_pem(&forger, "hodor").expect("forger");
    let second_error = refused_again.error.clone();
    world
        .service
        .publish(
            &tenant,
            Author::Tenant,
            &files(&tenant, true),
            &forger,
            Caller::system(),
        )
        .await
        .expect("forged revision");
    let forged = eventually("the forged bundle to be refused", || async {
        world
            .service
            .statuses(&tenant)
            .await
            .expect("statuses")
            .into_iter()
            .find(|status| status.error.is_some() && status.error != second_error)
    })
    .await;
    assert_eq!(forged.active_revision.as_deref(), Some("2"), "{forged:?}");
    let still = engine
        .evaluate(&tenant, &read_input())
        .await
        .expect("answer");
    assert_eq!(still.effect, Effect::Deny, "the forged policy never ran");
    drop(container);
}

impl World {
    /// The archive of the tenant's latest bundle.
    async fn bundles_archive(&self, tenant: &TenantContext) -> Vec<u8> {
        let mut uow = self.units.begin(tenant).await.expect("begin");
        let latest = self
            .bundles
            .latest(uow.as_mut())
            .await
            .expect("latest")
            .expect("a bundle");
        uow.commit().await.expect("commit");
        latest.archive
    }
}

async fn send(router: &axum::Router, request: Request<Body>) -> axum::response::Response {
    router.clone().oneshot(request).await.expect("response")
}

fn get(path: &str, credential: Option<&str>) -> Request<Body> {
    let mut request = Request::get(path);
    if let Some(credential) = credential {
        request = request.header(header::AUTHORIZATION, format!("Bearer {credential}"));
    }
    request.body(Body::empty()).expect("request")
}

#[tokio::test]
async fn over_http_an_instance_reaches_only_what_it_may() {
    let world = world();
    let router = policy_agent_routes(world.service.clone());
    let tenant = TenantContext::assume(TenantId::generate());
    let other = TenantContext::assume(TenantId::generate());
    let (_, own) = world
        .service
        .register("own", Some(tenant.tenant_id()))
        .await
        .expect("own");
    let (_, shared) = world
        .service
        .register("shared", None)
        .await
        .expect("shared");
    let (_, disabled) = world.service.register("old", None).await.expect("old");
    assert!(world.service.disable("old").await.expect("disable"));
    world
        .service
        .publish(
            &tenant,
            Author::Tenant,
            &files(&tenant, true),
            &FakeSigner,
            Caller::system(),
        )
        .await
        .expect("tenant's own");
    world
        .service
        .publish(
            &other,
            Author::Operator,
            &files(&other, true),
            &FakeSigner,
            Caller::system(),
        )
        .await
        .expect("operator's");
    let path = |tenant: &TenantContext| format!("/opa/bundles/{}", bundle_name(tenant.tenant_id()));

    // Without a good credential: 401 and nothing else.
    for credential in [
        None,
        Some("hodor_pa_wrong"),
        Some(disabled.expose().as_str()),
    ] {
        let response = send(&router, get(&path(&tenant), credential)).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{credential:?}"
        );
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    }

    // Its own tenant's bundle, with its tag, and 304 for the same tag.
    let response = send(&router, get(&path(&tenant), Some(own.expose()))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/gzip");
    let tag = response.headers()[header::ETAG]
        .to_str()
        .expect("tag")
        .to_owned();
    let mut again = get(&path(&tenant), Some(own.expose()));
    again
        .headers_mut()
        .insert(header::IF_NONE_MATCH, tag.parse().expect("header"));
    let response = send(&router, again).await;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(response.headers()[header::ETAG], tag.as_str());

    // Another tenant's bundle, or a tenant's own on a shared instance:
    // 404, as for no bundle at all.
    for (bundle, credential) in [(&other, own.expose()), (&tenant, shared.expose())] {
        let response = send(&router, get(&path(bundle), Some(credential))).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    let response = send(&router, get(&path(&other), Some(shared.expose()))).await;
    assert_eq!(response.status(), StatusCode::OK, "the operator's bundle");

    // Reports: a status and decisions, compressed as Open Policy Agent
    // sends them.
    let status = json!({"bundles": {bundle_name(tenant.tenant_id()): {"active_revision": "1"}}});
    let request = Request::post("/opa/status")
        .header(header::AUTHORIZATION, format!("Bearer {}", own.expose()))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(status.to_string()))
        .expect("request");
    assert_eq!(
        send(&router, request).await.status(),
        StatusCode::NO_CONTENT
    );
    let decisions = json!([{
        "decision_id": "1",
        "path": format!("hodor/tenants/{}/resource_servers/r/decision", bundle_name(tenant.tenant_id())),
        "result": {"allow": true},
    }]);
    let request = Request::post("/opa/logs")
        .header(header::AUTHORIZATION, format!("Bearer {}", own.expose()))
        .header(header::CONTENT_ENCODING, "gzip")
        .body(Body::from(gzip(decisions.to_string().as_bytes())))
        .expect("request");
    assert_eq!(
        send(&router, request).await.status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        world
            .service
            .uploaded_decisions(&tenant, 10)
            .await
            .expect("decisions")
            .len(),
        1
    );
    let request = Request::post("/opa/logs")
        .header(header::AUTHORIZATION, format!("Bearer {}", own.expose()))
        .header(header::CONTENT_ENCODING, "gzip")
        .body(Body::from("not gzip"))
        .expect("request");
    assert_eq!(
        send(&router, request).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let request = Request::post("/opa/status")
        .body(Body::from("{}"))
        .expect("request");
    assert_eq!(
        send(&router, request).await.status(),
        StatusCode::UNAUTHORIZED
    );
}
