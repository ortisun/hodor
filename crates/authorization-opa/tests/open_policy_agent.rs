//! The engine against a real Open Policy Agent in a container.
//!
//! The policies are files the container starts with. Production never
//! loads a policy this way or through the Policy API: instances pull
//! signed bundles from Hodor (Issue-78). The instance requires a bearer
//! token, as an installation's must.
//!
//! Each test starts its own instance and reaches it through a gate of its
//! own (`Gate`), never through the port Docker forwards directly: a test
//! takes an instance away by closing its gate, not by stopping the
//! container.

use hodor_adapters_crypto::Sha256Digest;
use hodor_adapters_http::{OutboundPolicy, ServiceHttpClient};
use hodor_authorization::api::{
    Action, Attributes, AuthorizationEngine as _, AuthorizationRequest, BindingSettings, Effect,
    EngineId, EngineRegistry, EvaluationContext, EvaluationInput, EvaluationService, Namespace,
    Resource, Subject, SubjectKind,
};
use hodor_authorization::testing::{
    InMemoryEngineBindings, InMemoryRoleAssignments, StaticSubjectAttributes,
};
use hodor_authorization_opa::api::{ENGINE, Instances, OpenPolicyAgentEngine, decision_path};
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, HttpClient as _, HttpRequest, Secret, SystemClock, TenantContext, TenantId,
};
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use testcontainers::core::{IntoContainerPort as _, WaitFor};
use testcontainers::runners::AsyncRunner as _;
use testcontainers::{ContainerAsync, GenericImage, ImageExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Pinned, like every image a test starts.
const IMAGE: (&str, &str) = ("openpolicyagent/opa", "1.10.1");
const TOKEN: &str = "test-token-of-this-instance";
const DOCUMENTS: &str = "https://documents.example.com";
const BROKEN: &str = "urn:example:broken";
const SLOW: &str = "urn:example:slow";

/// Requires the token for every call of the instance's own interface.
const AUTHORIZATION: &str = r#"package system.authz

default allow := false

allow if input.identity == "test-token-of-this-instance"
"#;

/// The package a decision path names.
fn package(tenant: &TenantContext, namespace: &str) -> String {
    let path = decision_path(
        tenant,
        &Namespace::parse(namespace).expect("namespace"),
        &Sha256Digest,
    );
    path.trim_start_matches("/v1/data/")
        .trim_end_matches("/decision")
        .replace('/', ".")
}

fn policies(tenant: &TenantContext) -> String {
    format!(
        r#"package {documents}

# The owner may read; nobody may delete; a conflict is an error of
# evaluation; anything else is left undefined.
decision := {{"allow": true, "reason": "owner_may_read", "policies": ["documents/owner"]}} if {{
	input.action == "read"
	input.resource.attributes.owner == input.subject.id
}}

decision := {{"allow": false, "reason": "nobody_deletes"}} if input.action == "delete"

decision := {{"allow": true}} if input.action == "conflict"

decision := {{"allow": false}} if input.action == "conflict"
"#,
        documents = package(tenant, DOCUMENTS)
    ) + &format!(
        r#"
package {broken}

decision := "allow"
"#,
        broken = package(tenant, BROKEN)
    )
}

fn slow_policy(tenant: &TenantContext) -> String {
    format!(
        r#"package {slow}

# Nine million steps, and a set of one element: seconds, not memory.
decision := {{"allow": count({{1 | some x in numbers.range(1, 3000); some y in numbers.range(1, 3000)}}) > 0}}
"#,
        slow = package(tenant, SLOW)
    )
}

struct Instance {
    container: ContainerAsync<GenericImage>,
    /// The gate's address, which the engine is given.
    origin: String,
    gate: Gate,
}

impl Instance {
    /// Takes the instance away: from now on its address answers nothing
    /// and closes every connection at once.
    fn take_away(&self) {
        self.gate.close();
    }
}

/// A relay on the machine running the tests, between the engine and the
/// port Docker forwards to the container, which a test can close.
///
/// Stopping the container does not make the instance unreachable at once.
/// For a while after `docker stop` returns, and longer while other
/// containers start, stop or pause, Docker Desktop may still accept
/// connections on the stopped container's port and leave them unanswered:
/// the engine then sees its time limit run out, `policy_engine_timed_out`,
/// instead of `policy_engine_unreachable`. A closed gate closes the
/// connections it relays and every connection it accepts afterwards,
/// whatever Docker does.
struct Gate {
    open: watch::Sender<bool>,
}

impl Gate {
    /// Opens a gate to `port` and answers with the gate's own port.
    async fn to(port: u16) -> (Self, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("gate");
        let own = listener.local_addr().expect("gate address").port();
        let (open, watching) = watch::channel(true);
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let mut watching = watching.clone();
                if !*watching.borrow() {
                    // Dropping the connection closes it.
                    continue;
                }
                tokio::spawn(async move {
                    let Ok(mut instance) = TcpStream::connect(("127.0.0.1", port)).await else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut client, &mut instance) => {}
                        _ = watching.wait_for(|open| !open) => {}
                    }
                });
            }
        });
        (Self { open }, own)
    }

    fn close(&self) {
        self.open.send_replace(false);
    }
}

/// Waits until the instance answers a request with its token.
///
/// Open Policy Agent writes "Initializing server" before it listens, and
/// Docker accepts connections on the forwarded port before anything in
/// the container does, so a first request sent as soon as the message is
/// out may be cut off or left unanswered.
async fn answering(origin: &str) {
    let http =
        ServiceHttpClient::new(&[origin.to_owned()], OutboundPolicy::default()).expect("client");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let health = HttpRequest::get(format!("{origin}/health"))
            .header("authorization", format!("Bearer {TOKEN}"))
            .within(Duration::from_secs(1));
        if matches!(http.send(health).await, Ok(response) if response.status == 200) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Open Policy Agent did not answer within a minute"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn start(tenant: &TenantContext) -> Instance {
    let (name, tag) = IMAGE;
    // Rego allows one package per file.
    let mut documents = policies(tenant);
    let broken_at = documents.find("\npackage ").expect("two packages");
    let broken = documents.split_off(broken_at);
    let container = GenericImage::new(name, tag)
        .with_exposed_port(8181.tcp())
        .with_wait_for(WaitFor::message_on_either_std("Initializing server"))
        .with_copy_to("/policies/authz.rego", AUTHORIZATION.as_bytes().to_vec())
        .with_copy_to("/policies/documents.rego", documents.into_bytes())
        .with_copy_to("/policies/broken.rego", broken.into_bytes())
        .with_copy_to("/policies/slow.rego", slow_policy(tenant).into_bytes())
        .with_cmd([
            "run",
            "--server",
            "--addr=0.0.0.0:8181",
            "--authentication=token",
            "--authorization=basic",
            "--log-level=info",
            "/policies",
        ])
        .start()
        .await
        .expect("Open Policy Agent starts; is Docker running?");
    let port = container.get_host_port_ipv4(8181).await.expect("port");
    let (gate, own) = Gate::to(port).await;
    let origin = format!("http://127.0.0.1:{own}");
    answering(&origin).await;
    Instance {
        container,
        origin,
        gate,
    }
}

fn engine(origin: &str, instances: Instances, token: Option<&str>) -> OpenPolicyAgentEngine {
    let http =
        ServiceHttpClient::new(&[origin.to_owned()], OutboundPolicy::default()).expect("client");
    let engine = OpenPolicyAgentEngine::new(
        Arc::new(http),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
        instances,
    );
    match token {
        Some(token) => engine.with_token(Secret::from(token.to_owned())),
        None => engine,
    }
}

fn input(namespace: &str, action: &str, owner: &str) -> EvaluationInput {
    EvaluationInput {
        request: AuthorizationRequest {
            namespace: Namespace::parse(namespace).expect("namespace"),
            subject: Subject::new(SubjectKind::User, "ana").expect("subject"),
            asserted: Attributes::none(),
            resource: Resource::new(
                "document",
                Some("1"),
                Attributes::new([("owner".to_owned(), json!(owner))]).expect("attributes"),
            )
            .expect("resource"),
            action: Action::parse(action).expect("action"),
            context: EvaluationContext::default(),
        },
        subject_attributes: Attributes::none(),
        time_limit: Duration::from_millis(2000),
    }
}

async fn effect_and_reason(
    engine: &OpenPolicyAgentEngine,
    tenant: &TenantContext,
    input: &EvaluationInput,
) -> (Effect, String) {
    let answer = engine.evaluate(tenant, input).await.expect("answer");
    (answer.effect, answer.reason.as_str().to_owned())
}

#[tokio::test]
async fn the_policy_allows_and_denies_and_every_failure_is_indeterminate() {
    let tenant = TenantContext::assume(TenantId::generate());
    let instance = start(&tenant).await;
    let shared = Instances::parse(Some(&instance.origin), "").expect("instances");
    let engine = engine(&instance.origin, shared.clone(), Some(TOKEN));

    let allowed = engine
        .evaluate(&tenant, &input(DOCUMENTS, "read", "ana"))
        .await
        .expect("answer");
    assert_eq!(allowed.effect, Effect::Allow);
    assert_eq!(allowed.reason.as_str(), "owner_may_read");
    assert_eq!(allowed.matched_policies.len(), 1);
    assert_eq!(allowed.matched_policies[0].as_str(), "documents/owner");

    assert_eq!(
        effect_and_reason(&engine, &tenant, &input(DOCUMENTS, "delete", "ana")).await,
        (Effect::Deny, "nobody_deletes".to_owned())
    );
    assert_eq!(
        effect_and_reason(&engine, &tenant, &input(DOCUMENTS, "write", "ana")).await,
        (Effect::Indeterminate, "policy_undefined".to_owned()),
        "no rule for the action"
    );
    assert_eq!(
        effect_and_reason(&engine, &tenant, &input(DOCUMENTS, "read", "bruno")).await,
        (Effect::Indeterminate, "policy_undefined".to_owned()),
        "not the owner, and no rule that denies"
    );
    assert_eq!(
        effect_and_reason(&engine, &tenant, &input(BROKEN, "read", "ana")).await,
        (Effect::Indeterminate, "policy_answer_malformed".to_owned())
    );
    assert_eq!(
        effect_and_reason(&engine, &tenant, &input(DOCUMENTS, "conflict", "ana")).await,
        (Effect::Indeterminate, "policy_engine_error".to_owned()),
        "an error of evaluation is a status other than 200"
    );

    let mut slow = input(SLOW, "read", "ana");
    slow.time_limit = Duration::from_millis(50);
    let started = Instant::now();
    assert_eq!(
        effect_and_reason(&engine, &tenant, &slow).await,
        (Effect::Indeterminate, "policy_engine_timed_out".to_owned())
    );
    assert!(started.elapsed() < Duration::from_millis(1000));

    let without_token = self::engine(&instance.origin, shared.clone(), None);
    assert_eq!(
        effect_and_reason(&without_token, &tenant, &input(DOCUMENTS, "read", "ana")).await,
        (Effect::Indeterminate, "policy_engine_error".to_owned()),
        "the instance refuses a caller without its token"
    );

    instance.take_away();
    assert_eq!(
        effect_and_reason(&engine, &tenant, &input(DOCUMENTS, "read", "ana")).await,
        (
            Effect::Indeterminate,
            "policy_engine_unreachable".to_owned()
        )
    );
}

#[tokio::test]
async fn the_path_cannot_be_steered_from_the_request() {
    let owner = TenantContext::assume(TenantId::generate());
    let instance = start(&owner).await;
    let shared = Instances::parse(Some(&instance.origin), "").expect("instances");
    let engine = engine(&instance.origin, shared, Some(TOKEN));
    let stranger = TenantContext::assume(TenantId::generate());

    // The stranger asks about the same resource server, naming the
    // owner's tenant and path everywhere the request lets it.
    let mut steering = input(DOCUMENTS, "read", "ana");
    steering.request.resource = Resource::new(
        "document",
        Some(&decision_path(
            &owner,
            &steering.request.namespace,
            &Sha256Digest,
        )),
        Attributes::new([
            ("owner".to_owned(), json!("ana")),
            ("tenant".to_owned(), json!(owner.tenant_id().to_string())),
        ])
        .expect("attributes"),
    )
    .expect("resource");
    steering.request.context.attributes = Attributes::new([(
        "path".to_owned(),
        json!("hodor/tenants/other/resource_servers/other/decision"),
    )])
    .expect("context");

    assert_eq!(
        effect_and_reason(&engine, &stranger, &steering).await,
        (Effect::Indeterminate, "policy_undefined".to_owned()),
        "the stranger's own path, where no policy is"
    );
    assert_eq!(
        effect_and_reason(&engine, &owner, &steering).await,
        (Effect::Allow, "owner_may_read".to_owned()),
        "the same input in the owner's tenant"
    );
}

#[tokio::test]
async fn a_failing_instance_fails_closed_unless_the_action_fails_open() {
    let tenant = TenantContext::assume(TenantId::generate());
    let instance = start(&tenant).await;
    let shared = Instances::parse(Some(&instance.origin), "").expect("instances");
    let mut registry = EngineRegistry::new();
    registry
        .register(Arc::new(engine(&instance.origin, shared, Some(TOKEN))))
        .expect("register");
    let service = EvaluationService::new(
        Arc::new(InMemoryUnitOfWorkFactory::default()),
        Arc::new(InMemoryRoleAssignments::default()),
        Arc::new(InMemoryEngineBindings::default()),
        Arc::new(StaticSubjectAttributes::default()),
        registry,
        Arc::new(SystemClock),
    );
    let mut settings = BindingSettings::new(
        Namespace::parse(DOCUMENTS).expect("namespace"),
        EngineId::parse(ENGINE).expect("engine"),
    );
    settings.time_limit = Duration::from_millis(2000);
    settings.fail_open_actions = BTreeSet::from([Action::parse("list").expect("action")]);
    service
        .bind(&tenant, settings, Caller::system())
        .await
        .expect("bind");

    let read = input(DOCUMENTS, "read", "ana").request;
    let decision = service.evaluate(&tenant, &read).await;
    assert!(decision.permits());
    assert_eq!(decision.engine.as_ref().map(EngineId::as_str), Some(ENGINE));

    instance.take_away();
    let decision = service.evaluate(&tenant, &read).await;
    assert!(!decision.permits());
    assert_eq!(decision.effect, Effect::Indeterminate);
    assert_eq!(decision.reason.as_str(), "policy_engine_unreachable");

    let list = input(DOCUMENTS, "list", "ana").request;
    let decision = service.evaluate(&tenant, &list).await;
    assert!(decision.permits(), "this action was set to fail open");
    assert_eq!(decision.reason.as_str(), "fail_open");
}

#[tokio::test]
async fn the_circuit_opens_on_a_stopped_instance_and_closes_when_it_is_back() {
    let tenant = TenantContext::assume(TenantId::generate());
    let instance = start(&tenant).await;
    let port = instance
        .container
        .get_host_port_ipv4(8181)
        .await
        .expect("port");
    let shared = Instances::parse(Some(&instance.origin), "").expect("instances");
    let engine = engine(&instance.origin, shared, Some(TOKEN)).with_breaker(
        hodor_authorization_opa::api::BreakerSettings {
            open_for: time::Duration::seconds(1),
            ..hodor_authorization_opa::api::BreakerSettings::default()
        },
    );
    let read = input(DOCUMENTS, "read", "ana");

    instance.container.pause().await.expect("pause");
    let mut short = read.clone();
    short.time_limit = Duration::from_millis(100);
    for _ in 0..5 {
        assert_eq!(
            effect_and_reason(&engine, &tenant, &short).await,
            (Effect::Indeterminate, "policy_engine_timed_out".to_owned())
        );
    }
    let started = Instant::now();
    assert_eq!(
        effect_and_reason(&engine, &tenant, &short).await,
        (
            Effect::Indeterminate,
            "policy_engine_unavailable".to_owned()
        )
    );
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "an open circuit answers at once"
    );

    instance.container.unpause().await.expect("unpause");
    assert_eq!(
        instance
            .container
            .get_host_port_ipv4(8181)
            .await
            .expect("port"),
        port
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        effect_and_reason(&engine, &tenant, &read).await,
        (Effect::Allow, "owner_may_read".to_owned()),
        "the probe succeeds and closes the circuit"
    );
    assert_eq!(
        effect_and_reason(&engine, &tenant, &read).await,
        (Effect::Allow, "owner_may_read".to_owned())
    );
}
