//! The engine against a scripted HTTP client: what is sent, retries, time
//! and the circuit, deterministically.

use hodor_adapters_crypto::Sha256Digest;
use hodor_authorization::api::{
    Action, Attributes, AuthorizationEngine as _, AuthorizationRequest, Effect, EvaluationContext,
    EvaluationInput, Namespace, Resource, Subject, SubjectKind,
};
use hodor_authorization_opa::api::{ENGINE, Instances, OpenPolicyAgentEngine, decision_path};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{
    DomainError, ErrorKind, HttpClient, HttpRequest, HttpResponse, Secret, TenantContext, TenantId,
    Timestamp,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SHARED: &str = "http://localhost:8181";

/// What the scripted client does with one request.
enum Step {
    Answer(u16, &'static str),
    Fail(&'static str),
    /// Answers after the clock moved on by this much.
    Slow(time::Duration, &'static str),
}

struct Scripted {
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<HttpRequest>>,
    clock: Arc<FixedClock>,
}

impl Scripted {
    fn new(clock: Arc<FixedClock>, steps: Vec<Step>) -> Arc<Self> {
        Arc::new(Self {
            steps: Mutex::new(steps.into()),
            seen: Mutex::new(Vec::new()),
            clock,
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
        let step = self.steps.lock().expect("steps").pop_front();
        let answer = |status: u16, body: &str| HttpResponse {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        };
        match step {
            Some(Step::Answer(status, body)) => Ok(answer(status, body)),
            Some(Step::Slow(by, body)) => {
                self.clock.advance(by);
                Ok(answer(200, body))
            }
            Some(Step::Fail(code)) => Err(DomainError::new(ErrorKind::Unavailable, code, "failed")),
            None => Err(DomainError::new(
                ErrorKind::Unavailable,
                "http.unreachable",
                "nothing scripted",
            )),
        }
    }
}

fn clock() -> Arc<FixedClock> {
    Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
    ))
}

fn engine(http: Arc<Scripted>, clock: Arc<FixedClock>) -> OpenPolicyAgentEngine {
    OpenPolicyAgentEngine::new(
        http,
        Arc::new(Sha256Digest),
        clock,
        Instances::parse(Some(SHARED), "").expect("instances"),
    )
}

fn input() -> EvaluationInput {
    EvaluationInput {
        request: AuthorizationRequest {
            namespace: Namespace::parse("https://api.example.com").expect("namespace"),
            subject: Subject::new(SubjectKind::User, "ana").expect("subject"),
            asserted: Attributes::none(),
            resource: Resource::new("document", Some("1"), Attributes::none()).expect("resource"),
            action: Action::parse("read").expect("action"),
            context: EvaluationContext::default(),
        },
        subject_attributes: Attributes::none(),
        time_limit: Duration::from_millis(200),
    }
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

const ALLOW: &str = r#"{"result":{"allow":true}}"#;

#[tokio::test]
async fn the_engine_is_named_and_cannot_simulate() {
    let clock = clock();
    let engine = engine(Scripted::new(clock.clone(), Vec::new()), clock);
    assert_eq!(engine.id().as_str(), ENGINE);
    assert!(!engine.capabilities().simulation);
}

#[tokio::test]
async fn the_request_goes_to_the_path_of_the_tenant_and_the_binding() {
    let clock = clock();
    let http = Scripted::new(clock.clone(), vec![Step::Answer(200, ALLOW)]);
    let engine = engine(http.clone(), clock).with_token(Secret::from("token".to_owned()));
    let tenant = tenant();
    let mut input = input();
    // Everything a caller controls, pointing elsewhere.
    input.request.resource = Resource::new(
        "document",
        Some("../../tenants/other/decision"),
        Attributes::new([(
            "tenant".to_owned(),
            serde_json::json!(TenantId::generate().to_string()),
        )])
        .expect("attributes"),
    )
    .expect("resource");

    let answer = engine.evaluate(&tenant, &input).await.expect("answer");

    assert_eq!(answer.effect, Effect::Allow);
    let seen = http.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].url,
        format!(
            "{SHARED}{}",
            decision_path(&tenant, &input.request.namespace, &Sha256Digest)
        )
    );
    assert!(
        seen[0]
            .headers
            .contains(&("authorization".to_owned(), "Bearer token".to_owned()))
    );
    assert_eq!(seen[0].time_limit, Some(Duration::from_millis(200)));
    let body: serde_json::Value =
        serde_json::from_slice(seen[0].body.as_deref().expect("body")).expect("json");
    assert_eq!(body["input"]["action"], "read");
    assert_eq!(body["input"]["subject"]["id"], "ana");
    assert_eq!(
        body["input"]["resource"]["id"],
        "../../tenants/other/decision"
    );
}

#[tokio::test]
async fn a_tenant_without_an_instance_is_indeterminate_without_a_request() {
    let clock = clock();
    let http = Scripted::new(clock.clone(), Vec::new());
    let engine = OpenPolicyAgentEngine::new(
        http.clone(),
        Arc::new(Sha256Digest),
        clock,
        Instances::none(),
    );
    let answer = engine.evaluate(&tenant(), &input()).await.expect("answer");
    assert_eq!(answer.effect, Effect::Indeterminate);
    assert_eq!(answer.reason.as_str(), "policy_engine_not_configured");
    assert!(http.seen().is_empty());
}

#[tokio::test]
async fn a_connection_that_failed_is_tried_once_more() {
    let clock = clock();
    let http = Scripted::new(
        clock.clone(),
        vec![Step::Fail("http.unreachable"), Step::Answer(200, ALLOW)],
    );
    let answer = engine(http.clone(), clock)
        .evaluate(&tenant(), &input())
        .await
        .expect("answer");
    assert_eq!(answer.effect, Effect::Allow);
    assert_eq!(http.seen().len(), 2);

    let clock = self::clock();
    let http = Scripted::new(
        clock.clone(),
        vec![
            Step::Fail("http.unreachable"),
            Step::Fail("http.unreachable"),
        ],
    );
    let answer = engine(http.clone(), clock)
        .evaluate(&tenant(), &input())
        .await
        .expect("answer");
    assert_eq!(answer.effect, Effect::Indeterminate);
    assert_eq!(answer.reason.as_str(), "policy_engine_unreachable");
    assert_eq!(http.seen().len(), 2, "only once more");
}

#[tokio::test]
async fn a_time_out_or_an_error_status_is_never_retried() {
    for (step, reason) in [
        (Step::Fail("http.timed_out"), "policy_engine_timed_out"),
        (Step::Answer(500, "{}"), "policy_engine_error"),
        (Step::Answer(404, "{}"), "policy_engine_error"),
        (
            Step::Fail("http.destination_not_configured"),
            "policy_engine_unreachable",
        ),
    ] {
        let clock = clock();
        let http = Scripted::new(clock.clone(), vec![step, Step::Answer(200, ALLOW)]);
        let answer = engine(http.clone(), clock)
            .evaluate(&tenant(), &input())
            .await
            .expect("answer");
        assert_eq!(answer.effect, Effect::Indeterminate, "{reason}");
        assert_eq!(answer.reason.as_str(), reason);
        assert_eq!(http.seen().len(), 1, "{reason}");
    }
}

#[tokio::test]
async fn the_retry_gets_only_the_time_that_is_left() {
    let clock = clock();
    let http = Scripted::new(clock.clone(), vec![Step::Fail("http.unreachable")]);
    // The first attempt used 150 of the 200 milliseconds.
    struct Spending(Arc<Scripted>, Arc<FixedClock>);
    #[async_trait::async_trait]
    impl HttpClient for Spending {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
            if self.0.seen().is_empty() {
                self.1.advance(time::Duration::milliseconds(150));
            }
            self.0.send(request).await
        }
    }
    let engine = OpenPolicyAgentEngine::new(
        Arc::new(Spending(http.clone(), clock.clone())),
        Arc::new(Sha256Digest),
        clock,
        Instances::parse(Some(SHARED), "").expect("instances"),
    );
    let _ = engine.evaluate(&tenant(), &input()).await;
    let seen = http.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].time_limit, Some(Duration::from_millis(200)));
    assert_eq!(seen[1].time_limit, Some(Duration::from_millis(50)));
}

#[tokio::test]
async fn an_answer_after_the_time_limit_is_not_retried() {
    let clock = clock();
    let http = Scripted::new(
        clock.clone(),
        vec![
            Step::Slow(time::Duration::milliseconds(250), ALLOW),
            Step::Answer(200, ALLOW),
        ],
    );
    // The engine took the answer; the evaluation service discards an
    // answer that came after the limit by Hodor's clock.
    let answer = engine(http.clone(), clock)
        .evaluate(&tenant(), &input())
        .await
        .expect("answer");
    assert_eq!(answer.effect, Effect::Allow);
    assert_eq!(http.seen().len(), 1);
}

#[tokio::test]
async fn five_failures_open_the_circuit_and_a_probe_closes_it() {
    let clock = clock();
    let mut steps: Vec<Step> = (0..5).map(|_| Step::Answer(503, "{}")).collect();
    steps.push(Step::Answer(200, ALLOW));
    steps.push(Step::Answer(200, ALLOW));
    let http = Scripted::new(clock.clone(), steps);
    let engine = engine(http.clone(), clock.clone());
    let tenant = tenant();

    for _ in 0..5 {
        let answer = engine.evaluate(&tenant, &input()).await.expect("answer");
        assert_eq!(answer.reason.as_str(), "policy_engine_error");
    }
    let answer = engine.evaluate(&tenant, &input()).await.expect("answer");
    assert_eq!(answer.effect, Effect::Indeterminate);
    assert_eq!(answer.reason.as_str(), "policy_engine_unavailable");
    assert_eq!(http.seen().len(), 5, "an open circuit is not called");

    clock.advance(time::Duration::seconds(5));
    let answer = engine.evaluate(&tenant, &input()).await.expect("probe");
    assert_eq!(answer.effect, Effect::Allow);
    let answer = engine.evaluate(&tenant, &input()).await.expect("closed");
    assert_eq!(answer.effect, Effect::Allow);
    assert_eq!(http.seen().len(), 7);
}

#[tokio::test]
async fn an_undefined_or_malformed_answer_does_not_open_the_circuit() {
    let clock = clock();
    let mut steps: Vec<Step> = (0..6).map(|_| Step::Answer(200, "{}")).collect();
    steps.push(Step::Answer(200, r#"{"result":{"allow":"yes"}}"#));
    let http = Scripted::new(clock.clone(), steps);
    let engine = engine(http.clone(), clock);
    let tenant = tenant();
    for _ in 0..6 {
        let answer = engine.evaluate(&tenant, &input()).await.expect("answer");
        assert_eq!(answer.reason.as_str(), "policy_undefined");
    }
    let answer = engine.evaluate(&tenant, &input()).await.expect("answer");
    assert_eq!(answer.reason.as_str(), "policy_answer_malformed");
    assert_eq!(http.seen().len(), 7);
}

#[tokio::test]
async fn each_instance_has_a_circuit_of_its_own() {
    let clock = clock();
    let own = TenantId::generate();
    let steps: Vec<Step> = (0..5)
        .map(|_| Step::Answer(503, "{}"))
        .chain([Step::Answer(200, ALLOW)])
        .collect();
    let http = Scripted::new(clock.clone(), steps);
    let engine = OpenPolicyAgentEngine::new(
        http.clone(),
        Arc::new(Sha256Digest),
        clock,
        Instances::parse(Some(SHARED), &format!("{own}=http://policy-own:8181"))
            .expect("instances"),
    );
    let shared_tenant = tenant();
    for _ in 0..5 {
        let _ = engine.evaluate(&shared_tenant, &input()).await;
    }
    let answer = engine
        .evaluate(&shared_tenant, &input())
        .await
        .expect("open");
    assert_eq!(answer.reason.as_str(), "policy_engine_unavailable");

    let answer = engine
        .evaluate(&TenantContext::assume(own), &input())
        .await
        .expect("own");
    assert_eq!(answer.effect, Effect::Allow);
    assert!(
        http.seen()
            .last()
            .expect("request")
            .url
            .starts_with("http://policy-own:8181/v1/data/hodor/tenants/")
    );
}
