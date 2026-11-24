//! The Authorization API: applications ask whether a subject may do an
//! action to one of their resources.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "The
//! Authorization API", and `docs/api/api-spec.md`, "Authorization API".
//! These handlers read the caller's token, build the question and write the
//! answer; deciding is the authorization context's.

use crate::bearer::{bearer, not_cached, refused};
use crate::problem::Problem;
use crate::request::current_request_id;
use crate::tenant::TenantSlug;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use hodor_authorization::api::{
    Action, ApplicationReference, Attributes, AuthorizationDecision, AuthorizationRequest,
    EvaluationContext, EvaluationService, Namespace, OrganizationReference, PolicyReference,
    PolicyRevision, PolicySelection, Resource, Subject, SubjectKind,
};
use hodor_authorization::api::{Effect, MAX_BATCH};
use hodor_kernel::{DomainError, TenantContext};
use hodor_oauth::api::{BearerRefusal, ResourceAccessService, ResourceCaller};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;

/// The audience an access token must name to be taken by the API.
pub const AUTHORIZATION_API_AUDIENCE: &str = "urn:hodor:authorization";
/// Opens `evaluate` and `batch`.
pub const EVALUATE_SCOPE: &str = "authz:evaluate";
/// Opens `simulate`.
pub const SIMULATE_SCOPE: &str = "authz:simulate";
/// Adds the policies that decided, and a simulation's trace, to answers.
pub const EXPLAIN_SCOPE: &str = "authz:explain";

/// The OpenAPI document of the API, as served at `/openapi.json`.
pub const AUTHORIZATION_OPENAPI: &str = include_str!("../openapi/authorization-v1.json");

/// The operations the API serves, as `(method, path)` under its mount.
pub const AUTHORIZATION_OPERATIONS: &[(&str, &str)] = &[
    ("post", "/evaluate"),
    ("post", "/batch"),
    ("post", "/simulate"),
    ("get", "/openapi.json"),
];

const SURFACE: &str = "the Authorization API";

/// What the API needs.
#[derive(Clone)]
pub struct AuthorizationApiState {
    /// Checks the caller's access token.
    pub access: ResourceAccessService,
    /// Decides.
    pub evaluation: EvaluationService,
    /// The address people reach this installation at, without a path.
    pub public_url: String,
}

impl std::fmt::Debug for AuthorizationApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationApiState")
            .finish_non_exhaustive()
    }
}

/// The API, to be mounted under a tenant at `/api/v1/authorization`.
pub fn authorization_api_routes(state: AuthorizationApiState) -> Router {
    Router::new()
        .route("/evaluate", post(evaluate))
        .route("/batch", post(batch))
        .route("/simulate", post(simulate))
        .route("/openapi.json", get(openapi))
        .with_state(state)
}

async fn openapi() -> Response {
    let mut response = AUTHORIZATION_OPENAPI.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// One question, as the caller writes it. It never names a tenant or a
/// resource server.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Question {
    subject: SubjectBody,
    #[serde(default)]
    asserted: BTreeMap<String, Value>,
    resource: ResourceBody,
    action: String,
    #[serde(default)]
    context: BTreeMap<String, Value>,
    /// The organization the request is made in, by its identifier.
    #[serde(default)]
    organization: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectBody {
    #[serde(rename = "type")]
    kind: String,
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceBody {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    attributes: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchBody {
    requests: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgainstBody {
    #[serde(default)]
    published: Option<bool>,
    #[serde(default)]
    revision: Option<String>,
    #[serde(default)]
    draft: Option<String>,
}

fn body_invalid() -> Problem {
    Problem::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "request.body_invalid",
        "the body is not JSON of the expected shape",
    )
}

/// What the caller may ask about: the resource server of its client's
/// application, and that application.
struct Asker {
    caller: ResourceCaller,
    namespace: Namespace,
    application: ApplicationReference,
}

impl Asker {
    fn explains(&self) -> bool {
        self.caller.has_scope(EXPLAIN_SCOPE)
    }
}

fn issuer(public_url: &str, slug: &str) -> String {
    format!("{}/t/{slug}", public_url.trim_end_matches('/'))
}

/// The caller of a route that needs `scope`, or the response refusing it.
async fn asker(
    state: &AuthorizationApiState,
    tenant: &TenantContext,
    slug: &str,
    headers: &HeaderMap,
    scope: &str,
) -> Result<Asker, Box<Response>> {
    let Ok(token) = bearer(headers) else {
        return Err(Box::new(refused(
            BearerRefusal::InvalidToken("the Authorization header is not a bearer token"),
            scope,
            SURFACE,
        )));
    };
    let caller = match state
        .access
        .caller(
            tenant,
            &issuer(&state.public_url, slug),
            AUTHORIZATION_API_AUDIENCE,
            token,
        )
        .await
    {
        Ok(Ok(caller)) => caller,
        Ok(Err(refusal)) => return Err(Box::new(refused(refusal, scope, SURFACE))),
        Err(error) => return Err(Box::new(not_cached(Problem::from(error).into_response()))),
    };
    if !caller.has_scope(scope) {
        return Err(Box::new(refused(
            BearerRefusal::InsufficientScope,
            scope,
            SURFACE,
        )));
    }
    let Some(server) = &caller.resource_server else {
        return Err(Box::new(not_cached(
            Problem::new(
                StatusCode::FORBIDDEN,
                "authorization.no_resource_server",
                "the application of the token's client has no resource server to ask about",
            )
            .into_response(),
        )));
    };
    let built = Namespace::parse(server.audience().as_str()).and_then(|namespace| {
        ApplicationReference::parse(&caller.application_id.to_string())
            .map(|application| (namespace, application))
    });
    let (namespace, application) = match built {
        Ok(built) => built,
        Err(error) => return Err(Box::new(not_cached(Problem::from(error).into_response()))),
    };
    Ok(Asker {
        caller,
        namespace,
        application,
    })
}

/// The request of `question`, about the asker's resource server and for
/// its application.
fn request(question: Question, asker: &Asker) -> Result<AuthorizationRequest, DomainError> {
    let kind = SubjectKind::parse(&question.subject.kind)?;
    Ok(AuthorizationRequest {
        namespace: asker.namespace.clone(),
        subject: Subject::new(kind, &question.subject.id)?,
        asserted: Attributes::new(question.asserted)?,
        resource: Resource::new(
            &question.resource.kind,
            question.resource.id.as_deref(),
            Attributes::new(question.resource.attributes)?,
        )?,
        action: Action::parse(&question.action)?,
        context: EvaluationContext {
            attributes: Attributes::new(question.context)?,
            correlation_id: current_request_id(),
            application: Some(asker.application.clone()),
            organization: question
                .organization
                .as_deref()
                .map(OrganizationReference::parse)
                .transpose()?,
        },
    })
}

/// The request a JSON value asks, or the problem with it.
fn read_request(value: Value, asker: &Asker) -> Result<AuthorizationRequest, Box<Problem>> {
    let question: Question = serde_json::from_value(value).map_err(|_| Box::new(body_invalid()))?;
    request(question, asker).map_err(|error| Box::new(Problem::from(error)))
}

const fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "ALLOW",
        Effect::Deny => "DENY",
        Effect::Indeterminate => "INDETERMINATE",
    }
}

/// The answer to the caller. The policies that decided are shown only to a
/// caller that may see explanations; the subject's attributes never are.
fn answer(decision: &AuthorizationDecision, explain: bool) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert("decision".into(), json!(effect_name(decision.effect)));
    body.insert(
        "decision_id".into(),
        json!(decision.decision_id.to_string()),
    );
    body.insert(
        "evaluated_at".into(),
        json!(decision.evaluated_at.format(&Rfc3339).unwrap_or_default()),
    );
    body.insert(
        "engine".into(),
        json!(decision.engine.as_ref().map(|engine| engine.as_str())),
    );
    body.insert(
        "policy_version".into(),
        json!(decision.policy_version.as_ref().map(PolicyRevision::as_str)),
    );
    body.insert("reason".into(), json!(decision.reason.as_str()));
    if explain {
        body.insert(
            "matched_policies".into(),
            json!(
                decision
                    .matched_policies
                    .iter()
                    .map(PolicyReference::as_str)
                    .collect::<Vec<_>>()
            ),
        );
    }
    body
}

fn answered(body: Value) -> Response {
    not_cached(Json(body).into_response())
}

async fn evaluate(
    State(state): State<AuthorizationApiState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let asker = match asker(&state, &tenant, &slug, &headers, EVALUATE_SCOPE).await {
        Ok(asker) => asker,
        Err(response) => return *response,
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return not_cached(body_invalid().into_response());
    };
    let request = match read_request(value, &asker) {
        Ok(request) => request,
        Err(problem) => return not_cached((*problem).into_response()),
    };
    let decision = state.evaluation.evaluate(&tenant, &request).await;
    answered(Value::Object(answer(&decision, asker.explains())))
}

async fn batch(
    State(state): State<AuthorizationApiState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let asker = match asker(&state, &tenant, &slug, &headers, EVALUATE_SCOPE).await {
        Ok(asker) => asker,
        Err(response) => return *response,
    };
    let Ok(body) = serde_json::from_slice::<BatchBody>(&bytes) else {
        return not_cached(body_invalid().into_response());
    };
    if body.requests.len() > MAX_BATCH {
        return not_cached(
            Problem::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "authorization.batch_too_large",
                "a batch holds at most 100 requests",
            )
            .into_response(),
        );
    }
    let read: Vec<Result<AuthorizationRequest, Box<Problem>>> = body
        .requests
        .into_iter()
        .map(|value| read_request(value, &asker))
        .collect();
    let requests: Vec<AuthorizationRequest> = read
        .iter()
        .filter_map(|item| item.as_ref().ok().cloned())
        .collect();
    let decisions = match state.evaluation.evaluate_batch(&tenant, &requests).await {
        Ok(decisions) => decisions,
        Err(error) => return not_cached(Problem::from(error).into_response()),
    };
    let mut decisions = decisions.into_iter();
    let explain = asker.explains();
    let results: Vec<Value> = read
        .into_iter()
        .map(|item| match item {
            Ok(_) => decisions.next().map_or(Value::Null, |decision| {
                Value::Object(answer(&decision, explain))
            }),
            Err(problem) => serde_json::to_value(&problem).unwrap_or(Value::Null),
        })
        .collect();
    answered(json!({ "results": results }))
}

/// The policies a simulation names: exactly one of `published`, `revision`
/// and `draft`.
fn selection(against: AgainstBody) -> Result<PolicySelection, Box<Problem>> {
    match (against.published, against.revision, against.draft) {
        (Some(true), None, None) => Ok(PolicySelection::Published),
        (None, Some(revision), None) => PolicyRevision::parse(&revision)
            .map(PolicySelection::Revision)
            .map_err(|error| Box::new(Problem::from(error))),
        (None, None, Some(draft)) => PolicyReference::parse(&draft)
            .map(PolicySelection::Draft)
            .map_err(|error| Box::new(Problem::from(error))),
        _ => Err(Box::new(Problem::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "authorization.against_invalid",
            "against names exactly one of published (true), a revision or a draft",
        ))),
    }
}

async fn simulate(
    State(state): State<AuthorizationApiState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let asker = match asker(&state, &tenant, &slug, &headers, SIMULATE_SCOPE).await {
        Ok(asker) => asker,
        Err(response) => return *response,
    };
    let Ok(Value::Object(mut fields)) = serde_json::from_slice::<Value>(&bytes) else {
        return not_cached(body_invalid().into_response());
    };
    let Some(against) = fields.remove("against") else {
        return not_cached(body_invalid().into_response());
    };
    let against = match serde_json::from_value::<AgainstBody>(against)
        .map_err(|_| Box::new(body_invalid()))
        .and_then(selection)
    {
        Ok(against) => against,
        Err(problem) => return not_cached((*problem).into_response()),
    };
    let request = match read_request(Value::Object(fields), &asker) {
        Ok(request) => request,
        Err(problem) => return not_cached((*problem).into_response()),
    };
    match state.evaluation.simulate(&tenant, &request, &against).await {
        Ok(simulation) => {
            let explain = asker.explains();
            let mut body = answer(&simulation.decision, explain);
            if explain {
                body.insert("trace".into(), json!(simulation.trace));
            }
            answered(Value::Object(body))
        }
        Err(error) => not_cached(Problem::from(error).into_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_authorization::api::{DecisionId, DecisionMetadata, EngineId, ReasonCode};
    use hodor_kernel::Timestamp;

    fn decision() -> AuthorizationDecision {
        AuthorizationDecision {
            decision_id: DecisionId::generate(),
            effect: Effect::Allow,
            evaluated_at: Timestamp::UNIX_EPOCH,
            engine: Some(EngineId::native()),
            policy_version: None,
            reason: ReasonCode::parse("matching_role").expect("reason"),
            matched_policies: vec![
                PolicyReference::parse("urn:example:payroll#approver").expect("policy"),
            ],
            metadata: DecisionMetadata {
                duration_microseconds: 10,
                cache_hit: false,
                asserted_trusted: false,
            },
        }
    }

    #[test]
    fn the_policies_that_decided_are_shown_only_to_who_may_see_them() {
        let hidden = answer(&decision(), false);
        assert_eq!(hidden["decision"], "ALLOW");
        assert_eq!(hidden["reason"], "matching_role");
        assert_eq!(hidden["engine"], "native");
        assert_eq!(hidden["evaluated_at"], "1970-01-01T00:00:00Z");
        assert!(hidden.get("matched_policies").is_none());
        assert!(hidden.get("metadata").is_none());
        let shown = answer(&decision(), true);
        assert_eq!(
            shown["matched_policies"],
            json!(["urn:example:payroll#approver"])
        );
    }

    #[test]
    fn a_simulation_names_exactly_one_selection() {
        let against = |value: Value| selection(serde_json::from_value(value).expect("shape"));
        assert_eq!(
            against(json!({ "published": true })).expect("published"),
            PolicySelection::Published
        );
        assert!(matches!(
            against(json!({ "revision": "rev-42" })),
            Ok(PolicySelection::Revision(_))
        ));
        assert!(matches!(
            against(json!({ "draft": "invoices" })),
            Ok(PolicySelection::Draft(_))
        ));
        for wrong in [
            json!({}),
            json!({ "published": false }),
            json!({ "published": true, "revision": "rev-42" }),
        ] {
            assert!(against(wrong).is_err());
        }
    }

    #[test]
    fn the_document_names_every_operation_and_no_other() {
        let document: Value = serde_json::from_str(AUTHORIZATION_OPENAPI).expect("document");
        let mut documented: Vec<(String, String)> = document["paths"]
            .as_object()
            .expect("paths")
            .iter()
            .flat_map(|(path, operations)| {
                operations
                    .as_object()
                    .expect("operations")
                    .keys()
                    .map(|method| (method.clone(), path.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        documented.sort();
        let mut served: Vec<(String, String)> = AUTHORIZATION_OPERATIONS
            .iter()
            .map(|(method, path)| ((*method).to_owned(), (*path).to_owned()))
            .collect();
        served.sort();
        assert_eq!(documented, served);
    }
}
