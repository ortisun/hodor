//! `OpenPolicyAgentEngine`: one request, one question to one instance.

use crate::answer::{
    ERROR, NOT_CONFIGURED, TIMED_OUT, UNAVAILABLE, UNREACHABLE, indeterminate, read, revision,
};
use crate::breaker::{Admission, Breaker, BreakerSettings};
use crate::bundle::bundle_name;
use crate::instances::Instances;
use crate::path::decision_path;
use hodor_authorization::api::{
    Attributes, AuthorizationEngine, EngineAnswer, EngineCapabilities, EngineId, EvaluationInput,
};
use hodor_kernel::{Clock, Digest, DomainError, HttpClient, HttpRequest, Secret, TenantContext};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

/// The engine's name, as a binding names it.
pub const ENGINE: &str = "open_policy_agent";

/// How a request to an instance ended, for its circuit.
enum Exchange {
    /// The instance answered 200; its body says what was decided.
    Answered(EngineAnswer),
    /// The instance failed, with the reason the decision carries.
    Failed(&'static str),
}

/// Asks Open Policy Agent. See the crate's documentation.
pub struct OpenPolicyAgentEngine {
    http: Arc<dyn HttpClient>,
    digest: Arc<dyn Digest>,
    clock: Arc<dyn Clock>,
    instances: Instances,
    token: Option<Secret<String>>,
    settings: BreakerSettings,
    breakers: Mutex<BTreeMap<String, Breaker>>,
}

impl std::fmt::Debug for OpenPolicyAgentEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenPolicyAgentEngine")
            .field("instances", &self.instances)
            .field("token", &self.token.as_ref().map(|_| "set"))
            .finish_non_exhaustive()
    }
}

impl OpenPolicyAgentEngine {
    /// An engine that asks `instances` through `http`, which must call
    /// those addresses and nothing else.
    #[must_use]
    pub fn new(
        http: Arc<dyn HttpClient>,
        digest: Arc<dyn Digest>,
        clock: Arc<dyn Clock>,
        instances: Instances,
    ) -> Self {
        Self {
            http,
            digest,
            clock,
            instances,
            token: None,
            settings: BreakerSettings::default(),
            breakers: Mutex::new(BTreeMap::new()),
        }
    }

    /// Presents `token` as a bearer token to every instance.
    #[must_use]
    pub fn with_token(mut self, token: Secret<String>) -> Self {
        self.token = Some(token);
        self
    }

    /// Opens circuits by other rules than the defaults.
    #[must_use]
    pub const fn with_breaker(mut self, settings: BreakerSettings) -> Self {
        self.settings = settings;
        self
    }

    fn admit(&self, instance: &str) -> Admission {
        let now = self.clock.now();
        let mut breakers = self.breakers.lock().unwrap_or_else(PoisonError::into_inner);
        breakers
            .entry(instance.to_owned())
            .or_insert_with(|| Breaker::new(self.settings))
            .admit(now)
    }

    fn record(&self, instance: &str, failed: bool) {
        let now = self.clock.now();
        let mut breakers = self.breakers.lock().unwrap_or_else(PoisonError::into_inner);
        breakers
            .entry(instance.to_owned())
            .or_insert_with(|| Breaker::new(self.settings))
            .record(now, failed);
    }

    /// One request to the instance, with one retry when the first could
    /// not connect and time is left.
    async fn exchange(
        &self,
        url: &str,
        body: &[u8],
        input: &EvaluationInput,
        bundle: &str,
    ) -> Exchange {
        let Ok(budget) = time::Duration::try_from(input.time_limit) else {
            return Exchange::Failed(TIMED_OUT);
        };
        let deadline = self.clock.now() + budget;
        for attempt in 0..2 {
            let left = deadline - self.clock.now();
            let Ok(left) = std::time::Duration::try_from(left) else {
                return Exchange::Failed(TIMED_OUT);
            };
            if left.is_zero() {
                return Exchange::Failed(TIMED_OUT);
            }
            let mut request = HttpRequest::post(url, "application/json", body.to_vec())
                .header("accept", "application/json")
                .within(left);
            if let Some(token) = &self.token {
                request = request.header("authorization", format!("Bearer {}", token.expose()));
            }
            match self.http.send(request).await {
                Ok(response) if response.status == 200 => {
                    let mut answer = read(&response.body);
                    answer.policy_version = revision(&response.body, bundle);
                    return Exchange::Answered(answer);
                }
                Ok(_) => return Exchange::Failed(ERROR),
                Err(error) if error.code() == "http.timed_out" => {
                    return Exchange::Failed(TIMED_OUT);
                }
                // Only a connection that was not made is tried again.
                Err(error) if error.code() == "http.unreachable" && attempt == 0 => {}
                Err(_) => return Exchange::Failed(UNREACHABLE),
            }
        }
        Exchange::Failed(UNREACHABLE)
    }
}

fn attributes(set: &Attributes) -> Value {
    Value::Object(
        set.iter()
            .map(|(name, value)| (name.to_owned(), value.clone()))
            .collect::<Map<String, Value>>(),
    )
}

/// The input document: the request as the engine was given it. Nothing in
/// it decides where it is sent.
fn input_document(input: &EvaluationInput) -> Value {
    let request = &input.request;
    json!({
        "input": {
            "namespace": request.namespace.as_str(),
            "subject": {
                "kind": request.subject.kind().as_str(),
                "id": request.subject.id(),
                "attributes": attributes(&input.subject_attributes),
            },
            "asserted": attributes(&request.asserted),
            "resource": {
                "kind": request.resource.kind(),
                "id": request.resource.id(),
                "attributes": attributes(request.resource.attributes()),
            },
            "action": request.action.as_str(),
            "context": attributes(&request.context.attributes),
        }
    })
}

#[async_trait::async_trait]
impl AuthorizationEngine for OpenPolicyAgentEngine {
    fn id(&self) -> EngineId {
        EngineId::parse(ENGINE).expect("the engine's name is a name")
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities::default()
    }

    async fn evaluate(
        &self,
        tenant: &TenantContext,
        input: &EvaluationInput,
    ) -> Result<EngineAnswer, DomainError> {
        let Some(instance) = self.instances.for_tenant(tenant) else {
            return Ok(indeterminate(NOT_CONFIGURED));
        };
        let instance = instance.to_owned();
        // With provenance, the answer names the revision of each bundle.
        let url = format!(
            "{instance}{}?provenance=true",
            decision_path(tenant, &input.request.namespace, self.digest.as_ref())
        );
        let body = serde_json::to_vec(&input_document(input)).map_err(|error| {
            DomainError::internal(
                "authorization.open_policy_agent_input",
                "the input could not be written",
            )
            .with_detail(error.to_string())
        })?;
        if self.admit(&instance) == Admission::Refused {
            return Ok(indeterminate(UNAVAILABLE));
        }
        match self
            .exchange(&url, &body, input, &bundle_name(tenant.tenant_id()))
            .await
        {
            Exchange::Answered(answer) => {
                // An undefined or malformed answer is the policy's fault,
                // not the instance's: the instance answered.
                self.record(&instance, false);
                Ok(answer)
            }
            Exchange::Failed(reason) => {
                self.record(&instance, true);
                Ok(indeterminate(reason))
            }
        }
    }
}
