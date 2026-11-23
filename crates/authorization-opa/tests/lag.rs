//! A lagging instance: a decision made with an older revision than the
//! tenant's latest, published longer ago than the allowed lag, is
//! indeterminate. See "A lagging instance" in the authorization context.

use hodor_adapters_crypto::Sha256Digest;
use hodor_authorization::api::{
    Action, Attributes, AuthorizationEngine as _, AuthorizationRequest, Effect, EvaluationContext,
    EvaluationInput, Namespace, Resource, Subject, SubjectKind,
};
use hodor_authorization_opa::api::{
    Author, BundleStore as _, Instances, OpenPolicyAgentEngine, PublishedBundle,
    PublishedRevisions, StoredRevisions, bundle_name,
};
use hodor_authorization_opa::testing::InMemoryBundles;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    DomainError, ErrorKind, HttpClient, HttpRequest, HttpResponse, TenantContext, TenantId,
    Timestamp, UnitOfWorkFactory as _,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Answers every request with the revision it is told to.
struct Answering {
    revision: Mutex<Option<String>>,
    tenant: TenantId,
}

#[async_trait::async_trait]
impl HttpClient for Answering {
    async fn send(&self, _request: HttpRequest) -> Result<HttpResponse, DomainError> {
        let provenance = self
            .revision
            .lock()
            .expect("revision")
            .as_ref()
            .map_or_else(String::new, |revision| {
                format!(
                    r#","provenance":{{"bundles":{{"{}":{{"revision":"{revision}"}}}}}}"#,
                    bundle_name(self.tenant)
                )
            });
        Ok(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: format!(r#"{{"result":{{"allow":true}}{provenance}}}"#).into_bytes(),
        })
    }
}

/// Fails to say anything.
struct Broken;

#[async_trait::async_trait]
impl PublishedRevisions for Broken {
    async fn latest(&self, _tenant: TenantId) -> Result<Option<(u64, Timestamp)>, DomainError> {
        Err(DomainError::new(
            ErrorKind::Unavailable,
            "database.unavailable",
            "no database",
        ))
    }
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

struct World {
    clock: Arc<FixedClock>,
    http: Arc<Answering>,
    bundles: Arc<InMemoryBundles>,
    units: Arc<InMemoryUnitOfWorkFactory>,
    tenant: TenantContext,
}

fn world() -> World {
    let tenant = TenantContext::assume(TenantId::generate());
    World {
        clock: Arc::new(FixedClock::at(
            Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
        )),
        http: Arc::new(Answering {
            revision: Mutex::new(None),
            tenant: tenant.tenant_id(),
        }),
        bundles: Arc::new(InMemoryBundles::default()),
        units: Arc::new(InMemoryUnitOfWorkFactory::default()),
        tenant,
    }
}

impl World {
    fn engine(&self, revisions: Arc<dyn PublishedRevisions>) -> OpenPolicyAgentEngine {
        OpenPolicyAgentEngine::new(
            self.http.clone(),
            Arc::new(Sha256Digest),
            self.clock.clone(),
            Instances::parse(Some("http://localhost:8181"), "").expect("instances"),
        )
        .with_revisions(revisions, time::Duration::minutes(5))
    }

    fn stored(&self) -> Arc<StoredRevisions> {
        Arc::new(StoredRevisions::new(
            self.units.clone(),
            self.bundles.clone(),
            self.clock.clone(),
        ))
    }

    async fn publish(&self, revision: u64) {
        let mut uow = self.units.begin(&self.tenant).await.expect("begin");
        self.bundles
            .append(
                uow.as_mut(),
                &PublishedBundle {
                    revision,
                    author: Author::Tenant,
                    archive: vec![1],
                    digest: [0; 32],
                    published_at: self.clock.now(),
                },
            )
            .await
            .expect("append");
        uow.commit().await.expect("commit");
    }

    fn answers_with(&self, revision: Option<&str>) {
        *self.http.revision.lock().expect("revision") = revision.map(str::to_owned);
    }
}

use hodor_kernel::Clock as _;

#[tokio::test]
async fn an_older_revision_is_answered_within_the_lag_and_refused_after_it() {
    let world = world();
    let engine = world.engine(world.stored());
    world.publish(1).await;
    world.answers_with(Some("1"));
    let answer = engine
        .evaluate(&world.tenant, &input())
        .await
        .expect("answer");
    assert_eq!(answer.effect, Effect::Allow, "the latest revision answers");

    // Revision 2 is published; the instance still runs 1.
    world.clock.advance(time::Duration::minutes(1));
    world.publish(2).await;
    world.clock.advance(time::Duration::seconds(11));
    let within = engine
        .evaluate(&world.tenant, &input())
        .await
        .expect("answer");
    assert_eq!(within.effect, Effect::Allow, "within the lag, 1 stands");

    world.clock.advance(time::Duration::minutes(5));
    let after = engine
        .evaluate(&world.tenant, &input())
        .await
        .expect("answer");
    assert_eq!(after.effect, Effect::Indeterminate);
    assert_eq!(after.reason.as_str(), "policy_revision_stale");

    // Once the instance runs 2, or a later one, it answers again.
    world.answers_with(Some("2"));
    let current = engine
        .evaluate(&world.tenant, &input())
        .await
        .expect("answer");
    assert_eq!(current.effect, Effect::Allow);
    world.answers_with(Some("3"));
    assert_eq!(
        engine
            .evaluate(&world.tenant, &input())
            .await
            .expect("answer")
            .effect,
        Effect::Allow
    );
}

#[tokio::test]
async fn a_decision_without_a_revision_is_refused_once_the_tenant_published_long_enough_ago() {
    let world = world();
    let engine = world.engine(world.stored());
    world.answers_with(None);
    // Nothing published: nothing to lag behind.
    assert_eq!(
        engine
            .evaluate(&world.tenant, &input())
            .await
            .expect("answer")
            .effect,
        Effect::Allow
    );
    world.publish(1).await;
    world.clock.advance(time::Duration::minutes(6));
    let answer = engine
        .evaluate(&world.tenant, &input())
        .await
        .expect("answer");
    assert_eq!(answer.effect, Effect::Indeterminate);
    assert_eq!(answer.reason.as_str(), "policy_revision_stale");
    // A revision that is not a number is no revision.
    world.answers_with(Some("main"));
    assert_eq!(
        engine
            .evaluate(&world.tenant, &input())
            .await
            .expect("answer")
            .reason
            .as_str(),
        "policy_revision_stale"
    );
}

#[tokio::test]
async fn the_latest_revision_is_kept_for_ten_seconds() {
    let world = world();
    let revisions = world.stored();
    assert_eq!(
        revisions
            .latest(world.tenant.tenant_id())
            .await
            .expect("latest"),
        None
    );
    world.publish(1).await;
    assert_eq!(
        revisions
            .latest(world.tenant.tenant_id())
            .await
            .expect("latest"),
        None,
        "still what was read"
    );
    world.clock.advance(time::Duration::seconds(11));
    assert_eq!(
        revisions
            .latest(world.tenant.tenant_id())
            .await
            .expect("latest")
            .map(|(revision, _)| revision),
        Some(1)
    );
    // Another tenant's revision is its own.
    assert_eq!(
        revisions
            .latest(TenantId::generate())
            .await
            .expect("latest"),
        None
    );
}

#[tokio::test]
async fn when_the_latest_revision_cannot_be_read_the_answer_is_indeterminate() {
    let world = world();
    let engine = world.engine(Arc::new(Broken));
    world.answers_with(Some("1"));
    let answer = engine
        .evaluate(&world.tenant, &input())
        .await
        .expect("answer");
    assert_eq!(answer.effect, Effect::Indeterminate);
    assert_eq!(answer.reason.as_str(), "policy_revision_unknown");
}
