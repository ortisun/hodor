//! The access control lists of the authorization context, on PostgreSQL:
//! the contract, the rules the database keeps, and the native engine of
//! two instances reading the same entries.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgAccessListStore, PgNativeRoleStore, PgRoleAssignmentStore};
use hodor_authorization::api::{
    AccessListService, Action, Attributes, AuthorizationEngine, AuthorizationRequest, Effect,
    EvaluationContext, EvaluationInput, MATCHING_ENTRY, Namespace, NativeEngine, PermissionName,
    Resource, RoleService, Subject, SubjectKind,
};
use hodor_authorization::testing::{AccessListPorts, run_access_list_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp};
use std::sync::Arc;
use std::time::Duration;

const DOCUMENTS: &str = "urn:example:documents";

#[tokio::test]
async fn the_postgres_access_list_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_access_list_contract(AccessListPorts {
        units_of_work: database.app(),
        roles: &PgNativeRoleStore,
        entries: &PgAccessListStore,
    })
    .await;
}

#[tokio::test]
async fn the_database_refuses_entries_that_break_its_rules() {
    let database = TestDatabase::start().await;
    let owner = database.owner();
    let tenant: sqlx::types::Uuid = sqlx::query_scalar("SELECT gen_random_uuid()")
        .fetch_one(owner)
        .await
        .expect("uuid");
    let run = |statement: &'static str| async move {
        sqlx::query(statement).bind(tenant).execute(owner).await
    };
    run(
        "INSERT INTO \"authorization\".permission (tenant_id, namespace, name, description,
             created_at) VALUES ($1, 'urn:example:documents', 'document:read', '', now())",
    )
    .await
    .expect("permission");
    let good = run(
        "INSERT INTO \"authorization\".access_entry (tenant_id, id, namespace, permission,
             resource_id, principal_kind, principal_id, granted_at)
         VALUES ($1, gen_random_uuid(), 'urn:example:documents', 'document:read', 'd-42',
             'group', 'finance', now())",
    )
    .await;
    assert!(good.is_ok(), "{good:?}");
    let kind: String = sqlx::query_scalar(
        "SELECT resource_kind FROM \"authorization\".access_entry WHERE tenant_id = $1",
    )
    .bind(tenant)
    .fetch_one(owner)
    .await
    .expect("kind");
    assert_eq!(kind, "document");
    for (refused, why) in [
        (
            run(
                "INSERT INTO \"authorization\".access_entry (tenant_id, id, namespace, permission,
                     resource_id, principal_kind, principal_id, granted_at)
                 VALUES ($1, gen_random_uuid(), 'urn:example:documents', 'document:read', 'd-42',
                     'group', 'finance', now())",
            )
            .await,
            "the same grant twice",
        ),
        (
            run(
                "INSERT INTO \"authorization\".access_entry (tenant_id, id, namespace, permission,
                     resource_id, principal_kind, principal_id, granted_at)
                 VALUES ($1, gen_random_uuid(), 'urn:example:documents', 'document:write', 'd-42',
                     'group', 'finance', now())",
            )
            .await,
            "a permission that is not declared",
        ),
        (
            run(
                "INSERT INTO \"authorization\".access_entry (tenant_id, id, namespace, permission,
                     resource_id, principal_kind, principal_id, granted_at)
                 VALUES ($1, gen_random_uuid(), 'urn:example:documents', 'document:read', '',
                     'group', 'finance', now())",
            )
            .await,
            "an empty resource",
        ),
        (
            run(
                "INSERT INTO \"authorization\".access_entry (tenant_id, id, namespace, permission,
                     resource_id, principal_kind, principal_id, granted_at)
                 VALUES ($1, gen_random_uuid(), 'urn:example:documents', 'document:read', 'd-42',
                     'organization', 'acme', now())",
            )
            .await,
            "a principal of another kind",
        ),
        (
            run(
                "INSERT INTO \"authorization\".access_entry (tenant_id, id, namespace, permission,
                     resource_id, principal_kind, principal_id, granted_at)
                 VALUES ($1, gen_random_uuid(), 'hodor:admin', 'users:read', 'd-42',
                     'user', 'ana', now())",
            )
            .await,
            "Hodor's administration",
        ),
    ] {
        assert!(refused.is_err(), "{why}");
    }
    // An entry goes with its permission.
    run("DELETE FROM \"authorization\".permission
         WHERE tenant_id = $1 AND name = 'document:read'")
    .await
    .expect("remove permission");
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM \"authorization\".access_entry WHERE tenant_id = $1",
    )
    .bind(tenant)
    .fetch_one(owner)
    .await
    .expect("count");
    assert_eq!(left, 0);
}

fn reading(subject: &Subject, resource: &str) -> EvaluationInput {
    let attributes = Attributes::new([("groups".to_owned(), serde_json::json!(["finance"]))])
        .expect("attributes");
    EvaluationInput {
        request: AuthorizationRequest {
            namespace: Namespace::parse(DOCUMENTS).expect("namespace"),
            subject: subject.clone(),
            asserted: Attributes::none(),
            resource: Resource::new("document", Some(resource), Attributes::none())
                .expect("resource"),
            action: Action::parse("read").expect("action"),
            context: EvaluationContext::default(),
        },
        subject_attributes: attributes,
        time_limit: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn an_entry_granted_on_one_instance_decides_on_another_and_stops_when_removed() {
    let database = TestDatabase::start().await;
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
    ));
    let tenant = TenantContext::assume(TenantId::generate());
    let engine = || {
        NativeEngine::new(
            units(),
            Arc::new(PgRoleAssignmentStore),
            Arc::new(PgNativeRoleStore),
            clock.clone(),
        )
        .with_access_lists(Arc::new(PgAccessListStore))
    };
    let (first, second) = (engine(), engine());
    RoleService::new(units(), Arc::new(PgNativeRoleStore), clock.clone())
        .declare_permission(
            &tenant,
            Namespace::parse(DOCUMENTS).expect("namespace"),
            PermissionName::parse("document:read").expect("permission"),
            "",
            Caller::system(),
        )
        .await
        .expect("declare");
    let lists = AccessListService::new(
        units(),
        Arc::new(PgAccessListStore),
        Arc::new(PgNativeRoleStore),
        clock.clone(),
    );
    let ana =
        Subject::new(SubjectKind::User, "0193f2c0-0000-7000-8000-00000000000a").expect("user");
    // Nothing before.
    let before = second
        .evaluate(&tenant, &reading(&ana, "d-42"))
        .await
        .expect("answer");
    assert_eq!(before.effect, Effect::Deny);

    let granted = lists
        .grant(
            &tenant,
            Namespace::parse(DOCUMENTS).expect("namespace"),
            PermissionName::parse("document:read").expect("permission"),
            "d-42",
            Subject::new(SubjectKind::Group, "finance").expect("group"),
            Caller::system(),
        )
        .await
        .expect("grant");
    for engine in [&first, &second] {
        let answer = engine
            .evaluate(&tenant, &reading(&ana, "d-42"))
            .await
            .expect("answer");
        assert_eq!(answer.effect, Effect::Allow);
        assert_eq!(answer.reason.as_str(), MATCHING_ENTRY);
        let other = engine
            .evaluate(&tenant, &reading(&ana, "d-43"))
            .await
            .expect("answer");
        assert_eq!(other.effect, Effect::Deny, "only on its resource");
    }
    let elsewhere = TenantContext::assume(TenantId::generate());
    let theirs = first
        .evaluate(&elsewhere, &reading(&ana, "d-42"))
        .await
        .expect("answer");
    assert_eq!(theirs.effect, Effect::Deny, "never read in another tenant");

    assert!(
        lists
            .remove(&tenant, granted.entry.id(), Caller::system())
            .await
            .expect("remove")
    );
    let after = second
        .evaluate(&tenant, &reading(&ana, "d-42"))
        .await
        .expect("answer");
    assert_eq!(after.effect, Effect::Deny);
}
