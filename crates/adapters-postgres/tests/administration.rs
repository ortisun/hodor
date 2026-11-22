//! The stores behind the administration interface, on PostgreSQL.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgAccessTokenStore, PgEngineBindingStore, PgNativeRoleStore, PgRoleAssignmentStore,
    PgWebAuthnStore,
};
use hodor_authorization::api::{
    Action, AssignmentScope, Attributes, AuthorizationEngine, AuthorizationRequest,
    AuthorizationService, Effect, EvaluationContext, EvaluationInput, Namespace, NativeEngine,
    PermissionName, Resource, Role, RoleContents, RoleKey, RoleName, RoleService, Subject,
    SubjectKind, Validity,
};
use hodor_authorization::testing::{
    BindingPorts, NativeRolePorts, Ports, run_binding_contract, run_contract,
    run_native_role_contract,
};
use hodor_credential::testing::{
    AccessTokenPorts, WebAuthnPorts, run_access_token_contract, run_webauthn_contract,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp, UserId};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn the_postgres_role_assignment_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_contract(Ports {
        units_of_work: database.app(),
        assignments: &PgRoleAssignmentStore,
    })
    .await;
}

#[tokio::test]
async fn the_postgres_binding_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_binding_contract(BindingPorts {
        units_of_work: database.app(),
        bindings: &PgEngineBindingStore,
    })
    .await;
}

#[tokio::test]
async fn the_database_refuses_a_binding_that_breaks_its_rules() {
    let database = TestDatabase::start().await;
    let insert = |namespace: &'static str,
                  timeout: i32,
                  sensitive: bool,
                  actions: &'static [&'static str]| {
        let owner = database.owner().clone();
        async move {
            sqlx::query(
                "INSERT INTO \"authorization\".engine_binding (tenant_id, namespace, engine,
                     timeout_milliseconds, sensitive, fail_open_actions, trust_asserted,
                     created_at, updated_at)
                 VALUES (gen_random_uuid(), $1, 'native', $2, $3, $4, false, now(), now())",
            )
            .bind(namespace)
            .bind(timeout)
            .bind(sensitive)
            .bind(actions)
            .execute(&owner)
            .await
        }
    };
    assert!(
        insert("https://documents.example.com", 200, false, &["read"])
            .await
            .is_ok()
    );
    for refused in [
        insert("hodor:admin", 200, true, &[]).await,
        insert("documents", 200, false, &[]).await,
        insert("https://documents.example.com", 0, false, &[]).await,
        insert("https://documents.example.com", 5001, false, &[]).await,
        insert("https://documents.example.com", 200, true, &["read"]).await,
    ] {
        assert!(refused.is_err());
    }
}

#[tokio::test]
async fn the_postgres_access_token_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_access_token_contract(AccessTokenPorts {
        units_of_work: database.app(),
        tokens: &PgAccessTokenStore,
    })
    .await;
}

#[tokio::test]
async fn the_postgres_webauthn_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_webauthn_contract(WebAuthnPorts {
        units_of_work: database.app(),
        store: &PgWebAuthnStore,
    })
    .await;
}

#[tokio::test]
async fn the_database_refuses_a_built_in_assignment_that_breaks_its_rules() {
    let database = TestDatabase::start().await;
    let insert =
        |kind: &'static str, role: &'static str, application: &'static str, until: bool| {
            let owner = database.owner().clone();
            async move {
                sqlx::query(
                    "INSERT INTO \"authorization\".role_assignment (tenant_id, principal_kind,
                     principal_id, namespace, role, application, valid_until, assigned_at)
                 VALUES (gen_random_uuid(), $1, 'someone', 'hodor:admin', $2, $3,
                     CASE WHEN $4 THEN now() + interval '1 day' END, now())",
                )
                .bind(kind)
                .bind(role)
                .bind(application)
                .bind(until)
                .execute(&owner)
                .await
            }
        };
    assert!(insert("user", "tenant_auditor", "", false).await.is_ok());
    for refused in [
        insert("user", "owner", "", false).await,
        insert("client", "tenant_auditor", "", false).await,
        insert("user", "tenant_auditor", "portal", false).await,
        insert("user", "tenant_auditor", "", true).await,
        insert("group", "tenant_auditor", "", false).await,
    ] {
        assert!(refused.is_err());
    }
}

#[tokio::test]
async fn the_postgres_native_role_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_native_role_contract(NativeRolePorts {
        units_of_work: database.app(),
        roles: &PgNativeRoleStore,
    })
    .await;
}

#[tokio::test]
async fn the_database_refuses_native_roles_that_break_its_rules() {
    let database = TestDatabase::start().await;
    let owner = database.owner();
    let tenant = uuid_of(owner).await;
    let run = |statement: &'static str| async move {
        sqlx::query(statement).bind(tenant).execute(owner).await
    };
    for refused in [
        run(
            "INSERT INTO \"authorization\".permission (tenant_id, namespace, name, description,
                 created_at) VALUES ($1, 'hodor:admin', 'users:read', '', now())",
        )
        .await,
        run(
            "INSERT INTO \"authorization\".permission (tenant_id, namespace, name, description,
                 created_at) VALUES ($1, 'urn:example:documents', 'read', '', now())",
        )
        .await,
        run(
            "INSERT INTO \"authorization\".role (tenant_id, namespace, name, description,
                 created_at, updated_at) VALUES ($1, 'hodor:admin', 'owner', '', now(), now())",
        )
        .await,
        run(
            "INSERT INTO \"authorization\".role (tenant_id, namespace, name, description,
                 created_at, updated_at)
             VALUES ($1, 'urn:example:documents', 'Viewer', '', now(), now())",
        )
        .await,
        // An assignment of a role that does not exist.
        run(
            "INSERT INTO \"authorization\".role_assignment (tenant_id, principal_kind,
                 principal_id, namespace, role, application, assigned_at)
             VALUES ($1, 'user', 'ana', 'urn:example:documents', 'viewer', '', now())",
        )
        .await,
    ] {
        assert!(refused.is_err());
    }
    run("INSERT INTO \"authorization\".role (tenant_id, namespace, name, description,
             created_at, updated_at) VALUES ($1, 'urn:example:documents', 'viewer', '', now(), now())")
    .await
    .expect("role");
    for refused in [
        // Including itself.
        run(
            "INSERT INTO \"authorization\".role_inclusion (tenant_id, namespace, role,
                 included_namespace, included_role)
             VALUES ($1, 'urn:example:documents', 'viewer', 'urn:example:documents', 'viewer')",
        )
        .await,
        // An end before the start.
        run(
            "INSERT INTO \"authorization\".role_assignment (tenant_id, principal_kind,
                 principal_id, namespace, role, application, valid_from, valid_until, assigned_at)
             VALUES ($1, 'user', 'ana', 'urn:example:documents', 'viewer', '', now(),
                 now() - interval '1 hour', now())",
        )
        .await,
    ] {
        assert!(refused.is_err());
    }
}

async fn uuid_of(owner: &sqlx::PgPool) -> sqlx::types::Uuid {
    sqlx::query_scalar("SELECT gen_random_uuid()")
        .fetch_one(owner)
        .await
        .expect("uuid")
}

fn documents() -> Namespace {
    Namespace::parse("urn:example:documents").expect("namespace")
}

fn role_key(name: &str) -> RoleKey {
    RoleKey::new(documents(), RoleName::parse(name).expect("name"))
}

fn read_by(subject: &Subject) -> EvaluationInput {
    EvaluationInput {
        request: AuthorizationRequest {
            namespace: documents(),
            subject: subject.clone(),
            asserted: Attributes::none(),
            resource: Resource::new("document", None, Attributes::none()).expect("resource"),
            action: Action::parse("read").expect("action"),
            context: EvaluationContext::default(),
        },
        subject_attributes: Attributes::none(),
        time_limit: Duration::from_millis(200),
    }
}

#[tokio::test]
async fn a_change_on_one_instance_takes_effect_on_another_at_the_next_decision() {
    let database = TestDatabase::start().await;
    let units = Arc::new(database.app().clone());
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::days(20_000),
    ));
    let tenant = TenantContext::assume(TenantId::generate());
    let roles = RoleService::new(units.clone(), Arc::new(PgNativeRoleStore), clock.clone());
    // Two engines that keep what they read apart, as two servers would.
    let first = NativeEngine::new(
        units.clone(),
        Arc::new(PgRoleAssignmentStore),
        Arc::new(PgNativeRoleStore),
        clock.clone(),
    );
    let second = NativeEngine::new(
        units.clone(),
        Arc::new(PgRoleAssignmentStore),
        Arc::new(PgNativeRoleStore),
        clock.clone(),
    );
    roles
        .declare_permission(
            &tenant,
            documents(),
            PermissionName::parse("document:read").expect("permission"),
            "see documents",
            Caller::system(),
        )
        .await
        .expect("declare");
    roles
        .define_role(
            &tenant,
            role_key("viewer"),
            RoleContents {
                description: String::new(),
                permissions: [PermissionName::parse("document:read").expect("permission")].into(),
                includes: std::collections::BTreeSet::new(),
            },
            Caller::system(),
        )
        .await
        .expect("define");
    roles
        .define_role(
            &tenant,
            role_key("editor"),
            RoleContents {
                description: String::new(),
                permissions: std::collections::BTreeSet::new(),
                includes: [role_key("viewer")].into(),
            },
            Caller::system(),
        )
        .await
        .expect("define");
    let ana = Subject::new(SubjectKind::User, "ana").expect("user");
    roles
        .assign(
            &tenant,
            ana.clone(),
            role_key("editor"),
            AssignmentScope::Tenant,
            Validity::default(),
            Caller::system(),
        )
        .await
        .expect("assign");
    for engine in [&first, &second] {
        let answer = engine
            .evaluate(&tenant, &read_by(&ana))
            .await
            .expect("answer");
        assert_eq!(answer.effect, Effect::Allow);
    }
    roles
        .revoke(
            &tenant,
            &ana,
            &role_key("editor"),
            &AssignmentScope::Tenant,
            Caller::system(),
        )
        .await
        .expect("revoke");
    for engine in [&first, &second] {
        let answer = engine
            .evaluate(&tenant, &read_by(&ana))
            .await
            .expect("answer");
        assert_eq!(answer.effect, Effect::Deny);
    }
    // A role another role includes stays; a cycle is refused by the context.
    let in_use = roles
        .remove_role(&tenant, &role_key("viewer"), Caller::system())
        .await;
    assert_eq!(
        in_use.map_err(|e| e.code().to_owned()),
        Err("authorization.role_in_use".to_owned())
    );
    let cycle = roles
        .define_role(
            &tenant,
            role_key("viewer"),
            RoleContents {
                description: String::new(),
                permissions: std::collections::BTreeSet::new(),
                includes: [role_key("editor")].into(),
            },
            Caller::system(),
        )
        .await;
    assert_eq!(
        cycle.map(|_| ()).map_err(|e| e.code().to_owned()),
        Err("authorization.role_cycle".to_owned())
    );
}

#[tokio::test]
async fn the_built_in_roles_answer_from_the_same_table() {
    let database = TestDatabase::start().await;
    let units = Arc::new(database.app().clone());
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let tenant = TenantContext::assume(TenantId::generate());
    let administration = AuthorizationService::new(
        units.clone(),
        Arc::new(PgRoleAssignmentStore),
        clock.clone(),
    );
    let engine = NativeEngine::new(
        units,
        Arc::new(PgRoleAssignmentStore),
        Arc::new(PgNativeRoleStore),
        clock,
    );
    let person = UserId::generate();
    administration
        .assign(&tenant, person, Role::TenantAuditor, Caller::system())
        .await
        .expect("assign");
    let ask = |action: &str| EvaluationInput {
        request: AuthorizationRequest {
            namespace: Namespace::administration(),
            subject: Subject::user(person),
            asserted: Attributes::none(),
            resource: Resource::new("users", None, Attributes::none()).expect("resource"),
            action: Action::parse(action).expect("action"),
            context: EvaluationContext::default(),
        },
        subject_attributes: Attributes::none(),
        time_limit: Duration::from_millis(200),
    };
    let read = engine
        .evaluate(&tenant, &ask("read"))
        .await
        .expect("answer");
    assert_eq!(read.effect, Effect::Allow);
    assert_eq!(read.reason.as_str(), "tenant_auditor");
    let write = engine
        .evaluate(&tenant, &ask("write"))
        .await
        .expect("answer");
    assert_eq!(write.effect, Effect::Deny);
    // Not seen as a tenant's own assignment.
    let roles = RoleService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgNativeRoleStore),
        Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
    );
    assert!(
        roles
            .assignments_of(&tenant, &Subject::user(person))
            .await
            .expect("assignments")
            .is_empty()
    );
}
