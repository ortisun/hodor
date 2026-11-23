//! The commands of the record of decisions, run as the real binary
//! against a real database.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgDecisionLogStore, PgTenantDirectory};
use hodor_authorization::api::{DecisionLogStore as _, Effect};
use hodor_authorization::testing::sample_decision_record;
use hodor_kernel::{TenantContext, UnitOfWorkFactory};
use hodor_tenant::api::TenantDirectory as _;
use std::process::{Command, Output};

fn run(database: &TestDatabase, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .output()
        .expect("the command-line tool should run")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

#[tokio::test]
async fn an_operator_sets_what_is_recorded_and_reads_the_record() {
    let database = TestDatabase::start().await;
    let created = run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    );
    assert!(created.status.success(), "{created:?}");

    let defaults = run(
        &database,
        &["authorization", "decision-log", "show", "--tenant", "acme"],
    );
    assert!(defaults.status.success(), "{defaults:?}");
    assert_eq!(text(&defaults.stdout), "mode full\nretention_days 30");

    let set = run(
        &database,
        &[
            "authorization",
            "decision-log",
            "set",
            "--tenant",
            "acme",
            "--mode",
            "sampled",
            "--allow-sample-percent",
            "20",
            "--mask",
            "subject.attributes.email",
            "--retention-days",
            "60",
        ],
    );
    assert!(set.status.success(), "{set:?}");
    assert_eq!(
        text(&set.stdout),
        "mode sampled\nallow_sample_percent 20\nmask subject.attributes.email\nretention_days 60"
    );
    let refused = run(
        &database,
        &[
            "authorization",
            "decision-log",
            "set",
            "--tenant",
            "acme",
            "--mode",
            "full",
            "--mask",
            "subject.id",
        ],
    );
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("authorization.decision_log_invalid"),
        "{refused:?}"
    );

    let tenant = PgTenantDirectory::new(database.app().clone())
        .find_by_slug("acme")
        .await
        .expect("directory")
        .expect("acme");
    let context = TenantContext::assume(tenant.tenant_id);
    let older = sample_decision_record(1, Effect::Allow, "ana");
    let newer = sample_decision_record(2, Effect::Deny, "bea");
    let mut uow = UnitOfWorkFactory::begin(database.app(), &context)
        .await
        .expect("begin");
    PgDecisionLogStore
        .append(uow.as_mut(), &[older.clone(), newer.clone()])
        .await
        .expect("append");
    uow.commit().await.expect("commit");

    let listed = run(
        &database,
        &[
            "authorization",
            "decisions",
            "--tenant",
            "acme",
            "--limit",
            "1",
        ],
    );
    assert!(listed.status.success(), "{listed:?}");
    let said = text(&listed.stdout);
    let lines: Vec<&str> = said.lines().collect();
    assert_eq!(lines.len(), 2, "{said}");
    assert!(lines[0].contains(&newer.decision_id.to_string()), "{said}");
    assert!(
        lines[0].contains(" deny by_script user:bea read document/42 "),
        "{said}"
    );
    let cursor = lines[1].strip_prefix("next ").expect("a cursor");
    let rest = run(
        &database,
        &[
            "authorization",
            "decisions",
            "--tenant",
            "acme",
            "--cursor",
            cursor,
        ],
    );
    assert!(text(&rest.stdout).contains(&older.decision_id.to_string()));

    let only_ana = run(
        &database,
        &[
            "authorization",
            "decisions",
            "--tenant",
            "acme",
            "--subject",
            "user:ana",
            "--effect",
            "allow",
        ],
    );
    let said = text(&only_ana.stdout);
    assert_eq!(said.lines().count(), 1, "{said}");
    assert!(said.contains(&older.decision_id.to_string()));
}
