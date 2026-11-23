//! The server binary refusing Open Policy Agent settings that are wrong,
//! at startup rather than at the first decision.

use hodor_adapters_postgres::testing::TestDatabase;
use std::process::{Command, Stdio};

fn start_with(database: &TestDatabase, settings: &[(&str, &str)]) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hodor-server"));
    command
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_LISTEN_ADDR", "127.0.0.1:0")
        .env("HODOR_OPS_ADDR", "127.0.0.1:0")
        .stdin(Stdio::null());
    for (name, value) in settings {
        command.env(name, value);
    }
    let output = command.output().expect("the server should run");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), said)
}

#[tokio::test]
async fn an_address_that_is_not_an_origin_stops_the_server() {
    let database = TestDatabase::start().await;
    let (started, said) = start_with(
        &database,
        &[(
            "HODOR_OPEN_POLICY_AGENT_ADDRESS",
            "http://localhost:8181/v1/data/anything",
        )],
    );
    assert!(!started, "the server must not start");
    assert!(said.contains("http.origin_invalid"), "{said}");
}

#[tokio::test]
async fn an_instance_of_its_own_must_name_a_tenant() {
    let database = TestDatabase::start().await;
    let (started, said) = start_with(
        &database,
        &[(
            "HODOR_OPEN_POLICY_AGENT_TENANT_ADDRESSES",
            "acme=http://policy-acme:8181",
        )],
    );
    assert!(!started, "the server must not start");
    assert!(
        said.contains("authorization.open_policy_agent_instances_invalid"),
        "{said}"
    );
}
