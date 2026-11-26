//! The commands for a person's standard claims, run as the real binary
//! against a real database.

use hodor_adapters_postgres::testing::TestDatabase;
use std::process::{Command, Output};

fn run(database: &TestDatabase, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .output()
        .expect("the command-line tool should run")
}

fn said(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn refused(output: &Output) -> String {
    assert!(!output.status.success(), "it should be refused");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[tokio::test]
async fn an_operator_gives_and_removes_a_persons_standard_claims() {
    let database = TestDatabase::start().await;
    said(&run(
        &database,
        &["tenant", "create", "--slug", "acme", "--name", "Acme"],
    ));
    said(&run(
        &database,
        &[
            "admin",
            "bootstrap",
            "--tenant",
            "acme",
            "--email",
            "ana@example.com",
        ],
    ));
    let claims = |more: &[&str]| {
        let mut arguments = vec![
            "user",
            "claims",
            "--tenant",
            "acme",
            "--user",
            "ana@example.com",
        ];
        arguments.extend_from_slice(more);
        run(&database, &arguments)
    };

    assert_eq!(said(&claims(&[])), "", "a new person has none");
    let printed = said(&claims(&[
        "--given-name",
        "Ana",
        "--family-name",
        "Silva",
        "--birthdate",
        "1990-04-12",
        "--phone-number",
        "+55 11 91234-5678",
        "--phone-number-verified",
        "true",
        "--locality",
        "São Paulo",
        "--country",
        "BR",
    ]));
    assert_eq!(
        printed,
        "given_name Ana\nfamily_name Silva\nbirthdate 1990-04-12\nphone_number \
         +5511912345678\naddress.locality São Paulo\naddress.country BR\n\
         phone_number_verified true"
    );

    // Others are kept, an empty value removes one, and a new number is not
    // verified unless said.
    let printed = said(&claims(&[
        "--family-name",
        "",
        "--phone-number",
        "+351912345678",
    ]));
    assert!(printed.contains("given_name Ana"), "{printed}");
    assert!(!printed.contains("family_name"), "{printed}");
    assert!(printed.contains("phone_number_verified false"), "{printed}");

    // Named by its identifier too.
    let (id,): (sqlx::types::Uuid,) = sqlx::query_as(
        "SELECT user_id FROM identity.user_identifier WHERE value_normalized = 'ana@example.com'",
    )
    .fetch_one(database.owner())
    .await
    .expect("the user");
    let by_id = said(&run(
        &database,
        &[
            "user",
            "claims",
            "--tenant",
            "acme",
            "--user",
            &id.to_string(),
        ],
    ));
    assert!(by_id.contains("given_name Ana"));

    // A claim that breaks its rule is refused with the identity context's
    // code, and its value is not repeated.
    let error = refused(&claims(&["--birthdate", "31/12/1999"]));
    assert!(error.contains("identity.claim_invalid"), "{error}");
    assert!(!error.contains("1999"), "{error}");
    let nobody = refused(&run(
        &database,
        &[
            "user",
            "claims",
            "--tenant",
            "acme",
            "--user",
            "nobody@example.com",
        ],
    ));
    assert!(nobody.contains("identity.user_not_found"), "{nobody}");
}
