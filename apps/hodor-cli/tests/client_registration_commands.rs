//! The commands for client registration, run as the real binary against a
//! real database.

use hodor_adapters_postgres::testing::TestDatabase;
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

fn said(output: &Output) -> String {
    assert!(output.status.success(), "{output:?}");
    text(&output.stdout)
}

/// What follows `prefix ` on the first line that has it.
fn value(output: &Output, prefix: &str) -> String {
    said(output)
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{prefix} ")))
        .unwrap_or_else(|| panic!("no `{prefix}` in {output:?}"))
        .to_owned()
}

fn refused(output: &Output, code: &str) {
    assert!(!output.status.success(), "{output:?}");
    assert!(text(&output.stderr).contains(code), "{output:?}");
}

fn application(database: &TestDatabase, slug: &str, first_party: bool) -> String {
    let mut arguments = vec!["application", "add", "--tenant", slug, "--name", "Partners"];
    if first_party {
        arguments.push("--first-party");
    }
    value(&run(database, &arguments), "application")
        .split(' ')
        .next()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn an_operator_turns_registration_on_and_hands_out_initial_access_tokens() {
    let database = TestDatabase::start().await;
    for slug in ["acme", "globex"] {
        let created = run(
            &database,
            &["tenant", "create", "--slug", slug, "--name", slug],
        );
        assert!(created.status.success(), "{created:?}");
    }
    let shown = run(
        &database,
        &["client-registration", "show", "--tenant", "acme"],
    );
    assert_eq!(
        said(&shown),
        "registration off\napplication -\nways initial_access_token\nmost-clients 100\n\
         grants authorization_code\nresponse-types code\nscopes openid,profile,email\n\
         methods client_secret_basic,private_key_jwt\nsubject-types public\nhosts any"
    );
    refused(
        &run(
            &database,
            &[
                "client-registration",
                "token",
                "add",
                "--tenant",
                "acme",
                "--name",
                "Early",
            ],
        ),
        "oauth.client_registration_off",
    );

    let first_party = application(&database, "acme", true);
    refused(
        &run(
            &database,
            &[
                "client-registration",
                "on",
                "--tenant",
                "acme",
                "--application",
                &first_party,
            ],
        ),
        "oauth.client_registration_application_invalid",
    );
    let theirs = application(&database, "globex", false);
    refused(
        &run(
            &database,
            &[
                "client-registration",
                "on",
                "--tenant",
                "acme",
                "--application",
                &theirs,
            ],
        ),
        "oauth.client_registration_application_invalid",
    );
    let partners = application(&database, "acme", false);
    refused(
        &run(
            &database,
            &[
                "client-registration",
                "on",
                "--tenant",
                "acme",
                "--application",
                &partners,
                "--grant",
                "client_credentials",
            ],
        ),
        "oauth.client_registration_policy_invalid",
    );
    // Only a response type Hodor answers may be allowed.
    refused(
        &run(
            &database,
            &[
                "client-registration",
                "on",
                "--tenant",
                "acme",
                "--application",
                &partners,
                "--response-type",
                "code id_token",
            ],
        ),
        "oauth.client_registration_policy_invalid",
    );
    let on = run(
        &database,
        &[
            "client-registration",
            "on",
            "--tenant",
            "acme",
            "--application",
            &partners,
            "--way",
            "initial_access_token",
            "--way",
            "open",
            "--most-clients",
            "250",
            "--grant",
            "authorization_code",
            "--grant",
            "refresh_token",
            "--response-type",
            "code",
            "--scope",
            "openid",
            "--method",
            "none",
            "--host",
            "partner.example.com",
        ],
    );
    assert_eq!(
        said(&on),
        format!(
            "registration on\napplication {partners}\nways initial_access_token,open\n\
             most-clients 250\ngrants authorization_code,refresh_token\n\
             response-types code\nscopes openid\nmethods none\n\
             subject-types public\nhosts partner.example.com"
        )
    );

    let made = run(
        &database,
        &[
            "client-registration",
            "token",
            "add",
            "--tenant",
            "acme",
            "--name",
            "Partner portal team",
            "--hours",
            "24",
            "--registrations",
            "3",
        ],
    );
    let id = value(&made, "token");
    let token = value(&made, "initial-access-token");
    assert!(
        token.starts_with("hodor_iat_") && token.len() == 74,
        "{token}"
    );
    assert!(said(&made).contains("expires "));
    refused(
        &run(
            &database,
            &[
                "client-registration",
                "token",
                "add",
                "--tenant",
                "acme",
                "--name",
                "Too long",
                "--hours",
                "2161",
            ],
        ),
        "oauth.initial_access_token_lifetime_invalid",
    );
    let listed = said(&run(
        &database,
        &["client-registration", "token", "list", "--tenant", "acme"],
    ));
    assert!(listed.starts_with(&format!("{id} active 0/3 ")), "{listed}");
    assert!(
        listed.ends_with(&format!("…{} Partner portal team", &token[70..])),
        "{listed}"
    );
    assert!(!listed.contains(&token), "never shown again");

    // Globex sees none of it, and cannot revoke it.
    assert_eq!(
        said(&run(
            &database,
            &["client-registration", "token", "list", "--tenant", "globex"],
        )),
        ""
    );
    refused(
        &run(
            &database,
            &[
                "client-registration",
                "token",
                "revoke",
                "--tenant",
                "globex",
                "--id",
                &id,
            ],
        ),
        "oauth.initial_access_token_not_found",
    );
    assert!(
        said(&run(
            &database,
            &["client-registration", "show", "--tenant", "globex"]
        ))
        .starts_with("registration off")
    );

    let revoked = run(
        &database,
        &[
            "client-registration",
            "token",
            "revoke",
            "--tenant",
            "acme",
            "--id",
            &id,
        ],
    );
    assert_eq!(said(&revoked), format!("revoked {id}"));
    assert!(
        said(&run(
            &database,
            &["client-registration", "token", "list", "--tenant", "acme"],
        ))
        .starts_with(&format!("{id} revoked 0/3 "))
    );

    // Off keeps the settings.
    let off = said(&run(
        &database,
        &["client-registration", "off", "--tenant", "acme"],
    ));
    assert!(off.starts_with("registration off\n"), "{off}");
    assert!(off.contains("hosts partner.example.com"), "{off}");
    refused(
        &run(
            &database,
            &[
                "client-registration",
                "token",
                "add",
                "--tenant",
                "acme",
                "--name",
                "Off",
            ],
        ),
        "oauth.client_registration_off",
    );
}
