//! The commands for webhook endpoints and their deliveries, run as the
//! real binary against a real database.

use hodor_adapters_crypto::{OsRandom, SecretKeys};
use hodor_adapters_postgres::testing::TestDatabase;
use std::process::{Command, Output};

/// The development exception the endpoints of this test are named under:
/// nothing listens there, and nothing is sent, since no worker runs.
const RECEIVER: &str = "127.0.0.1:9";

struct Tool<'a> {
    database: &'a TestDatabase,
    keys: Option<String>,
}

impl Tool<'_> {
    fn run(&self, arguments: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hodor-cli"));
        command
            .args(arguments)
            .env("HODOR_DATABASE_URL", self.database.app_url())
            .env("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", RECEIVER);
        match &self.keys {
            Some(keys) => command.env("HODOR_SECRET_KEYS", keys),
            None => command.env_remove("HODOR_SECRET_KEYS"),
        };
        command.output().expect("the command-line tool should run")
    }

    fn said(&self, arguments: &[&str]) -> String {
        let output = self.run(arguments);
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn refused(&self, arguments: &[&str], code: &str) {
        let output = self.run(arguments);
        assert!(!output.status.success(), "{arguments:?} was not refused");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(code), "{arguments:?}: {error}");
    }
}

/// The value after `name ` on the line that starts with it.
fn value<'a>(said: &'a str, name: &str) -> &'a str {
    said.lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .unwrap_or_else(|| panic!("no {name} in {said}"))
}

#[tokio::test]
async fn endpoints_and_deliveries_are_managed_from_the_command_line() {
    let database = TestDatabase::start().await;
    let tool = Tool {
        database: &database,
        keys: Some(format!("test:{}", SecretKeys::generate(&OsRandom).expose())),
    };
    let without_keys = Tool {
        database: &database,
        keys: None,
    };
    for slug in ["acme", "globex"] {
        tool.said(&["tenant", "create", "--slug", slug, "--name", slug]);
    }

    let catalog = tool.said(&["webhook", "event-types"]);
    assert!(catalog.lines().any(|line| line == "session.started"));
    assert!(catalog.lines().all(|line| !line.starts_with("webhooks.")));

    let address = format!("http://{RECEIVER}/hodor");
    let add = [
        "webhook",
        "add",
        "--tenant",
        "acme",
        "--url",
        &address,
        "--event",
        "session.started",
        "--description",
        "Our directory",
    ];
    // Without keys nothing is sealed, so nothing is registered.
    without_keys.refused(&add, "secret.keys_missing");
    let created = tool.said(&add);
    let first = created.lines().next().expect("a line");
    let endpoint = first
        .strip_prefix("created ")
        .and_then(|rest| rest.split_whitespace().next())
        .expect("the identifier")
        .to_owned();
    assert_eq!(first, format!("created {endpoint} {address}"));
    let secret = value(&created, "secret").to_owned();
    assert!(secret.starts_with("whsec_"), "{secret}");

    // The rules are the context's: an address that may not be called, an
    // unknown event type, another tenant's endpoint.
    tool.refused(
        &[
            "webhook",
            "add",
            "--tenant",
            "acme",
            "--url",
            "https://127.0.0.1/hodor",
            "--event",
            "session.started",
        ],
        "webhooks.endpoint_address_forbidden",
    );
    tool.refused(
        &[
            "webhook",
            "add",
            "--tenant",
            "acme",
            "--url",
            &address,
            "--event",
            "webhooks.endpoint_registered",
        ],
        "webhooks.event_type_unknown",
    );
    tool.refused(
        &["webhook", "remove", "--tenant", "globex", "--id", &endpoint],
        "webhooks.endpoint_not_found",
    );
    assert!(
        tool.said(&["webhook", "list", "--tenant", "globex"])
            .is_empty()
    );

    // Listing needs no keys; the secret is never listed.
    let listed = without_keys.said(&["webhook", "list", "--tenant", "acme"]);
    assert_eq!(listed, format!("{endpoint} {address} session.started"));
    assert!(!listed.contains(&secret));

    let subscribed = tool.said(&[
        "webhook",
        "subscribe",
        "--tenant",
        "acme",
        "--id",
        &endpoint,
        "--event",
        "session.started",
        "--event",
        "identity.user_created",
    ]);
    assert_eq!(
        subscribed,
        format!("subscribed {endpoint} identity.user_created,session.started")
    );

    without_keys.refused(
        &[
            "webhook",
            "rotate-secret",
            "--tenant",
            "acme",
            "--id",
            &endpoint,
        ],
        "secret.keys_missing",
    );
    let rotated = tool.said(&[
        "webhook",
        "rotate-secret",
        "--tenant",
        "acme",
        "--id",
        &endpoint,
        "--overlap-hours",
        "2",
    ]);
    let next = value(&rotated, "secret");
    assert!(next.starts_with("whsec_") && next != secret, "{rotated}");
    assert!(!value(&rotated, "previous-until").is_empty());

    // A delivery, as the outbox dispatcher makes one, set aside after its
    // last attempt.
    let delivery = "0193f2d0-0000-7000-8000-000000000001";
    sqlx::query(
        "INSERT INTO webhooks.delivery
           (tenant_id, id, endpoint_id, event_id, event_type, payload, status, attempts,
            next_attempt_at, last_error, created_at, finished_at)
         SELECT tenant_id, $2::uuid, id, '0193f2cf-0000-7000-8000-000000000001'::uuid,
                'session.started', '{}', 'set_aside', 8, now(), 'the endpoint answered 503',
                now(), now()
         FROM webhooks.endpoint WHERE id = $1::uuid",
    )
    .bind(&endpoint)
    .bind(delivery)
    .execute(database.owner())
    .await
    .expect("a delivery set aside");

    let set_aside = without_keys.said(&[
        "webhook",
        "deliveries",
        "--tenant",
        "acme",
        "--endpoint",
        &endpoint,
        "--status",
        "set_aside",
    ]);
    assert_eq!(
        set_aside,
        format!("{delivery} set_aside 8 session.started 0193f2cf-0000-7000-8000-000000000001")
    );
    assert!(
        tool.said(&[
            "webhook",
            "deliveries",
            "--tenant",
            "acme",
            "--status",
            "pending"
        ])
        .is_empty()
    );
    tool.refused(
        &[
            "webhook",
            "deliveries",
            "--tenant",
            "acme",
            "--status",
            "lost",
        ],
        "request.query_invalid",
    );
    tool.refused(
        &[
            "webhook",
            "redeliver",
            "--tenant",
            "globex",
            "--delivery",
            delivery,
        ],
        "webhooks.delivery_not_found",
    );
    assert_eq!(
        tool.said(&[
            "webhook",
            "redeliver",
            "--tenant",
            "acme",
            "--delivery",
            delivery,
        ]),
        format!("pending {delivery}")
    );
    tool.refused(
        &[
            "webhook",
            "redeliver",
            "--tenant",
            "acme",
            "--delivery",
            delivery,
        ],
        "webhooks.delivery_not_set_aside",
    );

    assert_eq!(
        tool.said(&["webhook", "remove", "--tenant", "acme", "--id", &endpoint]),
        format!("removed {endpoint}")
    );
    assert!(
        tool.said(&["webhook", "list", "--tenant", "acme"])
            .is_empty()
    );
    assert!(
        tool.said(&["webhook", "deliveries", "--tenant", "acme"])
            .is_empty()
    );

    // What the operator did is in the audit log's outbox, as the system.
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM platform.outbox WHERE event_type LIKE 'webhooks.%'
         ORDER BY occurred_at, id",
    )
    .fetch_all(database.owner())
    .await
    .expect("the events");
    assert_eq!(
        events,
        [
            "webhooks.endpoint_registered",
            "webhooks.subscriptions_changed",
            "webhooks.secret_rotated",
            "webhooks.redelivery_requested",
            "webhooks.endpoint_removed",
        ]
    );
}
