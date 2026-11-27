//! The commands for trust domains, run as the real binary against a real
//! database, with a bundle endpoint the test runs on this machine.
//!
//! This machine's addresses are exactly what the guarded client refuses,
//! so the endpoint is named under the development exception, and the same
//! address without it shows the refusal.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_keys::testing::sample_bundle;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

/// A bundle endpoint on this machine, answering every request with the
/// bundle it holds.
struct Endpoint {
    address: String,
    bundle: Arc<Mutex<String>>,
}

impl Endpoint {
    fn start(bundle: &serde_json::Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address").to_string();
        let held = Arc::new(Mutex::new(bundle.to_string()));
        let answer = held.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                // The request is read up to its end; a GET has no body.
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                while !request.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => request.extend_from_slice(&buffer[..read]),
                    }
                }
                let body = answer.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Self {
            address,
            bundle: held,
        }
    }

    fn serve(&self, bundle: &serde_json::Value) {
        *self.bundle.lock().unwrap_or_else(|e| e.into_inner()) = bundle.to_string();
    }
}

struct Tool<'a> {
    database: &'a TestDatabase,
    development_hosts: String,
}

impl Tool<'_> {
    fn run_with(&self, arguments: &[&str], input: Option<&str>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
            .args(arguments)
            .env("HODOR_DATABASE_URL", self.database.app_url())
            .env("HODOR_OUTBOUND_DEVELOPMENT_HOSTS", &self.development_hosts)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the command-line tool should run");
        let mut stdin = child.stdin.take().expect("its input");
        stdin
            .write_all(input.unwrap_or_default().as_bytes())
            .expect("the input is written");
        drop(stdin);
        child
            .wait_with_output()
            .expect("the command-line tool ends")
    }

    fn said_with(&self, arguments: &[&str], input: Option<&str>) -> String {
        let output = self.run_with(arguments, input);
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn said(&self, arguments: &[&str]) -> String {
        self.said_with(arguments, None)
    }

    fn refused(&self, arguments: &[&str], code: &str) {
        let output = self.run_with(arguments, None);
        assert!(!output.status.success(), "{arguments:?} was not refused");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(code), "{arguments:?}: {error}");
    }
}

/// The value after `name ` on the line that starts with it, if any.
fn value<'a>(said: &'a str, name: &str) -> Option<&'a str> {
    said.lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
}

#[tokio::test]
async fn trust_domains_are_managed_from_the_command_line() {
    let database = TestDatabase::start().await;
    let endpoint = Endpoint::start(&sample_bundle(Some(4), &["spire-1"]));
    let tool = Tool {
        database: &database,
        development_hosts: endpoint.address.clone(),
    };
    let without_exception = Tool {
        database: &database,
        development_hosts: String::new(),
    };
    for slug in ["acme", "globex"] {
        tool.said(&["tenant", "create", "--slug", slug, "--name", slug]);
    }
    let directory = std::env::temp_dir().join(format!("hodor-bundles-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a directory");
    let file = directory.join("bundle.json");
    std::fs::write(&file, sample_bundle(Some(1), &["one", "two"]).to_string()).expect("written");
    let file = file.to_str().expect("a path");

    // A bundle given in a file: read as the server reads it, and named by
    // its SHA-256, never printed.
    let uploaded = tool.said(&[
        "trust-domain",
        "add",
        "--tenant",
        "acme",
        "--name",
        "partners.example.com",
        "--bundle-file",
        file,
    ]);
    let partners = value(&uploaded, "added")
        .expect("its identifier")
        .to_owned();
    assert_eq!(value(&uploaded, "name"), Some("partners.example.com"));
    assert_eq!(value(&uploaded, "source"), Some("uploaded"));
    assert_eq!(value(&uploaded, "sequence"), Some("1"));
    assert_eq!(value(&uploaded, "x509-authorities"), Some("1"));
    assert_eq!(value(&uploaded, "jwt-authorities"), Some("2"));
    let digest = value(&uploaded, "bundle-sha256").expect("its digest");
    assert!(
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{digest}"
    );
    assert!(value(&uploaded, "fetched").is_none(), "{uploaded}");
    assert!(!uploaded.contains("\"keys\""), "{uploaded}");

    // A bundle endpoint, checked and fetched now through the guarded
    // client, under the development exception of this test.
    let address = format!("http://{}/bundle", endpoint.address);
    let fetched = tool.said(&[
        "trust-domain",
        "add",
        "--tenant",
        "acme",
        "--name",
        "workloads.example.org",
        "--bundle-endpoint",
        &address,
    ]);
    let workloads = value(&fetched, "added").expect("its identifier").to_owned();
    assert_eq!(value(&fetched, "source"), Some("bundle_endpoint"));
    assert_eq!(value(&fetched, "bundle-endpoint"), Some(address.as_str()));
    assert_eq!(value(&fetched, "sequence"), Some("4"));
    assert_eq!(value(&fetched, "jwt-authorities"), Some("1"));
    assert!(value(&fetched, "fetched").is_some(), "{fetched}");
    assert!(value(&fetched, "next-fetch").is_some(), "{fetched}");
    assert!(value(&fetched, "failing-since").is_none(), "{fetched}");

    // The mesh in front of Hodor: no bundle.
    let mesh = tool.said(&[
        "trust-domain",
        "add",
        "--tenant",
        "acme",
        "--name",
        "cluster.local",
        "--mesh",
    ]);
    let cluster = value(&mesh, "added").expect("its identifier").to_owned();
    assert_eq!(value(&mesh, "source"), Some("mesh"));
    assert!(value(&mesh, "bundle-sha256").is_none(), "{mesh}");

    // The keys context's refusals, with its codes.
    let add = |name: &'static str, source: &'static str, given: &'static str| {
        vec![
            "trust-domain",
            "add",
            "--tenant",
            "acme",
            "--name",
            name,
            source,
            given,
        ]
    };
    tool.refused(
        &[
            "trust-domain",
            "add",
            "--tenant",
            "acme",
            "--name",
            "cluster.local",
            "--mesh",
        ],
        "keys.trust_domain_name_taken",
    );
    tool.refused(
        &[
            "trust-domain",
            "add",
            "--tenant",
            "acme",
            "--name",
            "Upper.Case",
            "--mesh",
        ],
        "keys.trust_domain_name_invalid",
    );
    tool.refused(
        &add(
            "private.example",
            "--bundle-endpoint",
            "https://127.0.0.1/bundle",
        ),
        "keys.bundle_endpoint_forbidden",
    );
    tool.refused(
        &add(
            "plain.example",
            "--bundle-endpoint",
            "http://bundles.example.com/",
        ),
        "keys.bundle_endpoint_invalid",
    );
    without_exception.refused(
        &[
            "trust-domain",
            "add",
            "--tenant",
            "acme",
            "--name",
            "again.example",
            "--bundle-endpoint",
            &address,
        ],
        "keys.bundle_endpoint",
    );
    std::fs::write(directory.join("broken.json"), "{\"keys\": 3}").expect("written");
    let broken = directory.join("broken.json");
    let broken = broken.to_str().expect("a path");
    tool.refused(
        &[
            "trust-domain",
            "add",
            "--tenant",
            "acme",
            "--name",
            "broken.example",
            "--bundle-file",
            broken,
        ],
        "keys.trust_bundle_invalid",
    );
    tool.refused(
        &[
            "trust-domain",
            "add",
            "--tenant",
            "acme",
            "--name",
            "nowhere.example",
            "--bundle-file",
            "/nonexistent/bundle.json",
        ],
        "keys.trust_bundle_invalid",
    );

    // Listed in the order of their identifiers, with whether the last
    // fetch read.
    let listed = tool.said(&["trust-domain", "list", "--tenant", "acme"]);
    let lines: Vec<&str> = listed.lines().collect();
    assert_eq!(lines.len(), 3, "{listed}");
    assert_eq!(
        lines[0],
        format!("{partners} partners.example.com uploaded")
    );
    assert!(
        lines[1].starts_with(&format!(
            "{workloads} workloads.example.org bundle_endpoint fetched "
        )),
        "{listed}"
    );
    assert_eq!(lines[2], format!("{cluster} cluster.local mesh"));

    // Shown by its name.
    let shown = tool.said(&[
        "trust-domain",
        "show",
        "--tenant",
        "acme",
        "--name",
        "partners.example.com",
    ]);
    assert_eq!(
        shown.lines().next(),
        Some(format!("trust-domain {partners}").as_str())
    );
    assert_eq!(value(&shown, "bundle-sha256"), Some(digest));

    // Replaced: by a bundle read from the standard input, and by the
    // endpoint again, which is fetched again. A bundle that does not read
    // leaves the trust domain as it was.
    let replaced = tool.said_with(
        &[
            "trust-domain",
            "replace",
            "--tenant",
            "acme",
            "--name",
            "cluster.local",
            "--bundle-file",
            "-",
        ],
        Some(&sample_bundle(Some(9), &["three"]).to_string()),
    );
    assert_eq!(value(&replaced, "replaced"), Some(cluster.as_str()));
    assert_eq!(value(&replaced, "source"), Some("uploaded"));
    assert_eq!(value(&replaced, "sequence"), Some("9"));
    tool.refused(
        &[
            "trust-domain",
            "replace",
            "--tenant",
            "acme",
            "--name",
            "cluster.local",
            "--bundle-file",
            broken,
        ],
        "keys.trust_bundle_invalid",
    );
    let kept = tool.said(&[
        "trust-domain",
        "show",
        "--tenant",
        "acme",
        "--name",
        "cluster.local",
    ]);
    assert_eq!(value(&kept, "sequence"), Some("9"));
    endpoint.serve(&sample_bundle(Some(5), &["spire-2"]));
    let refetched = tool.said(&[
        "trust-domain",
        "replace",
        "--tenant",
        "acme",
        "--name",
        "workloads.example.org",
        "--bundle-endpoint",
        &address,
    ]);
    assert_eq!(value(&refetched, "sequence"), Some("5"));

    // Another tenant knows none of them, whatever their names.
    assert!(
        tool.said(&["trust-domain", "list", "--tenant", "globex"])
            .is_empty()
    );
    for command in ["show", "remove"] {
        tool.refused(
            &[
                "trust-domain",
                command,
                "--tenant",
                "globex",
                "--name",
                "cluster.local",
            ],
            "keys.trust_domain_not_found",
        );
    }
    tool.refused(
        &[
            "trust-domain",
            "replace",
            "--tenant",
            "globex",
            "--name",
            "cluster.local",
            "--mesh",
        ],
        "keys.trust_domain_not_found",
    );

    // Removed, with its bundle.
    let removed = tool.said(&[
        "trust-domain",
        "remove",
        "--tenant",
        "acme",
        "--name",
        "partners.example.com",
    ]);
    assert_eq!(removed, format!("removed {partners} partners.example.com"));
    tool.refused(
        &[
            "trust-domain",
            "show",
            "--tenant",
            "acme",
            "--name",
            "partners.example.com",
        ],
        "keys.trust_domain_not_found",
    );

    // Every change is an event of the tenant, as the server's are.
    let (recorded,): (Vec<String>,) = sqlx::query_as(
        "SELECT array_agg(event_type ORDER BY occurred_at, id) FROM platform.outbox
         WHERE event_type LIKE 'keys.trust_domain_%'",
    )
    .fetch_one(database.owner())
    .await
    .expect("the events");
    assert_eq!(
        recorded,
        [
            "keys.trust_domain_added",
            "keys.trust_domain_added",
            "keys.trust_domain_added",
            "keys.trust_domain_replaced",
            "keys.trust_domain_replaced",
            "keys.trust_domain_removed",
        ]
    );
    let _ = std::fs::remove_dir_all(&directory);
}
