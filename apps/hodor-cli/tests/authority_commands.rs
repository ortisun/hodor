//! The commands of the intermediates a tenant's certificate authority
//! signs, run as the real binary against a real database.

use hodor_adapters_crypto::testing::certificates::{Leaf, MeshIntermediate, MeshRequest};
use hodor_adapters_crypto::{
    LocalKeyProvider, OsRandom, SecretKeys, Sha256Digest, X509Certificates, check_path,
};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgAuthorityStore, PgIntermediateStore, PgTenantDirectory, PgTenantRepository,
    PgTrustDomainStore,
};
use hodor_kernel::{Caller, Clock as _, Secret, SystemClock, TenantContext};
use hodor_keys::api::{AuthorityPorts, AuthorityService, NewAuthority};
use hodor_tenant::api::TenantService;
use std::io::Write as _;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

struct Tool<'a> {
    database: &'a TestDatabase,
    keys: String,
    setting: Option<&'a str>,
}

impl Tool<'_> {
    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hodor-cli"));
        command
            .args(arguments)
            .env("HODOR_DATABASE_URL", self.database.app_url())
            .env("HODOR_SECRET_KEYS", &self.keys)
            .env_remove("HODOR_OPENBAO_ADDRESS")
            .env_remove("HODOR_KEY_PROVIDER");
        match self.setting {
            Some(setting) => command.env("HODOR_CERTIFICATE_AUTHORITY", setting),
            None => command.env_remove("HODOR_CERTIFICATE_AUTHORITY"),
        };
        command
    }

    fn run(&self, arguments: &[&str]) -> Output {
        self.command(arguments)
            .output()
            .expect("the command-line tool should run")
    }

    fn run_with_input(&self, arguments: &[&str], input: &str) -> Output {
        let mut child = self
            .command(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the command-line tool should run");
        child
            .stdin
            .take()
            .expect("its input")
            .write_all(input.as_bytes())
            .expect("written");
        child.wait_with_output().expect("it ends")
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

/// The certificates of a PEM text, in DER, in order.
fn certificates(pem: &str) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    pem.split("-----END CERTIFICATE-----")
        .filter_map(|block| {
            let body: String = block
                .lines()
                .filter(|line| !line.starts_with("-----") && !line.trim().is_empty())
                .collect();
            (!body.is_empty()).then(|| {
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .expect("base64")
            })
        })
        .collect()
}

#[tokio::test]
async fn an_operator_signs_lists_and_withdraws_intermediates_from_the_command_line() {
    let database = TestDatabase::start().await;
    let keys = format!("test:{}", SecretKeys::generate(&OsRandom).expose());
    let tool = Tool {
        database: &database,
        keys: keys.clone(),
        setting: Some("development"),
    };
    let created = tool.run(&["tenant", "create", "--slug", "acme", "--name", "Acme"]);
    assert!(created.status.success(), "{created:?}");

    // The tenant's authority, made as the server makes it.
    let tenant = TenantService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        Arc::new(SystemClock),
    )
    .find_by_slug("acme")
    .await
    .expect("read")
    .expect("the tenant");
    let tenant = TenantContext::assume(tenant.tenant_id);
    let provider = Arc::new(LocalKeyProvider::new(Arc::new(
        SecretKeys::parse(&Secret::new(keys)).expect("keys"),
    )));
    let authority = AuthorityService::new(
        AuthorityPorts {
            units_of_work: Arc::new(database.app().clone()),
            store: Arc::new(PgAuthorityStore),
            trust_domains: Arc::new(PgTrustDomainStore),
            intermediates: Arc::new(PgIntermediateStore),
            maker: provider.clone(),
            signer: provider,
            certificates: Arc::new(X509Certificates),
            digest: Arc::new(Sha256Digest),
            clock: Arc::new(SystemClock),
        },
        true,
    )
    .create(
        &tenant,
        NewAuthority {
            kind: "root".to_owned(),
            trust_domains: vec!["cluster.local".to_owned()],
            ..NewAuthority::default()
        },
        Caller::system(),
    )
    .await
    .expect("the authority");
    let anchor = authority.certificate().expect("active").der.clone();

    let mesh = MeshIntermediate::new(&MeshRequest {
        dns_names: vec!["identity.linkerd.cluster.local".to_owned()],
        ..MeshRequest::authority("identity.linkerd.cluster.local")
    });
    let directory =
        std::env::temp_dir().join(format!("hodor-cli-authority-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a directory");
    let file = directory.join("issuer.csr");
    std::fs::write(&file, mesh.request()).expect("written");
    let file = file.to_str().expect("a path");

    // Signed from a file: the certificate, then the authority's.
    let signed = tool.run(&[
        "authority",
        "sign",
        "--tenant",
        "acme",
        "--request",
        file,
        "--lifetime-days",
        "2",
    ]);
    assert!(signed.status.success(), "{signed:?}");
    let printed = certificates(&text(&signed.stdout));
    assert_eq!(printed.len(), 2);
    assert_eq!(printed[1], anchor);
    let note = text(&signed.stderr);
    assert!(note.starts_with("signed "), "{note}");
    assert!(
        note.ends_with("CN=identity.linkerd.cluster.local"),
        "{note}"
    );
    let first = note.split(' ').nth(1).expect("its identifier").to_owned();
    let workload = mesh.issue(&Leaf::uri("spiffe://cluster.local/ns/shop/sa/web"));
    assert!(
        check_path(
            &workload,
            &printed[..1],
            std::slice::from_ref(&anchor),
            &[],
            SystemClock.now()
        )
        .is_ok()
    );

    // Signed again from standard input, as on a renewal of the same key.
    let again = tool.run_with_input(
        &["authority", "sign", "--tenant", "acme", "--request", "-"],
        mesh.request(),
    );
    assert!(again.status.success(), "{again:?}");

    // A refusal says its code and its reason.
    let deeper = MeshIntermediate::new(&MeshRequest {
        path_length: Some(1),
        ..MeshRequest::authority("deeper")
    });
    let refused = tool.run_with_input(
        &["authority", "sign", "--tenant", "acme", "--request", "-"],
        deeper.request(),
    );
    assert!(!refused.status.success());
    let said = text(&refused.stderr);
    assert!(
        said.contains("keys.intermediate_path_length_invalid"),
        "{said}"
    );
    assert!(said.contains("it asks for a path length of 1"), "{said}");

    // Nothing without the installation's setting.
    let off = Tool {
        database: &database,
        keys: tool.keys.clone(),
        setting: None,
    };
    let refused = off.run(&["authority", "intermediates", "--tenant", "acme"]);
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("keys.authority_setting_invalid"),
        "{refused:?}"
    );

    // Listed newest first, both active.
    let listed = tool.run(&["authority", "intermediates", "--tenant", "acme"]);
    assert!(listed.status.success(), "{listed:?}");
    let lines: Vec<String> = text(&listed.stdout).lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines
            .iter()
            .all(|line| line.split(' ').nth(1) == Some("active"))
    );
    assert_eq!(lines[1].split(' ').next(), Some(first.as_str()));

    // Withdrawing one withdraws both: the same key.
    let withdrawn = tool.run(&[
        "authority",
        "withdraw",
        "--tenant",
        "acme",
        "--intermediate",
        &first,
        "--reason",
        "the cluster was rebuilt",
    ]);
    assert!(withdrawn.status.success(), "{withdrawn:?}");
    let said = text(&withdrawn.stdout);
    assert_eq!(said.lines().count(), 2, "{said}");
    assert!(said.lines().all(|line| line.starts_with("withdrawn ")));
    let listed = tool.run(&["authority", "intermediates", "--tenant", "acme"]);
    assert!(
        text(&listed.stdout)
            .lines()
            .all(|line| line.split(' ').nth(1) == Some("withdrawn"))
    );
    let refused = tool.run(&["authority", "sign", "--tenant", "acme", "--request", file]);
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).contains("keys.intermediate_key_withdrawn"),
        "{refused:?}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}
