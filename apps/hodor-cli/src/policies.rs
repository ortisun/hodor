//! The commands of the policy lifecycle: drafting, checking, testing,
//! simulating, publishing and rolling back a tenant's policy.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "The policy
//! lifecycle". Checking, testing and simulating are done by the worker;
//! these commands ask and wait for its report.

use crate::{WrittenByArg, bundle_files, bundle_service, caller, existing};
use clap::Subcommand;
use hodor_adapters_crypto::{BundleSigningKey, Sha256Digest};
use hodor_adapters_postgres::{
    Database, PgPolicyVersionStore, PgPublicationStore, PgSimulationStore, PgTenantDirectory,
    PgTenantRepository,
};
use hodor_authorization::api::Namespace;
use hodor_authorization_opa::api::{
    Author, PolicyService, PolicyVersion, Report, Simulation, SimulationState, VersionState,
};
use hodor_kernel::{DomainError, Secret, SystemClock, TenantContext};
use hodor_tenant::api::TenantService;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;

/// How often a waiting command asks whether the worker is done.
const POLL: Duration = Duration::from_millis(500);

#[derive(Subcommand)]
pub(crate) enum PolicyCommand {
    /// Check the files of a directory and store them as the tenant's next
    /// policy version, a draft.
    ///
    /// Every file under the directory is a file of the version at the same
    /// path under the tenant's tree: `.rego` modules, `_test.rego` tests and
    /// `data.json` documents.
    Draft {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The directory that holds the files.
        #[arg(long)]
        directory: PathBuf,
        /// Who wrote the files. Only what the operator wrote is served to a
        /// shared instance.
        #[arg(long, value_enum, default_value = "tenant")]
        written_by: WrittenByArg,
    },
    /// Have the worker check a draft, and wait for its report.
    Validate {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The version's number.
        #[arg(long)]
        version: u64,
        /// How long to wait for the worker, in seconds; 0 does not wait.
        #[arg(long, default_value_t = 60)]
        wait: u64,
    },
    /// Have the worker run the tests of a validated version, and wait for
    /// its report.
    Test {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The version's number.
        #[arg(long)]
        version: u64,
        /// How long to wait for the worker, in seconds; 0 does not wait.
        #[arg(long, default_value_t = 60)]
        wait: u64,
    },
    /// Have the worker evaluate a validated or tested version against
    /// inputs, comparing it with the published version.
    Simulate {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The version's number.
        #[arg(long)]
        version: u64,
        /// The resource server's audience, whose rule `decision` is asked.
        #[arg(long)]
        namespace: String,
        /// A JSON file holding a list of input documents.
        #[arg(long)]
        inputs: PathBuf,
        /// How long to wait for the worker, in seconds; 0 does not wait.
        #[arg(long, default_value_t = 60)]
        wait: u64,
    },
    /// Publish a tested version as the tenant's next revision.
    Publish {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The version's number.
        #[arg(long)]
        version: u64,
        #[command(flatten)]
        key: SigningKeyArgs,
    },
    /// Publish the version an earlier revision was built from as the
    /// tenant's next revision.
    Rollback {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The revision to go back to.
        #[arg(long)]
        revision: u64,
        #[command(flatten)]
        key: SigningKeyArgs,
    },
    /// Show the latest revision, what each instance runs, and whether
    /// activation is pending.
    Status {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
    },
    /// List the tenant's latest versions.
    Versions {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
    },
    /// Show one version: its state, its files and its last report.
    Show {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The version's number.
        #[arg(long)]
        version: u64,
    },
}

/// The key that signs bundles.
#[derive(clap::Args)]
pub(crate) struct SigningKeyArgs {
    /// The file that holds the key that signs bundles.
    #[arg(long, env = "HODOR_OPEN_POLICY_AGENT_SIGNING_KEY_FILE")]
    signing_key_file: PathBuf,
    /// The name instances know the key by.
    #[arg(
        long,
        env = "HODOR_OPEN_POLICY_AGENT_SIGNING_KEY_ID",
        default_value = "hodor"
    )]
    signing_key_id: String,
}

impl SigningKeyArgs {
    fn signer(&self) -> Result<BundleSigningKey, DomainError> {
        let key = std::fs::read_to_string(&self.signing_key_file).map_err(|error| {
            DomainError::invalid(
                "authorization.bundle_signing_key_unreadable",
                "the file of the key that signs bundles could not be read",
            )
            .with_detail(error.to_string())
        })?;
        BundleSigningKey::from_pem(&key, &self.signing_key_id)
    }
}

fn when(time: time::OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap_or_else(|_| "-".to_owned())
}

/// The problems and tests of a report, one per line.
fn report_lines(report: &Report) -> String {
    let mut out = String::new();
    for diagnostic in &report.diagnostics {
        let place = match (&diagnostic.file, diagnostic.row) {
            (Some(file), Some(row)) => format!("{file}:{row}: "),
            (Some(file), None) => format!("{file}: "),
            _ => String::new(),
        };
        // Writing to a `String` cannot fail.
        let _ = writeln!(out, "{place}{}: {}", diagnostic.code, diagnostic.message);
    }
    for test in &report.tests {
        let outcome = if test.passed { "PASS" } else { "FAIL" };
        let _ = write!(out, "{outcome}\t{}.{}", test.package, test.name);
        if let Some(error) = &test.error {
            let _ = write!(out, "\t{error}");
        }
        out.push('\n');
    }
    out.trim_end().to_owned()
}

fn version_line(version: &PolicyVersion) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}",
        version.number,
        version.state.as_str(),
        version.author.as_str(),
        when(version.changed_at),
        version.digest_hex()
    )
}

fn policy_service(database: &Database) -> PolicyService {
    PolicyService::new(
        Arc::new(PgPolicyVersionStore),
        Arc::new(PgPublicationStore),
        Arc::new(PgSimulationStore),
        bundle_service(database),
        Arc::new(database.clone()),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    )
}

fn not_checked_in_time() -> DomainError {
    DomainError::new(
        hodor_kernel::ErrorKind::Unavailable,
        "authorization.policy_check_pending",
        "the worker has not finished yet: is it running with HODOR_OPEN_POLICY_AGENT_BINARY set?",
    )
}

/// Waits up to `wait` seconds for the worker to move version `number` out
/// of a waiting state, and answers what it found.
async fn awaited(
    policies: &PolicyService,
    tenant: &TenantContext,
    number: u64,
    wait: u64,
) -> Result<String, DomainError> {
    let mut version = policies.version(tenant, number).await?;
    if wait == 0 {
        return Ok(version_line(&version));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
    while version.state.is_waiting() {
        if tokio::time::Instant::now() >= deadline {
            return Err(not_checked_in_time());
        }
        tokio::time::sleep(POLL).await;
        version = policies.version(tenant, number).await?;
    }
    let report = version
        .report
        .as_ref()
        .map(report_lines)
        .unwrap_or_default();
    if version.state == VersionState::Rejected {
        return Err(DomainError::invalid(
            "authorization.policy_version_rejected",
            "the version is rejected",
        )
        .with_detail(report));
    }
    Ok(format!("{}\n{report}", version_line(&version))
        .trim_end()
        .to_owned())
}

fn simulation_lines(simulation: &Simulation) -> String {
    let mut out = format!(
        "{}\t{}\tcompared with {}",
        simulation.id,
        simulation.state.as_str(),
        simulation.compared_with.map_or_else(
            || "nothing published".to_owned(),
            |v| format!("version {v}")
        )
    );
    if let Some(report) = &simulation.report {
        let _ = write!(out, "\n{}", report_lines(report));
    }
    let undefined = || "undefined".to_owned();
    for answer in &simulation.results {
        let _ = write!(
            out,
            "\n{}\t{}\t{}\t{}",
            answer.index,
            if answer.differs { "differs" } else { "same" },
            answer
                .candidate
                .as_ref()
                .map_or_else(undefined, ToString::to_string),
            answer
                .published
                .as_ref()
                .map_or_else(undefined, ToString::to_string)
        );
    }
    out
}

fn read_inputs(path: &Path) -> Result<Vec<serde_json::Value>, DomainError> {
    let unreadable = |detail: String| {
        DomainError::invalid(
            "authorization.policy_simulation_inputs_invalid",
            "a simulation takes 1 to 100 input objects, 1 mebibyte in all",
        )
        .with_detail(detail)
    };
    let text = std::fs::read_to_string(path).map_err(|error| unreadable(error.to_string()))?;
    serde_json::from_str(&text).map_err(|error| unreadable(error.to_string()))
}

/// Runs one command of the policy lifecycle.
///
/// # Errors
///
/// Returns the lifecycle's error, `authorization.policy_check_pending`
/// when the worker did not finish in time, and
/// `authorization.policy_version_rejected` with the report when it
/// rejected the version.
pub(crate) async fn run_policy(
    database_url: Option<String>,
    command: PolicyCommand,
) -> Result<String, DomainError> {
    let url = database_url.ok_or_else(|| {
        DomainError::invalid(
            "database.url_missing",
            "HODOR_DATABASE_URL or --database-url is required",
        )
    })?;
    let database = Database::connect(&Secret::from(url), 2)
        .await
        .map_err(|error| {
            DomainError::internal("database.error", "the database could not be reached")
                .with_detail(error.to_string())
        })?;
    let tenants = TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    let policies = policy_service(&database);
    let tenant_of = |slug: String| {
        let tenants = &tenants;
        async move {
            existing(tenants, &slug)
                .await
                .map(|entry| TenantContext::assume(entry.tenant_id))
        }
    };
    match command {
        PolicyCommand::Draft {
            tenant,
            directory,
            written_by,
        } => {
            let tenant = tenant_of(tenant).await?;
            let author = match written_by {
                WrittenByArg::Operator => Author::Operator,
                WrittenByArg::Tenant => Author::Tenant,
            };
            let version = policies
                .draft(&tenant, author, &bundle_files(&directory)?, caller())
                .await?;
            Ok(format!("{}\t{}", version.number, version.digest_hex()))
        }
        PolicyCommand::Validate {
            tenant,
            version,
            wait,
        } => {
            let tenant = tenant_of(tenant).await?;
            policies.validate(&tenant, version).await?;
            awaited(&policies, &tenant, version, wait).await
        }
        PolicyCommand::Test {
            tenant,
            version,
            wait,
        } => {
            let tenant = tenant_of(tenant).await?;
            policies.test(&tenant, version).await?;
            awaited(&policies, &tenant, version, wait).await
        }
        PolicyCommand::Simulate {
            tenant,
            version,
            namespace,
            inputs,
            wait,
        } => {
            let tenant = tenant_of(tenant).await?;
            let namespace = Namespace::parse(&namespace)?;
            let mut simulation = policies
                .simulate(&tenant, version, &namespace, read_inputs(&inputs)?)
                .await?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
            while wait > 0 && simulation.state == SimulationState::Waiting {
                if tokio::time::Instant::now() >= deadline {
                    return Err(not_checked_in_time());
                }
                tokio::time::sleep(POLL).await;
                simulation = policies.simulation(&tenant, simulation.id).await?;
            }
            Ok(simulation_lines(&simulation))
        }
        PolicyCommand::Publish {
            tenant,
            version,
            key,
        } => {
            let tenant = tenant_of(tenant).await?;
            let publication = policies
                .publish(&tenant, version, &key.signer()?, caller())
                .await?;
            Ok(format!(
                "{}\t{}\t{}",
                publication.revision, publication.version, publication.entity_tag
            ))
        }
        PolicyCommand::Rollback {
            tenant,
            revision,
            key,
        } => {
            let tenant = tenant_of(tenant).await?;
            let publication = policies
                .roll_back(&tenant, revision, &key.signer()?, caller())
                .await?;
            Ok(format!(
                "{}\t{}\t{}",
                publication.revision, publication.version, publication.entity_tag
            ))
        }
        PolicyCommand::Status { tenant } => {
            let tenant = tenant_of(tenant).await?;
            let status = policies.status(&tenant).await?;
            let Some((revision, author, published_at, version)) = status.latest else {
                return Ok("nothing published".to_owned());
            };
            let mut out = format!(
                "revision {revision}\t{}\t{}\tversion {}\t{}",
                author.as_str(),
                when(published_at),
                version.map_or_else(|| "-".to_owned(), |v| v.to_string()),
                if status.instances.is_empty() {
                    "no instance runs it"
                } else if status.pending_activation {
                    "pending activation"
                } else {
                    "active"
                }
            );
            for instance in &status.instances {
                let _ = write!(
                    out,
                    "\n{}\t{}\t{}\t{}\t{}",
                    instance.instance,
                    if instance.own { "own" } else { "shared" },
                    instance.active_revision.as_deref().unwrap_or("-"),
                    instance
                        .reported_at
                        .map_or_else(|| "never".to_owned(), when),
                    instance.error.as_deref().unwrap_or("")
                );
            }
            Ok(out)
        }
        PolicyCommand::Versions { tenant } => {
            let tenant = tenant_of(tenant).await?;
            Ok(policies
                .versions(&tenant, 50)
                .await?
                .iter()
                .map(version_line)
                .collect::<Vec<_>>()
                .join("\n"))
        }
        PolicyCommand::Show { tenant, version } => {
            let tenant = tenant_of(tenant).await?;
            let version = policies.version(&tenant, version).await?;
            let mut out = version_line(&version);
            for file in &version.files {
                let _ = write!(out, "\n  {}", file.path);
            }
            if let Some(report) = &version.report {
                let lines = report_lines(report);
                if !lines.is_empty() {
                    let _ = write!(out, "\n{lines}");
                }
            }
            Ok(out)
        }
    }
}
