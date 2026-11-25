//! The commands for the SPIFFE trust domains of a tenant.
//!
//! Specified in `docs/architecture/contexts/keys.md`, "The command-line
//! tool for trust domains". The use cases are the keys context's own, so a
//! value the administration interface refuses is refused here with the
//! same code, and a bundle endpoint is checked and fetched by the guarded
//! outbound client as the server does it.

use crate::{caller, existing};
use clap::{Args, Subcommand};
use hodor_adapters_crypto::Sha256Digest;
use hodor_adapters_http::{GuardedHttpClient, OutboundPolicy};
use hodor_adapters_postgres::{
    Database, PgTenantDirectory, PgTenantRepository, PgTrustDomainStore,
};
use hodor_kernel::{Digest as _, DomainError, PageRequest, SystemClock, TenantContext};
use hodor_keys::api::{
    MAX_BUNDLE_BYTES, SvidKind, TrustDomain, TrustDomainPorts, TrustDomainService,
    TrustSourceRequest,
};
use hodor_tenant::api::TenantService;
use std::fmt::Write as _;
use std::io::Read as _;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

#[derive(Subcommand)]
pub(crate) enum TrustDomainCommand {
    /// Add a trust domain: its bundle from a file, its bundle endpoint, or
    /// the mesh in front of Hodor.
    Add {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The trust domain's name, as SPIFFE identifiers write it. Never
        /// changes.
        #[arg(long)]
        name: String,
        #[command(flatten)]
        source: SourceArguments,
    },
    /// List the tenant's trust domains.
    List {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
    /// Show a trust domain: its source, its bundle and its last fetch.
    Show {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The trust domain's name.
        #[arg(long)]
        name: String,
    },
    /// Give a trust domain another source, checked as when it is added. A
    /// refusal leaves it as it was.
    Replace {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The trust domain's name.
        #[arg(long)]
        name: String,
        #[command(flatten)]
        source: SourceArguments,
    },
    /// Remove a trust domain with its bundle. Its workloads are no longer
    /// trusted from the next request.
    Remove {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The trust domain's name.
        #[arg(long)]
        name: String,
    },
}

/// Exactly one source.
#[derive(Args)]
#[group(required = true, multiple = false)]
pub(crate) struct SourceArguments {
    /// A file holding the bundle, as SPIFFE writes it; `-` reads it from
    /// the standard input.
    #[arg(long)]
    bundle_file: Option<String>,
    /// The address of the trust domain's SPIFFE bundle endpoint, fetched
    /// now and again by the worker.
    #[arg(long)]
    bundle_endpoint: Option<String>,
    /// Checked by the mesh in front of Hodor, with no bundle.
    #[arg(long)]
    mesh: bool,
}

fn written(at: time::OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_else(|_| at.to_string())
}

fn not_found(name: &str) -> DomainError {
    DomainError::not_found(
        "keys.trust_domain_not_found",
        format!("the tenant has no trust domain named `{name}`"),
    )
}

/// Reads the bundle of `--bundle-file`, no more than a bundle may hold and
/// one byte, so that a bundle too large is refused by the rule of bundles.
fn bundle_from(path: &str) -> Result<Vec<u8>, DomainError> {
    let unreadable = |error: std::io::Error| {
        DomainError::invalid(
            "keys.trust_bundle_invalid",
            format!("the bundle file cannot be read: {error}"),
        )
    };
    let limit = u64::try_from(MAX_BUNDLE_BYTES).unwrap_or(u64::MAX) + 1;
    let mut bundle = Vec::new();
    if path == "-" {
        std::io::stdin()
            .take(limit)
            .read_to_end(&mut bundle)
            .map_err(unreadable)?;
    } else {
        std::fs::File::open(path)
            .map_err(unreadable)?
            .take(limit)
            .read_to_end(&mut bundle)
            .map_err(unreadable)?;
    }
    Ok(bundle)
}

impl SourceArguments {
    fn request(self) -> Result<TrustSourceRequest, DomainError> {
        match (self.bundle_file, self.bundle_endpoint, self.mesh) {
            (Some(path), None, false) => Ok(TrustSourceRequest::Uploaded {
                bundle: bundle_from(&path)?,
            }),
            (None, Some(url), false) => Ok(TrustSourceRequest::BundleEndpoint { url }),
            (None, None, true) => Ok(TrustSourceRequest::Mesh),
            // Clap allows exactly one; this is said for completeness.
            _ => TrustSourceRequest::from_parts("", None, None),
        }
    }
}

/// A trust domain, a fact a line: what `add`, `replace` and `show` print
/// after their first line. The bundle is named by its SHA-256, as the
/// audit log names it, and never printed.
fn described(domain: &TrustDomain) -> String {
    let state = domain.snapshot();
    let mut said = format!("name {}\nsource {}", state.name, state.source.as_str());
    if let Some(url) = &state.bundle_endpoint_url {
        let _ = write!(said, "\nbundle-endpoint {url}");
    }
    if let Some(bundle) = &state.bundle {
        let mut digest = String::with_capacity(64);
        for byte in Sha256Digest.sha256(bundle.document().as_bytes()) {
            let _ = write!(digest, "{byte:02x}");
        }
        if let Some(sequence) = bundle.sequence() {
            let _ = write!(said, "\nsequence {sequence}");
        }
        if let Some(hint) = bundle.refresh_hint() {
            let _ = write!(said, "\nrefresh-hint {hint}");
        }
        let _ = write!(
            said,
            "\nx509-authorities {}\njwt-authorities {}\nbundle-sha256 {digest}",
            bundle.authorities(SvidKind::X509),
            bundle.authorities(SvidKind::Jwt),
        );
    }
    if let Some(changed) = state.bundle_changed_at {
        let _ = write!(said, "\nbundle-changed {}", written(changed));
    }
    if let Some(fetched) = state.fetched_at {
        let _ = write!(said, "\nfetched {}", written(fetched));
    }
    if let Some(next) = state.next_refresh_at {
        let _ = write!(said, "\nnext-fetch {}", written(next));
    }
    if let Some(since) = state.failing_since {
        let _ = write!(said, "\nfailing-since {}", written(since));
    }
    if let Some(error) = &state.last_error {
        let _ = write!(said, "\nlast-error {error}");
    }
    said
}

/// One line of `list`: identifier, name and source, and for a bundle
/// endpoint whether its last fetch read.
fn line(domain: &TrustDomain) -> String {
    let state = domain.snapshot();
    let mut said = format!("{} {} {}", state.id, state.name, state.source.as_str());
    match (state.failing_since, &state.last_error, state.fetched_at) {
        (Some(since), Some(error), _) => {
            let _ = write!(said, " failing-since {} {error}", written(since));
        }
        (_, _, Some(fetched)) if state.bundle_endpoint_url.is_some() => {
            let _ = write!(said, " fetched {}", written(fetched));
        }
        _ => {}
    }
    said
}

/// The tenant's trust domain of `name`.
async fn named(
    service: &TrustDomainService,
    tenant: &TenantContext,
    name: &str,
) -> Result<TrustDomain, DomainError> {
    service
        .find_by_name(tenant, name)
        .await?
        .ok_or_else(|| not_found(name))
}

/// Runs one command against the tenant it names. `development_hosts` is
/// `HODOR_OUTBOUND_DEVELOPMENT_HOSTS`, as the server has it: empty
/// anywhere real.
pub(crate) async fn run(
    database: &Database,
    development_hosts: &[String],
    command: TrustDomainCommand,
) -> Result<String, DomainError> {
    let tenant = match &command {
        TrustDomainCommand::Add { tenant, .. }
        | TrustDomainCommand::List { tenant }
        | TrustDomainCommand::Show { tenant, .. }
        | TrustDomainCommand::Replace { tenant, .. }
        | TrustDomainCommand::Remove { tenant, .. } => tenant.clone(),
    };
    let tenants = TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    let context = TenantContext::assume(existing(&tenants, &tenant).await?.tenant_id);
    // A bundle endpoint is checked and fetched as the server does it: the
    // guarded client, the size of a bundle, the development exception.
    let guarded = || {
        GuardedHttpClient::new(OutboundPolicy {
            development_hosts: development_hosts
                .iter()
                .map(|host| host.trim().to_owned())
                .filter(|host| !host.is_empty())
                .collect(),
            max_response_bytes: MAX_BUNDLE_BYTES + 1,
            ..OutboundPolicy::default()
        })
    };
    let service = TrustDomainService::new(TrustDomainPorts {
        units_of_work: Arc::new(database.clone()),
        store: Arc::new(PgTrustDomainStore),
        destinations: Arc::new(guarded()?),
        http: Arc::new(guarded()?),
        digest: Arc::new(Sha256Digest),
        clock: Arc::new(SystemClock),
    });

    match command {
        TrustDomainCommand::Add { name, source, .. } => {
            let domain = service
                .add(&context, &name, source.request()?, caller())
                .await?;
            Ok(format!("added {}\n{}", domain.id(), described(&domain)))
        }
        TrustDomainCommand::List { .. } => {
            let mut lines = Vec::new();
            let mut page = PageRequest::new(Some(PageRequest::MAX_LIMIT), None);
            loop {
                let found = service.list(&context, &page).await?;
                lines.extend(found.items.iter().map(line));
                match found.next_cursor {
                    Some(cursor) => {
                        page = PageRequest::new(Some(PageRequest::MAX_LIMIT), Some(cursor));
                    }
                    None => break,
                }
            }
            Ok(lines.join("\n"))
        }
        TrustDomainCommand::Show { name, .. } => {
            let domain = named(&service, &context, &name).await?;
            Ok(format!(
                "trust-domain {}\n{}",
                domain.id(),
                described(&domain)
            ))
        }
        TrustDomainCommand::Replace { name, source, .. } => {
            // The source is read before anything is looked up, so that a
            // file that cannot be read is said first.
            let source = source.request()?;
            let id = named(&service, &context, &name).await?.id();
            let domain = service.replace(&context, id, source, caller()).await?;
            Ok(format!("replaced {}\n{}", domain.id(), described(&domain)))
        }
        TrustDomainCommand::Remove { name, .. } => {
            let id = named(&service, &context, &name).await?.id();
            service.remove(&context, id, caller()).await?;
            Ok(format!("removed {id} {name}"))
        }
    }
}
