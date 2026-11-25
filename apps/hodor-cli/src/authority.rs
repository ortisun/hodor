//! The commands for the intermediates a tenant's certificate authority
//! signs: signing one from a mesh's certificate signing request, listing
//! them and withdrawing one.
//!
//! Specified in `docs/architecture/contexts/keys.md`, "From the
//! command-line tool". The use cases are the keys context's own, so a
//! request the administration interface refuses is refused here with the
//! same code and reason.

use crate::{caller, existing, key_providers};
use clap::Subcommand;
use hodor_adapters_crypto::{SecretKeys, Sha256Digest, X509Certificates};
use hodor_adapters_postgres::{
    Database, PgAuthorityStore, PgIntermediateStore, PgTenantDirectory, PgTenantRepository,
    PgTrustDomainStore,
};
use hodor_kernel::{DomainError, PageRequest, Secret, SystemClock, TenantContext};
use hodor_keys::api::{
    AuthorityPorts, AuthorityService, AuthoritySetting, IntermediateId, SignedIntermediate, to_pem,
};
use hodor_tenant::api::TenantService;
use std::io::Read as _;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

#[derive(Subcommand)]
pub(crate) enum AuthorityCommand {
    /// Sign a mesh's intermediate from its certificate signing request,
    /// and print the certificate followed by the chain above it, in PEM.
    Sign {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The file holding the request in PEM, or `-` for standard input.
        #[arg(long)]
        request: String,
        /// How long it lives, in days: the authority's bound unless given.
        #[arg(long)]
        lifetime_days: Option<u32>,
    },
    /// List the intermediates of the tenant's authority, newest first.
    Intermediates {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
    /// Withdraw an intermediate, with every other of its key: Hodor stops
    /// trusting it at once.
    Withdraw {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The intermediate's identifier, as `intermediates` prints it.
        #[arg(long)]
        intermediate: IntermediateId,
        /// Why, for the audit log: 1 to 200 characters.
        #[arg(long)]
        reason: String,
    },
}

/// What the command needs of the installation, as the server has it.
pub(crate) struct Installation {
    /// `HODOR_SECRET_KEYS`.
    pub(crate) secret_keys: Option<String>,
    /// `HODOR_CERTIFICATE_AUTHORITY`.
    pub(crate) setting: Option<String>,
}

/// What a command printed: on standard output, and a line for standard
/// error.
pub(crate) struct Printed {
    /// For standard output.
    pub(crate) output: String,
    /// For standard error, if anything.
    pub(crate) note: Option<String>,
}

fn line(intermediate: &SignedIntermediate) -> String {
    let state = intermediate.snapshot();
    format!(
        "{} {} {} {} {}",
        state.id,
        state.state.as_str(),
        state.serial_number,
        state.not_after.format(&Rfc3339).unwrap_or_default(),
        state.subject
    )
}

/// The authority's use cases, as the server builds them.
fn service(
    database: &Database,
    installation: Installation,
) -> Result<AuthorityService, DomainError> {
    let setting = AuthoritySetting::parse(installation.setting.as_deref())?;
    if setting == AuthoritySetting::Off {
        return Err(DomainError::invalid(
            "keys.authority_setting_invalid",
            "HODOR_CERTIFICATE_AUTHORITY is `off`: set it to `on` or `development` as the server \
             has it",
        ));
    }
    let secret_keys = installation.secret_keys.ok_or_else(|| {
        DomainError::invalid(
            "secret.keys_missing",
            "HODOR_SECRET_KEYS or --secret-keys is required: the authority lives in the keys \
             context",
        )
    })?;
    let providers = key_providers(Arc::new(SecretKeys::parse(&Secret::from(secret_keys))?))?;
    Ok(AuthorityService::new(
        AuthorityPorts {
            units_of_work: Arc::new(database.clone()),
            store: Arc::new(PgAuthorityStore),
            trust_domains: Arc::new(PgTrustDomainStore),
            intermediates: Arc::new(PgIntermediateStore),
            maker: providers.authorities(),
            signer: Arc::new(providers),
            certificates: Arc::new(X509Certificates),
            digest: Arc::new(Sha256Digest),
            clock: Arc::new(SystemClock),
        },
        setting == AuthoritySetting::Development,
    ))
}

fn read_request(source: &str) -> Result<String, DomainError> {
    let unreadable = |error: std::io::Error| {
        DomainError::invalid(
            "keys.intermediate_request_invalid",
            "the certificate signing request could not be read",
        )
        .with_detail(error.kind().to_string())
    };
    if source == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(unreadable)?;
        Ok(text)
    } else {
        std::fs::read_to_string(source).map_err(unreadable)
    }
}

/// Runs an authority command.
pub(crate) async fn run(
    database: &Database,
    installation: Installation,
    command: AuthorityCommand,
) -> Result<Printed, DomainError> {
    let tenants = TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    let slug = match &command {
        AuthorityCommand::Sign { tenant, .. }
        | AuthorityCommand::Intermediates { tenant }
        | AuthorityCommand::Withdraw { tenant, .. } => tenant.clone(),
    };
    let service = service(database, installation)?;
    let entry = existing(&tenants, &slug).await?;
    // The command-line tool is one of the places allowed to establish a
    // tenant context: the operator names the tenant.
    let tenant = TenantContext::assume(entry.tenant_id);
    match command {
        AuthorityCommand::Sign {
            request,
            lifetime_days,
            ..
        } => {
            let pem = read_request(&request)?;
            let signed = service.sign(&tenant, &pem, lifetime_days, caller()).await?;
            let mut output = to_pem("CERTIFICATE", &signed.intermediate.snapshot().certificate);
            for above in &signed.chain {
                output.push_str(&to_pem("CERTIFICATE", above));
            }
            Ok(Printed {
                output: output.trim_end().to_owned(),
                note: Some(format!("signed {}", line(&signed.intermediate))),
            })
        }
        AuthorityCommand::Intermediates { .. } => {
            let mut lines = Vec::new();
            let mut page = PageRequest::new(Some(PageRequest::MAX_LIMIT), None);
            loop {
                let (found, _) = service.intermediates(&tenant, &page).await?;
                lines.extend(found.items.iter().map(line));
                match found.next_cursor {
                    Some(cursor) => {
                        page = PageRequest::new(Some(PageRequest::MAX_LIMIT), Some(cursor))
                    }
                    None => break,
                }
            }
            Ok(Printed {
                output: lines.join("\n"),
                note: None,
            })
        }
        AuthorityCommand::Withdraw {
            intermediate,
            reason,
            ..
        } => {
            let (withdrawn, _) = service
                .withdraw(&tenant, intermediate, &reason, caller())
                .await?;
            Ok(Printed {
                output: withdrawn
                    .iter()
                    .map(|row| format!("withdrawn {}", line(row)))
                    .collect::<Vec<_>>()
                    .join("\n"),
                note: None,
            })
        }
    }
}
