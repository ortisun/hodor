//! The commands for the record of decisions.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "The
//! record of decisions". The settings are checked by the authorization
//! context, so a value refused by the administration interface is refused
//! here with the same code.

use crate::{caller, existing};
use clap::{Subcommand, ValueEnum};
use hodor_adapters_crypto::OsRandom;
use hodor_adapters_postgres::{
    Database, PgDecisionLogStore, PgTenantDirectory, PgTenantRepository,
};
use hodor_authorization::api::{
    DecisionFilter, DecisionLog, DecisionLogMode, DecisionLogSettings, Effect, MaskPath,
    SubjectKind,
};
use hodor_kernel::{Cursor, DomainError, PageRequest, SystemClock, TenantContext};
use hodor_tenant::api::TenantService;
use std::fmt::Write as _;
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Subcommand)]
pub(crate) enum AuthorizationCommand {
    /// Read or set what the record of decisions keeps.
    DecisionLog {
        #[command(subcommand)]
        command: DecisionLogCommand,
    },
    /// Print recorded decisions, newest first, one per line.
    Decisions {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// Decided at or after this RFC 3339 time.
        #[arg(long)]
        since: Option<String>,
        /// Decided before this RFC 3339 time.
        #[arg(long)]
        until: Option<String>,
        /// Only this effect.
        #[arg(long, value_enum)]
        effect: Option<EffectArg>,
        /// Only about this resource server.
        #[arg(long)]
        namespace: Option<String>,
        /// Only about this subject, written `user:<id>` or `client:<id>`.
        #[arg(long)]
        subject: Option<String>,
        /// How many, at most 200.
        #[arg(long, default_value_t = 50)]
        limit: u32,
        /// Where the last page ended, as it printed.
        #[arg(long)]
        cursor: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum DecisionLogCommand {
    /// Print the settings in force.
    Show {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
    /// Replace the settings.
    Set {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// Which decisions are recorded.
        #[arg(long, value_enum)]
        mode: ModeArg,
        /// The share of allows kept, from 1 to 99 percent, with `sampled`.
        #[arg(long)]
        allow_sample_percent: Option<u8>,
        /// A path erased from the input before a record is stored; repeat
        /// for more, at most 32.
        #[arg(long = "mask")]
        masks: Vec<String>,
        /// How many days records are kept, from 1 to 400.
        #[arg(long, default_value_t = 30)]
        retention_days: u16,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum ModeArg {
    Full,
    Sampled,
    DenyOnly,
    Off,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum EffectArg {
    Allow,
    Deny,
    Indeterminate,
}

async fn context(
    database: &Database,
    slug: &str,
) -> Result<(TenantContext, DecisionLog), DomainError> {
    let tenants = TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    let entry = existing(&tenants, slug).await?;
    let log = DecisionLog::new(
        Arc::new(database.clone()),
        Arc::new(PgDecisionLogStore),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    );
    Ok((TenantContext::assume(entry.tenant_id), log))
}

fn settings_lines(settings: &DecisionLogSettings) -> String {
    let mut out = format!("mode {}", settings.mode().as_str());
    if let Some(share) = settings.mode().allow_percent() {
        let _ = write!(out, "\nallow_sample_percent {share}");
    }
    for mask in settings.masks() {
        let _ = write!(out, "\nmask {}", mask.as_str());
    }
    let _ = write!(out, "\nretention_days {}", settings.retention_days());
    out
}

fn time_of(value: &str) -> Result<OffsetDateTime, DomainError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| DomainError::invalid("request.query_invalid", "times are written in RFC 3339"))
}

const fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
        Effect::Indeterminate => "indeterminate",
    }
}

/// Runs a command on the record of decisions.
pub(crate) async fn run_authorization(
    database: &Database,
    command: AuthorizationCommand,
) -> Result<String, DomainError> {
    match command {
        AuthorizationCommand::DecisionLog {
            command: DecisionLogCommand::Show { tenant },
        } => {
            let (tenant, log) = context(database, &tenant).await?;
            Ok(settings_lines(&log.settings(&tenant).await?))
        }
        AuthorizationCommand::DecisionLog {
            command:
                DecisionLogCommand::Set {
                    tenant,
                    mode,
                    allow_sample_percent,
                    masks,
                    retention_days,
                },
        } => {
            let name = match mode {
                ModeArg::Full => "full",
                ModeArg::Sampled => "sampled",
                ModeArg::DenyOnly => "deny_only",
                ModeArg::Off => "off",
            };
            let mode = DecisionLogMode::parse(name, allow_sample_percent)?;
            let masks = masks
                .iter()
                .map(|mask| MaskPath::parse(mask))
                .collect::<Result<Vec<_>, _>>()?;
            let settings = DecisionLogSettings::new(mode, masks, retention_days)?;
            let (tenant, log) = context(database, &tenant).await?;
            let now = log.replace_settings(&tenant, settings, caller()).await?;
            Ok(settings_lines(&now))
        }
        AuthorizationCommand::Decisions {
            tenant,
            since,
            until,
            effect,
            namespace,
            subject,
            limit,
            cursor,
        } => {
            let subject = subject
                .map(|written| {
                    let (kind, id) = written.split_once(':').ok_or_else(|| {
                        DomainError::invalid(
                            "request.query_invalid",
                            "a subject is written user:<id> or client:<id>",
                        )
                    })?;
                    Ok::<_, DomainError>((SubjectKind::parse(kind)?, id.to_owned()))
                })
                .transpose()?;
            let filter = DecisionFilter {
                from: since.as_deref().map(time_of).transpose()?,
                to: until.as_deref().map(time_of).transpose()?,
                effect: effect.map(|effect| match effect {
                    EffectArg::Allow => Effect::Allow,
                    EffectArg::Deny => Effect::Deny,
                    EffectArg::Indeterminate => Effect::Indeterminate,
                }),
                namespace,
                subject,
            };
            let (tenant, log) = context(database, &tenant).await?;
            let page = log
                .page(
                    &tenant,
                    &filter,
                    &PageRequest::new(Some(limit), cursor.map(Cursor::new)),
                )
                .await?;
            let mut out = String::new();
            for record in &page.items {
                let _ = writeln!(
                    out,
                    "{} {} {} {} {}:{} {} {}{} {}",
                    record.decided_at.format(&Rfc3339).unwrap_or_default(),
                    record.decision_id,
                    effect_name(record.effect),
                    record.reason,
                    record.subject_kind.as_str(),
                    record.subject_id,
                    record.action,
                    record.resource_type,
                    record
                        .resource_id
                        .as_ref()
                        .map(|id| format!("/{id}"))
                        .unwrap_or_default(),
                    record.namespace,
                );
            }
            if let Some(next) = page.next_cursor {
                let _ = write!(out, "next {}", next.as_str());
            }
            Ok(out.trim_end().to_owned())
        }
    }
}
