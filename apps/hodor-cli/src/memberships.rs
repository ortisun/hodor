//! The commands for groups and organizations.
//!
//! Specified in `docs/architecture/contexts/identity.md`, "Command-line
//! tool". The rules are the identity context's, so a value the
//! administration interface refuses is refused here with the same code.

use crate::{caller, existing};
use clap::{Subcommand, ValueEnum};
use hodor_adapters_crypto::{
    Argon2Parameters, Argon2idHasher, HashingLimits, OsRandom, Sha256Digest,
};
use hodor_adapters_postgres::{
    Database, PgGroupPolicy, PgGroupRepository, PgInvitationRepository, PgMessageQueue,
    PgOrganizationRepository, PgPasswordStore, PgTenantDirectory, PgTenantRepository,
    PgUserRepository,
};
use hodor_authentication::api::{InvitationContexts, InvitationService};
use hodor_credential::api::CredentialService;
use hodor_identity::api::{
    GroupMember, GroupService, IdentityService, OrganizationService, UnitKind,
};
use hodor_kernel::{
    DomainError, GroupId, OrganizationId, PageRequest, SystemClock, TenantContext, UserId,
};
use hodor_notification::api::Notifier;
use hodor_tenant::api::TenantService;
use std::collections::BTreeSet;
use std::sync::Arc;

#[derive(Subcommand)]
pub(crate) enum GroupCommand {
    /// Create a group.
    Create {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// Its name, unique in the tenant without regard to case.
        #[arg(long)]
        name: String,
        /// What it is for.
        #[arg(long)]
        description: Option<String>,
    },
    /// List the tenant's groups.
    List {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
    /// Add a user or a group to a group.
    Add(MemberArgs),
    /// Take a user or a group out of a group.
    Remove(MemberArgs),
    /// Delete a group, with every membership it is part of.
    Delete {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The group's identifier.
        #[arg(long)]
        group: GroupId,
    },
}

#[derive(clap::Args)]
pub(crate) struct MemberArgs {
    /// Slug of the tenant.
    #[arg(long)]
    tenant: String,
    /// The group's identifier.
    #[arg(long)]
    group: GroupId,
    /// The user to add or take out.
    #[arg(
        long,
        conflicts_with = "member_group",
        required_unless_present = "member_group"
    )]
    user: Option<UserId>,
    /// The group to add or take out.
    #[arg(long)]
    member_group: Option<GroupId>,
}

impl MemberArgs {
    fn member(&self) -> GroupMember {
        match (self.user, self.member_group) {
            (Some(user), _) => GroupMember::User(user),
            (None, Some(group)) => GroupMember::Group(group),
            (None, None) => unreachable!("clap requires one of them"),
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum KindArg {
    Unit,
    Department,
}

#[derive(Subcommand)]
pub(crate) enum OrganizationCommand {
    /// Create an organization.
    Create {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// Its name, unique in the tenant without regard to case.
        #[arg(long)]
        name: String,
        /// What it is.
        #[arg(long)]
        description: Option<String>,
    },
    /// List the tenant's organizations.
    List {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
    },
    /// Create a unit of an organization.
    Unit {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The organization's identifier.
        #[arg(long)]
        organization: OrganizationId,
        /// The unit's name, unique among the units with the same parent.
        #[arg(long)]
        name: String,
        /// What the organization calls it.
        #[arg(long, value_enum, default_value = "unit")]
        kind: KindArg,
        /// The unit it is part of. Left out: at the top.
        #[arg(long)]
        parent: Option<hodor_identity::api::UnitId>,
    },
    /// Make a user a member with the given units, or replace a member's units.
    Member {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The organization's identifier.
        #[arg(long)]
        organization: OrganizationId,
        /// The user.
        #[arg(long)]
        user: UserId,
        /// A unit the user is in; given once for each.
        #[arg(long = "unit")]
        units: Vec<hodor_identity::api::UnitId>,
    },
    /// Invite an email address. A worker delivers the message.
    Invite {
        /// Slug of the tenant.
        #[arg(long)]
        tenant: String,
        /// The organization's identifier.
        #[arg(long)]
        organization: OrganizationId,
        /// The address to invite.
        #[arg(long)]
        email: String,
        /// A unit the person will be in; given once for each.
        #[arg(long = "unit")]
        units: Vec<hodor_identity::api::UnitId>,
        /// The language of the message, such as pt-BR.
        #[arg(long)]
        locale: Option<String>,
    },
}

fn tenants(database: &Database) -> TenantService {
    TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    )
}

async fn tenant_of(database: &Database, slug: &str) -> Result<TenantContext, DomainError> {
    Ok(TenantContext::assume(
        existing(&tenants(database), slug).await?.tenant_id,
    ))
}

pub(crate) fn groups(database: &Database) -> GroupService {
    GroupService::new(
        Arc::new(database.clone()),
        Arc::new(PgGroupRepository),
        Arc::new(PgUserRepository),
        Arc::new(PgGroupPolicy),
        Arc::new(SystemClock),
    )
}

pub(crate) fn organizations(database: &Database) -> OrganizationService {
    OrganizationService::new(
        Arc::new(database.clone()),
        Arc::new(PgOrganizationRepository),
        Arc::new(PgInvitationRepository),
        Arc::new(PgUserRepository),
        Arc::new(SystemClock),
    )
}

fn invitations(database: &Database, public_url: &str) -> Result<InvitationService, DomainError> {
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let random = Arc::new(OsRandom);
    // Inviting sets no password; the hasher is only what the service is
    // built with.
    let hasher = Arc::new(Argon2idHasher::new(
        Argon2Parameters::default(),
        HashingLimits {
            concurrent: 1,
            queued: 1,
        },
        random.clone(),
    )?);
    Ok(InvitationService::new(
        units(),
        InvitationContexts {
            organizations: organizations(database),
            identity: IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone()),
            credentials: CredentialService::new(
                units(),
                Arc::new(PgPasswordStore),
                hasher,
                clock.clone(),
            ),
            tenants: tenants(database),
            notifier: Notifier::new(Arc::new(PgMessageQueue), clock),
        },
        Arc::new(Sha256Digest),
        random,
        public_url,
    ))
}

pub(crate) async fn run_group(
    database: &Database,
    command: GroupCommand,
) -> Result<String, DomainError> {
    let service = groups(database);
    match command {
        GroupCommand::Create {
            tenant,
            name,
            description,
        } => {
            let tenant = tenant_of(database, &tenant).await?;
            let group = service
                .create(&tenant, &name, description, caller())
                .await?;
            Ok(format!("created {} {}", group.id(), group.name().as_str()))
        }
        GroupCommand::List { tenant } => {
            let tenant = tenant_of(database, &tenant).await?;
            let mut lines = Vec::new();
            let mut page = PageRequest::new(Some(200), None);
            loop {
                let found = service.list(&tenant, &page).await?;
                lines.extend(
                    found
                        .items
                        .iter()
                        .map(|group| format!("{} {}", group.id(), group.name().as_str())),
                );
                match found.next_cursor {
                    Some(cursor) => page = PageRequest::new(Some(200), Some(cursor)),
                    None => break,
                }
            }
            Ok(lines.join("\n"))
        }
        GroupCommand::Add(args) => {
            let tenant = tenant_of(database, &args.tenant).await?;
            service
                .add_member(&tenant, args.group, args.member(), caller())
                .await?;
            Ok(format!(
                "added {} to {}",
                args.member().id_text(),
                args.group
            ))
        }
        GroupCommand::Remove(args) => {
            let tenant = tenant_of(database, &args.tenant).await?;
            service
                .remove_member(&tenant, args.group, args.member(), caller())
                .await?;
            Ok(format!(
                "removed {} from {}",
                args.member().id_text(),
                args.group
            ))
        }
        GroupCommand::Delete { tenant, group } => {
            let tenant = tenant_of(database, &tenant).await?;
            service.delete(&tenant, group, caller()).await?;
            Ok(format!("deleted {group}"))
        }
    }
}

pub(crate) async fn run_organization(
    database: &Database,
    public_url: &str,
    command: OrganizationCommand,
) -> Result<String, DomainError> {
    let service = organizations(database);
    match command {
        OrganizationCommand::Create {
            tenant,
            name,
            description,
        } => {
            let tenant = tenant_of(database, &tenant).await?;
            let organization = service
                .create(&tenant, &name, description, caller())
                .await?;
            Ok(format!(
                "created {} {}",
                organization.id(),
                organization.name().as_str()
            ))
        }
        OrganizationCommand::List { tenant } => {
            let tenant = tenant_of(database, &tenant).await?;
            let mut lines = Vec::new();
            let mut page = PageRequest::new(Some(200), None);
            loop {
                let found = service.list(&tenant, &page).await?;
                lines.extend(found.items.iter().map(|organization| {
                    format!("{} {}", organization.id(), organization.name().as_str())
                }));
                match found.next_cursor {
                    Some(cursor) => page = PageRequest::new(Some(200), Some(cursor)),
                    None => break,
                }
            }
            Ok(lines.join("\n"))
        }
        OrganizationCommand::Unit {
            tenant,
            organization,
            name,
            kind,
            parent,
        } => {
            let tenant = tenant_of(database, &tenant).await?;
            let kind = match kind {
                KindArg::Unit => UnitKind::Unit,
                KindArg::Department => UnitKind::Department,
            };
            let unit = service
                .create_unit(&tenant, organization, parent, &name, kind, caller())
                .await?;
            Ok(format!("created {} {}", unit.id, unit.name.as_str()))
        }
        OrganizationCommand::Member {
            tenant,
            organization,
            user,
            units,
        } => {
            let tenant = tenant_of(database, &tenant).await?;
            let units: BTreeSet<_> = units.into_iter().collect();
            let member = service
                .organizations_of(&tenant, user)
                .await?
                .iter()
                .any(|membership| membership.organization == organization);
            let membership = if member {
                service
                    .change_member_units(&tenant, organization, user, units, caller())
                    .await?
            } else {
                service
                    .add_member(&tenant, organization, user, units, caller())
                    .await?
            };
            Ok(format!(
                "{} is a member of {} in {} units",
                membership.user,
                organization,
                membership.units.len()
            ))
        }
        OrganizationCommand::Invite {
            tenant,
            organization,
            email,
            units,
            locale,
        } => {
            let tenant = tenant_of(database, &tenant).await?;
            invitations(database, public_url)?
                .invite(
                    &tenant,
                    organization,
                    &email,
                    units.into_iter().collect(),
                    locale.as_deref(),
                    caller(),
                )
                .await?;
            Ok(format!("invited {email}"))
        }
    }
}
