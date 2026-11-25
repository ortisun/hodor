//! The commands for a person's standard claims.
//!
//! Specified in `docs/architecture/contexts/identity.md`, "Command-line
//! tool". The rules are the identity context's, so a value the
//! administration interface refuses is refused here with the same code.

use crate::{caller, existing};
use clap::Subcommand;
use hodor_adapters_postgres::{Database, PgTenantDirectory, PgTenantRepository, PgUserRepository};
use hodor_identity::api::{ClaimField, IdentityService, StandardClaims, User};
use hodor_kernel::{DomainError, SystemClock, TenantContext, UserId};
use hodor_tenant::api::TenantService;
use std::sync::Arc;

#[derive(Subcommand)]
pub(crate) enum UserCommand {
    /// Change a person's standard claims and print them. The claims not
    /// given are kept; an empty value removes one. Without any, only
    /// prints.
    Claims(Box<ClaimArgs>),
}

#[derive(clap::Args)]
pub(crate) struct ClaimArgs {
    /// Slug of the tenant.
    #[arg(long)]
    tenant: String,
    /// The user: its identifier, or a username or an email address it has.
    #[arg(long)]
    user: String,
    /// `given_name`.
    #[arg(long)]
    given_name: Option<String>,
    /// `family_name`.
    #[arg(long)]
    family_name: Option<String>,
    /// `middle_name`.
    #[arg(long)]
    middle_name: Option<String>,
    /// `nickname`.
    #[arg(long)]
    nickname: Option<String>,
    /// `profile`: the address of the person's page elsewhere.
    #[arg(long)]
    profile: Option<String>,
    /// `picture`: the address of a picture of the person.
    #[arg(long)]
    picture: Option<String>,
    /// `website`.
    #[arg(long)]
    website: Option<String>,
    /// `gender`.
    #[arg(long)]
    gender: Option<String>,
    /// `birthdate`: `YYYY-MM-DD`, `0000-MM-DD` or `YYYY`.
    #[arg(long)]
    birthdate: Option<String>,
    /// `zoneinfo`: a name of the time zone database, such as `Europe/Paris`.
    #[arg(long)]
    zoneinfo: Option<String>,
    /// `phone_number`, in E.164.
    #[arg(long)]
    phone_number: Option<String>,
    /// Whether someone vouched for the telephone number.
    #[arg(long)]
    phone_number_verified: Option<bool>,
    /// The whole postal address.
    #[arg(long)]
    formatted_address: Option<String>,
    /// The street of the postal address.
    #[arg(long)]
    street_address: Option<String>,
    /// The city or locality.
    #[arg(long)]
    locality: Option<String>,
    /// The state or region.
    #[arg(long)]
    region: Option<String>,
    /// The postal code.
    #[arg(long)]
    postal_code: Option<String>,
    /// The country.
    #[arg(long)]
    country: Option<String>,
}

impl ClaimArgs {
    /// Each field given, with its value.
    fn given(&self) -> Vec<(ClaimField, &str)> {
        [
            (ClaimField::GivenName, &self.given_name),
            (ClaimField::FamilyName, &self.family_name),
            (ClaimField::MiddleName, &self.middle_name),
            (ClaimField::Nickname, &self.nickname),
            (ClaimField::Profile, &self.profile),
            (ClaimField::Picture, &self.picture),
            (ClaimField::Website, &self.website),
            (ClaimField::Gender, &self.gender),
            (ClaimField::Birthdate, &self.birthdate),
            (ClaimField::Zoneinfo, &self.zoneinfo),
            (ClaimField::PhoneNumber, &self.phone_number),
            (ClaimField::AddressFormatted, &self.formatted_address),
            (ClaimField::AddressStreetAddress, &self.street_address),
            (ClaimField::AddressLocality, &self.locality),
            (ClaimField::AddressRegion, &self.region),
            (ClaimField::AddressPostalCode, &self.postal_code),
            (ClaimField::AddressCountry, &self.country),
        ]
        .into_iter()
        .filter_map(|(field, value)| value.as_deref().map(|value| (field, value)))
        .collect()
    }
}

fn identity(database: &Database) -> IdentityService {
    IdentityService::new(
        Arc::new(database.clone()),
        Arc::new(PgUserRepository),
        Arc::new(SystemClock),
    )
}

async fn tenant_of(database: &Database, slug: &str) -> Result<TenantContext, DomainError> {
    let tenants = TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    Ok(TenantContext::assume(
        existing(&tenants, slug).await?.tenant_id,
    ))
}

/// The user named by its identifier, or by a login identifier it has.
async fn named(
    service: &IdentityService,
    tenant: &TenantContext,
    named: &str,
) -> Result<User, DomainError> {
    if let Ok(id) = named.parse::<UserId>() {
        return service.get(tenant, id).await;
    }
    service
        .find_by_login(tenant, named)
        .await?
        .ok_or_else(not_found)
}

fn not_found() -> DomainError {
    DomainError::not_found("identity.user_not_found", "the user does not exist")
}

/// One line per claim the person has, `address.` and the part for the
/// parts of the address, then whether the number is verified.
fn printed(user: &User) -> String {
    let claims = &user.snapshot().claims;
    let mut lines: Vec<String> = ClaimField::ALL
        .into_iter()
        .filter_map(|field| {
            claims
                .get(field)
                .map(|value| format!("{} {}", field.as_str(), value.replace('\n', "\\n")))
        })
        .collect();
    if claims.phone_number.is_some() {
        lines.push(format!(
            "phone_number_verified {}",
            claims.phone_number_verified
        ));
    }
    lines.join("\n")
}

pub(crate) async fn run(database: &Database, command: UserCommand) -> Result<String, DomainError> {
    let service = identity(database);
    match command {
        UserCommand::Claims(arguments) => {
            let tenant = tenant_of(database, &arguments.tenant).await?;
            let user = named(&service, &tenant, &arguments.user).await?;
            let given = arguments.given();
            if given.is_empty() && arguments.phone_number_verified.is_none() {
                return Ok(printed(&user));
            }
            let mut claims: StandardClaims = user.snapshot().claims.clone();
            for (field, value) in given {
                claims.set(field, Some(value.to_owned()));
            }
            if let Some(verified) = arguments.phone_number_verified {
                claims.phone_number_verified = verified;
            } else if arguments.phone_number.is_some() {
                // A new number is not verified unless the operator says so.
                claims.phone_number_verified = false;
            }
            let user = service
                .change_claims(&tenant, user.id(), claims, caller())
                .await?;
            Ok(printed(&user))
        }
    }
}
