//! Operations tool: migrations, tenant management, the first
//! administrator, identity providers, applications, authenticator
//! applications, recovery codes and checking the audit log.

mod applications;
mod authority;
mod decisions;
mod memberships;
mod mesh;
mod policies;
mod registration;
mod roles;
mod trust_domains;
mod users;
mod webhooks;
mod workloads;

use clap::{Parser, Subcommand, ValueEnum};
use hodor_adapters_crypto::{
    AwsLcHmacSha1, BundleSigningKey, LocalKeyProvider, OsRandom, SecretKeys, Sha256Digest,
};
use hodor_adapters_http::{OutboundPolicy, ServiceHttpClient};
use hodor_adapters_kms::KeyProviderSettings;
use hodor_adapters_postgres::{
    Database, PgAccessTokenStore, PgAuditLog, PgBundleStore, PgGroupRepository,
    PgInstanceStatusStore, PgInstanceStore, PgKeyStore, PgLinkStore, PgOrganizationRepository,
    PgPool, PgProviderStore, PgRecoveryCodeStore, PgRoleAssignmentStore, PgSealingStateStore,
    PgTenantDirectory, PgTenantRepository, PgTotpStore, PgUploadedDecisionStore, PgUserRepository,
    reseal_tenant,
};
use hodor_audit::api::AuditService;
use hodor_authorization::api::{AuthorizationService, Namespace, Role};
use hodor_authorization_opa::api::{BundleFile, BundleService, bundle_name, decision_path};
use hodor_credential::api::{AccessTokenService, RecoveryCodeService, RecoveryCodes, TotpService};
use hodor_federation::api::{
    CreateProvider, DirectorySettings, FederationService, IdentityProvider, ProviderKind,
    ProviderSettings, ProviderStatus, SamlSettings, callback_address, saml_metadata_address,
};
use hodor_identity::api::{
    CreateUser, IdentifierKind, IdentityService, NormalizedIdentifier, Profile, UserKind,
};
use hodor_kernel::{
    Actor, CorrelationId, DomainError, HttpClient, Secret, SecretBox, SystemClock, TenantContext,
};
use hodor_keys::api::{
    KeyAlgorithm, KeyProvider, KeyProviders, KeyService, KeyState, KeyUse, KeyVersion,
    KeyVersionId, RotationPolicy, TenantSecretBox,
};
use hodor_tenant::api::{
    AssuranceLevel, AssuranceLevels, AssuranceRequirement, Caller, CreateTenant, Deprovisioning,
    DirectoryEntry, SecondFactorPolicy, TenantDirectory as _, TenantService,
};
use std::error::Error;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// Operate a Hodor installation.
#[derive(Parser)]
#[command(name = "hodor-cli", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[allow(
    clippy::large_enum_variant,
    reason = "parsed once when the tool starts; its size does not matter"
)]
#[derive(Subcommand)]
enum Command {
    /// Apply pending database migrations.
    ///
    /// Connects as the role that owns the schema. The server and worker use
    /// a different, less privileged role and never run migrations.
    Migrate {
        /// Connection URL of the schema owner.
        #[arg(long, env = "HODOR_DATABASE_OWNER_URL", hide_env_values = true)]
        database_url: String,
    },

    /// Manage tenants.
    ///
    /// Connects as a member of `hodor_app`; no cross-tenant role is needed.
    Tenant {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: TenantCommand,
    },

    /// Manage administrators.
    Admin {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: AdminCommand,
    },

    /// Check the audit log.
    Audit {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: AuditCommand,
    },

    /// Manage a tenant's identity providers.
    Provider {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        /// The keys that keep secrets encrypted at rest, as the server
        /// has them.
        #[arg(long, env = "HODOR_SECRET_KEYS", hide_env_values = true, global = true)]
        secret_keys: Option<String>,
        /// Hosts with their ports whose issuer may be plain HTTP,
        /// separated by commas, as the server has them. For a development
        /// stack; never set it anywhere real.
        #[arg(
            long,
            env = "HODOR_OUTBOUND_DEVELOPMENT_HOSTS",
            value_delimiter = ',',
            global = true
        )]
        development_hosts: Vec<String>,
        /// The LDAP directories providers may name, as `host:port`
        /// separated by commas, as the server has them.
        #[arg(
            long,
            env = "HODOR_DIRECTORY_HOSTS",
            value_delimiter = ',',
            global = true
        )]
        directory_hosts: Vec<String>,
        /// The address people reach this installation at, without a path.
        #[arg(
            long,
            env = "HODOR_PUBLIC_URL",
            default_value = "http://localhost:8080",
            global = true
        )]
        public_url: String,
        #[command(subcommand)]
        command: ProviderCommand,
    },

    /// Read and set the record of decisions an application's questions
    /// leave.
    Authorization {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: decisions::AuthorizationCommand,
    },

    /// Manage a tenant's groups and their members.
    Group {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: memberships::GroupCommand,
    },

    /// Manage a person's standard claims.
    User {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: users::UserCommand,
    },

    /// Manage a tenant's organizations, their units and members, and invite
    /// people to them.
    Organization {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        /// The address people reach this installation at, without a path:
        /// links in invitations start with it.
        #[arg(
            long,
            env = "HODOR_PUBLIC_URL",
            default_value = "http://localhost:8080",
            global = true
        )]
        public_url: String,
        #[command(subcommand)]
        command: memberships::OrganizationCommand,
    },

    /// Manage a tenant's service accounts: programs that act on their own.
    ServiceAccount {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: workloads::WorkloadCommand,
    },

    /// Manage a tenant's agents: artificial intelligence agents.
    Agent {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: workloads::WorkloadCommand,
    },

    /// Manage a tenant's applications.
    Application {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: applications::ApplicationCommand,
    },

    /// Manage the clients of a tenant's applications.
    Client {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        /// Hosts with their ports that a back-channel logout address may
        /// name over plain HTTP, separated by commas, as the server has
        /// them. For a development stack; never set it anywhere real.
        #[arg(
            long,
            env = "HODOR_OUTBOUND_DEVELOPMENT_HOSTS",
            value_delimiter = ',',
            global = true
        )]
        development_hosts: Vec<String>,
        #[command(subcommand)]
        command: applications::ClientCommand,
    },

    /// Turn client registration on or off in a tenant, and make, list and
    /// revoke its initial access tokens.
    ClientRegistration {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: registration::RegistrationCommand,
    },

    /// Manage a tenant's resource servers.
    ResourceServer {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: applications::ResourceServerCommand,
    },

    /// Write the policies of a service mesh from Hodor's roles, for the
    /// operator to apply.
    Mesh {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: mesh::MeshCommand,
    },

    /// Manage a tenant's webhook endpoints and their deliveries.
    Webhook {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        /// The keys that keep secrets encrypted at rest, as the server
        /// has them. Registering an endpoint and rotating its secret need
        /// them.
        #[arg(long, env = "HODOR_SECRET_KEYS", hide_env_values = true, global = true)]
        secret_keys: Option<String>,
        /// Hosts with their ports that an endpoint may name at a private
        /// address and over plain HTTP, separated by commas, as the server
        /// has them. For a development stack; never set it anywhere real.
        #[arg(
            long,
            env = "HODOR_OUTBOUND_DEVELOPMENT_HOSTS",
            value_delimiter = ',',
            global = true
        )]
        development_hosts: Vec<String>,
        #[command(subcommand)]
        command: webhooks::WebhookCommand,
    },

    /// Manage the SPIFFE trust domains a tenant trusts, and their bundles.
    TrustDomain {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        /// Hosts with their ports that a bundle endpoint may name at a
        /// private address and over plain HTTP, separated by commas, as the
        /// server has them. For a development stack; never set it anywhere
        /// real.
        #[arg(
            long,
            env = "HODOR_OUTBOUND_DEVELOPMENT_HOSTS",
            value_delimiter = ',',
            global = true
        )]
        development_hosts: Vec<String>,
        #[command(subcommand)]
        command: trust_domains::TrustDomainCommand,
    },

    /// Manage people's authenticator applications, until people can do it
    /// themselves from the account pages.
    Totp {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        /// The keys that keep secrets encrypted at rest, as the server
        /// has them.
        #[arg(long, env = "HODOR_SECRET_KEYS", hide_env_values = true, global = true)]
        secret_keys: Option<String>,
        #[command(subcommand)]
        command: TotpCommand,
    },

    /// Look at a tenant's keys, rotate its signing key and revoke versions.
    ///
    /// Keys rotate by themselves in the worker; these commands are for an
    /// operator who will not wait.
    Keys {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        /// The keys that wrap the tenants' keys, as the server has them.
        #[arg(long, env = "HODOR_SECRET_KEYS", hide_env_values = true, global = true)]
        secret_keys: Option<String>,
        /// How long a signing key replaced by hand stays published, in
        /// hours, as the server and the worker have it.
        #[arg(
            long,
            env = "HODOR_KEY_OVERLAP_HOURS",
            default_value_t = 24,
            global = true
        )]
        key_overlap_hours: i64,
        #[command(subcommand)]
        command: KeysCommand,
    },

    /// Sign, list and withdraw the intermediates a tenant's certificate
    /// authority signs for its meshes.
    Authority {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        /// The keys that wrap the tenants' keys, as the server has them.
        #[arg(long, env = "HODOR_SECRET_KEYS", hide_env_values = true, global = true)]
        secret_keys: Option<String>,
        /// The certificate authority of the tenants, as the server has it:
        /// `on` or `development`.
        #[arg(long, env = "HODOR_CERTIFICATE_AUTHORITY", global = true)]
        certificate_authority: Option<String>,
        #[command(subcommand)]
        command: authority::AuthorityCommand,
    },

    /// Manage people's recovery codes, until people can do it themselves
    /// from the account pages.
    RecoveryCodes {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: RecoveryCodeCommand,
    },

    /// Work with the keys that keep secrets encrypted at rest.
    Secrets {
        #[command(subcommand)]
        command: SecretsCommand,
    },

    /// Register Open Policy Agent instances, publish their bundles and
    /// read what they report.
    PolicyAgent {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: PolicyAgentCommand,
    },

    /// Draft, check, test, simulate, publish and roll back a tenant's
    /// policy for Open Policy Agent.
    Policy {
        /// Connection URL of the application role.
        #[arg(
            long,
            env = "HODOR_DATABASE_URL",
            hide_env_values = true,
            global = true
        )]
        database_url: Option<String>,
        #[command(subcommand)]
        command: policies::PolicyCommand,
    },

    /// Check a health endpoint and exit non-zero unless it answers 200.
    ///
    /// For container health checks: the runtime image has no shell or HTTP
    /// client of its own.
    Probe {
        /// Address of the operations listener.
        #[arg(long, default_value = "127.0.0.1:9090")]
        addr: SocketAddr,
        /// Path to request.
        #[arg(long, default_value = "/readyz")]
        path: String,
    },
}

#[derive(Subcommand)]
enum PolicyAgentCommand {
    /// Make a key that signs bundles, and print it and its public key.
    ///
    /// The private key goes into the file `HODOR_OPEN_POLICY_AGENT_SIGNING_KEY_FILE`
    /// names; the public key into each instance's configuration.
    SigningKey,
    /// Print the name of a tenant's bundle, or with a namespace the Rego
    /// package of a resource server's `decision` rule.
    BundleName {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// A resource server's audience.
        #[arg(long)]
        namespace: Option<String>,
    },
    /// Manage the registered instances.
    Instance {
        #[command(subcommand)]
        command: InstanceCommand,
    },
    /// Show which revision each instance reports for a tenant's bundle.
    Status {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
    },
}

#[derive(Subcommand)]
enum InstanceCommand {
    /// Register an instance and print its credential, once.
    Add {
        /// 1 to 63 lower-case letters, digits and `-`.
        #[arg(long)]
        name: String,
        /// The tenant whose instance it is; without it, a shared instance
        /// that runs only bundles written by the operator.
        #[arg(long)]
        tenant: Option<String>,
    },
    /// List the instances.
    List,
    /// Disable an instance: its credential is refused from now on.
    Disable {
        /// The instance's name.
        #[arg(long)]
        name: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum WrittenByArg {
    Operator,
    Tenant,
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Make a user an administrator of a tenant, creating the user if
    /// needed, and print an access token for the administration interface.
    ///
    /// The token is printed once. Running the command again issues a new
    /// one and leaves earlier ones as they are.
    Bootstrap {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The administrator's email address.
        #[arg(long)]
        email: String,
        /// How long the token lives, in minutes: 1 to 43200 (30 days).
        #[arg(long, default_value_t = 60)]
        token_minutes: u32,
    },
    /// Give a built-in role to a user who exists: a person, a service
    /// account or an agent. The administration interface gives none.
    Grant(RoleArgs),
    /// Take a built-in role away from a user.
    Revoke(RoleArgs),
}

#[derive(clap::Args)]
struct RoleArgs {
    /// The tenant's slug.
    #[arg(long)]
    tenant: String,
    /// The user's identifier.
    #[arg(long)]
    user: hodor_kernel::UserId,
    /// `tenant_administrator`, `tenant_auditor` or `certificate_signer`.
    #[arg(long)]
    role: String,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProviderKindArg {
    OpenidConnect,
    Github,
    Ldap,
    Saml,
}

#[allow(
    clippy::large_enum_variant,
    reason = "parsed once when the tool starts; its size does not matter"
)]
#[derive(Subcommand)]
enum ProviderCommand {
    /// Add an identity provider to a tenant, enabled.
    ///
    /// The client secret is read from the environment variable
    /// `HODOR_PROVIDER_CLIENT_SECRET`, never from an argument, so that it
    /// shows neither in the list of processes nor in a shell's history. A
    /// SAML provider has no secret.
    Add {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The provider's name in addresses, such as `google`. It never
        /// changes.
        #[arg(long)]
        alias: String,
        /// What a person reads on the sign-in page.
        #[arg(long)]
        name: String,
        /// How Hodor talks to the provider.
        #[arg(long, value_enum, default_value = "openid-connect")]
        kind: ProviderKindArg,
        /// The address that identifies the provider. May be left out for
        /// GitHub. For a SAML provider, its entity identifier.
        #[arg(long)]
        issuer: Option<String>,
        /// Who Hodor is to the provider. None for a SAML provider.
        #[arg(long)]
        client_id: Option<String>,
        /// What to ask the provider for. May be given several times;
        /// `openid email profile` unless given.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Do not create a person nobody knows yet on first sign-in.
        #[arg(long)]
        no_create_users: bool,
        /// For a directory: where people are searched for.
        #[arg(long)]
        base: Option<String>,
        /// For a directory: how a person is found, with `{identifier}`
        /// where what they type goes, such as `(uid={identifier})`.
        #[arg(long)]
        filter: Option<String>,
        /// For a directory: the attribute that never changes for a person.
        #[arg(long, default_value = "entryUUID")]
        subject_attribute: String,
        /// For a directory or a SAML provider: the attribute holding the
        /// address. `mail` for a directory, `email` for a SAML provider,
        /// unless given.
        #[arg(long)]
        email_attribute: Option<String>,
        /// For a directory or a SAML provider: the attribute holding the
        /// name. `cn` for a directory, `name` for a SAML provider, unless
        /// given.
        #[arg(long)]
        name_attribute: Option<String>,
        /// For a SAML provider: where the person is sent with the request.
        #[arg(long)]
        sign_on_address: Option<String>,
        /// For a SAML provider: its signing certificate, in PEM. It is not
        /// secret. PEM starts with dashes, which are not a flag here.
        #[arg(long, allow_hyphen_values = true)]
        certificate: Option<String>,
        /// Take every address this provider gives as vouched for, even
        /// when the provider does not say so. Only for a provider whose
        /// addresses the organization itself hands out.
        #[arg(long)]
        trust_email: bool,
        /// For a directory or a SAML provider: the attribute that gives a
        /// standard claim of a person it creates, as `claim=attribute`,
        /// such as `given_name=givenName` or `address.locality=l`. May be
        /// given once per claim.
        #[arg(long = "claim-attribute")]
        claim_attributes: Vec<String>,
    },
    /// List a tenant's providers.
    List {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
    },
    /// Stop a provider from signing people in.
    Disable {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The provider's alias.
        #[arg(long)]
        alias: String,
    },
    /// Let a provider sign people in again.
    Enable {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The provider's alias.
        #[arg(long)]
        alias: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum KeySetArg {
    /// The signing keys.
    Sig,
    /// The data keys.
    Data,
}

#[derive(Clone, Copy, ValueEnum)]
enum SigningAlgorithmArg {
    /// ECDSA on P-256, the default.
    Es256,
    /// RSA with PKCS#1 version 1.5 padding, for interoperability.
    Rs256,
    /// RSA with PSS padding, for interoperability.
    Ps256,
}

#[derive(Subcommand)]
enum KeysCommand {
    /// List a tenant's key versions, newest first.
    List {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// Which key set.
        #[arg(long, value_enum, default_value = "sig")]
        key_set: KeySetArg,
    },
    /// Activate a new signing key at once. The one it replaces stays
    /// published for the overlap.
    Rotate {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The algorithm to rotate.
        #[arg(long, value_enum, default_value = "es256")]
        algorithm: SigningAlgorithmArg,
    },
    /// Revoke a key version. A signing key leaves the published key set at
    /// once: rotate first if it is the active one.
    Revoke {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The version's identifier, as `keys list` shows it.
        #[arg(long)]
        version: String,
        /// Why, for the audit log: 1 to 200 characters.
        #[arg(long)]
        reason: String,
    },
}

#[derive(Subcommand)]
enum SecretsCommand {
    /// Print a new key for `HODOR_SECRET_KEYS`: 32 random bytes in Base64.
    ///
    /// The key is printed once and stored nowhere. Give it an identifier
    /// and put the pair first in the setting.
    GenerateKey,

    /// Seal again every secret that is not sealed as new secrets are, in
    /// every tenant or in one, and make each tenant with nothing left in
    /// the first format refuse it.
    ///
    /// Each secret is its own transaction: the command can be stopped and
    /// run again as often as wanted. See `docs/security/secrets-at-rest.md`.
    Reseal {
        /// Connection URL of the application role.
        #[arg(long, env = "HODOR_DATABASE_URL", hide_env_values = true)]
        database_url: Option<String>,
        /// The keys that keep secrets encrypted at rest, as the server
        /// has them.
        #[arg(long, env = "HODOR_SECRET_KEYS", hide_env_values = true)]
        secret_keys: Option<String>,
        /// Only this tenant, by its slug.
        #[arg(long)]
        tenant: Option<String>,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Check a tenant's whole chain of audit records and exit non-zero if
    /// a record was changed, removed or inserted.
    Verify {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
    },
}

#[derive(Subcommand)]
enum TotpCommand {
    /// Begin enrolling an authenticator application for a person: print
    /// its secret and the `otpauth://` address for a QR code, once.
    ///
    /// Nothing is in use until a code is confirmed with `totp confirm`
    /// within ten minutes.
    Enroll {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The person's login identifier.
        #[arg(long)]
        login: String,
    },
    /// Put the enrolled application in use with a code it shows.
    Confirm {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The person's login identifier.
        #[arg(long)]
        login: String,
        /// The six digits the application shows.
        #[arg(long)]
        code: String,
    },
    /// Remove a person's authenticator application.
    Remove {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The person's login identifier.
        #[arg(long)]
        login: String,
    },
}

#[derive(Subcommand)]
enum RecoveryCodeCommand {
    /// Make a new set of ten recovery codes for a person, in place of any
    /// earlier set, and print it once.
    Generate {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The person's login identifier.
        #[arg(long)]
        login: String,
    },
    /// Say how many unused recovery codes a person has.
    Count {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The person's login identifier.
        #[arg(long)]
        login: String,
    },
    /// Remove a person's recovery codes.
    Remove {
        /// The tenant's slug.
        #[arg(long)]
        tenant: String,
        /// The person's login identifier.
        #[arg(long)]
        login: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum SecondFactorArg {
    /// Every sign-in must prove a second factor.
    Required,
    /// A second factor is asked only of the people who have one.
    NotRequired,
}

#[derive(Clone, Copy, ValueEnum)]
enum OnOffArg {
    /// Offered.
    On,
    /// Not offered.
    Off,
}

impl OnOffArg {
    const fn is_on(self) -> bool {
        matches!(self, Self::On)
    }
}

/// `on` or `off`, as the command-line tool writes a setting.
const fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

#[derive(Clone, Copy, ValueEnum)]
enum DeprovisioningArg {
    /// Deactivate the person: they can be restored.
    Deactivate,
    /// Deactivate the person and mark them Deleted: they are erased.
    Delete,
}

#[derive(Subcommand)]
enum TenantCommand {
    /// Create and activate a tenant.
    Create {
        /// The name used in addresses: `/t/<slug>`.
        #[arg(long)]
        slug: String,
        /// A human-readable name.
        #[arg(long)]
        name: String,
        /// Let anyone register in the tenant.
        #[arg(long)]
        open_registration: bool,
    },
    /// Create the system tenant, unless it already exists.
    CreateSystem,
    /// List every tenant.
    List,
    /// Suspend a tenant.
    Suspend {
        /// The tenant's slug.
        #[arg(long)]
        slug: String,
        /// Why the tenant is suspended.
        #[arg(long)]
        reason: String,
    },
    /// Reactivate a suspended tenant.
    Reactivate {
        /// The tenant's slug.
        #[arg(long)]
        slug: String,
    },
    /// Say whether every sign-in to the tenant must prove a second factor.
    ///
    /// Turned on, a person without a second factor can no longer sign in:
    /// enroll people first with `totp enroll`.
    SecondFactor {
        /// The tenant's slug.
        #[arg(long)]
        slug: String,
        /// Whether a second factor is required.
        #[arg(long, value_enum)]
        policy: SecondFactorArg,
    },
    /// Set how deep groups of the tenant may be nested: the longest chain of
    /// groups inside a group, counting itself, from 1 to 10.
    GroupDepth {
        /// The tenant's slug.
        #[arg(long)]
        slug: String,
        /// The deepest a group may be.
        #[arg(long)]
        depth: u8,
    },
    /// Say whether people of the tenant may sign in with a code, or with a
    /// link, sent to their address. What is not given stays as it was.
    EmailSignIn {
        /// The tenant's slug.
        #[arg(long)]
        slug: String,
        /// Signing in with a code by email.
        #[arg(long, value_enum)]
        code: Option<OnOffArg>,
        /// Signing in with a link by email.
        #[arg(long, value_enum)]
        link: Option<OnOffArg>,
    },
    /// Set how long a request a client pushes waits for its browser, and
    /// whether every client must push its requests. What is not given
    /// stays as it was.
    PushedRequests {
        /// The tenant's slug.
        #[arg(long)]
        slug: String,
        /// The life of a pushed request, in seconds: 10 to 600.
        #[arg(long)]
        seconds: Option<u16>,
        /// Whether every client must push its requests.
        #[arg(long, value_enum)]
        required: Option<OnOffArg>,
    },
    /// Set what deprovisioning a person through SCIM does: `DELETE` of a
    /// user or `active: false`. Either way their sessions and grants end.
    ScimDeprovisioning {
        /// The tenant's slug.
        #[arg(long)]
        slug: String,
        /// Deactivate or delete.
        #[arg(long, value_enum)]
        policy: DeprovisioningArg,
    },
    /// Replace the assurance levels applications ask for in `acr_values`
    /// and tokens name in `acr`; without `--level`, print them.
    AssuranceLevels {
        /// The tenant's slug.
        #[arg(long)]
        slug: String,
        /// A level, as `<name>=<requirement>`, the requirement being
        /// `single_factor`, `multi_factor` or `phishing_resistant`. Given
        /// once per level; the levels given replace all the others.
        #[arg(long = "level")]
        levels: Vec<String>,
    },
}

/// The command-line tool acts as the system: no authenticated
/// administrator exists yet at this stage.
fn caller() -> Caller {
    Caller {
        actor: Actor::System,
        correlation_id: CorrelationId::generate(),
    }
}

async fn existing(service: &TenantService, slug: &str) -> Result<DirectoryEntry, DomainError> {
    service.find_by_slug(slug).await?.ok_or_else(|| {
        DomainError::not_found(
            "tenant.not_found",
            format!("no tenant has the slug `{slug}`"),
        )
    })
}

async fn run_tenant(
    service: &TenantService,
    command: TenantCommand,
) -> Result<String, DomainError> {
    match command {
        TenantCommand::Create {
            slug,
            name,
            open_registration,
        } => {
            let tenant = service
                .create(
                    CreateTenant {
                        slug,
                        display_name: name,
                        open_registration,
                        system: false,
                    },
                    caller(),
                )
                .await?;
            Ok(format!(
                "created {} {}",
                tenant.snapshot().slug,
                tenant.id()
            ))
        }
        TenantCommand::CreateSystem => {
            if let Some(entry) = service.find_by_slug("system").await? {
                return Ok(format!("exists {} {}", entry.slug, entry.tenant_id));
            }
            let tenant = service
                .create(
                    CreateTenant {
                        slug: String::new(),
                        display_name: "System".to_owned(),
                        open_registration: false,
                        system: true,
                    },
                    caller(),
                )
                .await?;
            Ok(format!(
                "created {} {}",
                tenant.snapshot().slug,
                tenant.id()
            ))
        }
        TenantCommand::List => {
            let lines: Vec<String> = service
                .list()
                .await?
                .into_iter()
                .map(|entry| {
                    format!(
                        "{} {} {}",
                        entry.slug,
                        entry.tenant_id,
                        entry.status.as_str()
                    )
                })
                .collect();
            Ok(lines.join("\n"))
        }
        TenantCommand::Suspend { slug, reason } => {
            let entry = existing(service, &slug).await?;
            let tenant = service
                .suspend(&TenantContext::assume(entry.tenant_id), &reason, caller())
                .await?;
            Ok(format!("{} {}", entry.slug, tenant.status().as_str()))
        }
        TenantCommand::Reactivate { slug } => {
            let entry = existing(service, &slug).await?;
            let tenant = service
                .reactivate(&TenantContext::assume(entry.tenant_id), caller())
                .await?;
            Ok(format!("{} {}", entry.slug, tenant.status().as_str()))
        }
        TenantCommand::SecondFactor { slug, policy } => {
            let entry = existing(service, &slug).await?;
            let tenant = TenantContext::assume(entry.tenant_id);
            let mut settings = service.get(&tenant).await?.snapshot().settings.clone();
            let (policy, said) = match policy {
                SecondFactorArg::Required => (SecondFactorPolicy::Required, "required"),
                SecondFactorArg::NotRequired => (SecondFactorPolicy::NotRequired, "not-required"),
            };
            settings.authentication.second_factor = policy;
            service.change_settings(&tenant, settings, caller()).await?;
            Ok(format!("{} second-factor {said}", entry.slug))
        }
        TenantCommand::GroupDepth { slug, depth } => {
            let entry = existing(service, &slug).await?;
            let tenant = TenantContext::assume(entry.tenant_id);
            let mut settings = service.get(&tenant).await?.snapshot().settings.clone();
            settings.groups.max_depth = depth;
            service.change_settings(&tenant, settings, caller()).await?;
            Ok(format!("{} group-depth {depth}", entry.slug))
        }
        TenantCommand::EmailSignIn { slug, code, link } => {
            let entry = existing(service, &slug).await?;
            let tenant = TenantContext::assume(entry.tenant_id);
            let mut settings = service.get(&tenant).await?.snapshot().settings.clone();
            let policy = &mut settings.authentication.email_sign_in;
            if let Some(code) = code {
                policy.code = code.is_on();
            }
            if let Some(link) = link {
                policy.link = link.is_on();
            }
            let now = if code.is_some() || link.is_some() {
                service.change_settings(&tenant, settings, caller()).await?
            } else {
                service.get(&tenant).await?
            };
            let policy = now.snapshot().settings.authentication.email_sign_in;
            Ok(format!(
                "{} email-sign-in code {} link {}",
                entry.slug,
                on_off(policy.code),
                on_off(policy.link)
            ))
        }
        TenantCommand::PushedRequests {
            slug,
            seconds,
            required,
        } => {
            let entry = existing(service, &slug).await?;
            let tenant = TenantContext::assume(entry.tenant_id);
            let mut settings = service.get(&tenant).await?.snapshot().settings.clone();
            let policy = &mut settings.pushed_requests;
            if let Some(seconds) = seconds {
                policy.lifetime_seconds = seconds;
            }
            if let Some(required) = required {
                policy.required = required.is_on();
            }
            let now = if seconds.is_some() || required.is_some() {
                service.change_settings(&tenant, settings, caller()).await?
            } else {
                service.get(&tenant).await?
            };
            let policy = now.snapshot().settings.pushed_requests;
            Ok(format!(
                "{} pushed-requests seconds {} required {}",
                entry.slug,
                policy.lifetime_seconds,
                on_off(policy.required)
            ))
        }
        TenantCommand::ScimDeprovisioning { slug, policy } => {
            let entry = existing(service, &slug).await?;
            let tenant = TenantContext::assume(entry.tenant_id);
            let mut settings = service.get(&tenant).await?.snapshot().settings.clone();
            settings.provisioning.deprovisioning = match policy {
                DeprovisioningArg::Deactivate => Deprovisioning::Deactivate,
                DeprovisioningArg::Delete => Deprovisioning::Delete,
            };
            let changed = service.change_settings(&tenant, settings, caller()).await?;
            Ok(format!(
                "{} scim-deprovisioning {}",
                entry.slug,
                changed
                    .snapshot()
                    .settings
                    .provisioning
                    .deprovisioning
                    .as_str()
            ))
        }
        TenantCommand::AssuranceLevels { slug, levels } => {
            let entry = existing(service, &slug).await?;
            let tenant = TenantContext::assume(entry.tenant_id);
            let mut settings = service.get(&tenant).await?.snapshot().settings.clone();
            if !levels.is_empty() {
                let parsed = levels
                    .iter()
                    .map(|given| {
                        given
                            .split_once('=')
                            .and_then(|(acr, requirement)| {
                                Some(AssuranceLevel {
                                    acr: acr.to_owned(),
                                    requirement: AssuranceRequirement::from_name(requirement)?,
                                })
                            })
                            .ok_or_else(|| {
                                DomainError::invalid(
                                    "tenant.settings_invalid",
                                    "a level is written <name>=<requirement>, the requirement \
                                     being single_factor, multi_factor or phishing_resistant",
                                )
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                settings.authentication.assurance_levels = AssuranceLevels::new(parsed)?;
                settings = service
                    .change_settings(&tenant, settings, caller())
                    .await?
                    .snapshot()
                    .settings
                    .clone();
            }
            let lines: Vec<String> = settings
                .authentication
                .assurance_levels
                .levels()
                .iter()
                .map(|level| {
                    format!(
                        "{} {} {}",
                        entry.slug,
                        level.acr,
                        level.requirement.as_str()
                    )
                })
                .collect();
            Ok(lines.join("\n"))
        }
    }
}

/// Runs a command about authenticator applications against a person of a
/// tenant, both named by the operator.
async fn run_totp(
    database: &Database,
    secret_keys: Option<String>,
    command: TotpCommand,
) -> Result<String, DomainError> {
    let setting = secret_keys.ok_or_else(|| {
        DomainError::invalid(
            "secret.keys_missing",
            "HODOR_SECRET_KEYS or --secret-keys is required: the secrets of authenticator applications are kept encrypted",
        )
    })?;
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        clock.clone(),
    );
    let totp = TotpService::new(
        units(),
        Arc::new(PgTotpStore),
        secret_box(database, setting)?,
        Arc::new(AwsLcHmacSha1),
        Arc::new(OsRandom),
        clock.clone(),
    );
    let (slug, login) = match &command {
        TotpCommand::Enroll { tenant, login }
        | TotpCommand::Confirm { tenant, login, .. }
        | TotpCommand::Remove { tenant, login } => (tenant.clone(), login.clone()),
    };
    let (tenant, user) = person(database, &tenants, &slug, &login).await?;

    match command {
        TotpCommand::Enroll { .. } => {
            let issuer = tenants.get(&tenant).await?.snapshot().display_name.clone();
            let enrollment = totp
                .begin_enrollment(&tenant, user, &issuer, &login)
                .await?;
            Ok(format!(
                "secret {}\naddress {}",
                enrollment.secret(),
                enrollment.address()
            ))
        }
        TotpCommand::Confirm { code, .. } => {
            totp.confirm_enrollment(&tenant, user, &Secret::from(code), caller())
                .await?;
            // A first second factor comes with recovery codes, shown once;
            // a person who still has unused codes keeps them.
            let codes = recovery_code_service(database)
                .generate_if_none(&tenant, user, caller())
                .await?;
            Ok(match codes {
                Some(codes) => format!("confirmed\n{}", code_lines(&codes)),
                None => "confirmed".to_owned(),
            })
        }
        TotpCommand::Remove { .. } => Ok(if totp.remove(&tenant, user, caller()).await? {
            "removed".to_owned()
        } else {
            "nothing to remove".to_owned()
        }),
    }
}

/// The tenant a slug names and the person of that tenant a login
/// identifier names.
async fn person(
    database: &Database,
    tenants: &TenantService,
    slug: &str,
    login: &str,
) -> Result<(TenantContext, hodor_kernel::UserId), DomainError> {
    let entry = existing(tenants, slug).await?;
    // The command-line tool is one of the places allowed to establish a
    // tenant context: the operator names the tenant.
    let tenant = TenantContext::assume(entry.tenant_id);
    let identity = IdentityService::new(
        Arc::new(database.clone()),
        Arc::new(PgUserRepository),
        Arc::new(SystemClock),
    )
    .with_groups(Arc::new(PgGroupRepository))
    .with_organizations(Arc::new(PgOrganizationRepository));
    let user = identity
        .find_by_login(&tenant, login)
        .await?
        .ok_or_else(|| {
            DomainError::not_found(
                "identity.user_not_found",
                "no person of this tenant has this login identifier",
            )
        })?
        .id();
    Ok((tenant, user))
}

fn recovery_code_service(database: &Database) -> RecoveryCodeService {
    RecoveryCodeService::new(
        Arc::new(database.clone()),
        Arc::new(PgRecoveryCodeStore),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    )
}

/// The codes of a set, one per line after a line that says what they are.
fn code_lines(codes: &RecoveryCodes) -> String {
    let mut lines = format!("recovery codes, shown once: {}", codes.len());
    for code in codes.codes() {
        lines.push('\n');
        lines.push_str(code);
    }
    lines
}

/// Runs a command about recovery codes against a person of a tenant, both
/// named by the operator.
async fn run_recovery_codes(
    database: &Database,
    command: RecoveryCodeCommand,
) -> Result<String, DomainError> {
    let tenants = TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    let (slug, login) = match &command {
        RecoveryCodeCommand::Generate { tenant, login }
        | RecoveryCodeCommand::Count { tenant, login }
        | RecoveryCodeCommand::Remove { tenant, login } => (tenant.clone(), login.clone()),
    };
    let (tenant, user) = person(database, &tenants, &slug, &login).await?;
    let codes = recovery_code_service(database);
    match command {
        RecoveryCodeCommand::Generate { .. } => {
            Ok(code_lines(&codes.generate(&tenant, user, caller()).await?))
        }
        RecoveryCodeCommand::Count { .. } => {
            Ok(format!("unused {}", codes.unused(&tenant, user).await?))
        }
        RecoveryCodeCommand::Remove { .. } => Ok(if codes.remove(&tenant, user, caller()).await? {
            "removed".to_owned()
        } else {
            "nothing to remove".to_owned()
        }),
    }
}

/// Makes a user an administrator of a tenant and issues an access token
/// for them. See `docs/api/admin-api.md`, "The first administrator".
/// One line about a provider: its alias, status, issuer and the address
/// to register at the provider.
fn provider_line(provider: &IdentityProvider, public_url: &str, slug: &str) -> String {
    let state = provider.snapshot();
    let back = match state.kind {
        // Nobody leaves for a directory.
        ProviderKind::Ldap => "-".to_owned(),
        // A SAML identity provider is given Hodor's metadata.
        ProviderKind::Saml => saml_metadata_address(public_url, slug, state.alias.as_str()),
        ProviderKind::OpenIdConnect | ProviderKind::GitHub => {
            callback_address(public_url, slug, state.alias.as_str())
        }
    };
    format!(
        "{} {} {} {back}",
        state.alias.as_str(),
        state.status.as_str(),
        state.settings.issuer,
    )
}

/// Runs a provider command against a tenant named by its slug.
async fn run_provider(
    database: &Database,
    secret_keys: Option<String>,
    development_hosts: &[String],
    directory_hosts: &[String],
    public_url: &str,
    command: ProviderCommand,
) -> Result<String, DomainError> {
    let setting = secret_keys.ok_or_else(|| {
        DomainError::invalid(
            "secret.keys_missing",
            "HODOR_SECRET_KEYS or --secret-keys is required: provider secrets are kept encrypted",
        )
    })?;
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        clock.clone(),
    );
    let federation = FederationService::new(
        units(),
        Arc::new(PgProviderStore),
        Arc::new(PgLinkStore),
        secret_box(database, setting)?,
        clock,
    )
    .allowing_development_hosts(development_hosts)
    .allowing_directory_hosts(directory_hosts);
    let slug = match &command {
        ProviderCommand::Add { tenant, .. }
        | ProviderCommand::List { tenant }
        | ProviderCommand::Disable { tenant, .. }
        | ProviderCommand::Enable { tenant, .. } => tenant.clone(),
    };
    let entry = existing(&tenants, &slug).await?;
    // The command-line tool is one of the places allowed to establish a
    // tenant context: the operator names the tenant.
    let tenant = TenantContext::assume(entry.tenant_id);

    match command {
        ProviderCommand::Add {
            alias,
            name,
            kind,
            issuer,
            client_id,
            scopes,
            no_create_users,
            trust_email,
            base,
            filter,
            subject_attribute,
            email_attribute,
            name_attribute,
            sign_on_address,
            certificate,
            claim_attributes,
            ..
        } => {
            let mut claims = hodor_federation::api::ClaimAttributes::new();
            for pair in claim_attributes {
                let Some((claim, attribute)) = pair.split_once('=') else {
                    return Err(DomainError::invalid(
                        "federation.claim_attribute_invalid",
                        "a claim attribute is written claim=attribute",
                    ));
                };
                claims.insert(claim.trim().to_owned(), attribute.trim().to_owned());
            }
            let kind = match kind {
                ProviderKindArg::OpenidConnect => ProviderKind::OpenIdConnect,
                ProviderKindArg::Github => ProviderKind::GitHub,
                ProviderKindArg::Ldap => ProviderKind::Ldap,
                ProviderKindArg::Saml => ProviderKind::Saml,
            };
            // A directory's settings, given for a directory; any other
            // kind that is given them is refused by the federation context.
            let directory = match (base, filter) {
                (None, None) => None,
                (base, filter) => Some(DirectorySettings {
                    base: base.unwrap_or_default(),
                    filter: filter.unwrap_or_default(),
                    subject_attribute,
                    email_attribute: email_attribute.clone().unwrap_or_else(|| "mail".to_owned()),
                    name_attribute: name_attribute.clone().unwrap_or_else(|| "cn".to_owned()),
                    claim_attributes: claims.clone(),
                }),
            };
            // The same for a SAML identity provider's settings.
            let saml = match (sign_on_address, certificate) {
                (None, None) => None,
                (address, certificate) => {
                    let mut settings = SamlSettings::new(
                        &address.unwrap_or_default(),
                        &certificate.unwrap_or_default(),
                    );
                    if let Some(email) = email_attribute {
                        settings.email_attribute = email;
                    }
                    if let Some(name) = name_attribute {
                        settings.name_attribute = name;
                    }
                    settings.claim_attributes = claims.clone();
                    Some(settings)
                }
            };
            if !claims.is_empty() && directory.is_none() && saml.is_none() {
                return Err(DomainError::invalid(
                    "federation.claim_attribute_invalid",
                    "claim attributes are for a directory or a SAML provider",
                ));
            }
            // A SAML identity provider is not proved anything with a secret.
            let client_secret = if kind == ProviderKind::Saml {
                String::new()
            } else {
                std::env::var("HODOR_PROVIDER_CLIENT_SECRET").map_err(|_| {
                    DomainError::invalid(
                        "federation.client_secret_invalid",
                        "the client secret is read from HODOR_PROVIDER_CLIENT_SECRET, which is not set",
                    )
                })?
            };
            let provider = federation
                .create_provider(
                    &tenant,
                    CreateProvider {
                        alias,
                        kind,
                        settings: ProviderSettings {
                            saml,
                            display_name: name,
                            issuer: issuer
                                .or_else(|| {
                                    ProviderSettings::default_issuer_for(kind).map(str::to_owned)
                                })
                                .unwrap_or_default(),
                            client_id: client_id.unwrap_or_default(),
                            scopes: if scopes.is_empty() {
                                ProviderSettings::default_scopes_for(kind)
                            } else {
                                scopes
                            },
                            creates_users: !no_create_users,
                            trusts_email: trust_email,
                            directory,
                        },
                        client_secret: Secret::from(client_secret),
                    },
                    caller(),
                )
                .await?;
            let created = format!("created {}", provider_line(&provider, public_url, &slug));
            let alias = provider.alias().as_str();
            Ok(match kind {
                ProviderKind::Ldap => created,
                ProviderKind::Saml => format!(
                    "{created}\ngive this metadata to the identity provider: {}",
                    saml_metadata_address(public_url, &slug, alias)
                ),
                ProviderKind::OpenIdConnect | ProviderKind::GitHub => format!(
                    "{created}\nregister this address at the provider: {}",
                    callback_address(public_url, &slug, alias)
                ),
            })
        }
        ProviderCommand::List { .. } => Ok(federation
            .providers(&tenant)
            .await?
            .iter()
            .map(|provider| provider_line(provider, public_url, &slug))
            .collect::<Vec<_>>()
            .join("\n")),
        ProviderCommand::Disable { alias, .. } => {
            let provider = federation.provider_by_alias(&tenant, &alias).await?;
            let provider = federation
                .set_provider_status(&tenant, provider.id(), ProviderStatus::Disabled, caller())
                .await?;
            Ok(provider_line(&provider, public_url, &slug))
        }
        ProviderCommand::Enable { alias, .. } => {
            let provider = federation.provider_by_alias(&tenant, &alias).await?;
            let provider = federation
                .set_provider_status(&tenant, provider.id(), ProviderStatus::Enabled, caller())
                .await?;
            Ok(provider_line(&provider, public_url, &slug))
        }
    }
}

/// A moment as RFC 3339, to the second.
fn written(moment: time::OffsetDateTime) -> String {
    moment
        .replace_nanosecond(0)
        .unwrap_or(moment)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// One line of `keys list`: the version, its algorithm, its state and
/// the times that matter for that state.
fn key_line(version: &KeyVersion) -> String {
    let state = version.snapshot();
    let at = |moment: Option<time::OffsetDateTime>| moment.map(written).unwrap_or_default();
    let mut line = format!(
        "{} {} {} created {}",
        state.id,
        state.algorithm.as_str(),
        state.state.as_str(),
        written(state.created_at)
    );
    match state.state {
        KeyState::Active => line.push_str(&format!(" activated {}", at(state.activated_at))),
        KeyState::Retiring => line.push_str(&format!(" retire-after {}", at(state.retire_after))),
        KeyState::Retired => line.push_str(&format!(" retired {}", at(state.retired_at))),
        KeyState::Revoked => line.push_str(&format!(
            " revoked {} {}",
            at(state.revoked_at),
            state.revocation_reason.as_deref().unwrap_or_default()
        )),
        KeyState::Pending => {}
    }
    line
}

/// Runs a keys command against a tenant named by its slug.
/// The files of a bundle: every file under `directory`, at its path
/// relative to it.
pub(crate) fn bundle_files(directory: &std::path::Path) -> Result<Vec<BundleFile>, DomainError> {
    let unreadable = |error: std::io::Error| {
        DomainError::invalid(
            "authorization.bundle_directory_unreadable",
            "the directory of the bundle could not be read",
        )
        .with_detail(error.to_string())
    };
    let mut files = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).map_err(unreadable)? {
            let entry = entry.map_err(unreadable)?;
            let kind = entry.file_type().map_err(unreadable)?;
            let path = entry.path();
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                let relative = path
                    .strip_prefix(directory)
                    .map_err(|_| unreadable(std::io::Error::other("outside the directory")))?
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                files.push(BundleFile {
                    path: relative,
                    contents: std::fs::read(&path).map_err(unreadable)?,
                });
            } else {
                return Err(unreadable(std::io::Error::other(
                    "a bundle's directory holds only files and directories",
                )));
            }
        }
    }
    Ok(files)
}

pub(crate) fn bundle_service(database: &Database) -> BundleService {
    BundleService::new(
        Arc::new(PgInstanceStore::new(database.clone())),
        Arc::new(PgBundleStore),
        Arc::new(PgInstanceStatusStore),
        Arc::new(PgUploadedDecisionStore),
        Arc::new(database.clone()),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        Arc::new(SystemClock),
    )
}

fn when(time: Option<hodor_kernel::Timestamp>) -> String {
    time.and_then(|time| {
        time.format(&time::format_description::well_known::Rfc3339)
            .ok()
    })
    .unwrap_or_else(|| "-".to_owned())
}

async fn run_policy_agent(
    database_url: Option<String>,
    command: PolicyAgentCommand,
) -> Result<String, DomainError> {
    if matches!(command, PolicyAgentCommand::SigningKey) {
        let (private, public) = BundleSigningKey::generate()?;
        return Ok(format!("{private}{public}").trim_end().to_owned());
    }
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
    let bundles = bundle_service(&database);
    match command {
        PolicyAgentCommand::SigningKey => Ok(String::new()),
        PolicyAgentCommand::BundleName { tenant, namespace } => {
            let entry = existing(&tenants, &tenant).await?;
            match namespace {
                None => Ok(bundle_name(entry.tenant_id)),
                Some(namespace) => {
                    let namespace = Namespace::parse(&namespace)?;
                    let path = decision_path(
                        &TenantContext::assume(entry.tenant_id),
                        &namespace,
                        &Sha256Digest,
                    );
                    Ok(path
                        .trim_start_matches("/v1/data/")
                        .trim_end_matches("/decision")
                        .replace('/', "."))
                }
            }
        }
        PolicyAgentCommand::Instance {
            command: InstanceCommand::Add { name, tenant },
        } => {
            let tenant = match tenant {
                Some(slug) => Some(existing(&tenants, &slug).await?.tenant_id),
                None => None,
            };
            let (instance, credential) = bundles.register(&name, tenant).await?;
            Ok(format!(
                "{}\t{}\n{}",
                instance.id(),
                instance.name().as_str(),
                credential.expose()
            ))
        }
        PolicyAgentCommand::Instance {
            command: InstanceCommand::List,
        } => Ok(bundles
            .instances()
            .await?
            .iter()
            .map(|instance| {
                format!(
                    "{}\t{}\t{}\t{}",
                    instance.name().as_str(),
                    instance
                        .tenant()
                        .map_or_else(|| "shared".to_owned(), |tenant| tenant.to_string()),
                    when(Some(instance.registered_at())),
                    instance.disabled_at().map_or_else(
                        || "enabled".to_owned(),
                        |at| format!("disabled {}", when(Some(at)))
                    )
                )
            })
            .collect::<Vec<_>>()
            .join("\n")),
        PolicyAgentCommand::Instance {
            command: InstanceCommand::Disable { name },
        } => {
            if bundles.disable(&name).await? {
                Ok(String::new())
            } else {
                Err(DomainError::not_found(
                    "authorization.policy_agent_instance_not_found",
                    "no enabled instance has this name",
                ))
            }
        }
        PolicyAgentCommand::Status { tenant } => {
            let entry = existing(&tenants, &tenant).await?;
            let instances = bundles.instances().await?;
            Ok(bundles
                .statuses(&TenantContext::assume(entry.tenant_id))
                .await?
                .iter()
                .map(|status| {
                    let name = instances
                        .iter()
                        .find(|instance| instance.id() == status.instance)
                        .map_or_else(
                            || status.instance.to_string(),
                            |i| i.name().as_str().to_owned(),
                        );
                    format!(
                        "{name}\t{}\t{}\t{}",
                        status.active_revision.as_deref().unwrap_or("-"),
                        when(Some(status.reported_at)),
                        status.error.as_deref().unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"))
        }
    }
}

async fn run_keys(
    database: &Database,
    secret_keys: Option<String>,
    key_overlap_hours: i64,
    command: KeysCommand,
) -> Result<String, DomainError> {
    let setting = secret_keys.ok_or_else(|| {
        DomainError::invalid(
            "secret.keys_missing",
            "HODOR_SECRET_KEYS or --secret-keys is required: keys are kept wrapped under them",
        )
    })?;
    let default = RotationPolicy::DEFAULT;
    let policy = RotationPolicy::new(
        default.period(),
        default.publication(),
        time::Duration::hours(key_overlap_hours),
    )?;
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        clock.clone(),
    );
    let keys = KeyService::new(
        units(),
        Arc::new(PgKeyStore),
        key_provider(Arc::new(SecretKeys::parse(&Secret::from(setting))?))?,
        clock,
    );
    let slug = match &command {
        KeysCommand::List { tenant, .. }
        | KeysCommand::Rotate { tenant, .. }
        | KeysCommand::Revoke { tenant, .. } => tenant.clone(),
    };
    let entry = existing(&tenants, &slug).await?;
    // The command-line tool is one of the places allowed to establish a
    // tenant context: the operator names the tenant.
    let tenant = TenantContext::assume(entry.tenant_id);

    match command {
        KeysCommand::List { key_set, .. } => {
            let key_use = match key_set {
                KeySetArg::Sig => KeyUse::Signing,
                KeySetArg::Data => KeyUse::Data,
            };
            let set = keys.key_set(&tenant, key_use).await?;
            Ok(set
                .versions()
                .iter()
                .map(key_line)
                .collect::<Vec<_>>()
                .join("\n"))
        }
        KeysCommand::Rotate { algorithm, .. } => {
            let algorithm = match algorithm {
                SigningAlgorithmArg::Es256 => KeyAlgorithm::Es256,
                SigningAlgorithmArg::Rs256 => KeyAlgorithm::Rs256,
                SigningAlgorithmArg::Ps256 => KeyAlgorithm::Ps256,
            };
            let version = keys
                .rotate_now(&tenant, algorithm, &policy, caller())
                .await?;
            Ok(key_line(&version))
        }
        KeysCommand::Revoke {
            version, reason, ..
        } => {
            let id: KeyVersionId = version.parse().map_err(|_| {
                DomainError::not_found("keys.version_not_found", "the key version does not exist")
            })?;
            let version = keys.revoke(&tenant, id, &reason, caller()).await?;
            Ok(key_line(&version))
        }
    }
}

/// Where secrets at rest are sealed, as the server seals them: under the
/// tenant's data keys, the root keys still opening the first format until
/// the tenant refuses it.
fn secret_box(database: &Database, setting: String) -> Result<Arc<dyn SecretBox>, DomainError> {
    Ok(Arc::new(tenant_secret_box(database, setting)?))
}

fn tenant_secret_box(database: &Database, setting: String) -> Result<TenantSecretBox, DomainError> {
    let root = Arc::new(SecretKeys::parse(&Secret::from(setting))?);
    Ok(TenantSecretBox::new(
        Arc::new(database.clone()),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root.clone())),
        Arc::new(PgSealingStateStore),
        Some(root),
        Arc::new(SystemClock),
    ))
}

/// Seals again what needs it, tenant by tenant, and returns one line per
/// tenant and whether every tenant now refuses the first format.
async fn run_reseal(
    database: &Database,
    secret_keys: Option<String>,
    only: Option<&str>,
) -> Result<(String, bool), DomainError> {
    let setting = secret_keys.ok_or_else(|| {
        DomainError::invalid(
            "secret.keys_missing",
            "HODOR_SECRET_KEYS or --secret-keys is required: secrets are opened and sealed again with them",
        )
    })?;
    let secrets = tenant_secret_box(database, setting)?;
    let directory = PgTenantDirectory::new(database.clone());
    let entries = match only {
        Some(slug) => {
            let tenants = TenantService::new(
                Arc::new(database.clone()),
                Arc::new(PgTenantRepository),
                Arc::new(directory),
                Arc::new(SystemClock),
            );
            vec![existing(&tenants, slug).await?]
        }
        None => directory.list().await?,
    };
    let mut lines = Vec::with_capacity(entries.len());
    let mut complete = true;
    for entry in entries {
        // The command-line tool is one of the places allowed to establish
        // a tenant context: the operator runs it for the installation.
        let tenant = TenantContext::assume(entry.tenant_id);
        let report = reseal_tenant(database, &secrets, &tenant).await?;
        let refused = if report.complete() {
            secrets.refuse_first_format(&tenant).await?;
            "the first format is refused"
        } else {
            complete = false;
            "the first format is still accepted"
        };
        lines.push(format!(
            "{}: {} sealed again, {} already current, {} did not open; {refused}",
            entry.slug, report.resealed, report.current, report.unreadable
        ));
    }
    Ok((lines.join("\n"), complete))
}

/// Gives or takes away a built-in role of a user who exists in the tenant.
async fn built_in_role(
    database: &Database,
    args: &RoleArgs,
    give: bool,
) -> Result<String, DomainError> {
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        clock.clone(),
    );
    let tenant = TenantContext::assume(existing(&tenants, &args.tenant).await?.tenant_id);
    let role = Role::from_name(&args.role)?;
    let user = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
        .get(&tenant, args.user)
        .await?;
    if user.status() == hodor_identity::api::UserStatus::Deleted {
        return Err(DomainError::not_found(
            "identity.user_not_found",
            "the user does not exist",
        ));
    }
    let service = AuthorizationService::new(units(), Arc::new(PgRoleAssignmentStore), clock);
    if give {
        service.assign(&tenant, user.id(), role, caller()).await?;
        Ok(format!("granted {} {}", role.as_str(), user.id()))
    } else {
        service.revoke(&tenant, user.id(), role, caller()).await?;
        Ok(format!("revoked {} {}", role.as_str(), user.id()))
    }
}

async fn bootstrap_administrator(
    database: &Database,
    slug: &str,
    email: &str,
    token_minutes: u32,
) -> Result<String, DomainError> {
    let units = || Arc::new(database.clone());
    let clock = Arc::new(SystemClock);
    let tenants = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        clock.clone(),
    );
    let entry = tenants.find_by_slug(slug).await?.ok_or_else(|| {
        DomainError::not_found("tenant.not_found", "there is no tenant with this slug")
    })?;
    // The command-line tool is one of the places allowed to establish a
    // tenant context: the operator names the tenant.
    let tenant = TenantContext::assume(entry.tenant_id);

    let identity = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
        .with_groups(Arc::new(PgGroupRepository))
        .with_organizations(Arc::new(PgOrganizationRepository));
    let address = NormalizedIdentifier::parse(IdentifierKind::Email, email)?;
    let user = match identity
        .find_by_login(&tenant, address.normalized())
        .await?
    {
        Some(user) => user,
        None => {
            let command = CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, email.to_owned())],
                profile: Profile::default(),
                confirmed: true,
            };
            identity.create(&tenant, command, caller()).await?
        }
    };
    if !user.may_sign_in() {
        return Err(DomainError::conflict(
            "identity.user_may_not_sign_in",
            "this user may not sign in, so a token for them would not work",
        ));
    }

    let role = Role::TenantAdministrator;
    AuthorizationService::new(units(), Arc::new(PgRoleAssignmentStore), clock.clone())
        .assign(&tenant, user.id(), role, caller())
        .await?;
    let (token, secret) = AccessTokenService::new(
        units(),
        Arc::new(PgAccessTokenStore),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        clock,
    )
    .issue(
        &tenant,
        user.id(),
        "bootstrap administrator",
        time::Duration::minutes(i64::from(token_minutes)),
        caller(),
    )
    .await?;

    // Written to the second: nobody plans around less.
    let expires_at = token.snapshot().expires_at;
    let expires = expires_at
        .replace_nanosecond(0)
        .unwrap_or(expires_at)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    Ok(format!(
        "user {} {}\nrole {}\ntoken {}\nexpires {expires}",
        user.id(),
        address.display(),
        role.as_str(),
        secret.expose()
    ))
}

/// Checks a tenant's chain of audit records. The outer error is a failure
/// to check; the inner one is a chain that is broken.
async fn verify_audit(
    database: &Database,
    slug: &str,
) -> Result<Result<String, String>, DomainError> {
    let tenants = TenantService::new(
        Arc::new(database.clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.clone())),
        Arc::new(SystemClock),
    );
    let entry = tenants.find_by_slug(slug).await?.ok_or_else(|| {
        DomainError::not_found("tenant.not_found", "there is no tenant with this slug")
    })?;
    let audit = AuditService::new(
        Arc::new(database.clone()),
        Arc::new(PgAuditLog),
        Arc::new(Sha256Digest),
        Arc::new(SystemClock),
    );
    // The command-line tool is one of the places allowed to establish a
    // tenant context: the operator names the tenant.
    let verification = audit
        .verify(&TenantContext::assume(entry.tenant_id))
        .await?;
    Ok(match verification.broken {
        None => Ok(format!("intact: {} records", verification.records)),
        Some((sequence, problem)) => Err(format!(
            "the audit chain of {slug} is broken at record {sequence}: {}; {} records before it are in order",
            problem.description(),
            verification.records
        )),
    })
}

/// Performs a minimal HTTP/1.1 GET and reports whether the status is 200.
fn probe(addr: SocketAddr, path: &str) -> Result<bool, std::io::Error> {
    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    let mut status_line = [0_u8; 12];
    stream.read_exact(&mut status_line)?;
    Ok(&status_line == b"HTTP/1.1 200")
}

/// Connects as the application role, which the commands need.
async fn connect(database_url: Option<String>) -> Result<Database, Box<dyn Error>> {
    let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
    Ok(Database::connect(&Secret::from(url), 2).await?)
}

/// Writes what a command printed, or turns its refusal into the error the
/// tool exits with.
fn print(result: Result<String, DomainError>) -> Result<(), Box<dyn Error>> {
    let output = result.map_err(|error| format!("{}: {}", error.code(), error.message()))?;
    if !output.is_empty() {
        writeln!(std::io::stdout(), "{output}")?;
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::Migrate { database_url } => {
            let pool = PgPool::connect(&database_url).await?;
            hodor_adapters_postgres::migrate(&pool).await?;
            writeln!(std::io::stdout(), "migrations applied")?;
        }
        Command::Tenant {
            database_url,
            command,
        } => {
            let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
            let database = Database::connect(&Secret::from(url), 2).await?;
            let service = TenantService::new(
                Arc::new(database.clone()),
                Arc::new(PgTenantRepository),
                Arc::new(PgTenantDirectory::new(database)),
                Arc::new(SystemClock),
            );
            match run_tenant(&service, command).await {
                Ok(output) if output.is_empty() => {}
                Ok(output) => writeln!(std::io::stdout(), "{output}")?,
                Err(error) => {
                    return Err(format!("{}: {}", error.code(), error.message()).into());
                }
            }
        }
        Command::Admin {
            database_url,
            command:
                AdminCommand::Bootstrap {
                    tenant,
                    email,
                    token_minutes,
                },
        } => {
            let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
            let database = Database::connect(&Secret::from(url), 2).await?;
            let output = bootstrap_administrator(&database, &tenant, &email, token_minutes)
                .await
                .map_err(|error| format!("{}: {}", error.code(), error.message()))?;
            writeln!(std::io::stdout(), "{output}")?;
        }
        Command::Admin {
            database_url,
            command: AdminCommand::Grant(args),
        } => {
            let database = connect(database_url).await?;
            print(built_in_role(&database, &args, true).await)?;
        }
        Command::Admin {
            database_url,
            command: AdminCommand::Revoke(args),
        } => {
            let database = connect(database_url).await?;
            print(built_in_role(&database, &args, false).await)?;
        }
        Command::Audit {
            database_url,
            command: AuditCommand::Verify { tenant },
        } => {
            let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
            let database = Database::connect(&Secret::from(url), 2).await?;
            let output = verify_audit(&database, &tenant)
                .await
                .map_err(|error| format!("{}: {}", error.code(), error.message()))??;
            writeln!(std::io::stdout(), "{output}")?;
        }
        Command::Provider {
            database_url,
            secret_keys,
            development_hosts,
            directory_hosts,
            public_url,
            command,
        } => {
            let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
            let database = Database::connect(&Secret::from(url), 2).await?;
            let output = run_provider(
                &database,
                secret_keys,
                &development_hosts,
                &directory_hosts,
                &public_url,
                command,
            )
            .await
            .map_err(|error| format!("{}: {}", error.code(), error.message()))?;
            if !output.is_empty() {
                writeln!(std::io::stdout(), "{output}")?;
            }
        }
        Command::Authorization {
            database_url,
            command,
        } => {
            let database = connect(database_url).await?;
            print(decisions::run_authorization(&database, command).await)?;
        }
        Command::Group {
            database_url,
            command,
        } => {
            let database = connect(database_url).await?;
            print(memberships::run_group(&database, command).await)?;
        }
        Command::User {
            database_url,
            command,
        } => {
            let database = connect(database_url).await?;
            print(users::run(&database, command).await)?;
        }
        Command::ServiceAccount {
            database_url,
            command,
        } => {
            let database = connect(database_url).await?;
            print(workloads::run(&database, UserKind::ServiceAccount, command).await)?;
        }
        Command::Agent {
            database_url,
            command,
        } => {
            let database = connect(database_url).await?;
            print(workloads::run(&database, UserKind::Agent, command).await)?;
        }
        Command::Organization {
            database_url,
            public_url,
            command,
        } => {
            let database = connect(database_url).await?;
            print(memberships::run_organization(&database, &public_url, command).await)?;
        }
        Command::Application {
            database_url,
            command,
        } => {
            let database = connect(database_url).await?;
            print(applications::run_application(&database, command).await)?;
        }
        Command::Client {
            database_url,
            development_hosts,
            command,
        } => {
            let database = connect(database_url).await?;
            print(applications::run_client(&database, command, &development_hosts).await)?;
        }
        Command::ClientRegistration {
            database_url,
            command,
        } => {
            let database = connect(database_url).await?;
            print(registration::run(&database, command).await)?;
        }
        Command::ResourceServer {
            database_url,
            command,
        } => {
            let database = connect(database_url).await?;
            print(applications::run_resource_server(&database, command).await)?;
        }
        Command::Mesh {
            database_url,
            command,
        } => {
            let database = connect(database_url).await?;
            print(mesh::run(&database, command).await)?;
        }
        Command::Webhook {
            database_url,
            secret_keys,
            development_hosts,
            command,
        } => {
            let database = connect(database_url).await?;
            print(
                webhooks::run(
                    &database,
                    webhooks::Installation {
                        secret_keys,
                        development_hosts: &development_hosts,
                    },
                    command,
                )
                .await,
            )?;
        }
        Command::TrustDomain {
            database_url,
            development_hosts,
            command,
        } => {
            let database = connect(database_url).await?;
            print(trust_domains::run(&database, &development_hosts, command).await)?;
        }
        Command::Totp {
            database_url,
            secret_keys,
            command,
        } => {
            let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
            let database = Database::connect(&Secret::from(url), 2).await?;
            let output = run_totp(&database, secret_keys, command)
                .await
                .map_err(|error| format!("{}: {}", error.code(), error.message()))?;
            writeln!(std::io::stdout(), "{output}")?;
        }
        Command::Keys {
            database_url,
            secret_keys,
            key_overlap_hours,
            command,
        } => {
            let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
            let database = Database::connect(&Secret::from(url), 2).await?;
            let output = run_keys(&database, secret_keys, key_overlap_hours, command)
                .await
                .map_err(|error| format!("{}: {}", error.code(), error.message()))?;
            if !output.is_empty() {
                writeln!(std::io::stdout(), "{output}")?;
            }
        }
        Command::Authority {
            database_url,
            secret_keys,
            certificate_authority,
            command,
        } => {
            let database = connect(database_url).await?;
            let printed = authority::run(
                &database,
                authority::Installation {
                    secret_keys,
                    setting: certificate_authority,
                },
                command,
            )
            .await
            .map_err(|error| match error.detail() {
                Some(detail) if !detail.is_empty() => {
                    format!("{}: {}\n{detail}", error.code(), error.message())
                }
                _ => format!("{}: {}", error.code(), error.message()),
            })?;
            if let Some(note) = printed.note {
                writeln!(std::io::stderr(), "{note}")?;
            }
            if !printed.output.is_empty() {
                writeln!(std::io::stdout(), "{}", printed.output)?;
            }
        }
        Command::RecoveryCodes {
            database_url,
            command,
        } => {
            let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
            let database = Database::connect(&Secret::from(url), 2).await?;
            let output = run_recovery_codes(&database, command)
                .await
                .map_err(|error| format!("{}: {}", error.code(), error.message()))?;
            writeln!(std::io::stdout(), "{output}")?;
        }
        Command::PolicyAgent {
            database_url,
            command,
        } => {
            let output = run_policy_agent(database_url, command)
                .await
                .map_err(|error| format!("{}: {}", error.code(), error.message()))?;
            if !output.is_empty() {
                writeln!(std::io::stdout(), "{output}")?;
            }
        }
        Command::Policy {
            database_url,
            command,
        } => {
            let output = policies::run_policy(database_url, command)
                .await
                .map_err(|error| match error.detail() {
                    Some(detail) if !detail.is_empty() => {
                        format!("{}: {}\n{detail}", error.code(), error.message())
                    }
                    _ => format!("{}: {}", error.code(), error.message()),
                })?;
            if !output.is_empty() {
                writeln!(std::io::stdout(), "{output}")?;
            }
        }
        Command::Secrets {
            command: SecretsCommand::GenerateKey,
        } => {
            let key = SecretKeys::generate(&OsRandom);
            writeln!(std::io::stdout(), "{}", key.expose())?;
        }
        Command::Secrets {
            command:
                SecretsCommand::Reseal {
                    database_url,
                    secret_keys,
                    tenant,
                },
        } => {
            let url = database_url.ok_or("HODOR_DATABASE_URL or --database-url is required")?;
            let database = Database::connect(&Secret::from(url), 2).await?;
            let (output, complete) = run_reseal(&database, secret_keys, tenant.as_deref())
                .await
                .map_err(|error| format!("{}: {}", error.code(), error.message()))?;
            writeln!(std::io::stdout(), "{output}")?;
            if !complete {
                return Err("some secrets did not open and were left as they were".into());
            }
        }
        Command::Probe { addr, path } => {
            if !probe(addr, &path)? {
                return Err(format!("{addr}{path} did not answer 200").into());
            }
        }
    }
    Ok(())
}

/// The key provider of the keys context: the local one, wrapping keys
/// under `root`, and OpenBao when `HODOR_OPENBAO_ADDRESS` is set, reached
/// through a client that calls its address alone. New signing keys are
/// made where `HODOR_KEY_PROVIDER` says, and every version is used by the
/// provider that made it (`docs/operations/keys-in-openbao.md`).
fn key_provider(root: Arc<SecretKeys>) -> Result<Arc<dyn KeyProvider>, DomainError> {
    Ok(Arc::new(key_providers(root)?))
}

/// Every key provider, as [`key_provider`] has them, with the one that
/// makes the keys of certificate authorities.
fn key_providers(root: Arc<SecretKeys>) -> Result<KeyProviders, DomainError> {
    let settings = KeyProviderSettings::from_lookup(|name| std::env::var(name).ok())?;
    let providers = settings.providers(Arc::new(LocalKeyProvider::new(root)), |openbao| {
        let origins = [openbao.address.clone()];
        let policy = OutboundPolicy {
            timeout: openbao.time_limit,
            connect_timeout: openbao.time_limit.min(std::time::Duration::from_secs(5)),
            ..OutboundPolicy::default()
        };
        let client = match &openbao.certificate_authorities {
            Some(path) => {
                let authorities = std::fs::read(path).map_err(|error| {
                    DomainError::invalid(
                        "keys.provider_settings_invalid",
                        "the settings of the key provider are not valid",
                    )
                    .with_detail(format!(
                        "HODOR_OPENBAO_CA_FILE cannot be read: {}",
                        error.kind()
                    ))
                })?;
                ServiceHttpClient::trusting_only(&origins, policy, &authorities)?
            }
            None => ServiceHttpClient::new(&origins, policy)?,
        };
        Ok(Arc::new(client) as Arc<dyn HttpClient>)
    })?;
    Ok(providers)
}
