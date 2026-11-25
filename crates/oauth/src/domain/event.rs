//! What the OAuth context tells the rest of the system. Events carry
//! identifiers, names and audiences; never a secret or its hash.

use crate::domain::application::ApplicationId;
use crate::domain::authorization::GrantId;
use crate::domain::backchannel::LogoutDeliveryId;
use crate::domain::claim_mapper::ClaimMapperId;
use crate::domain::client::ClientId;
use crate::domain::refresh::RefreshFamilyId;
use crate::domain::resource_server::ResourceServerId;
use crate::domain::secret::ClientSecretId;
use hodor_kernel::{DomainEvent, Timestamp, UserId};
use hodor_session::api::SessionId;
use serde::Serialize;

/// An event of the OAuth context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum OauthEvent {
    /// An application was registered.
    ApplicationCreated {
        /// The application.
        application_id: ApplicationId,
        /// Its name.
        name: String,
    },
    /// An application's settings changed.
    ApplicationChanged {
        /// The application.
        application_id: ApplicationId,
        /// Its name.
        name: String,
    },
    /// An application was enabled.
    ApplicationEnabled {
        /// The application.
        application_id: ApplicationId,
    },
    /// An application was disabled.
    ApplicationDisabled {
        /// The application.
        application_id: ApplicationId,
    },
    /// A client was created.
    ClientCreated {
        /// The client.
        client_id: ClientId,
        /// Its application.
        application_id: ApplicationId,
        /// `confidential` or `public`.
        client_type: &'static str,
        /// The service account or agent it acts as, if any.
        principal_id: Option<UserId>,
    },
    /// A client's settings changed.
    ClientChanged {
        /// The client.
        client_id: ClientId,
        /// Its application.
        application_id: ApplicationId,
        /// `confidential` or `public`.
        client_type: &'static str,
        /// The service account or agent it acts as, if any.
        principal_id: Option<UserId>,
    },
    /// A client was enabled.
    ClientEnabled {
        /// The client.
        client_id: ClientId,
    },
    /// A client was disabled.
    ClientDisabled {
        /// The client.
        client_id: ClientId,
    },
    /// A client got a new secret.
    ClientSecretIssued {
        /// The client.
        client_id: ClientId,
        /// The secret's identifier.
        secret_id: ClientSecretId,
        /// When it stops working.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: Timestamp,
    },
    /// A secret of a client stopped working before it expired.
    ClientSecretRevoked {
        /// The client.
        client_id: ClientId,
        /// The secret's identifier.
        secret_id: ClientSecretId,
    },
    /// A client got a public key.
    ClientKeyAdded {
        /// The client.
        client_id: ClientId,
        /// The `kid` of the key.
        key_id: String,
    },
    /// A public key of a client was removed.
    ClientKeyRemoved {
        /// The client.
        client_id: ClientId,
        /// The `kid` of the key.
        key_id: String,
    },
    /// A resource server was registered.
    ResourceServerCreated {
        /// The resource server.
        resource_server_id: ResourceServerId,
        /// Its audience.
        audience: String,
    },
    /// A resource server's name or scopes changed.
    ResourceServerChanged {
        /// The resource server.
        resource_server_id: ResourceServerId,
        /// Its audience.
        audience: String,
    },
    /// An authorization code was issued. Never carries the code or its
    /// hash.
    AuthorizationCodeIssued {
        /// The client it was issued to.
        client_id: ClientId,
        /// The grant it was issued under.
        grant_id: GrantId,
        /// The person who signed in.
        user_id: UserId,
    },
    /// A grant was revoked, and everything issued from it with it.
    GrantRevoked {
        /// The grant.
        grant_id: GrantId,
        /// Its client.
        client_id: ClientId,
        /// Why, such as `code_reused`.
        reason: &'static str,
    },
    /// A person agreed to what a client asked for.
    ConsentGiven {
        /// The client.
        client_id: ClientId,
        /// The person.
        user_id: UserId,
        /// The scopes the consent now holds.
        scopes: Vec<String>,
    },
    /// A person refused what a client asked for.
    ConsentRefused {
        /// The client.
        client_id: ClientId,
        /// The person.
        user_id: UserId,
    },
    /// A consent was withdrawn, and the grants made under it revoked.
    ConsentWithdrawn {
        /// The client.
        client_id: ClientId,
        /// The person.
        user_id: UserId,
        /// `person` or `administrator`.
        by: &'static str,
    },
    /// An access token was issued. Never carries the token.
    AccessTokenIssued {
        /// The client it was issued to.
        client_id: ClientId,
        /// The grant it was issued under.
        grant_id: GrantId,
        /// The person it speaks for.
        user_id: UserId,
        /// The token's `jti`.
        token_id: String,
        /// When it expires.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: Timestamp,
    },
    /// An access token was issued to a client for itself, with client
    /// credentials. Never carries the token.
    ClientAccessTokenIssued {
        /// The client.
        client_id: ClientId,
        /// The service account or agent the client acts as, if it is bound
        /// to one: the token's `sub`.
        principal_id: Option<UserId>,
        /// The token's `jti`.
        token_id: String,
        /// When it expires.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: Timestamp,
    },
    /// A family of refresh tokens started with a code. Never carries a
    /// token or its hash.
    RefreshTokenFamilyStarted {
        /// The family.
        family_id: RefreshFamilyId,
        /// The grant it belongs to.
        grant_id: GrantId,
        /// The client.
        client_id: ClientId,
        /// The person.
        user_id: UserId,
        /// Whether it outlives its session.
        offline: bool,
    },
    /// A family of refresh tokens moved one generation.
    RefreshTokenRotated {
        /// The family.
        family_id: RefreshFamilyId,
        /// The client.
        client_id: ClientId,
        /// The generation it moved to.
        generation: i32,
    },
    /// A family of refresh tokens was revoked.
    RefreshTokenFamilyRevoked {
        /// The family.
        family_id: RefreshFamilyId,
        /// The grant it belongs to.
        grant_id: GrantId,
        /// The client.
        client_id: ClientId,
        /// Why: `refresh_token_reused`, `other_client` or
        /// `revoked_by_client`.
        reason: &'static str,
    },
    /// An agent exchanged a person's token for one it holds on the
    /// person's behalf. Never carries a token.
    TokenExchanged {
        /// The agent's client that asked.
        client_id: ClientId,
        /// The person the new token is about, its `sub`.
        subject_id: String,
        /// Every actor of the new token, the newest first.
        actors: Vec<String>,
        /// The audience the new token is for.
        audience: String,
        /// The new token's `jti`.
        token_id: String,
        /// When it expires.
        #[serde(with = "time::serde::rfc3339")]
        expires_at: Timestamp,
    },
    /// A claim mapper was created.
    ClaimMapperCreated {
        /// The mapper.
        claim_mapper_id: ClaimMapperId,
        /// Its client.
        client_id: ClientId,
        /// The claim it writes.
        claim: String,
        /// The tokens it writes into.
        targets: Vec<&'static str>,
        /// The kind of its source; never a constant's value.
        source: &'static str,
    },
    /// A claim mapper was replaced.
    ClaimMapperChanged {
        /// The mapper.
        claim_mapper_id: ClaimMapperId,
        /// Its client.
        client_id: ClientId,
        /// The claim it writes.
        claim: String,
        /// The tokens it writes into.
        targets: Vec<&'static str>,
        /// The kind of its source; never a constant's value.
        source: &'static str,
    },
    /// A claim mapper was deleted.
    ClaimMapperDeleted {
        /// The mapper.
        claim_mapper_id: ClaimMapperId,
        /// Its client.
        client_id: ClientId,
        /// The claim it wrote.
        claim: String,
    },
    /// An access token was revoked. Never carries the token.
    AccessTokenRevoked {
        /// The client it was issued to.
        client_id: ClientId,
        /// The token's `jti`.
        token_id: String,
        /// Why: `revoked_by_client`, or `workload_disabled` or
        /// `workload_deleted` when its workload was.
        reason: &'static str,
    },
    /// A logout token was not delivered: every attempt failed, or its
    /// client could no longer be sent to. Never carries the address or the
    /// token.
    BackchannelLogoutSetAside {
        /// The delivery.
        delivery_id: LogoutDeliveryId,
        /// The client it was for.
        client_id: ClientId,
        /// The session that ended.
        session_id: SessionId,
        /// How many attempts were made.
        attempts: u32,
    },
}

impl DomainEvent for OauthEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::ApplicationCreated { .. } => "oauth.application_created",
            Self::ApplicationChanged { .. } => "oauth.application_changed",
            Self::ApplicationEnabled { .. } => "oauth.application_enabled",
            Self::ApplicationDisabled { .. } => "oauth.application_disabled",
            Self::ClientCreated { .. } => "oauth.client_created",
            Self::ClientChanged { .. } => "oauth.client_changed",
            Self::ClientEnabled { .. } => "oauth.client_enabled",
            Self::ClientDisabled { .. } => "oauth.client_disabled",
            Self::ClientSecretIssued { .. } => "oauth.client_secret_issued",
            Self::ClientSecretRevoked { .. } => "oauth.client_secret_revoked",
            Self::ClientKeyAdded { .. } => "oauth.client_key_added",
            Self::ClientKeyRemoved { .. } => "oauth.client_key_removed",
            Self::ResourceServerCreated { .. } => "oauth.resource_server_created",
            Self::ResourceServerChanged { .. } => "oauth.resource_server_changed",
            Self::AuthorizationCodeIssued { .. } => "oauth.authorization_code_issued",
            Self::GrantRevoked { .. } => "oauth.grant_revoked",
            Self::ConsentGiven { .. } => "oauth.consent_given",
            Self::ConsentRefused { .. } => "oauth.consent_refused",
            Self::ConsentWithdrawn { .. } => "oauth.consent_withdrawn",
            Self::AccessTokenIssued { .. } => "oauth.access_token_issued",
            Self::ClientAccessTokenIssued { .. } => "oauth.client_access_token_issued",
            Self::RefreshTokenFamilyStarted { .. } => "oauth.refresh_token_family_started",
            Self::RefreshTokenRotated { .. } => "oauth.refresh_token_rotated",
            Self::RefreshTokenFamilyRevoked { .. } => "oauth.refresh_token_family_revoked",
            Self::ClaimMapperCreated { .. } => "oauth.claim_mapper_created",
            Self::ClaimMapperChanged { .. } => "oauth.claim_mapper_changed",
            Self::ClaimMapperDeleted { .. } => "oauth.claim_mapper_deleted",
            Self::AccessTokenRevoked { .. } => "oauth.access_token_revoked",
            Self::TokenExchanged { .. } => "oauth.token_exchanged",
            Self::BackchannelLogoutSetAside { .. } => "oauth.backchannel_logout_set_aside",
        }
    }
}
