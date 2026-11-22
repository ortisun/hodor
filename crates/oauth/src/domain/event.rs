//! What the OAuth context tells the rest of the system. Events carry
//! identifiers, names and audiences; never a secret or its hash.

use crate::domain::application::ApplicationId;
use crate::domain::authorization::GrantId;
use crate::domain::client::ClientId;
use crate::domain::resource_server::ResourceServerId;
use crate::domain::secret::ClientSecretId;
use hodor_kernel::{DomainEvent, Timestamp, UserId};
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
    },
    /// A client's settings changed.
    ClientChanged {
        /// The client.
        client_id: ClientId,
        /// Its application.
        application_id: ApplicationId,
        /// `confidential` or `public`.
        client_type: &'static str,
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
        }
    }
}
