//! The OAuth context.
//!
//! Makes Hodor an OAuth 2.x authorization server and an OpenID Provider.
//! This part holds the applications a tenant registers, the clients that
//! ask for tokens on their behalf, and the resource servers those tokens
//! are for. It does not sign anyone in.
//!
//! The specification is `docs/architecture/contexts/oauth.md`; this crate
//! follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::ports::{ApplicationStore, ClientStore, ResourceServerStore};
    pub use crate::application::service::{
        ApplicationPorts, ApplicationService, CreateClient, CreateResourceServer, RotateSecret,
    };
    pub use crate::domain::application::{
        Application, ApplicationId, ApplicationSettings, ApplicationSnapshot, MAX_APPLICATIONS,
        Status,
    };
    pub use crate::domain::client::{
        AuthenticationMethod, Client, ClientId, ClientSettings, ClientSnapshot, ClientType,
        GrantType, MAX_CLIENTS, MAX_REDIRECT_URIS, MAX_SCOPES, TokenPolicy,
    };
    pub use crate::domain::event::OauthEvent;
    pub use crate::domain::key::{ClientKey, MAX_KEYS};
    pub use crate::domain::resource_server::{
        Audience, OPENID_SCOPES, ResourceServer, ResourceServerId, ResourceServerSettings,
        ResourceServerSnapshot, ScopeDefinition,
    };
    pub use crate::domain::secret::{
        ClientSecret, ClientSecretHash, ClientSecretId, ClientSecretValue,
    };
    pub use crate::domain::text::{MAX_SCOPE_LENGTH, is_scope};
}
