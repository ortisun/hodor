//! The OAuth context.
//!
//! Makes Hodor an OAuth 2.x authorization server and an OpenID Provider.
//! It holds the applications a tenant registers, the clients that ask for
//! tokens on their behalf, the resource servers those tokens are for, and
//! the authorization endpoint's requests, grants and codes, and the token
//! endpoint with the access tokens it issues, the OpenID Provider, and
//! logout initiated by the relying party. It does not sign anyone in.
//!
//! The specification is `docs/architecture/contexts/oauth.md`; this crate
//! follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::authorization::{
        AuthorizationCodePorts, AuthorizationCodeService, RedeemedCode, ResumedRequest,
    };
    pub use crate::application::introspection::AccessTokenRegister;
    pub use crate::application::logout::{LogoutPorts, LogoutRefusal, LogoutService};
    pub use crate::application::ports::{
        AccessTokenRecordStore, ApplicationStore, AuthorizationCodeStore,
        AuthorizationRequestStore, ClientAssertionStore, ClientStore, GrantStore, PersonStanding,
        RefreshTokenStore, ResourceServerStore,
    };
    pub use crate::application::resource_access::{
        ResourceAccessPorts, ResourceAccessService, ResourceCaller,
    };
    pub use crate::application::service::{
        ApplicationPorts, ApplicationService, CreateClient, CreateResourceServer, RotateSecret,
    };
    pub use crate::application::token::{IssuedTokens, Issuer, TokenPorts, TokenService};
    pub use crate::application::userinfo::{UserInfoPorts, UserInfoService};
    pub use crate::domain::application::{
        Application, ApplicationId, ApplicationSettings, ApplicationSnapshot, MAX_APPLICATIONS,
        Status,
    };
    pub use crate::domain::authorization::{
        AuthorizationCode, AuthorizationError, AuthorizationParameters, AuthorizationRefusal,
        AuthorizationRequest, BrowserSecret, CODE_LIFETIME, CodeHash, CodePresentation,
        CodeRefusal, CodeValue, Grant, GrantId, GrantStatus, MAX_RESOURCES, PENDING_LIFETIME,
        PendingAuthorization, PendingAuthorizationId, Proof, SessionDecision, SignedInPerson,
        check_request, s256_challenge,
    };
    pub use crate::domain::client::{
        AuthenticationMethod, Client, ClientId, ClientSettings, ClientSnapshot, ClientType,
        GrantType, MAX_CLIENTS, MAX_REDIRECT_URIS, MAX_SCOPES, TokenPolicy,
    };
    pub use crate::domain::event::OauthEvent;
    pub use crate::domain::introspection::{
        AccessTokenRecord, ActiveRefreshToken, REVOKED_BY_CLIENT, TokenQuery, TokenTypeHint,
        active_access_token, active_refresh_token, inactive,
    };
    pub use crate::domain::key::{ClientKey, MAX_KEYS};
    pub use crate::domain::logout::{
        CurrentSession, IdTokenHint, LogoutDecision, LogoutParameters, LogoutRequest,
        MAX_LOGOUT_LOCALES_LENGTH, MAX_LOGOUT_STATE_LENGTH, ReturnAddress, check_id_token_hint,
        refusal as logout_refusal,
    };
    pub use crate::domain::openid::{
        BearerRefusal, CheckedAccessToken, OPENID_SCOPE, PersonClaims, PublishedKey,
        ReadAccessToken, UI_LOCALES, access_token_hash, asks_for_openid, authentication_methods,
        check_access_token, discovery_document, id_token_claims, is_multi_factor,
        read_access_token, userinfo_claims,
    };
    pub use crate::domain::refresh::{
        DEFAULT_RETRY_WINDOW, FAMILY_SECRET_PURPOSE, FamilySecret, FamilyStatus,
        LONGEST_RETRY_WINDOW, OFFLINE_ACCESS, RefreshAsk, RefreshDecision, RefreshFamily,
        RefreshFamilyId, RefreshRefusal, RefreshTokenHash, RefreshTokenRecord, RefreshTokenValue,
    };
    pub use crate::domain::resource_server::{
        Audience, OPENID_SCOPES, ResourceServer, ResourceServerId, ResourceServerSettings,
        ResourceServerSnapshot, ScopeDefinition,
    };
    pub use crate::domain::secret::{
        ClientSecret, ClientSecretHash, ClientSecretId, ClientSecretValue,
    };
    pub use crate::domain::text::{MAX_SCOPE_LENGTH, is_scope};
    pub use crate::domain::token::{
        ASSERTION_LONGEST_AHEAD, ASSERTION_TYPE, AccessTokenClaims, AssertionAudience,
        BasicCredentials, CLOCK_ALLOWANCE, CheckedAssertion, GrantRequest, MAX_ASSERTION_BYTES,
        MAX_ASSERTION_ID_LENGTH, PresentedClient, SUPPORTED_GRANT_TYPES, TokenError, TokenRequest,
        TokenSubject, access_token_claims, assertion_issuer, check_assertion, claims_for,
    };
}
