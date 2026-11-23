//! HTTP layer of Hodor.
//!
//! This crate turns HTTP requests into calls on the contexts' use cases and
//! their results back into responses. It owns what is common to every
//! route: resolving the tenant from the URL, request identifiers, security
//! headers, limits, error documents and health endpoints.
//!
//! It never depends on an adapter. What it needs from the outside world
//! comes in through traits ([`TenantResolver`], [`ReadinessCheck`]) that the
//! composition root implements.

mod admin;
mod authorization_api;
mod authorize;
mod bearer;
mod consent;
mod health;
mod interaction;
mod key_set;
mod logout;
mod openid;
mod pages;
mod policy_agent;
mod problem;
mod request;
mod server;
mod tenant;
mod token;

pub use admin::{
    ADMIN_OPENAPI, ADMIN_OPERATIONS, AdminState, CONSOLE_SESSION_HOURS, ConsoleState, admin_routes,
    console_routes,
};
pub use authorization_api::{
    AUTHORIZATION_API_AUDIENCE, AUTHORIZATION_OPENAPI, AUTHORIZATION_OPERATIONS,
    AuthorizationApiState, EVALUATE_SCOPE, EXPLAIN_SCOPE, SIMULATE_SCOPE, authorization_api_routes,
};
pub use authorize::{AuthorizationState, authorization_routes};
pub use consent::{ConsentState, consent_routes};
pub use health::{Health, ReadinessCheck, ops_router};
pub use interaction::{InteractionState, interaction_routes};
pub use key_set::key_set_routes;
pub use logout::{LogoutState, logout_routes};
pub use openid::{DiscoveryState, UserInfoState, discovery_routes, userinfo_routes};
pub use pages::{
    CONSOLE_ASSETS_PATH, CONSOLE_PATHS, PAGE_ASSETS_PATH, PAGE_PATHS,
    PAGES_CONTENT_SECURITY_POLICY, PROVIDER_CALLBACK_PAGE, Pages,
};
pub use policy_agent::policy_agent_routes;
pub use problem::Problem;
pub use request::ClientAddress;
pub use server::{Limits, public_router, serve};
pub use tenant::{ResolvedTenant, TenantResolver, TenantSlug, TenantStatus};
pub use token::{TokenState, token_routes};
