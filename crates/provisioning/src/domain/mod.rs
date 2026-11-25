//! The domain of the provisioning context: SCIM's schemas and resources,
//! their mapping to the identity context's users and groups, the filter
//! parser, `PATCH`, versions and bulk requests. Computation on values
//! only; nothing here reads storage.

pub(crate) mod attribute;
pub(crate) mod bulk;
pub(crate) mod error;
pub(crate) mod evaluate;
pub(crate) mod event;
pub(crate) mod filter;
pub(crate) mod patch;
pub(crate) mod query;
pub(crate) mod replace;
pub(crate) mod resource;
pub(crate) mod schema;
pub(crate) mod version;
