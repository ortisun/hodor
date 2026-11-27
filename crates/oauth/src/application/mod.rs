//! The use cases of the OAuth context and the ports they need.

pub(crate) mod authorization;
pub(crate) mod backchannel;
pub(crate) mod claim_mapper;
pub(crate) mod client_keys;
pub(crate) mod consent;
pub(crate) mod exchange;
pub(crate) mod forwarded;
pub(crate) mod introspection;
pub(crate) mod logout;
pub(crate) mod pairwise;
pub(crate) mod ports;
pub(crate) mod pushed;
pub(crate) mod registration;
pub(crate) mod resource_access;
pub(crate) mod service;
pub(crate) mod token;
pub(crate) mod userinfo;
