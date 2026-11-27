//! Key providers outside the server.
//!
//! `OpenBaoKeyProvider` implements the keys context's `KeyProvider` on
//! OpenBao's Transit secrets engine: keys are made there, not exportable,
//! and every signature is made there; Hodor keeps only a name and the
//! public key. Requests go through the kernel's `HttpClient` port, which
//! the composition root fills with a client that calls only the address of
//! OpenBao. The settings are read by `KeyProviderSettings`.
//!
//! The specification is `docs/architecture/contexts/keys.md`, "The OpenBao
//! provider", and `docs/operations/keys-in-openbao.md`.

mod openbao;
mod public_key;
mod settings;

pub use openbao::{NAME as OPENBAO, OpenBaoKeyProvider};
pub use settings::{
    DEFAULT_KUBERNETES_TOKEN_FILE, DEFAULT_TRANSIT_MOUNT, KeyProviderSettings, OpenBaoLogin,
    OpenBaoSettings, SigningKeysIn,
};
