//! The settings of the key providers, read from the environment of the
//! server, the worker and the command-line tool alike. See
//! `docs/operations/keys-in-openbao.md`, "Settings".

use crate::openbao::OpenBaoKeyProvider;
use hodor_kernel::{DomainError, HttpClient, Secret};
use hodor_keys::api::{KeyProvider, KeyProviders};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Where Transit is mounted for Hodor unless the operator says otherwise.
pub const DEFAULT_TRANSIT_MOUNT: &str = "hodor-transit";
/// Where Kubernetes puts the token of a pod's service account.
pub const DEFAULT_KUBERNETES_TOKEN_FILE: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/token";
const DEFAULT_TIME_LIMIT: Duration = Duration::from_secs(5);
const LONGEST_TIME_LIMIT: Duration = Duration::from_secs(60);

/// Which provider makes new signing keys. Data keys are always made by
/// the local provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKeysIn {
    /// Made and used inside the server, wrapped under the root keys.
    Local,
    /// Made and used in OpenBao.
    OpenBao,
}

/// How Hodor signs in to OpenBao.
#[derive(Debug, Clone)]
pub enum OpenBaoLogin {
    /// With the token of the pod's service account, which OpenBao checks
    /// with the cluster.
    Kubernetes {
        /// Where the Kubernetes authentication method is mounted.
        mount: String,
        /// The role of that method that gives Hodor its policy.
        role: String,
        /// The file the token is read from at every sign-in, since the
        /// cluster replaces it before it expires.
        token_file: PathBuf,
    },
    /// With an AppRole's role identifier and secret identifier.
    AppRole {
        /// Where the AppRole authentication method is mounted.
        mount: String,
        /// The role identifier.
        role_id: String,
        /// The secret identifier.
        secret_id: Secret<String>,
    },
}

/// Where OpenBao is and how Hodor uses it.
#[derive(Debug, Clone)]
pub struct OpenBaoSettings {
    /// Its origin, such as `https://openbao.openbao.svc:8200`.
    pub address: String,
    /// Where Hodor's Transit secrets engine is mounted.
    pub transit_mount: String,
    /// How Hodor signs in.
    pub login: OpenBaoLogin,
    /// The longest one request may take.
    pub time_limit: Duration,
    /// The certificate authorities trusted for OpenBao's certificate, as a
    /// file of PEM certificates; `None` trusts the system's.
    pub certificate_authorities: Option<PathBuf>,
}

/// Every setting of the key providers.
#[derive(Debug, Clone)]
pub struct KeyProviderSettings {
    /// Which provider makes new signing keys.
    pub signing_keys_in: SigningKeysIn,
    /// OpenBao, when its address is set. Its versions are used whichever
    /// provider makes new keys.
    pub openbao: Option<OpenBaoSettings>,
}

fn invalid(detail: impl Into<String>) -> DomainError {
    DomainError::invalid(
        "keys.provider_settings_invalid",
        "the settings of the key provider are not valid",
    )
    .with_detail(detail)
}

/// A mount path: segments of letters, digits, `-` and `_`, joined by `/`.
fn mount(name: &str, value: String) -> Result<String, DomainError> {
    let value = value.trim_matches('/').to_owned();
    let usable = !value.is_empty()
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        });
    if usable {
        Ok(value)
    } else {
        Err(invalid(format!(
            "{name} is a path of letters, digits, `-` and `_`"
        )))
    }
}

impl KeyProviderSettings {
    /// Reads the settings, each variable through `lookup`, which answers
    /// `None` for a variable that is not set. An empty value counts as not
    /// set.
    ///
    /// # Errors
    ///
    /// Returns `keys.provider_settings_invalid`, naming the variable, for
    /// a value that cannot be used or a setting that is missing.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, DomainError> {
        let read = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());
        let required = |name: &str, because: &str| {
            read(name).ok_or_else(|| invalid(format!("{name} is required {because}")))
        };
        let signing_keys_in = match read("HODOR_KEY_PROVIDER").as_deref().map(str::trim) {
            None | Some("local") => SigningKeysIn::Local,
            Some("openbao") => SigningKeysIn::OpenBao,
            Some(_) => return Err(invalid("HODOR_KEY_PROVIDER is `local` or `openbao`")),
        };
        let Some(address) = read("HODOR_OPENBAO_ADDRESS") else {
            if signing_keys_in == SigningKeysIn::OpenBao {
                return Err(invalid(
                    "HODOR_OPENBAO_ADDRESS is required when HODOR_KEY_PROVIDER is `openbao`",
                ));
            }
            return Ok(Self {
                signing_keys_in,
                openbao: None,
            });
        };
        let address = address.trim().trim_end_matches('/').to_owned();
        let transit_mount = mount(
            "HODOR_OPENBAO_TRANSIT_MOUNT",
            read("HODOR_OPENBAO_TRANSIT_MOUNT").unwrap_or_else(|| DEFAULT_TRANSIT_MOUNT.to_owned()),
        )?;
        let method = required("HODOR_OPENBAO_AUTH_METHOD", "with HODOR_OPENBAO_ADDRESS")?;
        let login = match method.trim() {
            "kubernetes" => OpenBaoLogin::Kubernetes {
                mount: mount(
                    "HODOR_OPENBAO_AUTH_MOUNT",
                    read("HODOR_OPENBAO_AUTH_MOUNT").unwrap_or_else(|| "kubernetes".to_owned()),
                )?,
                role: required(
                    "HODOR_OPENBAO_KUBERNETES_ROLE",
                    "for Kubernetes authentication",
                )?
                .trim()
                .to_owned(),
                token_file: read("HODOR_OPENBAO_KUBERNETES_TOKEN_FILE").map_or_else(
                    || PathBuf::from(DEFAULT_KUBERNETES_TOKEN_FILE),
                    PathBuf::from,
                ),
            },
            "approle" => OpenBaoLogin::AppRole {
                mount: mount(
                    "HODOR_OPENBAO_AUTH_MOUNT",
                    read("HODOR_OPENBAO_AUTH_MOUNT").unwrap_or_else(|| "approle".to_owned()),
                )?,
                role_id: required(
                    "HODOR_OPENBAO_APPROLE_ROLE_ID",
                    "for AppRole authentication",
                )?
                .trim()
                .to_owned(),
                secret_id: Secret::new(
                    required(
                        "HODOR_OPENBAO_APPROLE_SECRET_ID",
                        "for AppRole authentication",
                    )?
                    .trim()
                    .to_owned(),
                ),
            },
            _ => {
                return Err(invalid(
                    "HODOR_OPENBAO_AUTH_METHOD is `kubernetes` or `approle`",
                ));
            }
        };
        let time_limit = match read("HODOR_OPENBAO_TIMEOUT_MS") {
            None => DEFAULT_TIME_LIMIT,
            Some(value) => value
                .trim()
                .parse::<u64>()
                .ok()
                .map(Duration::from_millis)
                .filter(|limit| !limit.is_zero() && *limit <= LONGEST_TIME_LIMIT)
                .ok_or_else(|| invalid("HODOR_OPENBAO_TIMEOUT_MS is 1 to 60000"))?,
        };
        Ok(Self {
            signing_keys_in,
            openbao: Some(OpenBaoSettings {
                address,
                transit_mount,
                login,
                time_limit,
                certificate_authorities: read("HODOR_OPENBAO_CA_FILE").map(PathBuf::from),
            }),
        })
    }
}

impl KeyProviderSettings {
    /// The provider the keys context is given: `local`, the provider
    /// inside the server, and OpenBao when its address is set, through the
    /// client `http` builds for it. New signing keys are made where
    /// [`KeyProviderSettings::signing_keys_in`] says, data keys always by
    /// `local`, the keys of certificate authorities by OpenBao when it is
    /// set, and every version is used by the provider that made it.
    ///
    /// # Errors
    ///
    /// Returns what `http` returns.
    pub fn providers(
        &self,
        local: Arc<dyn KeyProvider>,
        http: impl FnOnce(&OpenBaoSettings) -> Result<Arc<dyn HttpClient>, DomainError>,
    ) -> Result<KeyProviders, DomainError> {
        let Some(settings) = &self.openbao else {
            return Ok(KeyProviders::new(local.clone(), local));
        };
        let openbao: Arc<dyn KeyProvider> =
            Arc::new(OpenBaoKeyProvider::new(http(settings)?, settings));
        // The keys of certificate authorities are made in OpenBao whenever
        // it is configured, whatever makes the signing keys.
        Ok(match self.signing_keys_in {
            SigningKeysIn::OpenBao => KeyProviders::new(openbao.clone(), local),
            SigningKeysIn::Local => KeyProviders::new(local.clone(), local),
        }
        .with_authorities(openbao))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn read(pairs: &[(&str, &str)]) -> Result<KeyProviderSettings, DomainError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        KeyProviderSettings::from_lookup(|name| map.get(name).cloned())
    }

    fn detail(pairs: &[(&str, &str)]) -> String {
        let error = read(pairs).expect_err("refused");
        assert_eq!(error.code(), "keys.provider_settings_invalid");
        error.detail().unwrap_or_default().to_owned()
    }

    const APPROLE: [(&str, &str); 4] = [
        ("HODOR_OPENBAO_ADDRESS", "https://openbao.internal:8200/"),
        ("HODOR_OPENBAO_AUTH_METHOD", "approle"),
        ("HODOR_OPENBAO_APPROLE_ROLE_ID", "role"),
        ("HODOR_OPENBAO_APPROLE_SECRET_ID", "secret"),
    ];

    #[test]
    fn nothing_set_is_the_local_provider_alone() {
        for pairs in [
            &[][..],
            &[("HODOR_KEY_PROVIDER", ""), ("HODOR_OPENBAO_ADDRESS", "")][..],
            &[("HODOR_KEY_PROVIDER", "local")][..],
        ] {
            let settings = read(pairs).expect("settings");
            assert_eq!(settings.signing_keys_in, SigningKeysIn::Local);
            assert!(settings.openbao.is_none());
        }
    }

    #[test]
    fn an_approle_with_the_defaults() {
        let mut pairs = APPROLE.to_vec();
        pairs.push(("HODOR_KEY_PROVIDER", "openbao"));
        let settings = read(&pairs).expect("settings");
        assert_eq!(settings.signing_keys_in, SigningKeysIn::OpenBao);
        let openbao = settings.openbao.expect("openbao");
        assert_eq!(openbao.address, "https://openbao.internal:8200");
        assert_eq!(openbao.transit_mount, "hodor-transit");
        assert_eq!(openbao.time_limit, Duration::from_secs(5));
        assert_eq!(openbao.certificate_authorities, None);
        let OpenBaoLogin::AppRole {
            mount,
            role_id,
            secret_id,
        } = openbao.login
        else {
            panic!("an AppRole");
        };
        assert_eq!((mount.as_str(), role_id.as_str()), ("approle", "role"));
        assert_eq!(secret_id.expose(), "secret");
    }

    #[test]
    fn kubernetes_with_every_setting() {
        let settings = read(&[
            ("HODOR_OPENBAO_ADDRESS", "https://openbao.internal:8200"),
            ("HODOR_OPENBAO_TRANSIT_MOUNT", "/teams/hodor-transit/"),
            ("HODOR_OPENBAO_AUTH_METHOD", "kubernetes"),
            ("HODOR_OPENBAO_AUTH_MOUNT", "cluster-one"),
            ("HODOR_OPENBAO_KUBERNETES_ROLE", "hodor"),
            (
                "HODOR_OPENBAO_KUBERNETES_TOKEN_FILE",
                "/var/run/secrets/openbao/token",
            ),
            ("HODOR_OPENBAO_TIMEOUT_MS", "2500"),
            ("HODOR_OPENBAO_CA_FILE", "/etc/hodor/openbao-ca.pem"),
        ])
        .expect("settings");
        assert_eq!(settings.signing_keys_in, SigningKeysIn::Local);
        let openbao = settings.openbao.expect("openbao");
        assert_eq!(openbao.transit_mount, "teams/hodor-transit");
        assert_eq!(openbao.time_limit, Duration::from_millis(2500));
        assert_eq!(
            openbao.certificate_authorities,
            Some(PathBuf::from("/etc/hodor/openbao-ca.pem"))
        );
        let OpenBaoLogin::Kubernetes {
            mount,
            role,
            token_file,
        } = openbao.login
        else {
            panic!("Kubernetes");
        };
        assert_eq!((mount.as_str(), role.as_str()), ("cluster-one", "hodor"));
        assert_eq!(token_file, PathBuf::from("/var/run/secrets/openbao/token"));
    }

    #[test]
    fn what_cannot_be_used_is_refused_by_name() {
        assert!(detail(&[("HODOR_KEY_PROVIDER", "vault")]).contains("HODOR_KEY_PROVIDER"));
        assert!(detail(&[("HODOR_KEY_PROVIDER", "openbao")]).contains("HODOR_OPENBAO_ADDRESS"));
        assert!(
            detail(&[("HODOR_OPENBAO_ADDRESS", "https://openbao.internal")])
                .contains("HODOR_OPENBAO_AUTH_METHOD")
        );
        let with = |extra: (&'static str, &'static str)| {
            let mut pairs = APPROLE.to_vec();
            pairs.retain(|(name, _)| *name != extra.0);
            pairs.push(extra);
            detail(&pairs)
        };
        assert!(with(("HODOR_OPENBAO_AUTH_METHOD", "token")).contains("AUTH_METHOD"));
        assert!(with(("HODOR_OPENBAO_APPROLE_SECRET_ID", " ")).contains("SECRET_ID"));
        assert!(with(("HODOR_OPENBAO_TRANSIT_MOUNT", "a/../b")).contains("TRANSIT_MOUNT"));
        assert!(with(("HODOR_OPENBAO_TRANSIT_MOUNT", "a//b")).contains("TRANSIT_MOUNT"));
        assert!(with(("HODOR_OPENBAO_AUTH_MOUNT", "app role")).contains("AUTH_MOUNT"));
        for limit in ["0", "60001", "soon"] {
            assert!(with(("HODOR_OPENBAO_TIMEOUT_MS", limit)).contains("TIMEOUT_MS"));
        }
        assert!(
            detail(&[
                ("HODOR_OPENBAO_ADDRESS", "https://openbao.internal"),
                ("HODOR_OPENBAO_AUTH_METHOD", "kubernetes"),
            ])
            .contains("KUBERNETES_ROLE")
        );
    }

    #[test]
    fn the_secret_identifier_is_never_printed() {
        let settings = read(&APPROLE).expect("settings");
        assert!(!format!("{settings:?}").contains("secret\""));
    }
}
