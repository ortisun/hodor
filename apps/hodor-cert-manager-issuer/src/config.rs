//! The configuration file: where Hodor is, the tenant, and the client the
//! issuer signs in as.
//!
//! Specified in `docs/operations/hodor-cert-manager-issuer.md`,
//! "Configuration".

use serde::Deserialize;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// How long one call to Hodor may take, unless the configuration says.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(10_000);
/// The longest a call to Hodor may be allowed to take.
const MAX_TIMEOUT_MILLISECONDS: u64 = 60_000;

/// Why the configuration cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the configuration cannot be used: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

fn refused(reason: impl Into<String>) -> ConfigError {
    ConfigError(reason.into())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    hodor: HodorFile,
    client: ClientFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HodorFile {
    url: String,
    tenant: String,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    timeout_milliseconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientFile {
    client_id: String,
    authentication: AuthenticationFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "method", rename_all = "snake_case")]
enum AuthenticationFile {
    Forwarded,
    PrivateKeyJwt {
        key_file: PathBuf,
        #[serde(default)]
        key_id: Option<String>,
    },
}

/// How the issuer's client proves who it is at the token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authentication {
    /// With nothing but `client_id`: the proxy in front of Hodor forwards
    /// the identity the issuer's sidecar presented.
    Forwarded,
    /// With an assertion signed by the key in `key_file`.
    PrivateKeyJwt {
        /// The file holding the key, in PEM.
        key_file: PathBuf,
        /// The key's `kid` among the client's keys, if given.
        key_id: Option<String>,
    },
}

/// The configuration, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Hodor's address, without a path and without a final `/`.
    pub hodor_url: String,
    /// The tenant's slug.
    pub tenant: String,
    /// The tenant's issuer, which an assertion names as its audience.
    pub issuer: String,
    /// How long one call to Hodor may take.
    pub timeout: Duration,
    /// The issuer's client.
    pub client_id: String,
    /// How that client proves who it is.
    pub authentication: Authentication,
}

impl Settings {
    /// Reads and checks a configuration file's text.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] saying what is wrong.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let file: FileConfig =
            serde_json::from_str(text).map_err(|error| refused(error.to_string()))?;
        let hodor_url = hodor_url(&file.hodor.url)?;
        let tenant = file.hodor.tenant;
        if tenant.is_empty()
            || !tenant
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(refused(
                "hodor.tenant is a tenant's slug: lowercase letters, digits and `-`",
            ));
        }
        let issuer = match file.hodor.issuer {
            Some(issuer) if issuer.is_empty() => {
                return Err(refused("hodor.issuer, when given, is not empty"));
            }
            Some(issuer) => issuer,
            None => format!("{hodor_url}/t/{tenant}"),
        };
        let timeout = match file.hodor.timeout_milliseconds {
            None => DEFAULT_TIMEOUT,
            Some(milliseconds) if (1..=MAX_TIMEOUT_MILLISECONDS).contains(&milliseconds) => {
                Duration::from_millis(milliseconds)
            }
            Some(_) => {
                return Err(refused("hodor.timeout_milliseconds is from 1 to 60000"));
            }
        };
        let client_id = file.client.client_id;
        if client_id.is_empty() || client_id.len() > 255 {
            return Err(refused(
                "client.client_id is the client's identifier, 1 to 255 characters",
            ));
        }
        let authentication = match file.client.authentication {
            AuthenticationFile::Forwarded => Authentication::Forwarded,
            AuthenticationFile::PrivateKeyJwt { key_file, key_id } => {
                if key_file.as_os_str().is_empty() {
                    return Err(refused(
                        "client.authentication.key_file names the file holding the key",
                    ));
                }
                if key_id
                    .as_deref()
                    .is_some_and(|kid| kid.is_empty() || kid.len() > 128)
                {
                    return Err(refused(
                        "client.authentication.key_id, when given, is 1 to 128 characters",
                    ));
                }
                Authentication::PrivateKeyJwt { key_file, key_id }
            }
        };
        Ok(Self {
            hodor_url,
            tenant,
            issuer,
            timeout,
            client_id,
            authentication,
        })
    }

    /// The token endpoint of the tenant.
    #[must_use]
    pub fn token_endpoint(&self) -> String {
        format!("{}/t/{}/oauth2/token", self.hodor_url, self.tenant)
    }

    /// The signing operation of the tenant's certificate authority.
    #[must_use]
    pub fn signing_endpoint(&self) -> String {
        format!(
            "{}/t/{}/api/v1/admin/certificate-authority/intermediates",
            self.hodor_url, self.tenant
        )
    }
}

/// Hodor's address: `http` or `https`, a host, no path, query or fragment.
fn hodor_url(text: &str) -> Result<String, ConfigError> {
    let shape = || {
        refused(
            "hodor.url is Hodor's address, http or https, with no path, such as http://hodor:8080",
        )
    };
    let url = reqwest::Url::parse(text).map_err(|_| shape())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(shape());
    }
    Ok(text.trim_end_matches('/').to_owned())
}

#[cfg(test)]
mod tests {
    use super::{Authentication, DEFAULT_TIMEOUT, Settings};
    use std::path::PathBuf;
    use std::time::Duration;

    fn reads(text: &str) -> Settings {
        Settings::from_json(text).expect("the configuration reads")
    }

    fn refused(text: &str, says: &str) {
        let error = Settings::from_json(text).expect_err("refused").to_string();
        assert!(error.contains(says), "{error}");
    }

    #[test]
    fn a_forwarded_client_needs_nothing_but_its_identifier() {
        let settings = reads(
            r#"{ "hodor": { "url": "http://hodor.hodor.svc:8080/", "tenant": "acme" },
                 "client": { "client_id": "issuer", "authentication": { "method": "forwarded" } } }"#,
        );
        assert_eq!(settings.hodor_url, "http://hodor.hodor.svc:8080");
        assert_eq!(settings.issuer, "http://hodor.hodor.svc:8080/t/acme");
        assert_eq!(settings.timeout, DEFAULT_TIMEOUT);
        assert_eq!(settings.authentication, Authentication::Forwarded);
        assert_eq!(
            settings.token_endpoint(),
            "http://hodor.hodor.svc:8080/t/acme/oauth2/token"
        );
        assert_eq!(
            settings.signing_endpoint(),
            "http://hodor.hodor.svc:8080/t/acme/api/v1/admin/certificate-authority/intermediates"
        );
    }

    #[test]
    fn a_key_names_its_file_and_perhaps_its_identifier() {
        let settings = reads(
            r#"{ "hodor": { "url": "https://login.example.com", "tenant": "acme",
                            "issuer": "https://login.example.com/t/acme", "timeout_milliseconds": 2500 },
                 "client": { "client_id": "issuer",
                             "authentication": { "method": "private_key_jwt", "key_file": "/keys/key.pem", "key_id": "k1" } } }"#,
        );
        assert_eq!(settings.timeout, Duration::from_millis(2500));
        assert_eq!(
            settings.authentication,
            Authentication::PrivateKeyJwt {
                key_file: PathBuf::from("/keys/key.pem"),
                key_id: Some("k1".to_owned()),
            }
        );
    }

    #[test]
    fn what_breaks_a_rule_is_refused_with_its_reason() {
        let client =
            r#""client": { "client_id": "issuer", "authentication": { "method": "forwarded" } }"#;
        refused(
            &format!(
                r#"{{ "hodor": {{ "url": "http://hodor/path", "tenant": "acme" }}, {client} }}"#
            ),
            "hodor.url",
        );
        refused(
            &format!(r#"{{ "hodor": {{ "url": "ftp://hodor", "tenant": "acme" }}, {client} }}"#),
            "hodor.url",
        );
        refused(
            &format!(r#"{{ "hodor": {{ "url": "http://hodor", "tenant": "Acme" }}, {client} }}"#),
            "hodor.tenant",
        );
        refused(
            &format!(r#"{{ "hodor": {{ "url": "http://hodor", "tenant": "" }}, {client} }}"#),
            "hodor.tenant",
        );
        refused(
            &format!(
                r#"{{ "hodor": {{ "url": "http://hodor", "tenant": "acme", "issuer": "" }}, {client} }}"#
            ),
            "hodor.issuer",
        );
        refused(
            &format!(
                r#"{{ "hodor": {{ "url": "http://hodor", "tenant": "acme", "timeout_milliseconds": 0 }}, {client} }}"#
            ),
            "timeout_milliseconds",
        );
        refused(
            &format!(
                r#"{{ "hodor": {{ "url": "http://hodor", "tenant": "acme", "timeout_milliseconds": 60001 }}, {client} }}"#
            ),
            "timeout_milliseconds",
        );
        refused(
            r#"{ "hodor": { "url": "http://hodor", "tenant": "acme" },
                 "client": { "client_id": "", "authentication": { "method": "forwarded" } } }"#,
            "client.client_id",
        );
        refused(
            r#"{ "hodor": { "url": "http://hodor", "tenant": "acme" },
                 "client": { "client_id": "issuer", "authentication": { "method": "private_key_jwt", "key_file": "" } } }"#,
            "key_file",
        );
        refused(
            r#"{ "hodor": { "url": "http://hodor", "tenant": "acme" },
                 "client": { "client_id": "issuer", "authentication": { "method": "private_key_jwt", "key_file": "/k", "key_id": "" } } }"#,
            "key_id",
        );
        refused(
            r#"{ "hodor": { "url": "http://hodor", "tenant": "acme" },
                 "client": { "client_id": "issuer", "authentication": { "method": "client_secret_basic" } } }"#,
            "unknown variant",
        );
        refused(
            r#"{ "hodor": { "url": "http://hodor", "tenant": "acme" },
                 "client": { "client_id": "issuer", "authentication": { "method": "forwarded" } }, "more": 1 }"#,
            "unknown field",
        );
        refused(
            r#"{ "hodor": { "url": "http://hodor", "tenant": "acme" } }"#,
            "client",
        );
    }
}
