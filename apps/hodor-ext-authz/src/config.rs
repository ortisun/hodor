//! The configuration file: where Hodor is, where the checked token's claims
//! are, and one entry per protected application with its route rules.
//!
//! Specified in `docs/operations/hodor-ext-authz.md`, "Configuration".

use crate::pattern::PathPattern;
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

/// Where Envoy's JWT filter writes the claims it checked, unless the
/// configuration names another namespace.
pub const JWT_FILTER_NAMESPACE: &str = "envoy.filters.http.jwt_authn";
/// How long one call to Hodor may take, unless the configuration says.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);
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
    #[serde(default)]
    token: Option<TokenFile>,
    #[serde(default)]
    applications: Vec<ApplicationFile>,
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
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum TokenFile {
    Metadata(MetadataFile),
    Header(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataFile {
    #[serde(default)]
    namespace: Option<String>,
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationFile {
    destination: String,
    client_id: String,
    #[serde(default)]
    routes: Vec<RouteFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteFile {
    methods: Vec<String>,
    path: String,
    resource_type: String,
    action: String,
}

/// Where the claims of the token the proxy checked are found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    /// In the request's metadata: `filter_metadata[namespace][key]`, as
    /// Envoy's JWT filter writes it with `payload_in_metadata`.
    Metadata {
        /// The filter's namespace.
        namespace: String,
        /// The key, the value of `payload_in_metadata`.
        key: String,
    },
    /// In a header the proxy writes, base64url-encoded, believed only when
    /// it is the claims of the bearer token in `Authorization`.
    Header(String),
}

/// One route rule: these methods and this path give this resource type and
/// action.
#[derive(Debug, Clone)]
pub struct Route {
    /// The methods, in capitals.
    pub methods: Vec<String>,
    /// The path pattern.
    pub path: PathPattern,
    /// The resource type asked about.
    pub resource_type: String,
    /// The action asked about.
    pub action: String,
}

/// One protected application.
#[derive(Debug, Clone)]
pub struct Application {
    /// The workload's identity, as Envoy gives it in
    /// `destination.principal`.
    pub destination: String,
    /// The application's client, bound to the adapter's identity.
    pub client_id: String,
    /// The route rules, in order.
    pub routes: Vec<Route>,
}

/// The configuration, checked.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Hodor's address, without a path and without a final `/`.
    pub hodor_url: String,
    /// The tenant's slug.
    pub tenant: String,
    /// The tenant's issuer, which `iss` must be exactly.
    pub issuer: String,
    /// How long one call to Hodor may take.
    pub timeout: Duration,
    /// Where the checked token's claims are, if any is read.
    pub token: Option<TokenSource>,
    /// The protected applications.
    pub applications: Vec<Application>,
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
        let token = file.token.map(token_source).transpose()?;
        let mut destinations = HashSet::new();
        let mut applications = Vec::with_capacity(file.applications.len());
        for (index, application) in file.applications.into_iter().enumerate() {
            if application.destination.is_empty() {
                return Err(refused(format!(
                    "applications[{index}].destination is not empty"
                )));
            }
            if !destinations.insert(application.destination.clone()) {
                return Err(refused(format!(
                    "applications[{index}].destination `{}` is named twice",
                    application.destination
                )));
            }
            if application.client_id.is_empty() {
                return Err(refused(format!(
                    "applications[{index}].client_id is not empty"
                )));
            }
            let routes = application
                .routes
                .into_iter()
                .enumerate()
                .map(|(position, route)| {
                    self::route(route).map_err(|reason| {
                        refused(format!(
                            "applications[{index}].routes[{position}]: {reason}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            applications.push(Application {
                destination: application.destination,
                client_id: application.client_id,
                routes,
            });
        }
        Ok(Self {
            hodor_url,
            tenant,
            issuer,
            timeout,
            token,
            applications,
        })
    }

    /// The token endpoint of the tenant.
    #[must_use]
    pub fn token_endpoint(&self) -> String {
        format!("{}/t/{}/oauth2/token", self.hodor_url, self.tenant)
    }

    /// The Authorization API's `evaluate` of the tenant.
    #[must_use]
    pub fn evaluate_endpoint(&self) -> String {
        format!(
            "{}/t/{}/api/v1/authorization/evaluate",
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

fn token_source(file: TokenFile) -> Result<TokenSource, ConfigError> {
    match file {
        TokenFile::Metadata(metadata) => {
            let namespace = metadata
                .namespace
                .unwrap_or_else(|| JWT_FILTER_NAMESPACE.to_owned());
            if namespace.is_empty() || metadata.key.is_empty() {
                return Err(refused(
                    "token.metadata names a namespace, if given, and a key, neither empty",
                ));
            }
            Ok(TokenSource::Metadata {
                namespace,
                key: metadata.key,
            })
        }
        TokenFile::Header(name) => {
            let name = name.to_ascii_lowercase();
            let fits = !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
            if !fits || name == "authorization" {
                return Err(refused(
                    "token.header is the name of a header other than authorization",
                ));
            }
            Ok(TokenSource::Header(name))
        }
    }
}

fn route(file: RouteFile) -> Result<Route, String> {
    if file.methods.is_empty()
        || !file.methods.iter().all(|method| {
            !method.is_empty() && method.bytes().all(|byte| byte.is_ascii_uppercase())
        })
    {
        return Err("methods are one or more methods in capitals, such as GET".to_owned());
    }
    let path = PathPattern::parse(&file.path)?;
    if file.resource_type.is_empty() || file.action.is_empty() {
        return Err("resource_type and action are not empty".to_owned());
    }
    Ok(Route {
        methods: file.methods,
        path,
        resource_type: file.resource_type,
        action: file.action,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALLEST: &str = r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" } }"#;

    fn refusal(text: &str) -> String {
        Settings::from_json(text).expect_err("refused").0
    }

    #[test]
    fn the_smallest_file_takes_the_defaults() {
        let settings = Settings::from_json(SMALLEST).expect("read");
        assert_eq!(settings.hodor_url, "http://hodor:8080");
        assert_eq!(settings.issuer, "http://hodor:8080/t/acme");
        assert_eq!(settings.timeout, DEFAULT_TIMEOUT);
        assert_eq!(settings.token, None);
        assert!(settings.applications.is_empty());
        assert_eq!(
            settings.token_endpoint(),
            "http://hodor:8080/t/acme/oauth2/token"
        );
        assert_eq!(
            settings.evaluate_endpoint(),
            "http://hodor:8080/t/acme/api/v1/authorization/evaluate"
        );
    }

    #[test]
    fn a_whole_file_is_read() {
        let settings = Settings::from_json(
            r#"{
              "hodor": { "url": "https://hodor.example/", "tenant": "acme",
                         "issuer": "https://login.example.com/t/acme", "timeout_milliseconds": 250 },
              "token": { "metadata": { "key": "hodor" } },
              "applications": [
                { "destination": "spiffe://cluster.local/ns/shop/sa/orders", "client_id": "c1",
                  "routes": [ { "methods": ["GET", "HEAD"], "path": "/orders/{id}",
                                "resource_type": "order", "action": "read" } ] },
                { "destination": "spiffe://cluster.local/ns/shop/sa/invoices", "client_id": "c2" }
              ]
            }"#,
        )
        .expect("read");
        assert_eq!(settings.hodor_url, "https://hodor.example");
        assert_eq!(settings.issuer, "https://login.example.com/t/acme");
        assert_eq!(settings.timeout, Duration::from_millis(250));
        assert_eq!(
            settings.token,
            Some(TokenSource::Metadata {
                namespace: JWT_FILTER_NAMESPACE.to_owned(),
                key: "hodor".to_owned()
            })
        );
        assert_eq!(settings.applications.len(), 2);
        assert_eq!(settings.applications[0].routes[0].methods, ["GET", "HEAD"]);
        assert!(settings.applications[1].routes.is_empty());
        let header = Settings::from_json(
            r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" },
                 "token": { "header": "X-Hodor-Token-Claims" } }"#,
        )
        .expect("read");
        assert_eq!(
            header.token,
            Some(TokenSource::Header("x-hodor-token-claims".to_owned()))
        );
    }

    #[test]
    fn a_file_that_breaks_a_rule_is_refused_with_its_reason() {
        for (text, says) in [
            ("{", "EOF"),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" }, "extra": 1 }"#,
                "unknown field",
            ),
            (
                r#"{ "hodor": { "url": "ftp://hodor", "tenant": "acme" } }"#,
                "hodor.url",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080/path", "tenant": "acme" } }"#,
                "hodor.url",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080?a=b", "tenant": "acme" } }"#,
                "hodor.url",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "Acme" } }"#,
                "hodor.tenant",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme", "issuer": "" } }"#,
                "hodor.issuer",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme", "timeout_milliseconds": 0 } }"#,
                "timeout",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme", "timeout_milliseconds": 60001 } }"#,
                "timeout",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" }, "token": { "metadata": { "key": "" } } }"#,
                "token.metadata",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" }, "token": { "header": "authorization" } }"#,
                "token.header",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" }, "token": { "header": "a b" } }"#,
                "token.header",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" },
                  "applications": [ { "destination": "", "client_id": "c" } ] }"#,
                "destination",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" },
                  "applications": [ { "destination": "d", "client_id": "c" }, { "destination": "d", "client_id": "e" } ] }"#,
                "named twice",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" },
                  "applications": [ { "destination": "d", "client_id": "" } ] }"#,
                "client_id",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" },
                  "applications": [ { "destination": "d", "client_id": "c", "routes": [
                    { "methods": [], "path": "/", "resource_type": "t", "action": "a" } ] } ] }"#,
                "routes[0]: methods",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" },
                  "applications": [ { "destination": "d", "client_id": "c", "routes": [
                    { "methods": ["get"], "path": "/", "resource_type": "t", "action": "a" } ] } ] }"#,
                "methods",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" },
                  "applications": [ { "destination": "d", "client_id": "c", "routes": [
                    { "methods": ["GET"], "path": "orders", "resource_type": "t", "action": "a" } ] } ] }"#,
                "path",
            ),
            (
                r#"{ "hodor": { "url": "http://hodor:8080", "tenant": "acme" },
                  "applications": [ { "destination": "d", "client_id": "c", "routes": [
                    { "methods": ["GET"], "path": "/", "resource_type": "", "action": "a" } ] } ] }"#,
                "resource_type",
            ),
        ] {
            let reason = refusal(text);
            assert!(reason.contains(says), "{text}: {reason}");
        }
    }
}
