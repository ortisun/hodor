//! The client for services the operator runs.
//!
//! The guarded client calls any public address and nothing else. Some
//! services Hodor calls live on a private network, often on the same
//! machine: Open Policy Agent. This client reverses the rule. It calls
//! only the origins the operator configured, exactly, and refuses every
//! other address whatever it resolves to. See
//! `docs/security/outbound-http.md`, "What does not go through this
//! client".

use crate::client::{OutboundPolicy, exchange, failure, url_invalid};
use hodor_kernel::{DomainError, ErrorKind, HttpClient, HttpRequest, HttpResponse};
use reqwest::redirect::Policy;
use reqwest::{Client, Url};
use std::net::IpAddr;

/// One configured origin: a scheme, a host and a port.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    fn of(url: &Url) -> Option<Self> {
        Some(Self {
            scheme: url.scheme().to_owned(),
            host: url.host_str()?.to_ascii_lowercase(),
            port: url.port_or_known_default()?,
        })
    }

    /// Whether the host is this machine, by name or by number.
    fn is_this_machine(&self) -> bool {
        let host = self.host.trim_start_matches('[').trim_end_matches(']');
        host == "localhost"
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    }
}

/// Reads one configured origin.
///
/// # Errors
///
/// Returns `http.origin_invalid` unless `value` is `http://` or
/// `https://`, a host and an optional port, with no path other than `/`,
/// no query, no fragment and no name or password.
fn parse_origin(value: &str) -> Result<Origin, DomainError> {
    let invalid = || {
        DomainError::invalid(
            "http.origin_invalid",
            "a service's address is http:// or https://, a host and an optional port, and \
             nothing else",
        )
    };
    let url = Url::parse(value).map_err(|_| invalid())?;
    let bare = matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none();
    if !bare {
        return Err(invalid());
    }
    Origin::of(&url).ok_or_else(invalid)
}

/// The client for services the operator configured. See the module's
/// documentation.
#[derive(Debug, Clone)]
pub struct ServiceHttpClient {
    client: Client,
    origins: Vec<Origin>,
    policy: OutboundPolicy,
}

impl ServiceHttpClient {
    /// Builds a client that calls only `origins`. The policy's
    /// development hosts are ignored: every origin here is already named
    /// by the operator.
    ///
    /// # Errors
    ///
    /// Returns `http.origin_invalid` for an origin that is not one, or an
    /// error if the TLS library cannot be set up.
    pub fn new(origins: &[String], policy: OutboundPolicy) -> Result<Self, DomainError> {
        let origins = origins
            .iter()
            .map(|origin| parse_origin(origin))
            .collect::<Result<Vec<_>, _>>()?;
        for origin in &origins {
            if origin.scheme == "http" && !origin.is_this_machine() {
                tracing::warn!(
                    host = origin.host,
                    port = origin.port,
                    "a service is called over plain HTTP on another machine: its token and the \
                     decisions travel in the clear"
                );
            }
        }
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .timeout(policy.timeout)
            .connect_timeout(policy.connect_timeout)
            .user_agent("hodor")
            .build()
            .map_err(|error| {
                DomainError::internal(
                    "http.client_unavailable",
                    "outbound requests cannot be made",
                )
                .with_detail(error.to_string())
            })?;
        Ok(Self {
            client,
            origins,
            policy,
        })
    }

    /// Whether `value` is an origin this client would accept.
    ///
    /// # Errors
    ///
    /// Returns `http.origin_invalid` as [`ServiceHttpClient::new`] would.
    pub fn check_origin(value: &str) -> Result<(), DomainError> {
        parse_origin(value).map(|_| ())
    }
}

#[async_trait::async_trait]
impl HttpClient for ServiceHttpClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        let url = Url::parse(&request.url).map_err(|_| url_invalid())?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(url_invalid());
        }
        let configured = Origin::of(&url)
            .is_some_and(|origin| self.origins.iter().any(|known| known == &origin));
        if !configured {
            tracing::warn!("outbound request refused: the origin is not a configured service");
            return Err(failure(
                ErrorKind::Forbidden,
                "http.destination_not_configured",
                "the address is not a service this installation calls",
            ));
        }
        exchange(&self.client, url, request, &self.policy).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_origin_is_a_scheme_a_host_and_a_port_only() {
        for good in [
            "http://localhost:8181",
            "https://policy.internal",
            "http://10.0.0.5:8181/",
            "http://[::1]:8181",
        ] {
            assert!(parse_origin(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "localhost:8181",
            "ftp://localhost",
            "http://localhost:8181/v1/data",
            "http://localhost:8181?x=1",
            "http://localhost:8181#part",
            "http://user:password@localhost:8181",
            "http://user@localhost:8181",
        ] {
            assert_eq!(
                parse_origin(bad)
                    .map(|_| ())
                    .map_err(|e| e.code().to_owned()),
                Err("http.origin_invalid".to_owned()),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_default_port_makes_the_same_origin() {
        assert_eq!(
            parse_origin("https://policy.internal").ok(),
            parse_origin("https://POLICY.internal:443").ok()
        );
        assert_ne!(
            parse_origin("http://policy.internal").ok(),
            parse_origin("https://policy.internal").ok()
        );
    }

    #[test]
    fn this_machine_is_told_apart() {
        for local in ["http://localhost:1", "http://127.0.0.1:1", "http://[::1]:1"] {
            assert!(
                parse_origin(local).expect(local).is_this_machine(),
                "{local}"
            );
        }
        assert!(
            !parse_origin("http://10.0.0.5:1")
                .expect("private")
                .is_this_machine()
        );
    }
}
