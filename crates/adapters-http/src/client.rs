//! The guarded client.

use crate::address::is_public;
use hodor_kernel::{
    DestinationCheck, DomainError, ErrorKind, HttpClient, HttpMethod, HttpRequest, HttpResponse,
};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;
use reqwest::{Client, Url};
use std::error::Error as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Said by the resolver when a name leads somewhere that may not be
/// called; looked for in the error that comes back from the connection.
const FORBIDDEN: &str = "hodor: destination forbidden";

/// The limits of the client, and its one exception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPolicy {
    /// The longest a whole exchange may take.
    pub timeout: Duration,
    /// The longest connecting may take.
    pub connect_timeout: Duration,
    /// The largest response body accepted, in bytes.
    pub max_response_bytes: usize,
    /// Hosts with their ports, such as `provider:8080`, that are called
    /// without the address check and may use plain HTTP. For a
    /// development stack on one machine; empty anywhere real.
    pub development_hosts: Vec<String>,
}

impl Default for OutboundPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            max_response_bytes: 1024 * 1024,
            development_hosts: Vec::new(),
        }
    }
}

/// Resolves a name and refuses it unless every address it leads to is
/// public. The connection is then made to what this answered, so the
/// address that was checked is the address that is connected to.
struct PublicOnly;

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let found: Vec<SocketAddr> =
                tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            if found.is_empty() || found.iter().any(|address| !is_public(address.ip())) {
                tracing::warn!(
                    host = name.as_str(),
                    "outbound request refused: the name does not resolve to public addresses only"
                );
                return Err(FORBIDDEN.into());
            }
            Ok(Box::new(found.into_iter()) as Addrs)
        })
    }
}

/// The one way out. See the crate's documentation.
#[derive(Debug, Clone)]
pub struct GuardedHttpClient {
    guarded: Client,
    development: Client,
    policy: OutboundPolicy,
}

pub(crate) fn failure(kind: ErrorKind, code: &'static str, message: &'static str) -> DomainError {
    DomainError::new(kind, code, message)
}

pub(crate) fn url_invalid() -> DomainError {
    failure(
        ErrorKind::Invalid,
        "http.url_invalid",
        "the address cannot be called",
    )
}

fn forbidden() -> DomainError {
    failure(
        ErrorKind::Forbidden,
        "http.destination_forbidden",
        "the address may not be called",
    )
}

fn unreachable() -> DomainError {
    failure(
        ErrorKind::Unavailable,
        "http.unreachable",
        "the address did not answer",
    )
}

fn timed_out() -> DomainError {
    failure(
        ErrorKind::Unavailable,
        "http.timed_out",
        "the address did not answer in time",
    )
}

impl GuardedHttpClient {
    /// Builds the client.
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS library cannot be set up.
    pub fn new(policy: OutboundPolicy) -> Result<Self, DomainError> {
        let base = || {
            Client::builder()
                .redirect(Policy::none())
                .no_proxy()
                .timeout(policy.timeout)
                .connect_timeout(policy.connect_timeout)
                .user_agent("hodor")
        };
        let built = |client: Result<Client, reqwest::Error>| {
            client.map_err(|error| {
                DomainError::internal(
                    "http.client_unavailable",
                    "outbound requests cannot be made",
                )
                .with_detail(error.to_string())
            })
        };
        let guarded = built(
            base()
                .https_only(true)
                .dns_resolver(Arc::new(PublicOnly))
                .build(),
        )?;
        let development = built(base().build())?;
        if !policy.development_hosts.is_empty() {
            tracing::warn!(
                hosts = ?policy.development_hosts,
                "outbound requests to these hosts skip the address check and may use plain HTTP; this must not be set anywhere real"
            );
        }
        Ok(Self {
            guarded,
            development,
            policy,
        })
    }

    /// Whether `url` names one of the development hosts, exactly.
    fn is_development(&self, url: &Url) -> bool {
        let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
            return false;
        };
        let named = format!("{host}:{port}");
        self.policy
            .development_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&named))
    }

    /// Chooses the client for `url`, or refuses it.
    fn client_for(&self, url: &Url) -> Result<&Client, DomainError> {
        if !url.username().is_empty() || url.password().is_some() {
            return Err(url_invalid());
        }
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(url_invalid());
        }
        if self.is_development(url) {
            return Ok(&self.development);
        }
        if url.scheme() != "https" {
            return Err(url_invalid());
        }
        // An address written as numbers never reaches the resolver.
        let literal: Option<IpAddr> = url.host_str().and_then(|host| {
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .parse()
                .ok()
        });
        if literal.is_some_and(|address| !is_public(address)) {
            tracing::warn!("outbound request refused: the address is not public");
            return Err(forbidden());
        }
        Ok(&self.guarded)
    }
}

/// Whether an error, or anything that caused it, is the resolver's refusal.
fn was_forbidden(error: &reqwest::Error) -> bool {
    let mut cause = error.source();
    while let Some(inner) = cause {
        if inner.to_string().contains(FORBIDDEN) {
            return true;
        }
        cause = inner.source();
    }
    false
}

#[async_trait::async_trait]
impl HttpClient for GuardedHttpClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        let url = Url::parse(&request.url).map_err(|_| url_invalid())?;
        let client = self.client_for(&url)?;
        exchange(client, url, request, &self.policy).await
    }
}

#[async_trait::async_trait]
impl DestinationCheck for GuardedHttpClient {
    async fn check(&self, url: &str) -> Result<(), DomainError> {
        let url = Url::parse(url).map_err(|_| url_invalid())?;
        let client = self.client_for(&url)?;
        if std::ptr::eq(client, &self.development) {
            return Ok(());
        }
        let Some(name) = url.host_str() else {
            return Err(url_invalid());
        };
        // An address written as numbers was checked by `client_for`.
        if name
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok()
        {
            return Ok(());
        }
        let port = url.port_or_known_default().unwrap_or(443);
        let found: Vec<SocketAddr> = tokio::net::lookup_host((name, port))
            .await
            .map_err(|_| unreachable())?
            .collect();
        if found.is_empty() {
            return Err(unreachable());
        }
        if found.iter().any(|address| !is_public(address.ip())) {
            tracing::warn!(
                host = name,
                "address refused: the name does not resolve to public addresses only"
            );
            return Err(forbidden());
        }
        Ok(())
    }
}

/// Sends `request` to `url` with `client` and reads the answer within the
/// limits of `policy`. Shared by both clients of this crate.
pub(crate) async fn exchange(
    client: &Client,
    url: Url,
    request: HttpRequest,
    policy: &OutboundPolicy,
) -> Result<HttpResponse, DomainError> {
    let mut call = match request.method {
        HttpMethod::Get => client.get(url),
        HttpMethod::Post => client.post(url),
    };
    // The shorter of the client's limit and the request's own.
    let limit = request
        .time_limit
        .map_or(policy.timeout, |own| own.min(policy.timeout));
    call = call.timeout(limit);
    for (name, value) in &request.headers {
        call = call.header(name, value);
    }
    if let Some(body) = request.body {
        call = call.body(body);
    }

    let mut response = call.send().await.map_err(|error| {
        if was_forbidden(&error) {
            return forbidden();
        }
        if error.is_builder() {
            return url_invalid();
        }
        if error.is_timeout() {
            return timed_out();
        }
        tracing::warn!(error = %error.without_url(), "outbound request failed");
        unreachable()
    })?;

    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
        })
        .collect();

    // The limit is on what arrives, whatever length was announced.
    let most = policy.max_response_bytes;
    let mut body = Vec::new();
    loop {
        let chunk = response.chunk().await.map_err(|error| {
            if error.is_timeout() {
                return timed_out();
            }
            tracing::warn!(error = %error.without_url(), "outbound response cut short");
            unreachable()
        })?;
        let Some(chunk) = chunk else { break };
        if body.len() + chunk.len() > most {
            return Err(failure(
                ErrorKind::Unavailable,
                "http.response_too_large",
                "the answer was too large",
            ));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}
