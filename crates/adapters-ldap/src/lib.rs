//! Directory adapter.
//!
//! Implements the federation context's `DirectoryClient` with `ldap3`:
//! binds as Hodor, searches for one entry, and binds as that entry with
//! the password a person typed. See
//! `docs/architecture/contexts/federation.md`, "Signing in through a
//! directory".
//!
//! Directories live on private networks, so the guarded outbound HTTP
//! client's rule about public addresses cannot hold here. The rule here is
//! the installation's list of directories: nothing else is ever connected
//! to.

use hodor_federation::api::{
    DirectoryAnswer, DirectoryClient, DirectoryEntry, DirectoryQuery, directory_host,
};
use hodor_kernel::{DomainError, ErrorKind, Secret};
use ldap3::{LdapConnAsync, LdapConnSettings, LdapError, Scope, SearchEntry, SearchOptions};
use std::time::Duration;

#[cfg(feature = "testing")]
pub mod testing;

/// LDAP's result for a wrong password.
const INVALID_CREDENTIALS: u32 = 49;
/// LDAP's result when a search found more entries than were allowed.
const SIZE_LIMIT_EXCEEDED: u32 = 4;

fn unavailable(detail: impl Into<String>) -> DomainError {
    DomainError::new(
        ErrorKind::Unavailable,
        "federation.provider_unavailable",
        "the identity provider cannot be used right now",
    )
    .with_detail(detail)
}

/// [`DirectoryClient`] over LDAP.
#[derive(Debug, Clone)]
pub struct LdapDirectoryClient {
    /// The directories that may be connected to, as `host:port`.
    allowed_hosts: Vec<String>,
    timeout: Duration,
}

impl LdapDirectoryClient {
    /// A client that connects to these directories and to no other, each
    /// written as `host:port`.
    #[must_use]
    pub fn new(allowed_hosts: &[String]) -> Self {
        Self {
            allowed_hosts: allowed_hosts.to_vec(),
            timeout: Duration::from_secs(10),
        }
    }

    fn is_allowed(&self, address: &str) -> bool {
        directory_host(address).is_some_and(|host| {
            self.allowed_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&host))
        })
    }

    async fn ask(
        &self,
        query: &DirectoryQuery,
        password: &Secret<String>,
    ) -> Result<DirectoryAnswer, LdapError> {
        let settings = LdapConnSettings::new().set_conn_timeout(self.timeout);
        let (connection, mut ldap) = LdapConnAsync::with_settings(settings, &query.address).await?;
        ldap3::drive!(connection);
        ldap.with_timeout(self.timeout);

        // As Hodor, to search.
        ldap.simple_bind(&query.bind_name, query.bind_password.expose())
            .await?
            .success()?;
        // Two at most: one is the answer, two are enough to know there is
        // more than one.
        let searched = ldap
            .with_search_options(SearchOptions::new().sizelimit(2))
            .with_timeout(self.timeout)
            .search(
                &query.base,
                Scope::Subtree,
                &query.filter,
                &query.attributes,
            )
            .await?;
        let (found, result) = (searched.0, searched.1);
        if result.rc == SIZE_LIMIT_EXCEEDED || found.len() > 1 {
            let _ = ldap.unbind().await;
            return Ok(DirectoryAnswer::Refused("ambiguous"));
        }
        result.success()?;
        let Some(found) = found.into_iter().next() else {
            let _ = ldap.unbind().await;
            return Ok(DirectoryAnswer::Refused("not_found"));
        };
        let found = SearchEntry::construct(found);

        // As the person: the directory deciding the password is right is
        // the proof.
        let bound = ldap.simple_bind(&found.dn, password.expose()).await?;
        let _ = ldap.unbind().await;
        if bound.rc == INVALID_CREDENTIALS {
            return Ok(DirectoryAnswer::Refused("wrong_password"));
        }
        bound.success()?;

        let mut attributes: Vec<(String, Vec<Vec<u8>>)> = found
            .attrs
            .into_iter()
            .map(|(name, values)| (name, values.into_iter().map(String::into_bytes).collect()))
            .collect();
        attributes.extend(found.bin_attrs);
        // In a fixed order, so that the same entry is always the same answer.
        attributes.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(DirectoryAnswer::Verified(DirectoryEntry {
            name: found.dn,
            attributes,
        }))
    }
}

#[async_trait::async_trait]
impl DirectoryClient for LdapDirectoryClient {
    async fn verify(
        &self,
        query: &DirectoryQuery,
        password: &Secret<String>,
    ) -> Result<DirectoryAnswer, DomainError> {
        if !self.is_allowed(&query.address) {
            return Err(DomainError::new(
                ErrorKind::Forbidden,
                "federation.directory_not_allowed",
                "this installation may not connect to that directory",
            ));
        }
        // An empty password is an anonymous bind, which a directory
        // answers as a success.
        if password.expose().is_empty() {
            return Ok(DirectoryAnswer::Refused("empty_password"));
        }
        self.ask(query, password).await.map_err(|error| {
            // Neither the password nor the filter is in an error of
            // `ldap3`; the directory's own message may be, and goes to
            // the log only.
            unavailable(format!("the directory could not be asked: {error}"))
        })
    }
}
