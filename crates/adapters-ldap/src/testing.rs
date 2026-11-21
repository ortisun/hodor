//! A directory for tests: OpenLDAP in a container, with people in it.
//! Never use outside tests.

use ldap3::{LdapConnAsync, Mod};
use std::collections::HashSet;
use std::time::Duration;
use testcontainers::core::{IntoContainerPort as _, WaitFor};
use testcontainers::runners::AsyncRunner as _;
use testcontainers::{ContainerAsync, GenericImage, ImageExt as _};

/// Where people are, in the test directory.
pub const BASE: &str = "ou=people,dc=example,dc=org";
/// The name Hodor binds with: a read-only account, as it would be in a
/// real installation.
pub const BIND_NAME: &str = "cn=readonly,dc=example,dc=org";
/// Its password.
pub const BIND_PASSWORD: &str = "readonly-password";
const ADMIN_NAME: &str = "cn=admin,dc=example,dc=org";
const ADMIN_PASSWORD: &str = "admin-password";

/// One person to put in the directory.
#[derive(Debug, Clone)]
pub struct Person<'a> {
    /// The login name, `uid`.
    pub uid: &'a str,
    /// The name, `cn`.
    pub name: &'a str,
    /// The address, `mail`.
    pub email: &'a str,
    /// The password.
    pub password: &'a str,
}

/// A running OpenLDAP. Removed when dropped.
pub struct TestDirectory {
    _container: ContainerAsync<GenericImage>,
    /// Its address, `ldap://127.0.0.1:port`.
    pub address: String,
    /// Its host and port, as the list of allowed directories names it.
    pub host: String,
}

impl std::fmt::Debug for TestDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestDirectory")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl TestDirectory {
    /// Starts a directory with an empty `ou=people`.
    ///
    /// # Panics
    ///
    /// Panics if the directory cannot be started.
    pub async fn start() -> Self {
        // The directory sets itself up, stops, and starts for good: only
        // that last start says `slapd starting`.
        let container = GenericImage::new("osixia/openldap", "1.5.0")
            .with_exposed_port(389.tcp())
            .with_wait_for(WaitFor::message_on_either_std("slapd starting"))
            .with_env_var("LDAP_ORGANISATION", "Example")
            .with_env_var("LDAP_DOMAIN", "example.org")
            .with_env_var("LDAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
            .with_env_var("LDAP_READONLY_USER", "true")
            .with_env_var("LDAP_READONLY_USER_USERNAME", "readonly")
            .with_env_var("LDAP_READONLY_USER_PASSWORD", BIND_PASSWORD)
            .with_env_var("LDAP_TLS", "false")
            .start()
            .await
            .expect("start the directory");
        let port = container.get_host_port_ipv4(389).await.expect("port");
        let directory = Self {
            _container: container,
            address: format!("ldap://127.0.0.1:{port}"),
            host: format!("127.0.0.1:{port}"),
        };
        // The directory takes a few seconds to set itself up: it is ready
        // when both its admin and the account Hodor uses are accepted.
        for _ in 0..150 {
            if directory.accepts(BIND_NAME, BIND_PASSWORD).await
                && let Ok((connection, mut ldap)) = LdapConnAsync::new(&directory.address).await
            {
                ldap3::drive!(connection);
                let bound = ldap.simple_bind(ADMIN_NAME, ADMIN_PASSWORD).await;
                if bound.is_ok_and(|result| result.rc == 0) {
                    // The directory restarts once at the end of setting
                    // itself up, which can cut this short: then try again.
                    let created = ldap
                        .add(
                            BASE,
                            vec![
                                ("objectClass", HashSet::from(["organizationalUnit"])),
                                ("ou", HashSet::from(["people"])),
                            ],
                        )
                        .await;
                    let _ = ldap.unbind().await;
                    // Already there after a retry is fine.
                    if created.is_ok_and(|result| matches!(result.rc, 0 | 68)) {
                        return directory;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("the directory did not become ready");
    }

    async fn accepts(&self, name: &str, password: &str) -> bool {
        let Ok((connection, mut ldap)) = LdapConnAsync::new(&self.address).await else {
            return false;
        };
        ldap3::drive!(connection);
        let accepted = ldap
            .simple_bind(name, password)
            .await
            .is_ok_and(|result| result.rc == 0);
        let _ = ldap.unbind().await;
        accepted
    }

    /// Puts a person in the directory.
    ///
    /// # Panics
    ///
    /// Panics if the person cannot be added.
    pub async fn add(&self, person: &Person<'_>) {
        let (connection, mut ldap) = LdapConnAsync::new(&self.address).await.expect("connect");
        ldap3::drive!(connection);
        ldap.simple_bind(ADMIN_NAME, ADMIN_PASSWORD)
            .await
            .expect("bind")
            .success()
            .expect("admin");
        ldap.add(
            &format!("uid={},{BASE}", person.uid),
            vec![
                ("objectClass", HashSet::from(["inetOrgPerson"])),
                ("uid", HashSet::from([person.uid])),
                ("cn", HashSet::from([person.name])),
                ("sn", HashSet::from([person.name])),
                ("mail", HashSet::from([person.email])),
                ("userPassword", HashSet::from([person.password])),
            ],
        )
        .await
        .expect("add")
        .success()
        .expect("added");
        let _ = ldap.unbind().await;
    }

    /// Changes a person's address, as an administrator of the directory
    /// would.
    ///
    /// # Panics
    ///
    /// Panics if the change cannot be made.
    pub async fn change_email(&self, uid: &str, email: &str) {
        let (connection, mut ldap) = LdapConnAsync::new(&self.address).await.expect("connect");
        ldap3::drive!(connection);
        ldap.simple_bind(ADMIN_NAME, ADMIN_PASSWORD)
            .await
            .expect("bind")
            .success()
            .expect("admin");
        ldap.modify(
            &format!("uid={uid},{BASE}"),
            vec![Mod::Replace("mail", HashSet::from([email]))],
        )
        .await
        .expect("modify")
        .success()
        .expect("modified");
        let _ = ldap.unbind().await;
    }
}
