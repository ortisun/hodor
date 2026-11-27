//! Starts the containers the integration tests need and finds their ports,
//! the same way for every test that starts one. Never use outside tests.
//!
//! Specified in `docs/architecture/testing.md`, "Containers in tests".
//!
//! Every port a test asks for is published on `127.0.0.1` alone, on a port
//! Docker chooses, and the test reaches it there ([`HOST`]):
//!
//! * Docker chooses a host port without knowing what the machine's own
//!   processes listen on. Docker Desktop on macOS then listens on that port
//!   of every address, and a process of the machine, such as a server
//!   started by another test, may already listen on `127.0.0.1` at the same
//!   port: a connection to `127.0.0.1` reaches that process, not the
//!   container. Published on `127.0.0.1` alone, the port cannot be shared:
//!   the start fails, and is tried again with a new container.
//! * Docker answers the ports of a container that is not running with an
//!   empty list, which `get_host_port_ipv4` reports as `PortNotExposed`.
//!   The ports are read again until every one is published; a container
//!   that stopped is reported with its exit code and the last lines it
//!   wrote, and tried again.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::time::{Duration, Instant};
use testcontainers::bollard::models::{HostConfig, PortBinding};
use testcontainers::core::ContainerPort;
use testcontainers::runners::AsyncRunner as _;
use testcontainers::{ContainerAsync, ContainerRequest, Image, ImageExt as _};

/// The address every port is published on, and the one tests reach
/// containers at.
pub const HOST: &str = "127.0.0.1";

/// How many containers are started, at most, before a test gives up.
const ATTEMPTS: usize = 3;
/// How long Docker has to say where the ports of a running container are.
const PORTS_WITHIN: Duration = Duration::from_secs(30);
/// How many of the last lines a stopped container wrote are shown.
const LAST_LINES: usize = 30;

/// A running container whose ports are published on [`HOST`]. Removed
/// when dropped.
pub struct Started<I: Image> {
    container: ContainerAsync<I>,
    ports: Vec<(ContainerPort, u16)>,
}

impl<I: Image> fmt::Debug for Started<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Started")
            .field("container", &self.container.id())
            .field("ports", &self.ports)
            .finish()
    }
}

impl<I: Image> Started<I> {
    /// The port of [`HOST`] that `inside`, a port of the container, is
    /// published on.
    ///
    /// # Panics
    ///
    /// Panics if `inside` was not among the ports asked for.
    pub fn port(&self, inside: impl Into<ContainerPort>) -> u16 {
        let inside = inside.into();
        self.ports
            .iter()
            .find(|(asked, _)| *asked == inside)
            .map(|(_, published)| *published)
            .unwrap_or_else(|| panic!("{inside} was not among the ports asked for"))
    }

    /// The container.
    #[must_use]
    pub const fn container(&self) -> &ContainerAsync<I> {
        &self.container
    }

    /// The container, which the caller keeps from now on.
    #[must_use]
    pub fn into_container(self) -> ContainerAsync<I> {
        self.container
    }
}

/// Starts a container made by `request`, with each of `ports` published on
/// [`HOST`], and waits until Docker says where. `what` names the container
/// in a failure.
///
/// `request` is called once for each container started: when a start fails,
/// or the container stops before its ports are published, another one is
/// started, at most three in all.
///
/// # Panics
///
/// Panics, with the reason each container failed, when none could be
/// started.
pub async fn start<I, R>(what: &str, request: impl Fn() -> R, ports: &[ContainerPort]) -> Started<I>
where
    I: Image,
    R: Into<ContainerRequest<I>>,
{
    let (started, ()) = start_checked(what, request, ports, |_| async { Ok(()) }).await;
    started
}

/// Like [`start`], and then runs `check` on the container, such as a first
/// connection, and answers what it made too; when it fails, the container
/// is removed and another one is started, as for a failed start.
///
/// # Panics
///
/// Panics, with the reason each container failed, when none could be
/// started and checked.
pub async fn start_checked<I, R, C, F, T>(
    what: &str,
    request: impl Fn() -> R,
    ports: &[ContainerPort],
    check: C,
) -> (Started<I>, T)
where
    I: Image,
    R: Into<ContainerRequest<I>>,
    C: Fn(&Started<I>) -> F,
    F: Future<Output = Result<T, String>>,
{
    let mut failures = Vec::new();
    for attempt in 1..=ATTEMPTS {
        let started = match published(request().into(), ports).await {
            Ok(started) => started,
            Err(failure) => {
                failures.push(format!("container {attempt}: {failure}"));
                continue;
            }
        };
        match check(&started).await {
            Ok(made) => return (started, made),
            Err(failure) => failures.push(format!(
                "container {attempt}, {}: {failure}",
                started.container.id()
            )),
        }
    }
    panic!(
        "{what} could not be started; is Docker running?\n{}",
        failures.join("\n")
    );
}

/// Starts one container and reads its ports until every one is published.
async fn published<I: Image>(
    request: ContainerRequest<I>,
    ports: &[ContainerPort],
) -> Result<Started<I>, String> {
    let bindings: HashMap<String, Option<Vec<PortBinding>>> = ports
        .iter()
        .map(|port| {
            (
                port.to_string(),
                Some(vec![PortBinding {
                    host_ip: Some(HOST.to_owned()),
                    // Empty: Docker chooses a free port.
                    host_port: Some(String::new()),
                }]),
            )
        })
        .collect();
    let container = request
        .with_host_config_modifier(move |config: &mut HostConfig| {
            config.publish_all_ports = Some(false);
            config.port_bindings = Some(bindings.clone());
        })
        .start()
        .await
        .map_err(|error| format!("it did not start: {error}"))?;

    let deadline = Instant::now() + PORTS_WITHIN;
    loop {
        let found = container
            .ports()
            .await
            .map_err(|error| format!("its ports could not be read: {error}"))?;
        let mapped: Option<Vec<(ContainerPort, u16)>> = ports
            .iter()
            .map(|&port| found.map_to_host_port_ipv4(port).map(|host| (port, host)))
            .collect();
        if let Some(ports) = mapped {
            return Ok(Started { container, ports });
        }
        if !container.is_running().await.unwrap_or(false) {
            return Err(stopped(&container).await);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{} is running, and Docker did not publish its ports within {} seconds",
                container.id(),
                PORTS_WITHIN.as_secs()
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Why a container that stopped before its ports were published did: its
/// exit code and the last lines it wrote.
async fn stopped<I: Image>(container: &ContainerAsync<I>) -> String {
    let code = container
        .exit_code()
        .await
        .ok()
        .flatten()
        .map_or_else(|| "unknown".to_owned(), |code| code.to_string());
    let mut written = String::new();
    for output in [
        container.stdout_to_vec().await,
        container.stderr_to_vec().await,
    ]
    .into_iter()
    .flatten()
    {
        written.push_str(&String::from_utf8_lossy(&output));
    }
    let lines: Vec<&str> = written.lines().collect();
    let last = lines[lines.len().saturating_sub(LAST_LINES)..].join("\n");
    format!(
        "{} stopped, with exit code {code}, before its ports were published; it last wrote:\n{last}",
        container.id()
    )
}
