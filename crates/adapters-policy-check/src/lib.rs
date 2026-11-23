//! `OpaProcessChecker`: the `PolicyChecker` of the policy lifecycle, which
//! runs the `opa` binary as a child process with nothing of its own.
//!
//! Each run gets a directory of its own, readable by its owner only, with
//! the version's files under the tenant's tree and Hodor's capabilities
//! file, and nothing else; it is removed afterwards. The process starts
//! with an empty environment but `HOME`, `GOMEMLIMIT` and `GOMAXPROCS`, no
//! standard input, a time limit after which it is killed, and a limit on
//! what is read of its output. It can reach no network: the built-ins that
//! would are not in the capabilities file, so a module calling them does
//! not compile. Decision 0026 records why this is the mechanism.

use hodor_authorization_opa::api::{
    BundleFile, Diagnostic, PolicyChecker, Report, TestResult, tenant_root,
};
use hodor_kernel::{Digest, DomainError, TenantId};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt as _;
use tokio::process::Command;

/// The version of `opa` the capabilities file was made from, and the only
/// one accepted.
pub const OPA_VERSION: &str = "1.10.1";

/// Hodor's capabilities file, carried in the code so that it cannot differ
/// from the one the checks were built with.
pub const CAPABILITIES: &str = include_str!("../../../deploy/open-policy-agent/capabilities.json");

/// How a run is bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLimits {
    /// After this long the process is killed.
    pub time: Duration,
    /// What `GOMEMLIMIT` asks the Go runtime to stay under, in mebibytes.
    pub memory_mebibytes: u32,
    /// At most this many bytes of each of its outputs are read.
    pub output_bytes: usize,
}

impl Default for RunLimits {
    fn default() -> Self {
        Self {
            time: Duration::from_secs(30),
            memory_mebibytes: 256,
            output_bytes: 1024 * 1024,
        }
    }
}

fn unavailable(message: &str, detail: impl Into<String>) -> DomainError {
    DomainError::internal(
        "authorization.policy_checker_unavailable",
        message.to_owned(),
    )
    .with_detail(detail.into())
}

/// What a run of `opa` gave.
struct Outcome {
    /// Its exit status, unless it was killed.
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
    too_large: bool,
}

/// A directory of one run, removed when dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        // Nothing can be done about a directory that cannot be removed;
        // the next run makes another.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs `opa`. See the crate's documentation.
#[derive(Debug, Clone)]
pub struct OpaProcessChecker {
    binary: PathBuf,
    limits: RunLimits,
    scratch: PathBuf,
}

/// The SHA-256 of `bytes`, as 64 hexadecimal digits.
fn hexadecimal(bytes: &[u8]) -> String {
    hodor_authorization_opa::api::hexadecimal(bytes)
}

impl OpaProcessChecker {
    /// A checker over the binary at `binary`, refused unless it reports
    /// version 1.10.1 and, when `sha256` is given (64 hexadecimal digits),
    /// its SHA-256 is that. Runs are made under `scratch`, the system's
    /// temporary directory unless given.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_checker_binary_refused` for a binary
    /// that is missing, of another digest or of another version.
    pub async fn verified(
        binary: PathBuf,
        sha256: Option<&str>,
        digest: &dyn Digest,
        limits: RunLimits,
        scratch: Option<PathBuf>,
    ) -> Result<Self, DomainError> {
        let refused = |detail: String| {
            DomainError::invalid(
                "authorization.policy_checker_binary_refused",
                "the opa binary is not the one Hodor checks policies with",
            )
            .with_detail(detail)
        };
        let bytes = tokio::fs::read(&binary)
            .await
            .map_err(|error| refused(format!("{}: {error}", binary.display())))?;
        if let Some(expected) = sha256 {
            let actual = hexadecimal(&digest.sha256(&bytes));
            if !actual.eq_ignore_ascii_case(expected.trim()) {
                return Err(refused(format!(
                    "its SHA-256 is {actual}, not {}",
                    expected.trim()
                )));
            }
        }
        drop(bytes);
        let checker = Self {
            binary,
            limits,
            scratch: scratch.unwrap_or_else(std::env::temp_dir),
        };
        // Asking the version has a limit of its own, whatever the limit of
        // a check.
        let asking = Self {
            limits: RunLimits {
                time: limits.time.max(Duration::from_secs(10)),
                ..limits
            },
            ..checker.clone()
        };
        let version = asking
            .run(&checker.scratch, &["version"])
            .await
            .map_err(|error| refused(error.detail().unwrap_or_default().to_owned()))?;
        let reported = String::from_utf8_lossy(&version.stdout);
        if !reported
            .lines()
            .any(|line| line.trim() == format!("Version: {OPA_VERSION}"))
        {
            return Err(refused(format!(
                "it reports {:?}, not version {OPA_VERSION}",
                reported.lines().next().unwrap_or_default()
            )));
        }
        Ok(checker)
    }

    /// Runs `opa` with `arguments` in `directory`.
    async fn run(&self, directory: &Path, arguments: &[&str]) -> Result<Outcome, DomainError> {
        let mut child = Command::new(&self.binary)
            .args(arguments)
            .current_dir(directory)
            .env_clear()
            .env("HOME", directory)
            .env("GOMEMLIMIT", format!("{}MiB", self.limits.memory_mebibytes))
            .env("GOMAXPROCS", "2")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                unavailable("the opa binary could not be started", error.to_string())
            })?;
        let limit = u64::try_from(self.limits.output_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            return Err(unavailable(
                "the opa binary's output could not be read",
                "no pipe",
            ));
        };
        let reading = async {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let mut stdout = stdout.take(limit);
            let mut stderr = stderr.take(limit);
            let (read_out, read_err) =
                tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
            read_out.and(read_err).map(|_| (out, err))
        };
        let most = self.limits.output_bytes;
        let finished = tokio::time::timeout(self.limits.time, async {
            let read = reading.await;
            // Past the limit nothing more is read, so the process would
            // wait on its pipe: it is stopped instead.
            if read
                .as_ref()
                .is_ok_and(|(out, err)| out.len() > most || err.len() > most)
            {
                let _ = child.start_kill();
            }
            let status = child.wait().await;
            (read, status)
        })
        .await;
        match finished {
            Err(_) => {
                // Killed on drop as well; this ends it now.
                let _ = child.start_kill();
                Ok(Outcome {
                    status: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    timed_out: true,
                    too_large: false,
                })
            }
            Ok((read, status)) => {
                let (stdout, stderr) = read.map_err(|error| {
                    unavailable(
                        "the opa binary's output could not be read",
                        error.to_string(),
                    )
                })?;
                let status = status.map_err(|error| {
                    unavailable("the opa binary did not finish", error.to_string())
                })?;
                let too_large = stdout.len() > self.limits.output_bytes
                    || stderr.len() > self.limits.output_bytes;
                Ok(Outcome {
                    status: status.code(),
                    stdout,
                    stderr,
                    timed_out: false,
                    too_large,
                })
            }
        }
    }

    /// A new directory for one run, with the capabilities file and `files`
    /// under `policy/` at the tenant's tree.
    async fn prepare(
        &self,
        tenant: TenantId,
        files: &[BundleFile],
    ) -> Result<Scratch, DomainError> {
        let cannot = |error: std::io::Error| {
            unavailable(
                "the run's directory could not be written",
                error.to_string(),
            )
        };
        let directory = self
            .scratch
            .join(format!("hodor-policy-{}", uuid::Uuid::now_v7().simple()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&directory).map_err(cannot)?;
        let scratch = Scratch(directory);
        tokio::fs::write(scratch.0.join("capabilities.json"), CAPABILITIES)
            .await
            .map_err(cannot)?;
        let root = scratch.0.join("policy").join(tenant_root(tenant));
        tokio::fs::create_dir_all(&root).await.map_err(cannot)?;
        for file in files {
            // The paths were checked when the version was drafted; this
            // only refuses to leave the directory if they were not.
            let safe = file
                .path
                .split('/')
                .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
            if !safe {
                return Err(DomainError::invalid(
                    "authorization.bundle_file_invalid",
                    "a file of the bundle is refused",
                ));
            }
            let path = root.join(&file.path);
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(cannot)?;
            }
            tokio::fs::write(&path, &file.contents)
                .await
                .map_err(cannot)?;
        }
        Ok(scratch)
    }

    /// The problems of a run that did not end as it should, or `None`.
    fn bounded_out(&self, outcome: &Outcome) -> Option<Report> {
        if outcome.timed_out {
            return Some(single(
                "policy_check_timed_out",
                &format!(
                    "the run took longer than {} seconds and was stopped",
                    self.limits.time.as_secs()
                ),
            ));
        }
        if outcome.too_large {
            return Some(single(
                "policy_check_output_too_large",
                "the run printed more than Hodor reads",
            ));
        }
        None
    }
}

fn single(code: &str, message: &str) -> Report {
    Report {
        diagnostics: vec![Diagnostic::general(code, message)],
        tests: Vec::new(),
    }
}

/// The path of a file as the version names it: relative to the tenant's
/// tree, without the run's `policy/` directory.
fn relative(file: &str, tenant: TenantId) -> Option<String> {
    if file.is_empty() {
        return None;
    }
    let prefix = format!("policy/{}/", tenant_root(tenant));
    Some(file.strip_prefix(&prefix).unwrap_or(file).to_owned())
}

/// The problems `opa` lists as `{"errors":[…]}`, if that is what it said.
fn errors(text: &[u8], tenant: TenantId) -> Option<Vec<Diagnostic>> {
    let document: Value = serde_json::from_slice(text).ok()?;
    let listed = document.get("errors")?.as_array()?;
    Some(
        listed
            .iter()
            .map(|error| {
                let location = error.get("location");
                Diagnostic {
                    file: location
                        .and_then(|l| l.get("file"))
                        .and_then(Value::as_str)
                        .and_then(|file| relative(file, tenant)),
                    row: location
                        .and_then(|l| l.get("row"))
                        .and_then(Value::as_u64)
                        .and_then(|row| u32::try_from(row).ok()),
                    code: error
                        .get("code")
                        .and_then(Value::as_str)
                        .unwrap_or("policy_check_failed")
                        .to_owned(),
                    message: error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                }
            })
            .collect(),
    )
}

/// What a run printed, read as `opa`'s errors, or else one general problem
/// with the start of what it printed.
fn failure(outcome: &Outcome, tenant: TenantId) -> Report {
    let diagnostics = errors(&outcome.stdout, tenant)
        .or_else(|| errors(&outcome.stderr, tenant))
        .filter(|found| !found.is_empty())
        .unwrap_or_else(|| {
            let printed = if outcome.stderr.is_empty() {
                &outcome.stdout
            } else {
                &outcome.stderr
            };
            vec![Diagnostic::general(
                "policy_check_failed",
                String::from_utf8_lossy(printed).trim(),
            )]
        });
    Report {
        diagnostics,
        tests: Vec::new(),
    }
}

/// The module that evaluates the rule `decision` of `package` for each
/// input, run only in a simulation and never published.
fn simulation_module(package: &str) -> Option<String> {
    let plain = !package.is_empty()
        && package
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
    plain.then(|| {
        format!(
            "package hodor_simulation\n\nresults[i] := answer if {{\n\tsome i\n\tcandidate := data.hodor_simulation_inputs[i]\n\tanswer := data.{package}.decision with input as candidate\n}}\n"
        )
    })
}

#[async_trait::async_trait]
impl PolicyChecker for OpaProcessChecker {
    async fn check(&self, tenant: TenantId, files: &[BundleFile]) -> Result<Report, DomainError> {
        let scratch = self.prepare(tenant, files).await?;
        let outcome = self
            .run(
                &scratch.0,
                &[
                    "check",
                    "--strict",
                    "--capabilities",
                    "capabilities.json",
                    "--format",
                    "json",
                    "policy",
                ],
            )
            .await?;
        if let Some(report) = self.bounded_out(&outcome) {
            return Ok(report);
        }
        Ok(if outcome.status == Some(0) {
            Report::default()
        } else {
            failure(&outcome, tenant)
        })
    }

    async fn test(&self, tenant: TenantId, files: &[BundleFile]) -> Result<Report, DomainError> {
        let scratch = self.prepare(tenant, files).await?;
        let timeout = format!("{}s", self.limits.time.as_secs().max(1));
        let outcome = self
            .run(
                &scratch.0,
                &[
                    "test",
                    "--capabilities",
                    "capabilities.json",
                    "--format",
                    "json",
                    "--timeout",
                    &timeout,
                    "policy",
                ],
            )
            .await?;
        if let Some(report) = self.bounded_out(&outcome) {
            return Ok(report);
        }
        let Ok(Value::Array(results)) = serde_json::from_slice::<Value>(&outcome.stdout) else {
            return Ok(failure(&outcome, tenant));
        };
        let tests = results
            .iter()
            .map(|result| {
                let error = result.get("error").map(|error| {
                    error
                        .get("message")
                        .and_then(Value::as_str)
                        .map_or_else(|| error.to_string(), str::to_owned)
                });
                TestResult {
                    package: result
                        .get("package")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    name: result
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    passed: error.is_none()
                        && !result.get("fail").and_then(Value::as_bool).unwrap_or(false),
                    error,
                }
            })
            .collect();
        let mut report = Report {
            diagnostics: Vec::new(),
            tests,
        };
        // A run that failed without saying which test is a failure of its
        // own.
        if outcome.status != Some(0) && report.passed() {
            report = failure(&outcome, tenant);
        }
        Ok(report)
    }

    async fn evaluate(
        &self,
        tenant: TenantId,
        files: &[BundleFile],
        package: &str,
        inputs: &[Value],
    ) -> Result<Result<Vec<Option<Value>>, Report>, DomainError> {
        let Some(module) = simulation_module(package) else {
            return Ok(Err(single(
                "policy_simulation_invalid",
                "the resource server's package is not one Hodor makes",
            )));
        };
        let scratch = self.prepare(tenant, files).await?;
        let cannot = |error: std::io::Error| {
            unavailable(
                "the run's directory could not be written",
                error.to_string(),
            )
        };
        let simulation = scratch.0.join("simulation");
        tokio::fs::create_dir_all(&simulation)
            .await
            .map_err(cannot)?;
        tokio::fs::write(simulation.join("simulation.rego"), module)
            .await
            .map_err(cannot)?;
        let document = serde_json::json!({ "hodor_simulation_inputs": inputs });
        tokio::fs::write(simulation.join("data.json"), document.to_string())
            .await
            .map_err(cannot)?;
        let outcome = self
            .run(
                &scratch.0,
                &[
                    "eval",
                    "--capabilities",
                    "capabilities.json",
                    "--format",
                    "json",
                    "--data",
                    "policy",
                    "--data",
                    "simulation",
                    "data.hodor_simulation.results",
                ],
            )
            .await?;
        if let Some(report) = self.bounded_out(&outcome) {
            return Ok(Err(report));
        }
        if outcome.status != Some(0) {
            return Ok(Err(failure(&outcome, tenant)));
        }
        let document: Value = serde_json::from_slice(&outcome.stdout).map_err(|error| {
            unavailable(
                "the opa binary's answer could not be read",
                error.to_string(),
            )
        })?;
        let answers = document
            .get("result")
            .and_then(|result| result.get(0))
            .and_then(|result| result.get("expressions"))
            .and_then(|expressions| expressions.get(0))
            .and_then(|expression| expression.get("value"))
            .and_then(Value::as_object);
        Ok(Ok((0..inputs.len())
            .map(|index| answers.and_then(|answers| answers.get(&index.to_string()).cloned()))
            .collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_given_back_relative_to_the_tenant() {
        let tenant = TenantId::generate();
        let inside = format!("policy/{}/p/policy.rego", tenant_root(tenant));
        assert_eq!(relative(&inside, tenant).as_deref(), Some("p/policy.rego"));
        assert_eq!(relative("", tenant), None);
        assert_eq!(
            relative("simulation/simulation.rego", tenant).as_deref(),
            Some("simulation/simulation.rego")
        );
    }

    #[test]
    fn the_errors_opa_prints_become_problems() {
        let tenant = TenantId::generate();
        let printed = format!(
            r#"{{"errors":[{{"message":"undefined function http.send","code":"rego_type_error","location":{{"file":"policy/{}/a.rego","row":3,"col":6}}}}]}}"#,
            tenant_root(tenant)
        );
        let found = errors(printed.as_bytes(), tenant).expect("errors");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file.as_deref(), Some("a.rego"));
        assert_eq!(found[0].row, Some(3));
        assert_eq!(found[0].code, "rego_type_error");
        assert_eq!(errors(b"not json", tenant), None);
    }

    #[test]
    fn only_a_package_hodor_makes_is_simulated() {
        assert!(simulation_module("hodor.tenants.tab.resource_servers.rcd").is_some());
        for refused in ["", "hodor.x\ninjected := 1", "hodor[\"x\"]", "a b"] {
            assert_eq!(simulation_module(refused), None, "{refused}");
        }
    }

    #[test]
    fn the_capabilities_file_has_no_built_in_that_reaches_the_network() {
        let capabilities: Value = serde_json::from_str(CAPABILITIES).expect("JSON");
        let names: Vec<&str> = capabilities["builtins"]
            .as_array()
            .expect("built-ins")
            .iter()
            .filter_map(|builtin| builtin["name"].as_str())
            .collect();
        for removed in [
            "http.send",
            "net.lookup_ip_addr",
            "opa.runtime",
            "providers.aws.sign_req",
        ] {
            assert!(!names.contains(&removed), "{removed}");
        }
        assert!(names.contains(&"net.cidr_contains"));
    }
}
