//! Policy versions, the reports of their checks, and simulations.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "The policy
//! lifecycle".

use crate::bundle::{Author, BundleFile};
use crate::canonical::to_canonical;
use hodor_kernel::{Digest, DomainError, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt::Write as _;

hodor_kernel::define_id!(
    /// Identifies a simulation.
    SimulationId
);

/// At most this many inputs in one simulation.
pub const MAX_SIMULATION_INPUTS: usize = 100;
/// At most this many bytes of inputs in one simulation, as JSON.
pub const MAX_SIMULATION_BYTES: usize = 1024 * 1024;
/// At most this many problems are kept in a report.
const MAX_DIAGNOSTICS: usize = 100;
/// At most this many test results are kept in a report.
const MAX_TESTS: usize = 1000;
/// At most this many characters of a message are kept.
const MAX_MESSAGE: usize = 1000;

/// Where a version is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VersionState {
    /// Drafted, not checked.
    Draft,
    /// Waiting for the worker to check it.
    Validating,
    /// Compiles in strict mode against the capabilities file.
    Validated,
    /// Waiting for the worker to run its tests.
    Testing,
    /// Its tests pass. Only a tested version can be published.
    Tested,
    /// It did not compile, a test failed, or a run took too long.
    Rejected,
}

impl VersionState {
    /// The name storage and the command line use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Validating => "validating",
            Self::Validated => "validated",
            Self::Testing => "testing",
            Self::Tested => "tested",
            Self::Rejected => "rejected",
        }
    }

    /// Reads a name.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_version_state_invalid` for a name
    /// that is not one.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Ok(match value {
            "draft" => Self::Draft,
            "validating" => Self::Validating,
            "validated" => Self::Validated,
            "testing" => Self::Testing,
            "tested" => Self::Tested,
            "rejected" => Self::Rejected,
            _ => {
                return Err(DomainError::invalid(
                    "authorization.policy_version_state_invalid",
                    "not a state of a policy version",
                ));
            }
        })
    }

    /// Whether the worker has something to do with a version in this
    /// state.
    #[must_use]
    pub const fn is_waiting(self) -> bool {
        matches!(self, Self::Validating | Self::Testing)
    }

    /// Whether a simulation may be run on a version in this state.
    #[must_use]
    pub const fn may_simulate(self) -> bool {
        matches!(self, Self::Validated | Self::Testing | Self::Tested)
    }
}

/// One problem `opa` found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// The file, relative to the tenant's tree, when the problem is in one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The line, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<u32>,
    /// The code `opa` gave, or one of Hodor's: `policy_check_timed_out`,
    /// `policy_check_output_too_large`, `policy_check_failed`.
    pub code: String,
    /// What it says.
    pub message: String,
}

impl Diagnostic {
    /// A problem with no file, of `code`.
    #[must_use]
    pub fn general(code: &str, message: &str) -> Self {
        Self {
            file: None,
            row: None,
            code: shortened(code),
            message: shortened(message),
        }
    }
}

/// The outcome of one test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestResult {
    /// The package of the test, as `opa` names it: `data.hodor.tenants…`.
    pub package: String,
    /// The name of the rule: `test_…`.
    pub name: String,
    /// Whether it passed.
    pub passed: bool,
    /// The error it raised, if it raised one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What the worker found when it checked or tested a version.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Report {
    /// The problems. None means the step passed, unless a test failed.
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
    /// The tests that ran, for a test step.
    #[serde(default)]
    pub tests: Vec<TestResult>,
}

impl Report {
    /// Whether the step passed: no problem and no failing test.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.diagnostics.is_empty() && self.tests.iter().all(|test| test.passed)
    }

    /// The report with at most so many entries and so long messages as
    /// are kept.
    #[must_use]
    pub fn bounded(mut self) -> Self {
        self.diagnostics.truncate(MAX_DIAGNOSTICS);
        self.tests.truncate(MAX_TESTS);
        for diagnostic in &mut self.diagnostics {
            diagnostic.message = shortened(&diagnostic.message);
            diagnostic.code = shortened(&diagnostic.code);
        }
        for test in &mut self.tests {
            test.error = test.error.as_deref().map(shortened);
        }
        self
    }
}

fn shortened(text: &str) -> String {
    text.chars().take(MAX_MESSAGE).collect()
}

/// A version of a tenant's policy. It never changes but for its state and
/// report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVersion {
    /// 1 for a tenant's first version, then 2 and so on.
    pub number: u64,
    /// Who wrote it.
    pub author: Author,
    /// Its files, checked and in the form they are kept in, by path.
    pub files: Vec<BundleFile>,
    /// The SHA-256 of [`files_document`] of its files.
    pub digest: [u8; 32],
    /// Where it is in its lifecycle.
    pub state: VersionState,
    /// What the last check or test found.
    pub report: Option<Report>,
    /// When it was drafted.
    pub drafted_at: Timestamp,
    /// When its state last changed.
    pub changed_at: Timestamp,
}

impl PolicyVersion {
    /// Its files without the tests: what a bundle of it holds.
    #[must_use]
    pub fn published_files(&self) -> Vec<BundleFile> {
        self.files
            .iter()
            .filter(|file| !crate::bundle::is_test(&file.path))
            .cloned()
            .collect()
    }

    /// Its digest in hexadecimal.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hexadecimal(&self.digest)
    }
}

/// Lower-case hexadecimal of `bytes`.
#[must_use]
pub fn hexadecimal(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The canonical document a version's digest is the SHA-256 of:
/// `{"files":[{"path":…,"sha256":…},…]}`, files by path.
#[must_use]
pub fn files_document(files: &[BundleFile], digest: &dyn Digest) -> String {
    let mut sorted: Vec<&BundleFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let listed: Vec<Value> = sorted
        .iter()
        .map(|file| {
            json!({
                "path": file.path,
                "sha256": hexadecimal(&digest.sha256(&file.contents)),
            })
        })
        .collect();
    to_canonical(&json!({ "files": listed }))
}

/// The digest of a version made of `files`.
#[must_use]
pub fn version_digest(files: &[BundleFile], digest: &dyn Digest) -> [u8; 32] {
    digest.sha256(files_document(files, digest).as_bytes())
}

/// Where a simulation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SimulationState {
    /// Waiting for the worker.
    Waiting,
    /// Done: the results are kept and the inputs erased.
    Done,
    /// The version did not compile when it was simulated; the report says
    /// why.
    Failed,
}

impl SimulationState {
    /// The name storage uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }

    /// Reads a name.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_simulation_state_invalid` for a name
    /// that is not one.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Ok(match value {
            "waiting" => Self::Waiting,
            "done" => Self::Done,
            "failed" => Self::Failed,
            _ => {
                return Err(DomainError::invalid(
                    "authorization.policy_simulation_state_invalid",
                    "not a state of a simulation",
                ));
            }
        })
    }
}

/// What one input of a simulation was answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulatedAnswer {
    /// The input's position in the list, from 0.
    pub index: usize,
    /// The version's `decision`, or `None` where it is not defined.
    pub candidate: Option<Value>,
    /// The published version's `decision`, or `None` where it is not
    /// defined or nothing published comes from a version.
    pub published: Option<Value>,
    /// Whether the two differ.
    pub differs: bool,
}

/// A simulation of a version against inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Simulation {
    /// Its identifier.
    pub id: SimulationId,
    /// The version simulated.
    pub version: u64,
    /// The resource server's audience, whose `decision` rule is asked.
    pub namespace: String,
    /// The inputs, while the simulation waits; empty once it is done.
    pub inputs: Vec<Value>,
    /// The published version it was compared with, once done.
    pub compared_with: Option<u64>,
    /// The answers, once done.
    pub results: Vec<SimulatedAnswer>,
    /// The problems, when it failed.
    pub report: Option<Report>,
    /// Where it is.
    pub state: SimulationState,
    /// When it was asked for.
    pub asked_at: Timestamp,
    /// When it was done.
    pub done_at: Option<Timestamp>,
}

/// Checks the inputs of a simulation.
///
/// # Errors
///
/// Returns `authorization.policy_simulation_inputs_invalid` for no input,
/// more than 100, one that is not an object, or more than 1 mebibyte in
/// all.
pub fn check_inputs(inputs: &[Value]) -> Result<(), DomainError> {
    let invalid = |detail: &str| {
        DomainError::invalid(
            "authorization.policy_simulation_inputs_invalid",
            "a simulation takes 1 to 100 input objects, 1 mebibyte in all",
        )
        .with_detail(detail.to_owned())
    };
    if inputs.is_empty() || inputs.len() > MAX_SIMULATION_INPUTS {
        return Err(invalid("1 to 100 inputs"));
    }
    if inputs.iter().any(|input| !input.is_object()) {
        return Err(invalid("every input is a JSON object"));
    }
    let size: usize = inputs.iter().map(|input| input.to_string().len()).sum();
    if size > MAX_SIMULATION_BYTES {
        return Err(invalid("at most 1 mebibyte of inputs"));
    }
    Ok(())
}

/// Compares the answers of a candidate and of the published version,
/// input by input.
#[must_use]
pub fn compare(candidate: &[Option<Value>], published: &[Option<Value>]) -> Vec<SimulatedAnswer> {
    candidate
        .iter()
        .enumerate()
        .map(|(index, answer)| {
            let other = published.get(index).cloned().flatten();
            SimulatedAnswer {
                index,
                candidate: answer.clone(),
                differs: *answer != other,
                published: other,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::random::testing::FakeDigest;

    fn file(path: &str, contents: &str) -> BundleFile {
        BundleFile {
            path: path.to_owned(),
            contents: contents.as_bytes().to_vec(),
        }
    }

    #[test]
    fn states_are_read_by_name_and_say_what_waits() {
        for state in [
            VersionState::Draft,
            VersionState::Validating,
            VersionState::Validated,
            VersionState::Testing,
            VersionState::Tested,
            VersionState::Rejected,
        ] {
            assert_eq!(VersionState::parse(state.as_str()).expect("state"), state);
        }
        assert!(VersionState::parse("published").is_err());
        assert!(VersionState::Validating.is_waiting());
        assert!(VersionState::Testing.is_waiting());
        assert!(!VersionState::Tested.is_waiting());
        assert!(VersionState::Validated.may_simulate());
        assert!(!VersionState::Draft.may_simulate());
        assert!(!VersionState::Rejected.may_simulate());
        for state in [
            SimulationState::Waiting,
            SimulationState::Done,
            SimulationState::Failed,
        ] {
            assert_eq!(
                SimulationState::parse(state.as_str()).expect("state"),
                state
            );
        }
    }

    #[test]
    fn the_digest_names_the_files_whatever_their_order() {
        let a = [file("a.rego", "package x"), file("data.json", "{}")];
        let b = [file("data.json", "{}"), file("a.rego", "package x")];
        assert_eq!(
            version_digest(&a, &FakeDigest),
            version_digest(&b, &FakeDigest)
        );
        let changed = [file("a.rego", "package y"), file("data.json", "{}")];
        assert_ne!(
            version_digest(&a, &FakeDigest),
            version_digest(&changed, &FakeDigest)
        );
        let moved = [file("b.rego", "package x"), file("data.json", "{}")];
        assert_ne!(
            version_digest(&a, &FakeDigest),
            version_digest(&moved, &FakeDigest)
        );
        assert!(files_document(&a, &FakeDigest).starts_with(r#"{"files":[{"path":"a.rego""#));
    }

    #[test]
    fn tests_are_left_out_of_what_is_published() {
        let version = PolicyVersion {
            number: 1,
            author: Author::Tenant,
            files: vec![
                file("p/policy.rego", "package x"),
                file("p/policy_test.rego", "package x"),
                file("data.json", "{}"),
            ],
            digest: [0; 32],
            state: VersionState::Tested,
            report: None,
            drafted_at: Timestamp::UNIX_EPOCH,
            changed_at: Timestamp::UNIX_EPOCH,
        };
        let published: Vec<String> = version
            .published_files()
            .into_iter()
            .map(|file| file.path)
            .collect();
        assert_eq!(published, ["p/policy.rego", "data.json"]);
    }

    #[test]
    fn a_report_passes_only_without_problems_or_failing_tests() {
        assert!(Report::default().passed());
        let failing = Report {
            diagnostics: vec![],
            tests: vec![TestResult {
                package: "data.x".to_owned(),
                name: "test_a".to_owned(),
                passed: false,
                error: None,
            }],
        };
        assert!(!failing.passed());
        let broken = Report {
            diagnostics: vec![Diagnostic::general("rego_parse_error", "no")],
            tests: vec![],
        };
        assert!(!broken.passed());
        let long = Report {
            diagnostics: vec![Diagnostic::general("x", &"m".repeat(5000)); 500],
            tests: vec![],
        }
        .bounded();
        assert_eq!(long.diagnostics.len(), MAX_DIAGNOSTICS);
        assert_eq!(long.diagnostics[0].message.chars().count(), MAX_MESSAGE);
    }

    #[test]
    fn inputs_are_bounded_objects() {
        assert!(check_inputs(&[json!({"action": "read"})]).is_ok());
        assert!(check_inputs(&[]).is_err());
        assert!(check_inputs(&[json!([1])]).is_err());
        assert!(check_inputs(&vec![json!({}); MAX_SIMULATION_INPUTS + 1]).is_err());
        let large = json!({"text": "x".repeat(MAX_SIMULATION_BYTES)});
        assert!(check_inputs(&[large]).is_err());
    }

    #[test]
    fn answers_are_compared_input_by_input() {
        let candidate = [
            Some(json!({"allow": true})),
            None,
            Some(json!({"allow": false})),
        ];
        let published = [Some(json!({"allow": true})), Some(json!({"allow": true}))];
        let compared = compare(&candidate, &published);
        assert_eq!(compared.len(), 3);
        assert!(!compared[0].differs);
        assert!(compared[1].differs, "undefined against an answer");
        assert!(compared[2].differs, "an answer against nothing published");
        assert_eq!(compared[2].published, None);
    }
}
