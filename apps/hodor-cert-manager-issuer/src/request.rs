//! cert-manager's `CertificateRequest`, as the issuer reads it, and what it
//! decides about one before anything is sent to Hodor.
//!
//! Specified in `docs/operations/hodor-cert-manager-issuer.md`, "What it
//! signs" and "What it writes back". Only the fields the issuer needs are
//! read; the rest of the resource is left as it is.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

/// The group of the issuer's two kinds.
pub const GROUP: &str = "hodor.ortisun.github.io";
/// The version of the issuer's two kinds.
pub const VERSION: &str = "v1alpha1";
/// The kind that serves the requests of its own namespace.
pub const ISSUER_KIND: &str = "HodorIssuer";
/// The kind that serves the requests of every namespace.
pub const CLUSTER_ISSUER_KIND: &str = "HodorClusterIssuer";

/// The seconds in a day.
const DAY: u64 = 24 * 60 * 60;

/// The `spec` of a `CertificateRequest`, as far as the issuer reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRequestSpec {
    /// The certificate signing request in PEM, in base64.
    #[serde(default)]
    pub request: String,
    /// Whether it asks for an authority.
    #[serde(default, rename = "isCA")]
    pub is_ca: bool,
    /// The lifetime asked for, as Go writes a duration, such as `48h0m0s`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    /// The issuer it is addressed to.
    #[serde(default)]
    pub issuer_ref: IssuerReference,
}

/// The issuer a request names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct IssuerReference {
    /// Its name.
    #[serde(default)]
    pub name: String,
    /// Its kind; cert-manager's `Issuer` when empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Its group; `cert-manager.io` when empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// A condition of a `CertificateRequest`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// `Ready`, `Approved`, `Denied`, `InvalidRequest`.
    #[serde(rename = "type")]
    pub kind: String,
    /// `True`, `False` or `Unknown`.
    pub status: String,
    /// Why, in one word.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Why, for people.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// When the status last changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
    /// The generation of the resource it was set for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// The `status` of a `CertificateRequest`, as far as the issuer reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateRequestStatus {
    /// Its conditions.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// Which of the issuer's kinds a request is addressed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addressed {
    /// A `HodorIssuer` of this name, in the request's namespace.
    Issuer(String),
    /// A `HodorClusterIssuer` of this name.
    ClusterIssuer(String),
}

/// What the issuer does with a request before it reads its issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// It is addressed to another issuer: never read further.
    NotOurs,
    /// It is finished already: left alone.
    Finished,
    /// It was denied: marked so, and never sent.
    Deny,
    /// It is not approved yet: left alone until it is.
    AwaitApproval,
    /// It is approved: its issuer is looked for next.
    Approved(Addressed),
}

/// What the issuer sends of a request whose issuer exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prepared {
    /// It is not for an authority: marked failed, and never sent.
    NotAnAuthority,
    /// Its certificate signing request is not base64 text: marked failed,
    /// and never sent.
    Unreadable,
    /// It is sent: its certificate signing request in PEM, and its
    /// lifetime in days, if it asks for one.
    Send {
        /// The certificate signing request, in PEM.
        request: String,
        /// The lifetime in whole days, at least one.
        lifetime_days: Option<u32>,
    },
}

fn condition<'a>(conditions: &'a [Condition], kind: &str) -> Option<&'a Condition> {
    conditions.iter().find(|condition| condition.kind == kind)
}

/// What the issuer does first with a request of `spec` and `status`.
#[must_use]
pub fn step(spec: &CertificateRequestSpec, status: Option<&CertificateRequestStatus>) -> Step {
    let reference = &spec.issuer_ref;
    if reference.group.as_deref() != Some(GROUP) {
        return Step::NotOurs;
    }
    let addressed = match reference.kind.as_deref() {
        Some(ISSUER_KIND) => Addressed::Issuer(reference.name.clone()),
        Some(CLUSTER_ISSUER_KIND) => Addressed::ClusterIssuer(reference.name.clone()),
        _ => return Step::NotOurs,
    };
    let conditions = status.map_or(&[][..], |status| status.conditions.as_slice());
    if let Some(ready) = condition(conditions, "Ready") {
        let finished = ready.status == "True"
            || (ready.status == "False"
                && matches!(ready.reason.as_deref(), Some("Failed" | "Denied")));
        if finished {
            return Step::Finished;
        }
    }
    if condition(conditions, "Denied").is_some_and(|denied| denied.status == "True") {
        return Step::Deny;
    }
    if !condition(conditions, "Approved").is_some_and(|approved| approved.status == "True") {
        return Step::AwaitApproval;
    }
    Step::Approved(addressed)
}

/// What is sent of a request whose issuer exists.
#[must_use]
pub fn prepare(spec: &CertificateRequestSpec) -> Prepared {
    if !spec.is_ca {
        return Prepared::NotAnAuthority;
    }
    let Some(request) = STANDARD
        .decode(spec.request.trim())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
    else {
        return Prepared::Unreadable;
    };
    Prepared::Send {
        request,
        lifetime_days: spec.duration.as_deref().map(lifetime_days),
    }
}

/// A lifetime in whole days, rounded down and at least one, of a duration
/// as Go writes it. One that does not read is taken as one day.
#[must_use]
pub fn lifetime_days(duration: &str) -> u32 {
    let days = seconds(duration).map_or(0, |seconds| seconds / DAY);
    u32::try_from(days).unwrap_or(u32::MAX).max(1)
}

/// The whole seconds of a duration as Go writes it: a sequence of numbers,
/// each with a unit of `h`, `m`, `s`, `ms`, `us`, `µs` or `ns`.
fn seconds(duration: &str) -> Option<u64> {
    let mut rest = duration.trim();
    if rest.is_empty() {
        return None;
    }
    let mut nanoseconds: u128 = 0;
    while !rest.is_empty() {
        let digits = rest
            .find(|character: char| !character.is_ascii_digit() && character != '.')
            .unwrap_or(rest.len());
        let (number, after) = rest.split_at(digits);
        let number: f64 = number.parse().ok()?;
        let unit_length = after
            .find(|character: char| character.is_ascii_digit())
            .unwrap_or(after.len());
        let (unit, after) = after.split_at(unit_length);
        let scale: f64 = match unit {
            "h" => 3_600e9,
            "m" => 60e9,
            "s" => 1e9,
            "ms" => 1e6,
            "us" | "µs" => 1e3,
            "ns" => 1.0,
            _ => return None,
        };
        let part = number * scale;
        if !part.is_finite() || part < 0.0 {
            return None;
        }
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "finite, not negative, and a duration of days fits"
        )]
        let part = part as u128;
        nanoseconds = nanoseconds.checked_add(part)?;
        rest = after;
    }
    u64::try_from(nanoseconds / 1_000_000_000).ok()
}

/// What the issuer writes into a request's status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Signed: the certificate, the chain without its last certificate,
    /// and that last one, the root.
    Issued {
        /// The intermediate and the certificates above it but the root,
        /// in PEM.
        certificate: String,
        /// The root, in PEM.
        ca: String,
        /// Names the intermediate in Hodor.
        message: String,
    },
    /// Finished without a certificate: `Failed` or `Denied`.
    Finished {
        /// `Failed` or `Denied`.
        reason: &'static str,
        /// Why.
        message: String,
    },
    /// Not finished: looked at again later.
    Pending {
        /// Why.
        message: String,
    },
}

impl Outcome {
    /// What a signed intermediate is written as.
    #[must_use]
    pub fn issued(signed: &crate::hodor::Signed) -> Self {
        let mut certificate = vec![signed.certificate.trim_end().to_owned()];
        let (ca, above) = match signed.chain.split_last() {
            Some((root, above)) => (root.trim_end().to_owned(), above),
            // A chain is never empty; without one, the intermediate is its
            // own last certificate.
            None => (signed.certificate.trim_end().to_owned(), &[][..]),
        };
        certificate.extend(above.iter().map(|pem| pem.trim_end().to_owned()));
        Self::Issued {
            certificate: format!("{}\n", certificate.join("\n")),
            ca: format!("{ca}\n"),
            message: format!(
                "Signed by Hodor's certificate authority as the intermediate {}, serial number {}",
                signed.id, signed.serial_number
            ),
        }
    }

    /// The name of the outcome, for logs and metrics.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Issued { .. } => "issued",
            Self::Finished {
                reason: "Denied", ..
            } => "denied",
            Self::Finished { .. } => "refused",
            Self::Pending { .. } => "pending",
        }
    }

    /// The status to merge into the request's, its other conditions kept:
    /// `Ready` with this outcome, and the certificate or the failure time.
    #[must_use]
    pub fn status_patch(&self, conditions: &[Condition], now: &str) -> Value {
        let (status, reason, message) = match self {
            Self::Issued { message, .. } => ("True", "Issued", message.clone()),
            Self::Finished { reason, message } => ("False", *reason, message.clone()),
            Self::Pending { message } => ("False", "Pending", message.clone()),
        };
        let previous = condition(conditions, "Ready");
        let changed_at = match previous {
            Some(ready) if ready.status == status => ready
                .last_transition_time
                .clone()
                .unwrap_or_else(|| now.to_owned()),
            _ => now.to_owned(),
        };
        let ready = Condition {
            kind: "Ready".to_owned(),
            status: status.to_owned(),
            reason: Some(reason.to_owned()),
            message: Some(message),
            last_transition_time: Some(changed_at),
            observed_generation: None,
        };
        let mut written: Vec<Condition> = conditions
            .iter()
            .filter(|condition| condition.kind != "Ready")
            .cloned()
            .collect();
        written.push(ready);
        let mut patch = Map::new();
        patch.insert("conditions".to_owned(), json!(written));
        match self {
            Self::Issued {
                certificate, ca, ..
            } => {
                patch.insert(
                    "certificate".to_owned(),
                    Value::String(STANDARD.encode(certificate)),
                );
                patch.insert("ca".to_owned(), Value::String(STANDARD.encode(ca)));
            }
            Self::Finished { .. } => {
                patch.insert("failureTime".to_owned(), Value::String(now.to_owned()));
            }
            Self::Pending { .. } => {}
        }
        Value::Object(patch)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Addressed, CertificateRequestSpec, CertificateRequestStatus, Condition, IssuerReference,
        Outcome, Prepared, Step, lifetime_days, prepare, step,
    };
    use crate::hodor::Signed;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    fn ours(kind: &str) -> CertificateRequestSpec {
        CertificateRequestSpec {
            request: STANDARD.encode(
                "-----BEGIN CERTIFICATE REQUEST-----\nMII\n-----END CERTIFICATE REQUEST-----\n",
            ),
            is_ca: true,
            duration: Some("48h0m0s".to_owned()),
            issuer_ref: IssuerReference {
                name: "hodor".to_owned(),
                kind: Some(kind.to_owned()),
                group: Some("hodor.ortisun.github.io".to_owned()),
            },
        }
    }

    fn with(conditions: &[(&str, &str, Option<&str>)]) -> CertificateRequestStatus {
        CertificateRequestStatus {
            conditions: conditions
                .iter()
                .map(|(kind, status, reason)| Condition {
                    kind: (*kind).to_owned(),
                    status: (*status).to_owned(),
                    reason: reason.map(str::to_owned),
                    ..Condition::default()
                })
                .collect(),
        }
    }

    #[test]
    fn a_request_for_another_issuer_is_never_read_further() {
        let approved = with(&[("Approved", "True", None)]);
        for (kind, group) in [
            (Some("Issuer"), Some("cert-manager.io")),
            (None, None),
            (Some("HodorIssuer"), None),
            (Some("HodorIssuer"), Some("cert-manager.io")),
            (Some("ClusterIssuer"), Some("hodor.ortisun.github.io")),
            (Some("hodorissuer"), Some("hodor.ortisun.github.io")),
        ] {
            let mut spec = ours("HodorIssuer");
            spec.issuer_ref.kind = kind.map(str::to_owned);
            spec.issuer_ref.group = group.map(str::to_owned);
            assert_eq!(
                step(&spec, Some(&approved)),
                Step::NotOurs,
                "{kind:?} {group:?}"
            );
        }
    }

    #[test]
    fn only_an_approved_request_that_is_neither_denied_nor_finished_goes_on() {
        let spec = ours("HodorIssuer");
        assert_eq!(step(&spec, None), Step::AwaitApproval);
        assert_eq!(step(&spec, Some(&with(&[]))), Step::AwaitApproval);
        assert_eq!(
            step(&spec, Some(&with(&[("Approved", "False", None)]))),
            Step::AwaitApproval
        );
        assert_eq!(
            step(&spec, Some(&with(&[("Denied", "True", None)]))),
            Step::Deny
        );
        // Denied wins over approved, as cert-manager never sets both.
        assert_eq!(
            step(
                &spec,
                Some(&with(&[
                    ("Approved", "True", None),
                    ("Denied", "True", None)
                ]))
            ),
            Step::Deny
        );
        assert_eq!(
            step(&spec, Some(&with(&[("Approved", "True", None)]))),
            Step::Approved(Addressed::Issuer("hodor".to_owned()))
        );
        assert_eq!(
            step(
                &ours("HodorClusterIssuer"),
                Some(&with(&[("Approved", "True", None)]))
            ),
            Step::Approved(Addressed::ClusterIssuer("hodor".to_owned()))
        );
        // Pending is not finished: it goes on.
        assert_eq!(
            step(
                &spec,
                Some(&with(&[
                    ("Approved", "True", None),
                    ("Ready", "False", Some("Pending"))
                ]))
            ),
            Step::Approved(Addressed::Issuer("hodor".to_owned()))
        );
        for ready in [
            ("Ready", "True", Some("Issued")),
            ("Ready", "False", Some("Failed")),
            ("Ready", "False", Some("Denied")),
        ] {
            assert_eq!(
                step(&spec, Some(&with(&[("Approved", "True", None), ready]))),
                Step::Finished,
                "{ready:?}"
            );
            assert_eq!(
                step(&spec, Some(&with(&[("Denied", "True", None), ready]))),
                Step::Finished,
                "{ready:?}"
            );
        }
    }

    #[test]
    fn only_a_request_for_an_authority_is_sent() {
        let mut spec = ours("HodorIssuer");
        assert_eq!(
            prepare(&spec),
            Prepared::Send {
                request:
                    "-----BEGIN CERTIFICATE REQUEST-----\nMII\n-----END CERTIFICATE REQUEST-----\n"
                        .to_owned(),
                lifetime_days: Some(2),
            }
        );
        spec.duration = None;
        assert!(matches!(
            prepare(&spec),
            Prepared::Send {
                lifetime_days: None,
                ..
            }
        ));
        spec.request = "not base64!".to_owned();
        assert_eq!(prepare(&spec), Prepared::Unreadable);
        spec.is_ca = false;
        assert_eq!(prepare(&spec), Prepared::NotAnAuthority);
    }

    #[test]
    fn a_duration_is_whole_days_rounded_down_and_at_least_one() {
        for (duration, days) in [
            ("48h0m0s", 2),
            ("48h", 2),
            ("720h0m0s", 30),
            ("2160h0m0s", 90),
            ("47h59m59s", 1),
            ("25h", 1),
            ("1h", 1),
            ("90m", 1),
            ("0s", 1),
            ("1.5h", 1),
            ("72h0m0.5s", 3),
            ("", 1),
            ("forever", 1),
            ("12d", 1),
        ] {
            assert_eq!(lifetime_days(duration), days, "{duration}");
        }
    }

    fn signed(chain: &[&str]) -> Signed {
        Signed {
            id: "0193f3b1".to_owned(),
            serial_number: "41c2".to_owned(),
            certificate: "LEAF\n".to_owned(),
            chain: chain.iter().map(|pem| format!("{pem}\n")).collect(),
        }
    }

    #[test]
    fn a_signed_intermediate_is_written_with_its_root_apart() {
        assert_eq!(
            Outcome::issued(&signed(&["ROOT"])),
            Outcome::Issued {
                certificate: "LEAF\n".to_owned(),
                ca: "ROOT\n".to_owned(),
                message: "Signed by Hodor's certificate authority as the intermediate 0193f3b1, serial number 41c2".to_owned(),
            }
        );
        let Outcome::Issued {
            certificate, ca, ..
        } = Outcome::issued(&signed(&["AUTHORITY", "MIDDLE", "ROOT"]))
        else {
            panic!("issued");
        };
        assert_eq!(certificate, "LEAF\nAUTHORITY\nMIDDLE\n");
        assert_eq!(ca, "ROOT\n");
    }

    #[test]
    fn the_status_keeps_the_other_conditions_and_writes_ready() {
        let before = with(&[
            ("Approved", "True", None),
            ("Ready", "False", Some("Pending")),
        ]);
        let patch = Outcome::issued(&signed(&["ROOT"]))
            .status_patch(&before.conditions, "2026-11-25T10:00:00Z");
        let conditions = patch["conditions"].as_array().expect("conditions");
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0]["type"], "Approved");
        assert_eq!(conditions[1]["type"], "Ready");
        assert_eq!(conditions[1]["status"], "True");
        assert_eq!(conditions[1]["reason"], "Issued");
        assert_eq!(conditions[1]["lastTransitionTime"], "2026-11-25T10:00:00Z");
        assert_eq!(patch["certificate"], STANDARD.encode("LEAF\n"));
        assert_eq!(patch["ca"], STANDARD.encode("ROOT\n"));
        assert!(patch.get("failureTime").is_none());

        let refused = Outcome::Finished {
            reason: "Failed",
            message: "Hodor refused the request: keys.x: y".to_owned(),
        }
        .status_patch(&before.conditions, "2026-11-25T10:00:00Z");
        assert_eq!(refused["conditions"][1]["reason"], "Failed");
        assert_eq!(
            refused["conditions"][1]["message"],
            "Hodor refused the request: keys.x: y"
        );
        assert_eq!(refused["failureTime"], "2026-11-25T10:00:00Z");
        assert!(refused.get("certificate").is_none());

        // Pending again keeps the time it first became so.
        let mut pending = before.clone();
        pending.conditions[1].last_transition_time = Some("2026-11-25T09:00:00Z".to_owned());
        let again = Outcome::Pending {
            message: "Hodor could not be reached".to_owned(),
        }
        .status_patch(&pending.conditions, "2026-11-25T10:00:00Z");
        assert_eq!(
            again["conditions"][1]["lastTransitionTime"],
            "2026-11-25T09:00:00Z"
        );
        assert!(again.get("failureTime").is_none());
    }

    #[test]
    fn outcomes_are_named_for_the_metric() {
        assert_eq!(Outcome::issued(&signed(&["R"])).name(), "issued");
        assert_eq!(
            Outcome::Finished {
                reason: "Denied",
                message: String::new()
            }
            .name(),
            "denied"
        );
        assert_eq!(
            Outcome::Finished {
                reason: "Failed",
                message: String::new()
            }
            .name(),
            "refused"
        );
        assert_eq!(
            Outcome::Pending {
                message: String::new()
            }
            .name(),
            "pending"
        );
    }
}
