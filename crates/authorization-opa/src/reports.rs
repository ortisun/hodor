//! Reading what an instance reports: its status and its decisions.
//!
//! Only what Hodor keeps is read; everything else in a report is ignored,
//! and a report that is not the shape Open Policy Agent sends is refused.

use crate::bundle::{bundle_name, tenant_of};
use hodor_kernel::{DomainError, TenantId, Timestamp};
use serde_json::Value;
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;

/// At most this many bundles in a status report.
pub(crate) const MAX_REPORTED_BUNDLES: usize = 10_000;
/// At most this many decisions in one upload.
pub(crate) const MAX_UPLOADED_DECISIONS: usize = 10_000;
/// At most this many characters of a revision, an error or an identifier
/// are kept.
const MAX_TEXT: usize = 255;
/// At most this many characters of a path are kept.
const MAX_PATH: usize = 1024;

fn report_error(message: &'static str) -> DomainError {
    DomainError::invalid("authorization.policy_agent_report_invalid", message)
}

fn bounded(text: &str, limit: usize) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(limit)
        .collect()
}

fn timestamp(value: Option<&Value>) -> Option<Timestamp> {
    value
        .and_then(Value::as_str)
        .and_then(|text| Timestamp::parse(text, &Rfc3339).ok())
}

/// What an instance says about one bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportedBundle {
    /// The revision it runs, if it activated one.
    pub(crate) active_revision: Option<String>,
    /// When it last activated a revision.
    pub(crate) last_activation: Option<Timestamp>,
    /// Its last error, `code: message`, if it has one.
    pub(crate) error: Option<String>,
}

/// The bundles of a status report, by tenant. Bundles whose names are not
/// a tenant's are left out.
///
/// # Errors
///
/// Returns `authorization.policy_agent_report_invalid` for a body that is
/// not a JSON object, or that names too many bundles.
pub(crate) fn read_status(body: &[u8]) -> Result<BTreeMap<TenantId, ReportedBundle>, DomainError> {
    let document: Value =
        serde_json::from_slice(body).map_err(|_| report_error("the status report is not JSON"))?;
    let document = document
        .as_object()
        .ok_or_else(|| report_error("the status report is not a JSON object"))?;
    let Some(bundles) = document.get("bundles") else {
        return Ok(BTreeMap::new());
    };
    let bundles = bundles
        .as_object()
        .ok_or_else(|| report_error("the bundles of the status report are not an object"))?;
    if bundles.len() > MAX_REPORTED_BUNDLES {
        return Err(report_error("the status report names too many bundles"));
    }
    let mut found = BTreeMap::new();
    for (name, status) in bundles {
        let Some(tenant) = tenant_of(name) else {
            continue;
        };
        let active_revision = status
            .get("active_revision")
            .and_then(Value::as_str)
            .filter(|revision| !revision.is_empty())
            .map(|revision| bounded(revision, MAX_TEXT));
        let code = status.get("code").and_then(Value::as_str).unwrap_or("");
        let message = status.get("message").and_then(Value::as_str).unwrap_or("");
        let error = (!code.is_empty() || !message.is_empty())
            .then(|| bounded(&format!("{code}: {message}"), 4 * MAX_TEXT));
        found.insert(
            tenant,
            ReportedBundle {
                active_revision,
                last_activation: timestamp(status.get("last_successful_activation")),
                error,
            },
        );
    }
    Ok(found)
}

/// One decision as an instance uploads it, reduced to what Hodor keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportedDecision {
    /// The tenant whose tree the decision's path is in.
    pub(crate) tenant: TenantId,
    /// The decision's identifier, given by the instance.
    pub(crate) decision_id: String,
    /// The path that was asked.
    pub(crate) path: String,
    /// The revision of the tenant's bundle the decision was made with.
    pub(crate) revision: Option<String>,
    /// Whether the result allowed, when it says so.
    pub(crate) allowed: Option<bool>,
    /// When it was made, if the instance says.
    pub(crate) decided_at: Option<Timestamp>,
}

/// The tenant whose tree `path` is in, as the decision path writes it:
/// `hodor/tenants/t…/…`, with or without a leading `/` or `v1/data/`.
fn tenant_of_path(path: &str) -> Option<TenantId> {
    let path = path.trim_start_matches('/');
    let path = path.strip_prefix("v1/data/").unwrap_or(path);
    let rest = path.strip_prefix("hodor/tenants/")?;
    tenant_of(rest.split('/').next()?)
}

/// The decisions of an upload, already expanded. A decision whose path is
/// not in a tenant's tree, or that has no identifier, is left out.
///
/// # Errors
///
/// Returns `authorization.policy_agent_report_invalid` for a body that is
/// not a JSON array, or that holds too many decisions.
pub(crate) fn read_decisions(body: &[u8]) -> Result<Vec<ReportedDecision>, DomainError> {
    let document: Value =
        serde_json::from_slice(body).map_err(|_| report_error("the decisions are not JSON"))?;
    let events = document
        .as_array()
        .ok_or_else(|| report_error("the decisions are not a JSON array"))?;
    if events.len() > MAX_UPLOADED_DECISIONS {
        return Err(report_error("the upload holds too many decisions"));
    }
    let mut found = Vec::new();
    for event in events {
        let Some(path) = event.get("path").and_then(Value::as_str) else {
            continue;
        };
        let Some(tenant) = tenant_of_path(path) else {
            continue;
        };
        let Some(decision_id) = event
            .get("decision_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        let revision = event
            .get("bundles")
            .and_then(|bundles| bundles.get(bundle_name(tenant)))
            .and_then(|bundle| bundle.get("revision"))
            .and_then(Value::as_str)
            .map(|revision| bounded(revision, MAX_TEXT));
        let allowed = event
            .get("result")
            .and_then(|result| result.get("allow"))
            .and_then(Value::as_bool);
        found.push(ReportedDecision {
            tenant,
            decision_id: bounded(decision_id, MAX_TEXT),
            path: bounded(path, MAX_PATH),
            revision,
            allowed,
            decided_at: timestamp(event.get("timestamp")),
        });
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_status_report_gives_each_tenant_bundle_its_revision_and_error() {
        let tenant = TenantId::generate();
        let failing = TenantId::generate();
        let report = json!({
            "labels": {"id": "x"},
            "bundles": {
                bundle_name(tenant): {
                    "name": bundle_name(tenant),
                    "active_revision": "4",
                    "last_successful_activation": "2026-11-22T10:00:00.123456789Z",
                },
                bundle_name(failing): {
                    "code": "bundle_error",
                    "message": "signature verification failed",
                },
                "authz": {"active_revision": "9"},
            },
        });
        let found = read_status(report.to_string().as_bytes()).expect("status");
        assert_eq!(found.len(), 2);
        assert_eq!(found[&tenant].active_revision.as_deref(), Some("4"));
        assert!(found[&tenant].last_activation.is_some());
        assert_eq!(found[&tenant].error, None);
        assert_eq!(found[&failing].active_revision, None);
        assert_eq!(
            found[&failing].error.as_deref(),
            Some("bundle_error: signature verification failed")
        );
        assert!(read_status(b"{}").expect("empty").is_empty());
        assert!(read_status(b"[]").is_err());
        assert!(read_status(br#"{"bundles": []}"#).is_err());
    }

    #[test]
    fn decisions_are_reduced_to_what_is_kept() {
        let tenant = TenantId::generate();
        let upload = json!([
            {
                "decision_id": "d1",
                "path": format!("hodor/tenants/{}/resource_servers/rab/decision", bundle_name(tenant)),
                "input": {"subject": {"id": "secret person"}},
                "result": {"allow": true, "reason": "owner"},
                "bundles": {bundle_name(tenant): {"revision": "2"}},
                "timestamp": "2026-11-22T10:00:00Z",
            },
            {"decision_id": "d2", "path": "system/authz/allow", "result": true},
            {"path": format!("hodor/tenants/{}/x", bundle_name(tenant))},
            {"decision_id": "d3", "path": format!("/v1/data/hodor/tenants/{}/x", bundle_name(tenant)), "result": "yes"},
        ]);
        let found = read_decisions(upload.to_string().as_bytes()).expect("decisions");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].tenant, tenant);
        assert_eq!(found[0].decision_id, "d1");
        assert_eq!(found[0].revision.as_deref(), Some("2"));
        assert_eq!(found[0].allowed, Some(true));
        assert!(found[0].decided_at.is_some());
        assert_eq!(found[1].decision_id, "d3");
        assert_eq!(found[1].allowed, None);
        assert!(read_decisions(b"{}").is_err());
        let many = Value::Array(vec![json!({}); MAX_UPLOADED_DECISIONS + 1]);
        assert!(read_decisions(many.to_string().as_bytes()).is_err());
    }
}
