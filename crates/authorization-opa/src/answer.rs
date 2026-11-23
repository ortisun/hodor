//! Reading what an instance answered, strictly.

use hodor_authorization::api::{Effect, EngineAnswer, PolicyReference, PolicyRevision, ReasonCode};
use serde_json::Value;

/// At most this many policies are taken from an answer.
const MAX_POLICIES: usize = 64;

pub(crate) const ALLOWED: &str = "policy_allowed";
pub(crate) const DENIED: &str = "policy_denied";
pub(crate) const UNDEFINED: &str = "policy_undefined";
pub(crate) const MALFORMED: &str = "policy_answer_malformed";
pub(crate) const TIMED_OUT: &str = "policy_engine_timed_out";
pub(crate) const UNREACHABLE: &str = "policy_engine_unreachable";
pub(crate) const ERROR: &str = "policy_engine_error";
pub(crate) const UNAVAILABLE: &str = "policy_engine_unavailable";
pub(crate) const NOT_CONFIGURED: &str = "policy_engine_not_configured";
pub(crate) const STALE: &str = "policy_revision_stale";
pub(crate) const REVISION_UNKNOWN: &str = "policy_revision_unknown";

/// A reason of this crate. Each constant above is a valid code; the tests
/// say so.
pub(crate) fn reason(code: &'static str) -> ReasonCode {
    ReasonCode::parse(code).expect("the reasons of this crate are codes")
}

/// An indeterminate answer for `code`.
pub(crate) fn indeterminate(code: &'static str) -> EngineAnswer {
    EngineAnswer::new(Effect::Indeterminate, reason(code))
}

/// Reads the body of a 200 answer of the Data API. Only a `result` that
/// is an object with a boolean `allow` decides; anything else is
/// indeterminate.
pub(crate) fn read(body: &[u8]) -> EngineAnswer {
    let Ok(document) = serde_json::from_slice::<Value>(body) else {
        return indeterminate(MALFORMED);
    };
    let Some(document) = document.as_object() else {
        return indeterminate(MALFORMED);
    };
    let Some(result) = document.get("result") else {
        return indeterminate(UNDEFINED);
    };
    decide(result).unwrap_or_else(|| indeterminate(MALFORMED))
}

/// The revision of the bundle `name` an answer asked with `provenance`
/// says the instance used, if it says one.
pub(crate) fn revision(body: &[u8], name: &str) -> Option<PolicyRevision> {
    let document = serde_json::from_slice::<Value>(body).ok()?;
    let revision = document
        .get("provenance")?
        .get("bundles")?
        .get(name)?
        .get("revision")?
        .as_str()?;
    PolicyRevision::parse(revision).ok()
}

fn decide(result: &Value) -> Option<EngineAnswer> {
    let result = result.as_object()?;
    let allow = result.get("allow")?.as_bool()?;
    let reason = match result.get("reason") {
        None => reason(if allow { ALLOWED } else { DENIED }),
        Some(given) => ReasonCode::parse(given.as_str()?).ok()?,
    };
    let policies = match result.get("policies") {
        None => Vec::new(),
        Some(given) => {
            let given = given.as_array()?;
            if given.len() > MAX_POLICIES {
                return None;
            }
            given
                .iter()
                .map(|policy| PolicyReference::parse(policy.as_str()?).ok())
                .collect::<Option<Vec<_>>>()?
        }
    };
    let effect = if allow { Effect::Allow } else { Effect::Deny };
    let mut answer = EngineAnswer::new(effect, reason);
    answer.matched_policies = policies;
    Some(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn effect_and_reason(body: &str) -> (Effect, String) {
        let answer = read(body.as_bytes());
        (answer.effect, answer.reason.as_str().to_owned())
    }

    #[test]
    fn the_revision_is_that_of_the_named_bundle() {
        let body = br#"{"result":{"allow":true},"provenance":{"version":"1.10.1","bundles":{"tab":{"revision":"7"},"other":{"revision":"9"}}}}"#;
        assert_eq!(
            revision(body, "tab").map(|r| r.as_str().to_owned()),
            Some("7".to_owned())
        );
        assert_eq!(revision(body, "missing"), None);
        assert_eq!(revision(br#"{"result":{"allow":true}}"#, "tab"), None);
        assert_eq!(
            revision(
                br#"{"provenance":{"bundles":{"tab":{"revision":""}}}}"#,
                "tab"
            ),
            None
        );
    }

    #[test]
    fn every_reason_of_this_crate_is_a_code() {
        for code in [
            ALLOWED,
            DENIED,
            UNDEFINED,
            MALFORMED,
            TIMED_OUT,
            UNREACHABLE,
            ERROR,
            UNAVAILABLE,
            NOT_CONFIGURED,
        ] {
            assert!(ReasonCode::parse(code).is_ok(), "{code}");
        }
    }

    #[test]
    fn a_boolean_allow_decides() {
        assert_eq!(
            effect_and_reason(r#"{"result":{"allow":true}}"#),
            (Effect::Allow, ALLOWED.to_owned())
        );
        assert_eq!(
            effect_and_reason(r#"{"result":{"allow":false}}"#),
            (Effect::Deny, DENIED.to_owned())
        );
        let answer = read(
            br#"{"result":{"allow":true,"reason":"owner_may_read","policies":["documents/owner"]}}"#,
        );
        assert_eq!(answer.effect, Effect::Allow);
        assert_eq!(answer.reason.as_str(), "owner_may_read");
        assert_eq!(answer.matched_policies.len(), 1);
        assert_eq!(answer.matched_policies[0].as_str(), "documents/owner");
    }

    #[test]
    fn no_result_is_undefined() {
        for body in [r"{}", r#"{"decision_id":"x"}"#] {
            assert_eq!(
                effect_and_reason(body),
                (Effect::Indeterminate, UNDEFINED.to_owned()),
                "{body}"
            );
        }
    }

    #[test]
    fn anything_else_is_malformed() {
        let many = format!(
            r#"{{"result":{{"allow":true,"policies":[{}]}}}}"#,
            vec![r#""p""#; MAX_POLICIES + 1].join(",")
        );
        for body in [
            "",
            "not json",
            "[]",
            r#"{"result":true}"#,
            r#"{"result":"allow"}"#,
            r#"{"result":{}}"#,
            r#"{"result":{"allow":"true"}}"#,
            r#"{"result":{"allow":1}}"#,
            r#"{"result":{"allow":null}}"#,
            r#"{"result":{"allow":true,"reason":"Not A Code"}}"#,
            r#"{"result":{"allow":true,"reason":7}}"#,
            r#"{"result":{"allow":true,"policies":"documents"}}"#,
            r#"{"result":{"allow":true,"policies":[1]}}"#,
            many.as_str(),
        ] {
            assert_eq!(
                effect_and_reason(body),
                (Effect::Indeterminate, MALFORMED.to_owned()),
                "{body}"
            );
        }
    }
}
