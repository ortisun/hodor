//! Token exchange (RFC 8693): the `act` chain and the scopes of the new
//! token.
//!
//! See `docs/architecture/contexts/oauth.md`, "Token exchange".

use crate::domain::token::TokenError;
use hodor_kernel::UserId;
use serde_json::{Value, json};

/// The most actors a token's `act` chain holds.
pub const MAX_ACTORS: usize = 3;

/// How many actors `act` names, counted as far as one past the bound and
/// no further, so that a long chain costs nothing to refuse. Answers
/// `None` for a chain whose links are not objects naming a `sub`.
#[must_use]
pub fn chain_length(act: Option<&Value>) -> Option<usize> {
    let mut length = 0;
    let mut link = act;
    while let Some(actor) = link {
        let object = actor.as_object()?;
        object.get("sub").and_then(Value::as_str)?;
        length += 1;
        if length > MAX_ACTORS {
            return Some(length);
        }
        link = object.get("act");
    }
    Some(length)
}

/// The `sub` of every actor of `act`, the newest first, as far as the
/// bound.
#[must_use]
pub fn actors(act: Option<&Value>) -> Vec<String> {
    let mut found = Vec::new();
    let mut link = act;
    while let Some(actor) = link {
        let Some(sub) = actor.get("sub").and_then(Value::as_str) else {
            break;
        };
        found.push(sub.to_owned());
        if found.len() > MAX_ACTORS {
            break;
        }
        link = actor.get("act");
    }
    found
}

/// The `act` of a token the agent `agent` holds, exchanged from a token
/// whose own `act` was `previous`: the newest actor outermost.
#[must_use]
pub fn act_claim(agent: UserId, previous: Option<&Value>) -> Value {
    let mut act = json!({ "sub": agent.to_string(), "principal_kind": "agent" });
    if let Some(previous) = previous {
        act["act"] = previous.clone();
    }
    act
}

/// The scopes of the new token: those asked, or without `asked` every one
/// that meets the three rules; each must be held by the subject token,
/// allowed to the client and defined by the audience's resource server.
/// OpenID Connect's scopes are never exchanged.
///
/// # Errors
///
/// `invalid_scope` for a scope that breaks a rule, or when none is left.
pub fn exchanged_scopes(
    asked: Option<&str>,
    subject: &[String],
    allowed: &[String],
    defined: impl Fn(&str) -> bool,
    openid: &[&str],
) -> Result<Vec<String>, TokenError> {
    let fits = |scope: &str| {
        !openid.contains(&scope)
            && subject.iter().any(|held| held == scope)
            && allowed.iter().any(|held| held == scope)
            && defined(scope)
    };
    let mut scopes: Vec<String> = Vec::new();
    match asked {
        Some(asked) => {
            for scope in asked.split(' ').filter(|scope| !scope.is_empty()) {
                if !fits(scope) {
                    return Err(TokenError::invalid_scope(
                        "a scope is wider than the subject token, the client or the audience",
                    ));
                }
                if !scopes.iter().any(|known| known == scope) {
                    scopes.push(scope.to_owned());
                }
            }
        }
        None => scopes.extend(subject.iter().filter(|scope| fits(scope)).cloned()),
    }
    if scopes.is_empty() {
        return Err(TokenError::invalid_scope(
            "no scope of the subject token can be exchanged for this audience",
        ));
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn a_chain_is_counted_as_far_as_the_bound() {
        assert_eq!(chain_length(None), Some(0));
        let one = act_claim(UserId::generate(), None);
        assert_eq!(chain_length(Some(&one)), Some(1));
        let two = act_claim(UserId::generate(), Some(&one));
        let three = act_claim(UserId::generate(), Some(&two));
        assert_eq!(chain_length(Some(&three)), Some(3));
        let four = act_claim(UserId::generate(), Some(&three));
        assert_eq!(chain_length(Some(&four)), Some(4));
        // Past the bound, the rest is not read.
        let mut long = json!({ "sub": "a" });
        for _ in 0..100 {
            long = json!({ "sub": "a", "act": long });
        }
        assert_eq!(chain_length(Some(&long)), Some(MAX_ACTORS + 1));
        assert_eq!(chain_length(Some(&json!("nobody"))), None);
        assert_eq!(chain_length(Some(&json!({ "act": {} }))), None);
    }

    #[test]
    fn the_newest_actor_is_outermost() {
        let (first, second) = (UserId::generate(), UserId::generate());
        let one = act_claim(first, None);
        let two = act_claim(second, Some(&one));
        assert_eq!(two["sub"], second.to_string());
        assert_eq!(two["principal_kind"], "agent");
        assert_eq!(two["act"]["sub"], first.to_string());
        assert_eq!(actors(Some(&two)), [second.to_string(), first.to_string()]);
    }

    #[test]
    fn scopes_only_narrow() {
        let subject = names(&["openid", "invoices:read", "invoices:write", "profile"]);
        let allowed = names(&["invoices:read", "invoices:write", "openid"]);
        let defined = |scope: &str| scope.starts_with("invoices:");
        let openid = ["openid", "profile"];
        assert_eq!(
            exchanged_scopes(None, &subject, &allowed, defined, &openid).expect("scopes"),
            names(&["invoices:read", "invoices:write"])
        );
        assert_eq!(
            exchanged_scopes(Some("invoices:read"), &subject, &allowed, defined, &openid)
                .expect("scopes"),
            names(&["invoices:read"])
        );
        for wider in ["invoices:delete", "openid", "invoices:read reports:read"] {
            assert_eq!(
                exchanged_scopes(Some(wider), &subject, &allowed, defined, &openid)
                    .expect_err("wider")
                    .error,
                "invalid_scope",
                "{wider}"
            );
        }
        assert_eq!(
            exchanged_scopes(None, &names(&["profile"]), &allowed, defined, &openid)
                .expect_err("none left")
                .error,
            "invalid_scope"
        );
    }
}
