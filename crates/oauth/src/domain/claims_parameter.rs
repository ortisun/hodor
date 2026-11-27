//! The `claims` parameter of an authorization request (OpenID Connect
//! Core, section 5.5): which of the person's claims a client asks for, in
//! the ID token, at UserInfo or both; an `acr` asked as essential; a `sub`
//! asked with a value; and what a grant then gives.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "The `claims`
//! parameter", and Decisions 0047 and 0068.

use crate::domain::claim_mapper::MOST_MAPPED_BYTES;
use crate::domain::openid::{
    PERSON_CLAIMS, PersonClaims, asks_for_openid, person_claim, scope_of_claim,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The most bytes a `claims` parameter holds.
pub const MAX_CLAIMS_BYTES: usize = 4096;
/// The most claims a `claims` parameter names, across both members.
pub const MAX_CLAIMS_NAMED: usize = 64;

/// What a request asked for through `claims`, once read: the person's
/// claims it named for each target, in the order of [`PERSON_CLAIMS`], and
/// the `sub` it expects. Unknown names are not kept.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimsRequest {
    /// The person's claims asked for the ID token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub id_token: Vec<String>,
    /// The person's claims asked for UserInfo.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub userinfo: Vec<String>,
    /// The `sub` asked for with a value: the person the client expects, as
    /// it knows them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

/// A `claims` parameter, read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadClaims {
    /// What is kept with the request.
    pub request: ClaimsRequest,
    /// The values of an `acr` asked for the ID token as essential,
    /// separated by spaces: what the request's `acr_values` becomes.
    pub essential_acr: Option<String>,
    /// Whether `acr` was asked for with a value or values, essential or
    /// not, which `acr_values` may not be given beside.
    pub acr_with_values: bool,
}

/// What a grant gives through the `claims` parameter: the claims asked for
/// each target that a consented scope covers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantClaims {
    /// Added to the ID token of the code.
    pub id_token: Vec<String>,
    /// Added to the answer of UserInfo for every access token of the grant.
    pub userinfo: Vec<String>,
}

/// The person's claims of `names`, in the order of [`PERSON_CLAIMS`].
fn in_order(names: &[String]) -> Vec<String> {
    PERSON_CLAIMS
        .iter()
        .filter(|(claim, _)| names.iter().any(|name| name == claim))
        .map(|(claim, _)| (*claim).to_owned())
        .collect()
}

/// The texts of `value` and `values` of an asked claim: `None` when one is
/// not a text of printable characters without a space.
fn texts(asked: &Map<String, Value>) -> Option<Vec<String>> {
    let mut found = Vec::new();
    let mut push = |value: &Value| -> Option<()> {
        let text = value.as_str()?;
        let printable = !text.is_empty() && text.bytes().all(|b| (0x21..=0x7e).contains(&b));
        printable.then(|| found.push(text.to_owned()))
    };
    if let Some(value) = asked.get("value") {
        push(value)?;
    }
    if let Some(Value::Array(values)) = asked.get("values") {
        for value in values {
            push(value)?;
        }
    }
    Some(found)
}

/// Reads a `claims` parameter.
///
/// # Errors
///
/// Returns the description of `invalid_request` when the parameter is
/// longer than [`MAX_CLAIMS_BYTES`], names more than [`MAX_CLAIMS_NAMED`]
/// claims, or is not written as OpenID Connect Core, section 5.5, says.
pub fn read_claims(text: &str) -> Result<ReadClaims, &'static str> {
    if text.len() > MAX_CLAIMS_BYTES {
        return Err("claims holds at most 4096 bytes");
    }
    let Ok(Value::Object(members)) = serde_json::from_str::<Value>(text) else {
        return Err("claims is not a JSON object");
    };
    let mut read = ReadClaims::default();
    let mut named = 0_usize;
    let mut asked_for: [Vec<String>; 2] = [Vec::new(), Vec::new()];
    for (index, member) in ["id_token", "userinfo"].into_iter().enumerate() {
        let claims = match members.get(member) {
            None => continue,
            Some(Value::Object(claims)) => claims,
            Some(_) => return Err("a member of claims is not an object"),
        };
        named += claims.len();
        if named > MAX_CLAIMS_NAMED {
            return Err("claims names at most 64 claims");
        }
        for (name, asked) in claims {
            let asked = match asked {
                Value::Null => None,
                Value::Object(asked) => Some(asked),
                _ => return Err("a claim of claims is neither null nor an object"),
            };
            if let Some(asked) = asked {
                if asked
                    .get("essential")
                    .is_some_and(|value| !value.is_boolean())
                {
                    return Err("essential is not true or false");
                }
                if asked.get("values").is_some_and(|value| !value.is_array()) {
                    return Err("values is not a list");
                }
            }
            match name.as_str() {
                "acr" if member == "id_token" => {
                    let Some(asked) = asked else { continue };
                    let values = texts(asked).ok_or("a value of acr is not a level's name")?;
                    if values.is_empty() {
                        continue;
                    }
                    read.acr_with_values = true;
                    if asked.get("essential") == Some(&Value::Bool(true)) {
                        read.essential_acr = Some(values.join(" "));
                    }
                }
                "sub" => {
                    let Some(value) = asked.and_then(|asked| asked.get("value")) else {
                        continue;
                    };
                    let value = value.as_str().ok_or("the value of sub is not a text")?;
                    match &read.request.subject {
                        Some(earlier) if earlier != value => {
                            return Err("sub is asked for with two values");
                        }
                        _ => read.request.subject = Some(value.to_owned()),
                    }
                }
                _ if scope_of_claim(name).is_some() => asked_for[index].push(name.clone()),
                // Unknown, a claim of the sign-in the ID token always
                // has, or one with a language tag: ignored.
                _ => {}
            }
        }
    }
    let [id_token, userinfo] = asked_for;
    read.request.id_token = in_order(&id_token);
    read.request.userinfo = in_order(&userinfo);
    Ok(read)
}

impl ClaimsRequest {
    /// Whether it asks for nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.id_token.is_empty() && self.userinfo.is_empty() && self.subject.is_none()
    }

    /// What a grant for a request of `scopes` gives, when `consented` are
    /// the scopes consented to for the client: each claim asked that one of
    /// them covers. Nothing without `openid`.
    #[must_use]
    pub fn given(&self, scopes: &[String], consented: &[String]) -> GrantClaims {
        if !asks_for_openid(scopes) {
            return GrantClaims::default();
        }
        let covered = |names: &[String]| -> Vec<String> {
            names
                .iter()
                .filter(|name| {
                    scope_of_claim(name)
                        .is_some_and(|scope| consented.iter().any(|given| given == scope))
                })
                .cloned()
                .collect()
        };
        GrantClaims {
            id_token: covered(&self.id_token),
            userinfo: covered(&self.userinfo),
        }
    }
}

/// What a claim costs in a token, as JSON writes it: its name and value,
/// the two quotes of the name, the colon and the comma.
fn cost(name: &str, value: &Value) -> usize {
    name.len() + 4 + value.to_string().len()
}

/// Adds to the ID token `claims` the person's claims of `asked`, in the
/// order of [`PERSON_CLAIMS`], within the bound the client's mappers have
/// there: `mapped`, the mappers' claims, count first, and a claim that
/// would cross [`MOST_MAPPED_BYTES`] is left out whole, never cut. A claim
/// the person has no value of is left out.
pub fn add_asked_claims(
    claims: &mut Value,
    asked: &[String],
    person: &PersonClaims,
    mapped: &Map<String, Value>,
) {
    let Some(object) = claims.as_object_mut() else {
        return;
    };
    let used: usize = mapped.iter().map(|(name, value)| cost(name, value)).sum();
    let mut left = MOST_MAPPED_BYTES.saturating_sub(used);
    for name in in_order(asked) {
        if object.contains_key(&name) {
            continue;
        }
        let Some(value) = person_claim(&name, person) else {
            continue;
        };
        let costs = cost(&name, &value);
        if costs <= left {
            left -= costs;
            object.insert(name, value);
        }
    }
}

#[cfg(test)]
mod tests;
