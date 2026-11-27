//! What a check asks: the application, the subject, the resource and the
//! action, read from Envoy's `CheckRequest`, or why it is denied before
//! Hodor is asked.
//!
//! Specified in `docs/operations/hodor-ext-authz.md`, "What a check
//! becomes".

use crate::config::{Application, Settings, TokenSource};
use crate::pattern;
use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use envoy_types::pb::envoy::service::auth::v3::CheckRequest;
use envoy_types::pb::envoy::service::auth::v3::attribute_context::HttpRequest;
use envoy_types::pb::google::protobuf::{Struct, Value as ProtoValue, value::Kind};
use serde_json::{Map, Number, Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

/// Context per route that names the resource type.
pub const CONTEXT_RESOURCE_TYPE: &str = "hodor_resource_type";
/// Context per route that names the action.
pub const CONTEXT_ACTION: &str = "hodor_action";
/// Context per route that names the resource's identifier.
pub const CONTEXT_RESOURCE_ID: &str = "hodor_resource_id";

/// Why a request is denied before Hodor is asked. Logged, never sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denial(pub &'static str);

/// What one check asks Hodor.
#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    /// The index of the application in the settings.
    pub application: usize,
    /// The body of `evaluate`.
    pub body: Value,
}

/// The question a check asks, or why it is denied.
///
/// # Errors
///
/// Returns the [`Denial`] of a check that names no known destination, no
/// rule, no subject, or claims that fail.
pub fn question(settings: &Settings, check: &CheckRequest) -> Result<Question, Denial> {
    let attributes = check
        .attributes
        .as_ref()
        .ok_or(Denial("the check has no attributes"))?;
    let destination = attributes
        .destination
        .as_ref()
        .map(|peer| peer.principal.as_str())
        .unwrap_or_default();
    if destination.is_empty() {
        return Err(Denial("the check names no destination identity"));
    }
    let application = settings
        .applications
        .iter()
        .position(|application| application.destination == destination)
        .ok_or(Denial(
            "no application of the configuration has this destination",
        ))?;
    let http = attributes
        .request
        .as_ref()
        .and_then(|request| request.http.as_ref())
        .ok_or(Denial("the check has no HTTP request"))?;

    let (resource_type, resource_id, action) = match (
        attributes.context_extensions.get(CONTEXT_RESOURCE_TYPE),
        attributes.context_extensions.get(CONTEXT_ACTION),
    ) {
        (Some(resource_type), Some(action)) => (
            resource_type.clone(),
            attributes
                .context_extensions
                .get(CONTEXT_RESOURCE_ID)
                .cloned(),
            action.clone(),
        ),
        (None, None) => {
            let segments = pattern::segments(&http.path).ok_or(Denial(
                "the path holds a dot segment or an encoded separator",
            ))?;
            settings.applications[application]
                .routes
                .iter()
                .find_map(|route| {
                    if !route.methods.contains(&http.method) {
                        return None;
                    }
                    route.path.matches(&segments).map(|identifier| {
                        (
                            route.resource_type.clone(),
                            identifier,
                            route.action.clone(),
                        )
                    })
                })
                .ok_or(Denial("no route rule matches the method and the path"))?
        }
        _ => {
            return Err(Denial(
                "the context of the route names one of the resource type and the action",
            ));
        }
    };

    let source = attributes
        .source
        .as_ref()
        .map(|peer| peer.principal.as_str())
        .unwrap_or_default();
    let subject = match claims(settings, check, http)? {
        Some(claims) => subject_of(settings, &settings.applications[application], &claims)?,
        None if !source.is_empty() => json!({ "type": "workload_identity", "id": source }),
        None => {
            return Err(Denial(
                "the check has neither a token nor a caller's identity",
            ));
        }
    };

    let mut resource = Map::new();
    resource.insert("type".into(), json!(resource_type));
    if let Some(identifier) = resource_id {
        resource.insert("id".into(), json!(identifier));
    }
    Ok(Question {
        application,
        body: json!({
            "subject": subject,
            "resource": resource,
            "action": action,
        }),
    })
}

/// The subject named by claims that hold: the tenant's issuer, the
/// audience of the application's resource server, not expired, and a
/// `sub`.
fn subject_of(
    settings: &Settings,
    application: &Application,
    claims: &Map<String, Value>,
) -> Result<Value, Denial> {
    if claims.get("iss").and_then(Value::as_str) != Some(settings.issuer.as_str()) {
        return Err(Denial("the token is not of the tenant's issuer"));
    }
    if !holds(claims.get("aud"), &application.audience) {
        return Err(Denial(
            "the token is not for the audience of the application's resource server",
        ));
    }
    match claims.get("exp") {
        None => {}
        Some(expires) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0.0, |elapsed| elapsed.as_secs_f64());
            if !expires.as_f64().is_some_and(|expires| expires > now) {
                return Err(Denial("the token has expired"));
            }
        }
    }
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|subject| !subject.is_empty())
        .ok_or(Denial("the token has no subject"))?;
    let kind = if claims.get("client_id").and_then(Value::as_str) == Some(subject) {
        "client"
    } else {
        "user"
    };
    Ok(json!({ "type": kind, "id": subject }))
}

/// Whether `aud` names `audience`: one text equal to it, or a list with it
/// among its values, compared byte for byte.
fn holds(aud: Option<&Value>, audience: &str) -> bool {
    match aud {
        Some(Value::String(one)) => one == audience,
        Some(Value::Array(many)) => many.iter().any(|value| value.as_str() == Some(audience)),
        _ => false,
    }
}

/// The claims of the token the proxy checked, from where the settings say,
/// or `None` when there are none.
fn claims(
    settings: &Settings,
    check: &CheckRequest,
    http: &HttpRequest,
) -> Result<Option<Map<String, Value>>, Denial> {
    match &settings.token {
        None => Ok(None),
        Some(TokenSource::Metadata { namespace, key }) => {
            let found = check
                .attributes
                .as_ref()
                .and_then(|attributes| attributes.metadata_context.as_ref())
                .and_then(|metadata| metadata.filter_metadata.get(namespace))
                .and_then(|filter| filter.fields.get(key));
            match found.and_then(|value| value.kind.as_ref()) {
                None => Ok(None),
                Some(Kind::StructValue(claims)) => Ok(Some(object(claims))),
                Some(_) => Err(Denial(
                    "the token's claims in the metadata are not an object",
                )),
            }
        }
        Some(TokenSource::Header(name)) => {
            let Some(written) = header(http, name) else {
                return Ok(None);
            };
            let written = decode(written).ok_or(Denial("the claims header is not base64url"))?;
            let token = header(http, "authorization")
                .and_then(|value| {
                    let (scheme, token) = value.split_once(' ')?;
                    scheme
                        .eq_ignore_ascii_case("bearer")
                        .then_some(token.trim())
                })
                .ok_or(Denial("the claims header comes without a bearer token"))?;
            let mut parts = token.split('.');
            let checked = match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(_), Some(payload), Some(_), None) => decode(payload),
                _ => None,
            }
            .ok_or(Denial("the bearer token is not a JWT"))?;
            if checked != written {
                return Err(Denial("the claims header is not the bearer token's claims"));
            }
            match serde_json::from_slice(&written) {
                Ok(Value::Object(claims)) => Ok(Some(claims)),
                _ => Err(Denial("the token's claims are not a JSON object")),
            }
        }
    }
}

/// A header of the request, whichever of Envoy's two forms carries it.
fn header<'a>(http: &'a HttpRequest, name: &str) -> Option<&'a str> {
    if let Some(value) = http.headers.get(name) {
        return Some(value.as_str());
    }
    http.header_map.as_ref().and_then(|map| {
        map.headers.iter().find_map(|header| {
            (header.key.eq_ignore_ascii_case(name)).then(|| {
                if header.value.is_empty() {
                    std::str::from_utf8(&header.raw_value).unwrap_or_default()
                } else {
                    header.value.as_str()
                }
            })
        })
    })
}

/// base64url, with or without padding.
fn decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .or_else(|_| URL_SAFE.decode(text))
        .ok()
}

fn object(fields: &Struct) -> Map<String, Value> {
    fields
        .fields
        .iter()
        .map(|(name, value)| (name.clone(), json_of(value)))
        .collect()
}

fn json_of(value: &ProtoValue) -> Value {
    match &value.kind {
        None | Some(Kind::NullValue(_)) => Value::Null,
        Some(Kind::NumberValue(number)) => {
            Number::from_f64(*number).map_or(Value::Null, Value::Number)
        }
        Some(Kind::StringValue(text)) => Value::String(text.clone()),
        Some(Kind::BoolValue(flag)) => Value::Bool(*flag),
        Some(Kind::StructValue(fields)) => Value::Object(object(fields)),
        Some(Kind::ListValue(list)) => Value::Array(list.values.iter().map(json_of).collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_types::pb::envoy::config::core::v3::Metadata;
    use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
    use envoy_types::pb::envoy::service::auth::v3::attribute_context::{Peer, Request};
    use envoy_types::pb::google::protobuf::ListValue;
    use std::collections::HashMap;

    const ORDERS: &str = "spiffe://cluster.local/ns/shop/sa/orders";
    const WEB: &str = "spiffe://cluster.local/ns/shop/sa/web";
    const ISSUER: &str = "https://login.example.com/t/acme";
    const ORDERS_AUDIENCE: &str = "https://orders.example.com";

    fn settings(token: &str) -> Settings {
        Settings::from_json(&format!(
            r#"{{
              "hodor": {{ "url": "http://hodor:8080", "tenant": "acme", "issuer": "{ISSUER}" }},
              {token}
              "applications": [
                {{ "destination": "{ORDERS}", "client_id": "orders-client", "audience": "{ORDERS_AUDIENCE}",
                   "routes": [
                     {{ "methods": ["GET"], "path": "/orders", "resource_type": "order", "action": "list" }},
                     {{ "methods": ["GET"], "path": "/orders/{{id}}", "resource_type": "order", "action": "read" }},
                     {{ "methods": ["POST"], "path": "/orders/{{id}}/approve", "resource_type": "order", "action": "approve" }}
                   ] }}
              ]
            }}"#
        ))
        .expect("settings")
    }

    fn check(method: &str, path: &str) -> CheckRequest {
        CheckRequest {
            attributes: Some(AttributeContext {
                source: Some(Peer {
                    principal: WEB.to_owned(),
                    ..Peer::default()
                }),
                destination: Some(Peer {
                    principal: ORDERS.to_owned(),
                    ..Peer::default()
                }),
                request: Some(Request {
                    http: Some(HttpRequest {
                        method: method.to_owned(),
                        path: path.to_owned(),
                        ..HttpRequest::default()
                    }),
                    ..Request::default()
                }),
                ..AttributeContext::default()
            }),
        }
    }

    fn attributes(check: &mut CheckRequest) -> &mut AttributeContext {
        check.attributes.as_mut().expect("attributes")
    }

    fn http(check: &mut CheckRequest) -> &mut HttpRequest {
        attributes(check)
            .request
            .as_mut()
            .and_then(|request| request.http.as_mut())
            .expect("http")
    }

    fn proto(value: &Value) -> ProtoValue {
        let kind = match value {
            Value::Null => Kind::NullValue(0),
            Value::Bool(flag) => Kind::BoolValue(*flag),
            Value::Number(number) => Kind::NumberValue(number.as_f64().expect("number")),
            Value::String(text) => Kind::StringValue(text.clone()),
            Value::Array(values) => Kind::ListValue(ListValue {
                values: values.iter().map(proto).collect(),
            }),
            Value::Object(fields) => Kind::StructValue(Struct {
                fields: fields
                    .iter()
                    .map(|(name, value)| (name.clone(), proto(value)))
                    .collect(),
            }),
        };
        ProtoValue { kind: Some(kind) }
    }

    fn in_metadata(check: &mut CheckRequest, claims: &Value) {
        attributes(check).metadata_context = Some(Metadata {
            filter_metadata: HashMap::from([(
                "envoy.filters.http.jwt_authn".to_owned(),
                Struct {
                    fields: HashMap::from([("hodor".to_owned(), proto(claims))]),
                },
            )]),
            ..Metadata::default()
        });
    }

    fn later() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_secs()
            + 300
    }

    fn jwt(claims: &Value) -> (String, String) {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("json"));
        (
            format!("eyJhbGciOiJFUzI1NiJ9.{payload}.c2lnbmF0dXJl"),
            payload,
        )
    }

    const METADATA: &str = r#""token": { "metadata": { "key": "hodor" } },"#;
    const HEADER: &str = r#""token": { "header": "x-hodor-token-claims" },"#;

    #[test]
    fn a_route_rule_names_the_resource_and_the_action() {
        let settings = settings("");
        let asked = question(&settings, &check("POST", "/orders/42/approve?x=1")).expect("asked");
        assert_eq!(asked.application, 0);
        assert_eq!(
            asked.body,
            json!({
                "subject": { "type": "workload_identity", "id": WEB },
                "resource": { "type": "order", "id": "42" },
                "action": "approve"
            })
        );
        let listed = question(&settings, &check("GET", "/orders")).expect("asked");
        assert_eq!(listed.body["resource"], json!({ "type": "order" }));
        assert_eq!(listed.body["action"], "list");
    }

    #[test]
    fn a_route_with_no_rule_is_denied() {
        let settings = settings("");
        for (method, path) in [
            ("DELETE", "/orders/42"),
            ("GET", "/invoices/1"),
            ("GET", "/orders/42/approve"),
            ("GET", "/orders/../admin"),
        ] {
            assert!(
                question(&settings, &check(method, path)).is_err(),
                "{method} {path}"
            );
        }
    }

    #[test]
    fn a_destination_with_no_client_is_denied() {
        let settings = settings("");
        let mut unknown = check("GET", "/orders");
        attributes(&mut unknown).destination = Some(Peer {
            principal: "spiffe://cluster.local/ns/shop/sa/other".to_owned(),
            ..Peer::default()
        });
        assert_eq!(
            question(&settings, &unknown),
            Err(Denial(
                "no application of the configuration has this destination"
            ))
        );
        let mut none = check("GET", "/orders");
        attributes(&mut none).destination = None;
        assert!(question(&settings, &none).is_err());
        assert!(question(&settings, &CheckRequest::default()).is_err());
    }

    #[test]
    fn the_context_of_the_route_takes_the_place_of_the_rules() {
        let settings = settings("");
        let mut named = check("PUT", "/anything/at/all");
        attributes(&mut named).context_extensions = HashMap::from([
            (CONTEXT_RESOURCE_TYPE.to_owned(), "report".to_owned()),
            (CONTEXT_ACTION.to_owned(), "write".to_owned()),
            (CONTEXT_RESOURCE_ID.to_owned(), "r-1".to_owned()),
        ]);
        let asked = question(&settings, &named).expect("asked");
        assert_eq!(
            asked.body["resource"],
            json!({ "type": "report", "id": "r-1" })
        );
        assert_eq!(asked.body["action"], "write");
        let mut half = check("GET", "/orders");
        attributes(&mut half).context_extensions =
            HashMap::from([(CONTEXT_ACTION.to_owned(), "read".to_owned())]);
        assert!(question(&settings, &half).is_err(), "one without the other");
    }

    #[test]
    fn the_checked_token_in_the_metadata_names_the_subject() {
        let settings = settings(METADATA);
        let mut person = check("GET", "/orders/1");
        in_metadata(
            &mut person,
            &json!({ "iss": ISSUER, "aud": ORDERS_AUDIENCE, "sub": "user-1", "client_id": "app", "exp": later() }),
        );
        assert_eq!(
            question(&settings, &person).expect("asked").body["subject"],
            json!({ "type": "user", "id": "user-1" })
        );
        let mut itself = check("GET", "/orders/1");
        in_metadata(
            &mut itself,
            &json!({ "iss": ISSUER, "aud": [ISSUER, ORDERS_AUDIENCE], "sub": "app", "client_id": "app" }),
        );
        assert_eq!(
            question(&settings, &itself).expect("asked").body["subject"],
            json!({ "type": "client", "id": "app" })
        );
        // No claims: the caller's identity.
        assert_eq!(
            question(&settings, &check("GET", "/orders/1"))
                .expect("asked")
                .body["subject"]["type"],
            "workload_identity"
        );
    }

    #[test]
    fn claims_that_fail_are_denied_and_never_replaced_by_the_identity() {
        let settings = settings(METADATA);
        for claims in [
            json!({ "iss": "https://login.example.com/t/other", "aud": ORDERS_AUDIENCE, "sub": "user-1" }),
            json!({ "aud": ORDERS_AUDIENCE, "sub": "user-1" }),
            json!({ "iss": ISSUER, "aud": ORDERS_AUDIENCE, "sub": "user-1", "exp": 1 }),
            json!({ "iss": ISSUER, "aud": ORDERS_AUDIENCE, "sub": "user-1", "exp": "later" }),
            json!({ "iss": ISSUER, "aud": ORDERS_AUDIENCE }),
            json!({ "iss": ISSUER, "aud": ORDERS_AUDIENCE, "sub": "" }),
        ] {
            let mut failing = check("GET", "/orders/1");
            in_metadata(&mut failing, &claims);
            assert!(question(&settings, &failing).is_err(), "{claims}");
        }
        let mut not_an_object = check("GET", "/orders/1");
        in_metadata(&mut not_an_object, &json!("a text"));
        assert!(question(&settings, &not_an_object).is_err());
    }

    #[test]
    fn the_claims_header_is_believed_only_as_the_bearer_tokens_claims() {
        let settings = settings(HEADER);
        let claims =
            json!({ "iss": ISSUER, "aud": ORDERS_AUDIENCE, "sub": "user-1", "exp": later() });
        let (token, payload) = jwt(&claims);
        let mut forwarded = check("GET", "/orders/1");
        http(&mut forwarded).headers = HashMap::from([
            ("x-hodor-token-claims".to_owned(), payload.clone()),
            ("authorization".to_owned(), format!("Bearer {token}")),
        ]);
        assert_eq!(
            question(&settings, &forwarded).expect("asked").body["subject"],
            json!({ "type": "user", "id": "user-1" })
        );

        // Written by the caller, with no token or with another token.
        let forged = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(
                &json!({ "iss": ISSUER, "aud": ORDERS_AUDIENCE, "sub": "administrator" }),
            )
            .expect("json"),
        );
        let mut alone = check("GET", "/orders/1");
        http(&mut alone).headers =
            HashMap::from([("x-hodor-token-claims".to_owned(), forged.clone())]);
        assert!(question(&settings, &alone).is_err());
        let mut beside = check("GET", "/orders/1");
        http(&mut beside).headers = HashMap::from([
            ("x-hodor-token-claims".to_owned(), forged),
            ("authorization".to_owned(), format!("Bearer {token}")),
        ]);
        assert!(question(&settings, &beside).is_err());
        let mut garbled = check("GET", "/orders/1");
        http(&mut garbled).headers = HashMap::from([
            ("x-hodor-token-claims".to_owned(), "%%%".to_owned()),
            ("authorization".to_owned(), format!("Bearer {token}")),
        ]);
        assert!(question(&settings, &garbled).is_err());
    }

    #[test]
    fn a_token_for_another_audience_is_denied() {
        let metadata = settings(METADATA);
        let held =
            |aud: Value| json!({ "iss": ISSUER, "aud": aud, "sub": "user-1", "exp": later() });
        for (aud, allowed) in [
            (json!(ORDERS_AUDIENCE), true),
            (json!([ORDERS_AUDIENCE]), true),
            (
                json!(["https://invoices.example.com", ORDERS_AUDIENCE]),
                true,
            ),
            // Another application of the same tenant.
            (json!("https://invoices.example.com"), false),
            (json!(["https://invoices.example.com", ISSUER]), false),
            // The issuer alone: a token that named no resource server.
            (json!(ISSUER), false),
            // An ID token: its audience is a client.
            (json!("orders-client"), false),
            // Compared byte for byte.
            (json!("https://orders.example.com/"), false),
            (json!("HTTPS://ORDERS.EXAMPLE.COM"), false),
            (json!([]), false),
            (json!(42), false),
            (json!({ "aud": ORDERS_AUDIENCE }), false),
        ] {
            let mut asked = check("GET", "/orders/1");
            in_metadata(&mut asked, &held(aud.clone()));
            assert_eq!(question(&metadata, &asked).is_ok(), allowed, "{aud}");
        }
        let mut without = check("GET", "/orders/1");
        in_metadata(
            &mut without,
            &json!({ "iss": ISSUER, "sub": "user-1", "exp": later() }),
        );
        assert_eq!(
            question(&metadata, &without),
            Err(Denial(
                "the token is not for the audience of the application's resource server"
            ))
        );

        // Through the header too, and never replaced by the caller's identity.
        let through_header = settings(HEADER);
        let (token, payload) = jwt(&held(json!("https://invoices.example.com")));
        let mut forwarded = check("GET", "/orders/1");
        http(&mut forwarded).headers = HashMap::from([
            ("x-hodor-token-claims".to_owned(), payload),
            ("authorization".to_owned(), format!("Bearer {token}")),
        ]);
        assert!(question(&through_header, &forwarded).is_err());
    }

    #[test]
    fn with_neither_a_token_nor_an_identity_the_request_is_denied() {
        let settings = settings("");
        let mut anonymous = check("GET", "/orders");
        attributes(&mut anonymous).source = None;
        assert!(question(&settings, &anonymous).is_err());
    }
}
