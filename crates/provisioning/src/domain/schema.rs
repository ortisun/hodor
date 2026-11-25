//! The discovery documents: what this server supports, its resource types
//! and their schemas (RFC 7643, sections 5 to 7).
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "Discovery".
//! They are the same for every tenant except for their `location`.

use crate::domain::attribute::{ENTERPRISE_USER_SCHEMA, GROUP_SCHEMA, USER_SCHEMA};
use crate::domain::bulk::{MAX_BULK_BYTES, MAX_BULK_OPERATIONS};
use crate::domain::query::MAX_COUNT;
use serde_json::{Value, json};

/// The URI of the schema of the server's configuration.
pub(crate) const SERVICE_PROVIDER_CONFIG_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
/// The URI of the schema of a resource type.
pub(crate) const RESOURCE_TYPE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
/// The URI of the schema of a schema.
pub(crate) const SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";
/// The URI of a list answer.
pub const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
/// The URI of an error answer.
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// What this server supports. `base` is the address of the tenant's SCIM
/// surface.
#[must_use]
pub fn service_provider_config(base: &str) -> Value {
    json!({
        "schemas": [SERVICE_PROVIDER_CONFIG_SCHEMA],
        "patch": { "supported": true },
        "bulk": {
            "supported": true,
            "maxOperations": MAX_BULK_OPERATIONS,
            "maxPayloadSize": MAX_BULK_BYTES
        },
        "filter": { "supported": true, "maxResults": MAX_COUNT },
        "changePassword": { "supported": false },
        "sort": { "supported": true },
        "etag": { "supported": true },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "An access token of the tenant with the audience urn:hodor:scim and the scope scim",
            "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
            "primary": true
        }],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": format!("{base}/ServiceProviderConfig")
        }
    })
}

/// The resource types, `User` and `Group`.
#[must_use]
pub fn resource_types(base: &str) -> Vec<Value> {
    vec![
        json!({
            "schemas": [RESOURCE_TYPE_SCHEMA],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "A person of the tenant",
            "schema": USER_SCHEMA,
            "schemaExtensions": [{ "schema": ENTERPRISE_USER_SCHEMA, "required": false }],
            "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/User") }
        }),
        json!({
            "schemas": [RESOURCE_TYPE_SCHEMA],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "A group of the tenant",
            "schema": GROUP_SCHEMA,
            "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/Group") }
        }),
    ]
}

/// The resource type named `name`, if there is one.
#[must_use]
pub fn resource_type(name: &str, base: &str) -> Option<Value> {
    resource_types(base)
        .into_iter()
        .find(|kind| kind["id"].as_str().is_some_and(|id| id == name))
}

/// How an attribute is described in a schema.
struct Described {
    name: &'static str,
    kind: &'static str,
    multi_valued: bool,
    required: bool,
    case_exact: bool,
    mutability: &'static str,
    uniqueness: &'static str,
    description: &'static str,
    sub_attributes: Vec<Value>,
}

impl Described {
    const fn text(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            kind: "string",
            multi_valued: false,
            required: false,
            case_exact: false,
            mutability: "readWrite",
            uniqueness: "none",
            description,
            sub_attributes: Vec::new(),
        }
    }

    fn value(self) -> Value {
        let mut value = json!({
            "name": self.name,
            "type": self.kind,
            "multiValued": self.multi_valued,
            "description": self.description,
            "required": self.required,
            "caseExact": self.case_exact,
            "mutability": self.mutability,
            "returned": "default",
            "uniqueness": self.uniqueness,
        });
        if !self.sub_attributes.is_empty() {
            value["subAttributes"] = Value::Array(self.sub_attributes);
        }
        value
    }
}

fn schema(id: &str, name: &str, description: &str, attributes: Vec<Value>, base: &str) -> Value {
    json!({
        "schemas": [SCHEMA_SCHEMA],
        "id": id,
        "name": name,
        "description": description,
        "attributes": attributes,
        "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{id}") }
    })
}

fn user_schema(base: &str) -> Value {
    let attributes = vec![
        Described {
            required: true,
            uniqueness: "server",
            ..Described::text(
                "userName",
                "A username, or an email address; unique in the tenant without regard to case",
            )
        }
        .value(),
        Described {
            case_exact: true,
            ..Described::text(
                "externalId",
                "The SCIM client's own identifier of the person",
            )
        }
        .value(),
        Described {
            kind: "complex",
            sub_attributes: vec![
                Described::text("formatted", "The whole name").value(),
                Described::text("givenName", "The given name").value(),
                Described::text("familyName", "The family name").value(),
            ],
            ..Described::text("name", "The person's name")
        }
        .value(),
        Described::text("displayName", "The name shown for the person").value(),
        Described {
            kind: "complex",
            multi_valued: true,
            sub_attributes: vec![
                Described::text("value", "An email address, taken as verified").value(),
                Described::text("type", "What the address is for, such as work or home").value(),
                Described {
                    kind: "boolean",
                    ..Described::text("primary", "Whether it is the primary address")
                }
                .value(),
            ],
            ..Described::text("emails", "The person's email addresses")
        }
        .value(),
        Described {
            kind: "boolean",
            ..Described::text("active", "Whether the person is active")
        }
        .value(),
        Described {
            kind: "complex",
            multi_valued: true,
            mutability: "readOnly",
            sub_attributes: vec![
                Described {
                    case_exact: true,
                    mutability: "readOnly",
                    ..Described::text("value", "The group's identifier")
                }
                .value(),
                Described {
                    mutability: "readOnly",
                    ..Described::text("display", "The group's name")
                }
                .value(),
                Described {
                    mutability: "readOnly",
                    ..Described::text("type", "direct")
                }
                .value(),
            ],
            ..Described::text("groups", "The groups the person is directly in")
        }
        .value(),
    ];
    schema(
        USER_SCHEMA,
        "User",
        "A person of the tenant",
        attributes,
        base,
    )
}

fn enterprise_schema(base: &str) -> Value {
    let attributes = vec![
        Described::text("employeeNumber", "The employee number").value(),
        Described::text("costCenter", "The cost center").value(),
        Described::text("organization", "The organization").value(),
        Described::text("division", "The division").value(),
        Described::text("department", "The department").value(),
        Described {
            kind: "complex",
            sub_attributes: vec![
                Described {
                    case_exact: true,
                    ..Described::text("value", "The SCIM client's identifier of the manager")
                }
                .value(),
            ],
            ..Described::text("manager", "The person's manager")
        }
        .value(),
    ];
    schema(
        ENTERPRISE_USER_SCHEMA,
        "EnterpriseUser",
        "What an enterprise knows of a person",
        attributes,
        base,
    )
}

fn group_schema(base: &str) -> Value {
    let attributes = vec![
        Described {
            required: true,
            uniqueness: "server",
            ..Described::text(
                "displayName",
                "The group's name; unique in the tenant without regard to case",
            )
        }
        .value(),
        Described {
            case_exact: true,
            ..Described::text(
                "externalId",
                "The SCIM client's own identifier of the group",
            )
        }
        .value(),
        Described {
            kind: "complex",
            multi_valued: true,
            sub_attributes: vec![
                Described {
                    case_exact: true,
                    mutability: "immutable",
                    ..Described::text("value", "The identifier of a user or a group of the tenant")
                }
                .value(),
                Described {
                    mutability: "immutable",
                    ..Described::text("type", "User or Group")
                }
                .value(),
                Described {
                    mutability: "readOnly",
                    ..Described::text("display", "What the member reads as")
                }
                .value(),
            ],
            ..Described::text("members", "The group's direct members")
        }
        .value(),
    ];
    schema(
        GROUP_SCHEMA,
        "Group",
        "A group of the tenant",
        attributes,
        base,
    )
}

/// The schemas of the resources: core User, enterprise User and Group.
#[must_use]
pub fn schemas(base: &str) -> Vec<Value> {
    vec![
        user_schema(base),
        enterprise_schema(base),
        group_schema(base),
    ]
}

/// The schema whose URI is `id`, if there is one.
#[must_use]
pub fn schema_named(id: &str, base: &str) -> Option<Value> {
    schemas(base).into_iter().find(|schema| {
        schema["id"]
            .as_str()
            .is_some_and(|known| known.eq_ignore_ascii_case(id))
    })
}

/// A list answer holding `resources`, the page starting at `start_index`
/// of `total` resources.
#[must_use]
pub fn list_response(total: u64, start_index: u64, resources: Vec<Value>) -> Value {
    json!({
        "schemas": [LIST_RESPONSE_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_document_is_found_by_its_name() {
        let base = "https://id.example.com/t/acme/scim/v2";
        assert!(resource_type("User", base).is_some());
        assert!(resource_type("Other", base).is_none());
        for uri in [USER_SCHEMA, ENTERPRISE_USER_SCHEMA, GROUP_SCHEMA] {
            let found = schema_named(uri, base).expect("a schema");
            assert_eq!(found["meta"]["location"], format!("{base}/Schemas/{uri}"));
        }
        let config = service_provider_config(base);
        assert_eq!(config["patch"]["supported"], true);
        assert_eq!(config["etag"]["supported"], true);
        assert_eq!(config["bulk"]["maxOperations"], 100);
        assert_eq!(config["filter"]["maxResults"], 200);
    }
}
