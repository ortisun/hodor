# Provisioning domain

## Overview

Computation on values only: nothing here reads storage. The modules are
`pub(crate)`; the public types are re-exported through
`hodor_provisioning::api`.

## Interface

| File | What it holds |
| --- | --- |
| `attribute.rs` | The `Attribute` trait (`SCHEMA`, `named`, `name`, `value_type`, `multi_valued`, `sortable`, `sort_named`), `UserAttribute` and `GroupAttribute` (the fixed sets that can be filtered on), `AttributeType` (`Text { exact }`, `Boolean`, `DateTime`), `fold_case` (only `A` to `Z` change), the schema URIs |
| `filter.rs` | `parse_element_filter`: the value filter of a `PATCH` path, over the sub-attributes of one value, text without regard to case, with the same bounds. `parse::<A>(text) -> Result<Filter<A>, FilterRefusal>`: checks the length first, reads the grammar of RFC 7644 with the bounds of depth and comparisons, then resolves names to attributes and checks operators and values against the type. `eq null` and `ne null` become absence and presence; a multi-valued attribute is always `Filter::Any` with a `ValueFilter`. `Display` writes a filter that reads back as the same tree |
| `evaluate.rs` | `matches(filter, &dyn Facts<A>)`: a comparison with a missing value is false; text compared without case is folded on both sides; `sort_order` puts a missing value after every value |
| `query.rs` | `ListQuery::read(&ListParameters)`: `startIndex` below 1 is 1, `count` 100 by default and clamped to 0..=200, `sortBy` must be `sortable`, `sortOrder` `ascending` or `descending`; `Found` |
| `resource.rs` | `read_user` and `read_group` (attribute names without regard to case; booleans also as the strings `true` and `false`; an email's `type` kept; `invalidSyntax` for the body or `schemas`, `mutability` for `password`, `invalidValue` otherwise; at most 1000 members), the supplements, `UserResource::document` and `GroupResource::document` (the JSON a SCIM client reads, with `meta.location` under the base given), `UserFacts` and `GroupFacts`, `shown`, `user_name_of` |
| `replace.rs` | `replace_user(&mut User, &UserRequest, now) -> Replaced`: the `userName` first, removals before additions, every address verified, the primary of each kind, the display name, the status when `active` is `true`, and `deprovision` when it is `false` for a user not yet Deactivated |
| `patch.rs` | `read_patch` (at most 100 operations, `tooMany` past it) and `read_path`, then `apply_patch` on the resource's JSON: operations in order; `add`, `replace`, `remove` on an attribute, a sub-attribute or the values a value filter selects; a filter of `eq` and `and` that selects nothing makes a value; at most one value stays `primary`; read-only attributes are `mutability` |
| `version.rs` | `version_of`: `W/"…"`, FNV-1a of 64 bits over the JSON with its keys in order; `Precondition` of `If-Match` and `If-None-Match`, compared without regard to `W/` |
| `bulk.rs` | `read_bulk` within its bounds (refused whole with `tooMany`), `method_of`, `check_bulk_id`, and the replacement of `bulkId:` references in a path and in every string of data |
| `schema.rs` | The discovery documents and `list_response` |
| `error.rs` | The codes and their constructors |
| `event.rs` | `ProvisioningEvent`: `provisioning.user_attributes_changed`, `provisioning.group_attributes_changed`, with identifiers only |

## Invariants

- Every bound of a filter holds before work proportional to it is done: the length before tokens are made, depth and comparisons while reading. Recursion is bounded by the depth.
- `matches` is the meaning the PostgreSQL store's SQL must agree with; the contract checks the two on the corpus.

## Verification

- Run: `cargo test -p hodor-provisioning`
