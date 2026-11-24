# hodor-provisioning source

## Overview

The SCIM 2.0 server's context (`lib.rs` crate documentation). It follows
`docs/architecture/contexts/provisioning.md`. The `application` and `domain`
modules are private; other crates use the `api` module.

## Interface

- `lib.rs: pub mod api` re-exports:
  - Use cases: `ProvisioningService`, `ProvisioningPorts { units_of_work, identity, groups, users, provisioned_groups, deprovisioning, access, clock }`, `Listed { total, start_index, resources }`.
  - Ports: `ProvisionedUserRepository`, `ProvisionedGroupRepository`, `DeprovisioningPolicy` (with `Deprovisioning`), `AccessRevoker`.
  - `PATCH`: `read_patch`, `read_path`, `apply_patch`, `PatchRequest`, `PatchOperation`, `PatchOp`, `PatchPath`, `Shape`, `USER_SHAPE`, `GROUP_SHAPE`, `PATCH_SCHEMA`, `MAX_PATCH_OPERATIONS` (100), `MAX_PATH_CHARACTERS` (1000); value filters of paths: `parse_element_filter`, `ElementFilter`.
  - Versions: `version_of`, `Precondition` (`read`, `admits`).
  - Bulk requests: `read_bulk`, `BulkRequest`, `BulkOperation`, `BulkMethod`, `method_of`, `check_bulk_id`, `resolve_path`, `resolve_data`, `MAX_BULK_OPERATIONS` (100), `MAX_BULK_BYTES` (1 MiB), `BULK_REQUEST_SCHEMA`, `BULK_RESPONSE_SCHEMA`.
  - Attributes: `Attribute` (trait), `AttributeType`, `UserAttribute`, `GroupAttribute`, `fold_case`, and the schema URIs `USER_SCHEMA`, `ENTERPRISE_USER_SCHEMA`, `GROUP_SCHEMA`.
  - Filters: `parse`, `Filter`, `ValueFilter`, `Operator`, `Value`, `FilterRefusal`, the bounds `MAX_FILTER_CHARACTERS` (1000), `MAX_FILTER_DEPTH` (10), `MAX_FILTER_COMPARISONS` (20); evaluation: `matches`, `sort_order`, `Facts`, `Fact`.
  - Lists: `ListQuery`, `ListParameters`, `SortOrder`, `Found`, `DEFAULT_COUNT` (100), `MAX_COUNT` (200).
  - Resources: `read_user`, `read_group`, `UserRequest`, `GroupRequest`, `MemberReference`, `MemberKind`, `UserSupplement`, `GroupSupplement`, `StoredUserSupplement`, `StoredGroupSupplement`, `UserResource`, `GroupResource`, `MemberView`, `UserFacts`, `GroupFacts`, `shown`, `user_name_of`, `user_last_modified`, `group_last_modified`, `read_group_bounded`, `replace_user` with `Replaced { events, deprovision }`, `MAX_KEPT_CHARACTERS` (256), `MAX_MEMBERS_PER_REQUEST` (1000), `DEPROVISIONED`.
  - Discovery: `service_provider_config`, `resource_types`, `resource_type`, `schemas`, `schema_named`, `list_response`, `ERROR_SCHEMA`, `LIST_RESPONSE_SCHEMA`.
  - Errors and events: the codes `INVALID_FILTER`, `INVALID_SYNTAX`, `INVALID_VALUE`, `INVALID_PATH`, `NO_TARGET`, `TOO_MANY`, `MUTABILITY`, which the HTTP layer turns into `scimType`, and `VERSION_MISMATCH` (`412`); `ProvisioningEvent`.
- `lib.rs: pub mod testing` (`testing.rs`), compiled under `#[cfg(any(test, feature = "testing"))]`:
  - `InMemoryProvisionedUsers::new(Arc<dyn UserRepository>)` and `InMemoryProvisionedGroups::new(Arc<dyn GroupRepository>)`: the ports in memory. They find by listing the identity context's users or groups through their repositories and evaluating the filter tree with `matches`.
  - `user_corpus()`, `group_corpus()`: the corpus of filters, each `CorpusCase { filter, expected }` with `Expected::Finds(names)` or `Expected::Refused(FilterRefusal)`; `with_identifiers` replaces `{name}` with an identifier.
  - `FixedDeprovisioning` (a policy a test sets) and `RecordingAccessRevoker` (remembers whose access it ended and why).
  - `ContractPorts { units_of_work, users, groups, provisioned_users, provisioned_groups }` and `run_contract`: stores what is kept, finds every answered filter of the corpus with the population it makes, checks orders, pages and tenant isolation.
- Subdirectories:
  - [application](./application/EGM.md): `ProvisioningService` and the ports.
  - [domain](./domain/EGM.md): attributes, the filter parser and its evaluation, lists, resources, replacing a user, discovery documents, errors and events.
