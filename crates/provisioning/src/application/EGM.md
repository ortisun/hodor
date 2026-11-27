# Provisioning application layer

## Overview

The use cases of the provisioning context (`service.rs`) and the two storage
ports they need (`ports.rs`). Each use case opens one unit of work bound to
the caller's tenant and runs the identity context's `*_in` use cases in it,
with what this context keeps, so that a request changes everything or
nothing. Both modules are `pub(crate)`; other crates reach the types through
`hodor_provisioning::api`.

## Interface

### Ports (`ports.rs`)

Every method takes `uow: &mut dyn UnitOfWork` and works inside its tenant.

| Port | Methods |
| --- | --- |
| `ProvisionedUserRepository` | `get(uow, user) -> Option<StoredUserSupplement>`; `put(uow, stored)` stores in place of what was; `remove(uow, user)`; `find(uow, &ListQuery<UserAttribute>) -> Found<UserId>`: the people not marked Deleted that match, in the query's order, the page's identifiers and how many match |
| `ProvisionedGroupRepository` | `get`, `put`, `remove(uow, group)` (nothing when nothing was), `find(uow, &ListQuery<GroupAttribute>) -> Found<GroupId>` |
| `DeprovisioningPolicy` | `deprovisioning(uow) -> Deprovisioning`: `Deactivate` or `Delete`, read in the change's unit of work |
| `AccessRevoker` | `revoke_access(uow, user, reason, caller)`: ends every session and revokes every grant of the person in the caller's unit of work; implemented in `apps/hodor-server` |

Implemented by `PgProvisionedUserRepository` and `PgProvisionedGroupRepository`
(`crates/adapters-postgres/src/provisioning.rs`) and in memory in
`src/testing.rs`.

### `ProvisioningService` (`service.rs`)

- `new(ProvisioningPorts)`.
- `create_user(tenant, &UserRequest, caller) -> UserResource`: `IdentityService::create_with_claims_in` with the request's standard claims, kind `human`, `confirmed` and every address verified; `active: false` deactivates at once; a supplement that is not empty is put, with `provisioning.user_attributes_changed`.
- `replace_user` and `patch_user(tenant, id, …, precondition: Option<&Precondition>, caller) -> Option<UserResource>`: check the version against the user as loaded in the unit of work (`provisioning.version_mismatch`), apply the request or the `PATCH` to the user's JSON and read the result as a `PUT`; `active: false` deprovisions; `None` when the policy deleted the user.
- `delete_user(tenant, id, precondition, caller)`: deprovisions and marks the user removed, so SCIM no longer shows them while Deactivated.
- Deprovisioning (`deprovision_in`): reads `DeprovisioningPolicy`, deactivates, under `Delete` marks Deleted (`IdentityService::mark_deleted_in`) and removes what is kept, then `AccessRevoker::revoke_access` with `DEPROVISIONED`, all in the same unit of work.
- `get_user(tenant, id) -> UserResource`: `NotFound` `provisioning.user_not_found` for no user, a service account, an agent or a user marked Deleted (`shown`); with the supplement and the direct groups and their names.
- `replace_user(tenant, id, &UserRequest, caller)`: `IdentityService::change_in` with the domain's `replace_user`, which also replaces the standard claims SCIM names; the supplement is put only when it differs.
- `list_users(tenant, &ListQuery<UserAttribute>) -> Listed<UserResource>`.
- `create_group`, `get_group`, `replace_group`, `patch_group`, `delete_group`, `list_groups` (the changes take a precondition; `patch_group` bounds the members its operations name at 1000; current members are not looked up again): through `GroupService::create_in`, `get_in`, `change_in` (the description kept), `add_member_in`, `remove_member_in`, `all_members_in`, `delete_in`. A member is a user `shown`, or a group of the tenant; otherwise `provisioning.invalid_value`. `NotFound` is `provisioning.group_not_found`.

## Invariants

- One unit of work per use case, committed once at the end; reads that follow a change open their own.
- The group's supplement row is put on every SCIM create, and on a replace whose members or `externalId` changed, so that `updated_at` says when SCIM last changed the group.
- Events of this context carry identifiers only; the identity context's events are recorded by its use cases. Every event carries the caller given by the HTTP layer.

## Verification

- Run: `cargo test -p hodor-provisioning --test service`
