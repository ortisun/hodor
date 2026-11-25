# hodor-identity source

## Overview

The identity context owns users: who exists inside a tenant, how they are
found, and whether they may act. It does not know how a user proves who they
are (`lib.rs` crate documentation). The crate follows the specification in
`docs/architecture/contexts/identity.md`. The `application` and `domain`
modules are private; other crates use the `api` module.

## Interface

- `lib.rs: pub mod api` re-exports:
  - Ports: `UserRepository`, `GroupRepository`, `GroupPolicy`, `OrganizationRepository`, `WorkloadRepository`, `WorkloadAccess`.
  - Use cases: `CreateUser`, `IdentityService` (with `with_groups` and `with_organizations`, which take a user marked Deleted out of every group and organization), `GroupService`, `OrganizationService`, `WorkloadService` with `CreateWorkload` and `ChangeWorkload`, and the revocation reasons `WORKLOAD_DISABLED` and `WORKLOAD_DELETED`.
  - Service accounts and agents: `Workload`, `WorkloadStatus`, `WorkloadEvent`, `MAX_WORKLOAD_OWNERS` and the pure rules `checked_owners` and `workload_profile`.
  - Organizations: `Organization`, `OrganizationName`, `OrganizationSnapshot`, `OrganizationEvent`, `Unit`, `UnitId`, `UnitKind`, `UnitChange`, `Membership`, `Tree`, `MAX_UNIT_LEVELS` and the pure rule `check_placement`.
  - Groups: `Group`, `GroupEvent`, `GroupMember`, `GroupName`, `GroupSnapshot`, `MAX_NAME_CHARACTERS`, `MAX_DESCRIPTION_CHARACTERS`, and the pure rules `check_nesting`, `depth`, `effective_groups`.
  - Events: `UserEvent`.
  - Identifiers: `IdentifierId`, `IdentifierKind`, `LoginIdentifier`, `NormalizedIdentifier`.
  - Users: `Profile`, `User`, `UserKind`, `UserSnapshot`, `UserStatus`.
  - Standard claims: `StandardClaims`, `PostalAddress`, `ClaimField` and the bounds `LONGEST_NAME`, `LONGEST_PAGE_ADDRESS`, `LONGEST_GENDER`, `LONGEST_BIRTHDATE`, `LONGEST_ZONEINFO`, `LONGEST_PHONE_NUMBER`, `LONGEST_FORMATTED_ADDRESS`, `LONGEST_STREET_ADDRESS`, `LONGEST_ADDRESS_PART` and `LONGEST_POSTAL_CODE`.
- `lib.rs: pub mod testing` (`testing.rs`): public test support, compiled only under `#[cfg(any(test, feature = "testing"))]`. The `testing` feature turns on `hodor-kernel/testing` (`Cargo.toml`).
  - `InMemoryUsers`: an in-memory `UserRepository`.
  - `Ports<'a> { units_of_work, users }`: the ports under test.
  - `run_contract(ports)`: the contract suite every `UserRepository` must pass. The module documentation says the in-memory fake and the PostgreSQL adapter both run it.
  - `every_standard_claim()`: a `StandardClaims` with every claim given a value, the longest of a kind where it matters, so that a store that cuts or loses one is caught; other crates' tests use it too.
  - `InMemoryGroups`, `FixedGroupPolicy(depth)`, `GroupPorts<'a> { units_of_work, users, groups }` and `run_group_contract(ports)`: the same for groups.
  - `InMemoryOrganizations`, `OrganizationPorts<'a> { units_of_work, users, organizations }` and `run_organization_contract(ports)`: the same for organizations.
  - `InMemoryWorkloads::over(users)`, `WorkloadPorts<'a> { units_of_work, users, workloads }` and `run_workload_contract(ports)`: the same for the owners of service accounts and agents; the in-memory store lists from the `InMemoryUsers` it is given. `RecordingWorkloadAccess` remembers each `(tenant, workload, reason)` it was asked to end, for use case tests.
- Subdirectories:
  - [application](./application/EGM.md): `IdentityService`, `GroupService`, `OrganizationService` and `WorkloadService` use cases and their ports.
  - [domain](./domain/EGM.md): the `User` aggregate, login identifiers, a person's standard claims, groups, organizations, workloads and their events.

## Invariants

- The public surface is exactly what `api` re-exports, plus `testing` when the feature is on. `application` and `domain` are declared with plain `mod`.
- `InMemoryUsers` keys rows by `(TenantId, UserId)` and takes the tenant from `uow.tenant().tenant_id()`, so a user is invisible from another tenant. `insert` and `update` refuse an identifier another user of the same tenant has (`identity.identifier_taken`). `update` refuses a version mismatch (`identity.user_modified_concurrently`) or a missing user (`identity.user_not_found`), and stores the user with its version one higher. `list` returns users in identifier order, which the code comment says is creation order.
- `run_contract` checks that an implementation:
  - loads a stored user unchanged;
  - finds a user by any of its identifiers, however they are typed, and never matches the same text under another kind;
  - gives an identifier to one user per tenant, with a rejected insert leaving nothing behind;
  - allows the same identifier in two tenants;
  - hides users from other tenants;
  - stores changes to identifiers and status, and frees removed identifiers;
  - rejects a stale update;
  - rejects an update that takes another user's identifier, keeping nothing of it;
  - rejects an update from another tenant with `identity.user_not_found`;
  - frees the identifiers of an erased user while keeping its row;
  - lists users in creation order with `after` and `limit` paging.
  - stores every standard claim, stores a replacement that keeps fewer, and keeps none once the user is marked Deleted.
- Each case of the contract uses tenants of its own, so runs can share one database (`run_contract` doc comment).

## Side Effects

- `InMemoryUsers` keeps its rows in an `Arc<Mutex<BTreeMap<…>>>` shared by its clones. A poisoned lock is recovered (`unwrap_or_else(|e| e.into_inner())`). Writes go straight to the map; they do not wait for the unit of work to commit.
- `run_contract` writes to whatever implementation it is given, through units of work it begins and commits itself, and panics when the contract is broken.
- The rest of the crate's side effects are described in [application](./application/EGM.md) and [domain](./domain/EGM.md).

## Verification

- Run: `cargo test -p hodor-identity`
