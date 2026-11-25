# Tenant domain

## Overview

The tenant aggregate and its lifecycle, the slug a tenant is addressed by,
the policies that apply inside a tenant, and the events other contexts hear
about. The domain is pure; time is passed in. All modules are `pub(crate)` in
`mod.rs`; the types below are re-exported through `crate::api`.

## Interface

### `tenant.rs`

- `TenantStatus { Provisioning, Active, Suspended, PendingDeletion, Deleted }`
  with `serves_requests()`, `as_str()` and `from_stored(&str)`.
- `TenantSnapshot`: `id`, `slug`, `display_name`, `status`, `status_reason`,
  `settings`, `deletion_scheduled_for`, `created_at`, `updated_at`,
  `version: u32` (for optimistic locking).
- `Tenant`: `create(slug, display_name, now) -> Result<(Tenant, TenantEvent), DomainError>`,
  `from_snapshot`, `snapshot`, `id`, `status`, and the transitions `activate`,
  `suspend(reason, now)`, `reactivate`, `schedule_deletion(grace: Option<Duration>, now)`,
  `cancel_deletion`, `mark_deleted`, `change_settings(settings, now)`, each
  returning `Result<TenantEvent, DomainError>`.
  Constants: `MAX_DISPLAY_NAME_LENGTH = 100`,
  `DEFAULT_DELETION_GRACE = 30 days`, `MIN_DELETION_GRACE = 1 day`.

### `slug.rs`

- `Slug`: `parse(&str)`, `system()`, `from_stored(&str)`, `is_system()`,
  `as_str()`, `Display`; `MIN_LENGTH = 2`, `MAX_LENGTH = 63`.

### `settings.rs`

- `TenantSettings { password, session, lockout, registration, authentication, groups, provisioning }` with
  `validate()`; `Default`, `Serialize`, `Deserialize`. `authentication`,
  `groups` and `provisioning` are `#[serde(default)]`, so settings stored
  before they existed still read.
- `ProvisioningPolicy { deprovisioning: Deprovisioning }`, where
  `Deprovisioning` is `Deactivate` (the default) or `Delete`, stored as
  `deactivate` and `delete`: what SCIM deprovisioning does.
- `PasswordPolicy { min_length, max_length, history_depth, reject_breached }`.
- `SessionPolicy { idle_timeout_seconds, absolute_timeout_seconds }` with
  `idle_timeout()` and `absolute_timeout()` as `time::Duration`.
- `LockoutPolicy { max_failures, window_seconds, first_lockout_seconds, longest_lockout_seconds }`.
- `RegistrationPolicy { Closed (default), Open }`, serialized in snake case.
- `AuthenticationPolicy { second_factor, assurance_levels, email_sign_in }`. `email_sign_in` is `EmailSignInPolicy { code: bool, link: bool }`, both `false` by default and when absent from stored settings (`#[serde(default)]`). `assurance_levels`
  is `AssuranceLevels` (`settings.rs:AssuranceLevels`), one to three
  `AssuranceLevel { acr, requirement }` with `AssuranceRequirement`
  `SingleFactor < MultiFactor < PhishingResistant` (snake case); `new` sorts
  weakest first and validates, `levels()` lists weakest first, `asked(acr_values)`
  is the weakest level a request names, `reached(requirement)` the name of the
  strongest level at or below it. The default is `ACR_SINGLE_FACTOR` and
  `ACR_MULTI_FACTOR`; settings stored without the field read it.
- The second factor policy is
  `SecondFactorPolicy { NotRequired (default), Required }`, serialized in snake
  case. Read by the authentication context when a sign-in advances and completes.

### `event.rs`

`TenantEvent` (`Serialize`, untagged) implements `hodor_kernel::DomainEvent`:

| Variant | Fields | `event_type()` |
| --- | --- | --- |
| `Created` | `tenant_id`, `slug`, `display_name` | `tenant.created` |
| `Activated` | `tenant_id` | `tenant.activated` |
| `Suspended` | `tenant_id`, `reason` | `tenant.suspended` |
| `Reactivated` | `tenant_id` | `tenant.reactivated` |
| `DeletionScheduled` | `tenant_id`, `deletion_date` (RFC 3339) | `tenant.deletion_scheduled` |
| `DeletionCancelled` | `tenant_id` | `tenant.deletion_cancelled` |
| `Deleted` | `tenant_id` | `tenant.deleted` |
| `SettingsChanged` | `tenant_id`, `settings: TenantSettings` | `tenant.settings_changed` |

## Invariants

- Lifecycle (`tenant.rs:Tenant`): `create` starts in `Provisioning` with
  default settings and version 0; `activate` requires `Provisioning`;
  `suspend` requires `Active`; `reactivate` requires `Suspended` and clears
  the reason; `schedule_deletion` requires `Active` or `Suspended`;
  `cancel_deletion` requires `PendingDeletion` and leads to `Suspended` (never
  `Active`) with reason `"deletion cancelled"`; `mark_deleted` requires
  `PendingDeletion` and a passed deletion date
  (`tenant.deletion_date_not_reached` otherwise); `change_settings` is refused
  only for `Deleted`. A wrong status gives `Conflict`
  `tenant.invalid_transition`.
- Only `Active` serves requests (`TenantStatus::serves_requests`).
- The display name is trimmed and must have 1 to 100 characters
  (`tenant.display_name_invalid`); a suspension reason is trimmed and must not
  be empty (`tenant.suspension_reason_missing`); a grace period under one day
  gives `tenant.deletion_grace_too_short`.
- A slug has 2 to 63 bytes of lowercase letters, digits and hyphens, starts
  and ends with a letter or digit, and has no `--` (`tenant.slug_invalid`).
  `Slug::parse` also rejects the reserved slugs `system`, `platform`,
  `admin`, `api`, `static`, `health` (`tenant.slug_reserved`);
  `Slug::from_stored` accepts them (`slug.rs`).
- Settings are validated as a whole and the first broken rule gives `Invalid`
  `tenant.settings_invalid` (`settings.rs:TenantSettings::validate`):

| Policy | Default | Allowed |
| --- | --- | --- |
| Password minimum length | 12 | 8 to 128 |
| Password maximum length | 128 | minimum to 1024 |
| Password history depth | 5 | at most 24 |
| Reject breached passwords | `true` | any |
| Session idle timeout | 30 minutes | 1 minute to the absolute timeout |
| Session absolute timeout | 12 hours | at most 30 days |
| Lockout failures | 5 | 3 to 20 |
| Lockout window | 15 minutes | 1 minute to 24 hours |
| First lockout | 1 minute | 10 seconds to the longest lockout |
| Longest lockout | 1 hour | at most 24 hours |
| Registration | `Closed` | `Closed` or `Open` |

- `TenantStatus::from_stored` returns an internal `tenant.status_unknown`
  error for an unknown name.

## Side Effects

- None. `Tenant::create` calls `TenantId::generate` for the identifier.

## Verification

- Run: `cargo test -p hodor-tenant`
