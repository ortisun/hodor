# Decision 0065: The identity context keeps a person's standard claims, and each source writes only what it can vouch for

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile)

## Context

[Decision 0047](0047-claims-and-the-person-s-claims.md) says a person keeps the standard claims of [OpenID Connect Core, section 5.1](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims), each optional and bounded, and that they are edited on the account page, through the administration interface, by an identity provider and by SCIM. [Issue-123](../product/epics.md#slice-claims-and-the-parameters-of-a-request-epics-2-and-10) builds that. Before code could follow, six questions needed answers that Decision 0047 left open:

- Which claims exactly, and in what form each is kept.
- Where SCIM's `name.givenName` and `name.familyName` live: the provisioning context keeps them today ([what each attribute is](../architecture/contexts/provisioning.md#what-each-attribute-is)). They would then be kept twice.
- Who may say that a telephone number is verified, when Hodor sends no code to a telephone yet ([Phase 4](../product/roadmap.md)).
- When an identity provider's word is taken: at the first sign-in only, or at every sign-in.
- How a SAML identity provider or a directory, which have no standard names for these claims, says them.
- What happens to a claim that breaks its rule. A person typing it can be told. A provider or a directory cannot.

The suite also wants every claim of the scope `profile` at UserInfo. That includes `profile` itself, the address of the person's page somewhere else, which Decision 0047's list leaves out ([the conformance page](../operations/conformance.md#expected-results)).

## Decision

### The claims, and how each is kept

The identity context keeps, beside the display name and the locale, the thirteen claims below. They are one value of the person, the **standard claims**: replaced as a whole, kept in the person's row, erased with the person.

| Claim | Kept as | Rule |
|---|---|---|
| `given_name`, `family_name`, `middle_name`, `nickname` | Text | 1 to 200 characters, no control characters |
| `profile`, `picture`, `website` | An address | An absolute `https` or `http` address with a host, at most 1024 printable ASCII characters. Never fetched by Hodor |
| `gender` | Text | 1 to 50 characters. `female` and `male` are the values OpenID Connect names; any other is kept as given |
| `birthdate` | Text | `YYYY-MM-DD`, `0000-MM-DD` when the year is not told, or `YYYY` alone. A real day of the calendar, not after today |
| `zoneinfo` | Text | A name of the time zone database, such as `Europe/Paris` or `America/Argentina/Buenos_Aires`: parts of letters, digits, `_`, `-` and `+` separated by `/`, each starting with a letter, at most 64 characters. Not checked against the database itself, which changes with every release |
| `phone_number` | Text | E.164: `+` and 4 to 15 digits, with an extension `;ext=` of 1 to 10 digits. Spaces, hyphens, dots and parentheses are taken out before it is checked |
| `phone_number_verified` | A boolean | False when there is no telephone number |
| `address` | Six parts | `formatted` at most 300 characters and `street_address` at most 200, both of which may hold line breaks; `locality`, `region` and `country` at most 100; `postal_code` at most 20. No other control character. The address is there when one part is |

Every text is trimmed; an empty one is no value. The bounds make the largest address, as JSON writes it, fit in the bound of a token that [claim mappers](0041-claim-mappers.md) have, so that a mapper can carry it.

### One place for each value

**SCIM's given and family names move to the identity context.** `name.givenName` and `name.familyName` become the person's `given_name` and `family_name`. `name.middleName`, `nickName`, `profileUrl`, `timezone`, the primary telephone number and the primary postal address of the core schema are mapped too. Migration 0098 moves the stored names, and the provisioning context stops keeping them. `name.formatted` stays where it is: OpenID Connect has no claim for it, and it already gives the display name when SCIM sends none.

### A telephone number is verified only on someone's word

Hodor proves nothing about a telephone number yet. `phone_number_verified` is therefore what a source that can vouch for it says:

| Source | `phone_number_verified` |
|---|---|
| The person on the account page | False whenever the person types a new number. Kept as it was when the number stays the same |
| An administrator, through the administration interface or the command-line tool | What the administrator says, false unless said |
| SCIM | True, for the reason every email address SCIM sets is: the tenant's own system of record asserts it |
| An OpenID Connect provider | True only when the token says exactly `true`, as for `email_verified` |
| GitHub, a SAML identity provider, a directory | False: none of them says |

A telephone number is never a login identifier and is never used to reach the person ([Decision 0047](0047-claims-and-the-person-s-claims.md#a-person-keeps-the-standard-claims)). The verification of Phase 4 makes its own identifiers.

### An identity provider fills the claims of a person it creates

A provider gives its claims when it creates the person at the first sign-in, in the same unit of work, as it gives the name and the language today. A later sign-in changes nothing the person or an administrator may have corrected since. Keeping them in step on every sign-in is left for when a tenant asks ([not built yet](../architecture/contexts/federation.md#not-built-yet)).

- **An OpenID Connect provider** gives the claims by their own names, read from its ID token.
- **GitHub** gives `avatar_url` as `picture` and `blog` as `website`.
- **A SAML identity provider and a directory** give the claims an administrator names an attribute for. This is a provider's **claim attributes**, a map from a claim to an attribute name, such as `given_name` to `givenName` and `address.locality` to `l`. Nothing is mapped unless named. An attribute's first value is the claim's.

### What breaks a rule

- **From a person, an administrator, the command-line tool or SCIM**, a claim that breaks its rule refuses the whole change with `identity.claim_invalid`. The detail names the claim and never the value.
- **From an identity provider**, the claim is left out and the rest are kept. A person must not be kept out of a tenant because their directory holds a telephone number in a form Hodor does not take.

### Personal data

- Every change is one `identity.profile_changed` event, which carries the person's identifier only. No event, log line or problem document carries a claim's value.
- The claims are erased when the person is marked Deleted.
- The export of a person's data (Requirement-Identity-10) holds them when it is built, since they are part of the person.

## Consequences

- UserInfo answers every claim of `profile`, `address` and `phone` for a person who has them, and the suite's four tests of scopes pass without a warning or a skip, with a person given every claim.
- The ID token of a code still carries none of them, as [the ID token](../architecture/contexts/oauth.md#the-id-token) says. A claim mapper may now read each of them, and so put one in the ID token under a name of the tenant's choosing; the `claims` parameter puts them there under their own names ([Issue-124](../product/epics.md#slice-claims-and-the-parameters-of-a-request-epics-2-and-10)).
- Claim mappers may no longer use the claims' names, since UserInfo now writes them ([Decision 0041](0041-claim-mappers.md)). A mapper saved earlier under one of them is kept, but writes nothing from then on: a reserved name is never written by a mapper, whatever is stored. Its administrator renames it.
- A SCIM filter on `name.givenName` and `name.familyName` reads the identity context's columns. The provisioning context already reads that context's tables to filter.
- A tenant whose directory or identity provider is the system of record for these claims sees them only for people created after the provider was set up, until keeping them in step is built.

## Alternatives considered

- **Keeping the claims as custom attributes of the person.** Set aside by Decision 0047: they have fixed names and formats every relying party reads.
- **Keeping SCIM's names in both contexts.** Simpler to build. Set aside: two copies of a given name disagree as soon as a person edits theirs on the account page.
- **Refreshing the claims at every sign-in through a provider.** What Keycloak calls forcing the mapping. Set aside for now: a correction made in Hodor would be undone at the next sign-in, and a tenant can choose that only once a setting exists for it.
- **Treating `phone_number_verified` as the person's own word.** Set aside: a number nobody proved would reach every application as verified.
- **Checking `zoneinfo` against the time zone database.** Exact. Set aside: the database changes with every release, and a name valid on one server would be refused by another.
- **Fetching a `picture` to check it.** Set aside: an address a person types would make Hodor call out to it, and a relying party fetches the picture itself.
