# Decision 0047: The `claims` parameter asks only for claims the scopes and consent already allow, and a person keeps the standard claims of OpenID Connect

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile)

Which scopes count for the `claims` parameter is refined by [Decision 0068](0068-claims-of-every-consented-scope.md): every scope consented to for the client, not only those of the request.

## Context

Hodor does not read the `claims` parameter today, and discovery says `claims_parameter_supported` is false ([discovery](../architecture/contexts/oauth.md#discovery)). The suite's test `oidcc-claims-essential` ends in a warning because of it ([expected results](../operations/conformance.md#expected-results)). The person's claims are never put in the ID token: a client reads them at UserInfo with the access token Hodor always issues with it ([the ID token](../architecture/contexts/oauth.md#the-id-token)).

Two changes of this plan break that rule's ground:

- The response type `id_token` issues no access token at all ([Decision 0046](0046-responses-through-the-browser.md)). OpenID Connect Core, section 5.4, then puts the claims of the scopes in the ID token, since there is no UserInfo to read them from.
- The `claims` parameter ([section 5.5](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)) lets a client ask for one claim in the ID token, in UserInfo or both, as essential or voluntary, and with a value or values it expects. `acr` asked through it with `essential` and `values` is a requirement, as `acr_values` is.

A person also keeps only a display name, a username, a locale and email addresses ([the identity context](../architecture/contexts/identity.md)). The suite warns on `profile`, and skips `address`, `phone` and the test of every scope at once. Requirement-Identity-04 already asks for a profile with the standard claims of OpenID Connect.

## Decision

### What the `claims` parameter may ask for

- **Only claims the request may already have.** A claim asked for through `claims` is given only when a scope of the request, consented to, already covers it (section 5.4), or when it is a claim Hodor always gives (`sub`, `auth_time`, `acr`, `amr`, `sid`). The parameter chooses *where* a claim goes and *which* of the allowed ones are wanted; it never widens what the person consented to. A claim outside the scopes is left out, as a voluntary claim Hodor does not give.
- **Consent covers the claims, not only the scopes.** When a request asks through `claims` for a claim of a scope it did not ask for, the claim is left out rather than the person asked; the consent page stays a page of scopes.
- **Essential claims are not enforced as a refusal.** OpenID Connect says a provider that cannot give an essential claim does not fail the request. Hodor gives what it has and leaves out what it has not, and the client decides.
- **`acr` is the exception.** `"acr": {"essential": true, "values": [...]}` is read as `acr_values` is: the weakest of the tenant's levels named must be reached, by step-up if needed, or the answer is `unmet_authentication_requirements` ([assurance and step-up](../architecture/contexts/oauth.md#assurance-and-step-up)). Without `essential`, it is a preference and is met only if the session already reaches it. `acr_values` and `claims` naming `acr` together is `invalid_request`.
- **`value` and `values` of other claims are not checked.** A client that asks for `sub` with a value is answered `login_required` with `prompt=none` when the session is another person's, and otherwise the person signs in again, so the token never names someone else.
- **Bounds.** The parameter is at most 4 kibibytes of JSON, naming at most 64 claims; a name Hodor does not know is ignored. `claims_locales` picks the language of a claim that has several, among the languages the tenant has.

### Where the person's claims go

| Response | ID token | UserInfo |
|---|---|---|
| A code, or a response that also issues an access token | `sub` and the claims Hodor always gives; the person's claims only when asked through `claims` for the ID token, or mapped by a [claim mapper](0041-claim-mappers.md) | The claims of the scopes, and of `claims` for UserInfo |
| `id_token` alone | The claims of the scopes, and those of `claims` for the ID token | Nothing: no access token was issued |

The ID token's bound on size, 4096 bytes of mapped claims ([Decision 0041](0041-claim-mappers.md)), applies to claims asked through `claims` too: a claim that would cross it is left out, never cut.

### A person keeps the standard claims

- The identity context keeps, beside the display name and the locale, the claims of [section 5.1](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims): `given_name`, `family_name`, `middle_name`, `nickname`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `phone_number` with `phone_number_verified`, and `address` as its parts. Each is optional, each has a bound, and each change is an `identity.profile_changed` event that never carries a value.
- The scopes `address` and `phone` are offered, and `profile` gives every claim the person has.
- The person edits them on the account page, an administrator through the administration interface, an identity provider through its claim mapping, and SCIM through the attributes it already maps.
- A telephone number given as a claim is not a login identifier: the identifiers of [Phase 4](../product/roadmap.md) keep their own verification.

## Consequences

- `claims_parameter_supported` becomes true, `oidcc-claims-essential` passes, and the tests of the scopes `address`, `phone` and `profile` and of every scope at once pass with a person who has those claims.
- The ID token carries personal data only when a client asks for it through `claims`, maps it, or has no access token to read UserInfo with. The rule that keeps personal data out of a token a browser may hold becomes a default rather than an absolute.
- Hodor holds more personal data about a person when a tenant fills these claims. Each is optional, deleted with the person, and covered by the export of personal data (Requirement-Identity-10).

## Alternatives considered

- **Giving any claim asked for through `claims`, consented to or not.** What some providers do. Set aside: it would let a client read a claim the person never agreed to give it.
- **Refusing a request whose essential claim Hodor cannot give.** Stricter. Set aside: OpenID Connect says not to, and clients are written for that.
- **Keeping the standard claims in custom attributes only.** One mechanism. Set aside: custom attributes are not built, and the standard claims have fixed names and formats that every relying party reads; they belong in the person's profile.
