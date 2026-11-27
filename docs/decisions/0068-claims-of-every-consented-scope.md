# Decision 0068: The `claims` parameter gives a claim of any scope consented to for the client, not only of the scopes of the request

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile)

## Context

[Decision 0047](0047-claims-and-the-person-s-claims.md) says a claim asked for through the `claims` parameter is given only "when a scope of the request, consented to, already covers it". [Issue-124](../product/epics.md#slice-claims-and-the-parameters-of-a-request-epics-2-and-10), which builds the parameter, asks for two things that this wording cannot give together:

- **A claim of a scope the person did not consent to is never given.**
- **The suite's test `oidcc-claims-essential` passes.** The test asks for `name` at UserInfo through `claims`, with the scope `openid` alone, and ends in a warning when UserInfo leaves `name` out ([the conformance page](../operations/conformance.md#expected-results)). Under Decision 0047's wording, `name` is never given with the scope `openid` alone, so the test can only warn.

The issue words the rule as "a claim given only when a consented scope covers it". What Decision 0047 protects is consent: a client must not read a claim the person never agreed to give it. A scope of the request is one way to have agreed. It is not the only one:

- A client of a **first-party application** is never asked about: its administrator decided for the person, once, when the application was registered and given the scopes it may ask for ([consent](../architecture/contexts/oauth.md#consent)).
- A person who agreed to `profile` for a **third-party client** last week, and whose consent stands, has agreed to give that client their name. A later request with `openid` alone does not withdraw it.

Decision 0047 also left a few details open: where `acr` is read, what `acr_values` together with `claims` refuses, what happens when the person who signs in is still not the `sub` asked for, and where the claims of a grant are kept for UserInfo.

## Decision

### The scopes that count

A claim asked for through `claims` is given when its scope is **consented to for the client** when the code is issued:

| Client | Consented scopes |
|---|---|
| Of a first-party application | The scopes the client may ask for |
| Of a third-party application | The scopes of the request, which the person agreed to before the code, and those of the person's consent for the client that stands |

Every other rule of Decision 0047 stays: a claim of any other scope is left out rather than the person asked, the consent page stays a page of scopes, and nothing in `claims` widens what was agreed.

### The details

- **`acr`** is read under `id_token`, where OpenID Connect puts it. With `essential` and a value or values, it becomes the request's `acr_values`. `acr_values` and an `acr` with a value or values in one request is `invalid_request`; an `acr` asked without a value beside `acr_values` asks for nothing more and is not refused.
- **`sub`** with a value: a session of another person is treated as no session, so the person signs in, or with `prompt=none` the answer is `login_required`. When the person who then signs in is still another, the answer is `access_denied`, as it is for a request that asked for a new sign-in that did not happen.
- **What a grant gives.** The claims are resolved against the consented scopes when the code is issued, and kept with the grant: one list for the ID token and one for UserInfo (migration 0104). UserInfo then gives, for every access token of the grant, the claims of the token's scopes and those of the list. The values are read when each token is issued or UserInfo answers.
- **The bound of the ID token.** The mappers' claims count first; then the claims asked, in a fixed order, the order of the table of [the `claims` parameter](../architecture/contexts/oauth.md#the-claims-parameter). One that would cross 4096 bytes is left out, and those after it that still fit are added.

## Consequences

- `oidcc-claims-essential` passes: the suite's client is of a first-party application that may ask for `profile`, so `name` is given at UserInfo. With a third-party client and no consent to `profile`, it would end in the warning the suite allows.
- A first-party client reads, through `claims`, any claim of a scope it may ask for, without naming the scope. Its administrator already chose to give it those claims without asking the person.
- A grant keeps its claims for UserInfo after a refresh that narrows the scopes, as it keeps its audiences: they were agreed to when it was made.
- Withdrawing a consent revokes the grants made under it ([withdrawing a consent](../architecture/contexts/oauth.md#withdrawing-a-consent)), and with them what they give through `claims`.

## Alternatives considered

- **Only the scopes of the request, as Decision 0047 worded it.** The strictest. Set aside: `oidcc-claims-essential` could not pass, and a person who agreed to `profile` would be read as not having agreed.
- **Asking the person for the scope of a claim asked through `claims`.** Set aside by Decision 0047: the consent page stays a page of scopes, and a client could make the page ask for anything by naming claims.
- **Resolving the claims at UserInfo from the consent of that moment.** Would follow a consent that grew later. Set aside: what a grant gives is fixed when it is made, as its scopes are, and a consent that shrinks is withdrawn with its grants anyway.
