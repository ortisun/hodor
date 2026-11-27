# Decision 0080: The registration endpoint keeps what a client is made of, refuses what Hodor would need and does not have, and counts registrations from the clients it stored

Status: Accepted

## Context

[Decision 0049](0049-dynamic-client-registration.md) lets a tenant turn dynamic client registration on, and [Decision 0075](0075-the-registration-settings-of-a-tenant.md) settles the settings Issue-132 built: one policy per tenant, one list of hosts, initial access tokens spent under a lock. [Issue-133](../product/epics.md#milestone-15-clients-that-register-themselves) builds the endpoint itself, `POST {issuer}/oauth2/register`, which reads a client's metadata as [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) and [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html) write it, and makes a client of it.

Five questions were open. The specifications name more members than Hodor's clients hold: which are kept, which refused, which ignored? Their defaults are not always Hodor's: whose apply? Decision 0049 says the addresses Hodor calls are checked by the guarded outbound client, and an open registration lets anyone send them: when may Hodor call them? Decision 0049 bounds registrations to 10 a minute per tenant and address: where is that counted? And the consent page shows nothing a client chose ([what the page shows](../architecture/contexts/oauth.md#what-the-page-shows)), while the epic asks for a registered client's logo and links on it.

Reading, changing and removing a registration with a registration access token is Issue-134, software statements are Issue-135, and keys at a client's `jwks_uri` are Issue-136; this decision leaves room for each.

## Decision

### A member is kept, checked, refused or ignored

Every member is in one of four groups, written in [the registration endpoint](../architecture/contexts/oauth.md#the-registration-endpoint):

- **Kept**: what a client of Hodor holds, and what an administrator's client holds too, such as `redirect_uris`, `token_endpoint_auth_method`, `jwks` or `jwks_uri`, `subject_type`, `backchannel_logout_uri`, `request_uris` and `require_pushed_authorization_requests`; and, new to every client, `application_type` and the members a person is shown, `client_uri`, `logo_uri`, `policy_uri` and `tos_uri`. The answer gives them back as they were kept.
- **Checked, not kept**: `token_endpoint_auth_signing_alg`, which must be one Hodor accepts; a client does not hold it, so the answer leaves it out. `response_types` is kept, by the rules of [Decision 0072](0072-the-state-hash-and-the-response-types-of-a-client.md), and `implicit` among the grants is read as `authorization_code`, as that decision keeps no implicit grant.
- **Refused**, with `invalid_client_metadata`, when Hodor would need it and does not have it: the members of encryption, until [Decision 0048](0048-encryption.md); and `software_statement`, with `unapproved_software_statement`, until Issue-135. A client that relies on one of them would otherwise be made without what it relies on: answers it expects encrypted would arrive in the clear, or a statement it relies on would be read as nothing. `jwks` and `jwks_uri` together are refused, as RFC 7591 says.
- **Ignored**, and left out of the answer, as OpenID Connect Registration lets a provider do: `contacts`, `software_id`, `software_version`, `initiate_login_uri` until Issue-134, the front-channel logout members until [Decision 0050](0050-logout-and-session-state-in-the-browser.md), members with a language tag, and any member Hodor does not know. The client asked for nothing it depends on, and learns from the answer what was not kept.

### The specifications' defaults apply to what a registration leaves out

A registration that leaves a member out gets the default of the specification that defines it, where an administrator's client gets Hodor's: `token_endpoint_auth_method` is `client_secret_basic`, `grant_types` `authorization_code`, `response_types` `code`, `application_type` `web` and `id_token_signed_response_alg` `RS256`, where Hodor's own default is `ES256`. A client written to the specifications gets what it expects. Where the specifications give no default, Hodor chooses: a registration without `scope` may ask for every scope the policy allows, and one without `client_name` is named `Registered client`.

A registered client always uses PKCE, as an administrator's client does unless the administrator says otherwise: no member of the specifications says it, and RFC 9700 recommends it. The Dynamic plan of the conformance suite sends no code challenge in most of its tests; how the conformance tenant registers clients without PKCE is Issue-137's to decide.

### One set of checks, the administrator's, and the policy after it

The members are turned into the settings of a client, and those go through the checks every client goes through ([what a client may be](../architecture/contexts/oauth.md#what-a-client-may-be)): the redirect addresses, the method and the type, the keys one by one as an administrator adds them, the defaults for a sign-in, the sector. Then the policy's `check_registration`, then the two bounds. A registration is refused for exactly what would refuse an administrator's client, and for what the policy does not allow.

### Hodor calls nothing for a caller it has not admitted

The addresses Hodor will call, `backchannel_logout_uri`, `request_uris`, `jwks_uri` and `sector_identifier_uri`, are checked by the guarded outbound client, and the sector identifier document fetched, as for an administrator's client. Before that, the request is admitted once without being spent, in a unit of work that is never committed: registration is on, the initial access token is good, or registration is open; and the address has registered fewer than 10 clients in the last minute. Only then is anything called, and only then is the request admitted again, for good, in the unit of work that stores the client. A caller without a token reaches no outbound call in a tenant that is not open, and an open tenant's callers reach it at most 10 times a minute each.

### Registrations are counted from the clients stored

A client that registered itself is marked so for good, and keeps the SHA-256 of the address it was registered from, as the attempt counters of the authentication context keep addresses. The unit of work that stores a registration locks the tenant's settings first, then counts the clients of the application of registered clients and the clients registered from the address in the last 60 seconds: two registrations at the same moment cannot both pass a bound, and the count is the same on every instance of the server behind a load balancer.

### A registered client is never first party, and says who it is in its own words

The mark is what makes a registered client third party: consent is asked for it even if its application is made first party afterwards. The consent page shows, for a registered client, its own `client_name` in place of the application's, its `logo_uri`, and links to its `policy_uri` and `tos_uri`, with a sentence saying that the application named itself and that the tenant has not checked it. The page's content security policy lets images come from any HTTPS address, and the logo is loaded without a referrer.

## Consequences

- A client written to OpenID Connect Registration registers without knowing Hodor, and gets the members its specification defaults. A conformance tenant gets clients that sign ID tokens with `RS256` unless they ask otherwise.
- Every client gains `application_type` and four addresses a person is shown, through one set of rules. An administrator reads them through the administration interface, and does not set them yet.
- A client that relies on encryption or on a software statement is refused until each is built, and is told which member. A client of `private_key_jwt` registers its keys by value or at its `jwks_uri`, as [Decision 0079](0079-keys-at-a-client-s-address-kept-in-memory.md) keeps them.
- The bound per address is kept with the client, so a client that is later removed, by Issue-134, no longer counts; within a minute, that lets one address register more than 10 clients only by removing as many, each with its own registration access token.
- The hosted pages may load an image from any HTTPS address. Only the consent page shows one, the logo of a registered client; the image's host learns that someone is on the page, which the client that sent them there knows already.
- Each registration holds a lock of the tenant's settings while its client is stored: registrations of one tenant are made one at a time, which their bound of 10 a minute per address makes no burden.

## Alternatives considered

- **Ignoring encryption until it is built.** What OpenID Connect Registration allows for a member a provider does not support. Set aside: the client would be made, and would get answers in the clear it believes encrypted; a refusal that names the member is what it can act on.
- **Hodor's own defaults for every member**, `ES256` among them. One rule for every client. Set aside: a client of the specifications that leaves `id_token_signed_response_alg` out expects `RS256` and refuses anything else.
- **Checking the addresses before admitting the request**, the order an administrator's client is checked in. Set aside: anyone could make Hodor resolve and fetch addresses of their choosing, in any tenant with registration on, without a token.
- **Counting registrations in memory**, as a window per address in each server. No table, no column. Set aside: each instance behind a load balancer would count on its own, and a restart would forget.
- **A table of registration attempts**, counting refused attempts too. Set aside for now: it needs a cleanup of its own, and a refused registration costs Hodor no more than any other refused request; the limits per address of every endpoint, planned before any deployment behind a load balancer, will cover them.
- **Showing a registered client under its application's name**, as every client is today. Set aside: every registered client of a tenant would be shown under one name, the one of the application an administrator made for all of them, and a person could not tell which application asks.
