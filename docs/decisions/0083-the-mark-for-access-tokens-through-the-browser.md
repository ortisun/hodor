# Decision 0083: The mark for access tokens through the browser is a setting of the client, recorded with who set it, and the first finding of the security posture

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile)

## Context

[Decision 0046](0046-responses-through-the-browser.md) lets a client register `token`, `id_token token`, `code token` and `code id_token token` only when an administrator marks it so. The mark is "recorded with who set it and is a finding of the security posture for as long as it stands"; the access token issued through the browser "lives at most five minutes whatever the client's policy says, carries only the scopes of OpenID Connect and those the client marked", and never goes to a client held to a security profile. [Issue-128](../product/epics.md#slice-response-types-and-modes-epic-10) builds it, and leaves open:

- **Where the mark lives, and how it is set.** A client's settings are changed with `PATCH /clients/{client_id}` and made with `hodor-cli client add`, which the certification deployment and the conformance script use; the mark could be one more setting, or an operation of its own.
- **What "carries only the scopes the mark allows" does to a request that asks for more.** The scopes of a request decide the audiences of its tokens ([checking the request](../architecture/contexts/oauth.md#checking-the-request)): a token whose scopes were cut after the fact would still name the audience of a resource server whose scope it lost.
- **Where the finding is shown.** The [security posture](../design/control-plane.md#security-posture) is a resource of the server in the design, `/posture/findings`, with a score, acceptances and a dozen checks, none of which is built: there is nothing yet to show a finding on.
- **Security profiles** come with Issue-145, in 0.6.0. No client is held to one yet.

## Decision

### The mark is a setting of the client

**`browser_access_tokens` is a setting of the client**: `null`, or the scopes the access token through the browser may carry beyond those of OpenID Connect, with who set the mark and when. It is given on `POST /applications/{application_id}/clients` and `PATCH /clients/{client_id}` as `{ "scopes": […] }`, removed with `null`, and set by `hodor-cli client add --browser-access-tokens`, with `--browser-access-token-scope` once per scope. The server records who set it, the administrator who called the interface or Hodor itself for the command-line tool, and when; a change that keeps the same scopes keeps that record, and one that changes them records the new administrator. Setting it, changing its scopes and removing it are recorded as events of their own, `oauth.client_browser_access_tokens_marked` and `oauth.client_browser_access_tokens_unmarked`, beside `oauth.client_changed`, so that an alert can watch for them alone.

A setting, not an operation of its own: the mark and the response types it allows are given together, in the change that registers them, and the administration interface checks them together, as it checks every rule of a client at once ([what a client may be](../architecture/contexts/oauth.md#what-a-client-may-be)). The rules:

- **Only a marked client registers a type that returns an access token**; any other is refused with `oauth.client_response_types_invalid`.
- **Only a client with `authorization_code` is marked**, since only it has response types; and **never a client whose access tokens are bound to its certificate**, since the authorization endpoint sees the person's browser, not the client's certificate, and could not bind the token. Both are refused with `oauth.client_browser_access_tokens_invalid`, as are more than 50 scopes, a scope not written as one, and `offline_access`, which asks for a refresh token, never issued through the browser.
- **A change that removes the mark drops the types that return an access token**, leaving `code` if nothing else remains, unless the change names the response types; a change that takes `authorization_code` away drops the mark with the response types, unless it names it.

### A request asks only for what the mark allows

**A request for a type that returns an access token may ask only for the scopes of OpenID Connect, `openid`, `profile`, `email`, `address` and `phone`, `offline_access`, and the scopes of the mark**; any other is refused with `invalid_scope` at the redirect address, before the person signs in. The access token through the browser carries the request's scopes but `offline_access`, so it never names a scope, or the audience of a resource server, that the mark does not allow. `offline_access` stays allowed for `code token` and `code id_token token`, whose code is redeemed at the token endpoint as any code is, with a refresh token for a client that has the grant: no refresh token comes through the browser.

A request for one of these types from a client that is not marked is refused with `unauthorized_client`, as is one for a type the client did not register. A request kept while the person signs in or is asked for consent is checked against the client again when the token is made: if the client lost its mark or the type since, it is answered `unauthorized_client`, and if the mark no longer allows one of its scopes, `invalid_scope`, and nothing is issued.

### The access token through the browser

It is the access token of the token endpoint ([the access token](../architecture/contexts/oauth.md#the-access-token)), for the person and the grant made by the answer, with these differences: it lives the client's access token lifetime but **five minutes at most**; its scopes are those above; it is never bound to a certificate. It is recorded in the register of access tokens with its grant, so that revoking the grant, as a code used twice or a withdrawn consent does, ends it, and with `oauth.browser_access_token_issued`, which never carries the token. The answer holds `access_token`, `token_type` `Bearer`, `expires_in` and `scope`, always written, since it may differ from what was asked. An ID token that comes with it carries `at_hash`.

### The first finding of the security posture

**`GET /posture/findings` answers the findings of the tenant, computed when it is read**, with the permission `audit:read`, which the tenant auditor and the tenant administrator hold. Its first and, for now, only check is `client_marked_for_browser_access_tokens`, of severity `medium`, as the [design](../design/control-plane.md#security-posture) rates "a client uses a weakened setting": one finding for each marked client, naming the client, its application, the scopes of the mark, who set it and since when. A finding is not stored: it is there while the mark stands, and gone in the next answer once it is removed. The score, acceptances with a reason and an expiry, `/posture`, `POST /posture:evaluate` and the other checks come with the console's posture screen (Requirement-Console-07), which adds them to the same resource.

### Security profiles and registration

**A client held to a security profile is never marked.** No client is held to one until Issue-145, which refuses a profile to a marked client and the mark to a client held to a profile, with its other rules of a profile ([Decision 0052](0052-security-profiles.md)).

**A client that registers itself is never marked, and never has a type that returns an access token.** The mark is an administrator's choice about one client, made knowing what that client is; a registration is made by whoever holds an initial access token, or by anyone where registration is open, and a policy written ahead of time cannot know the client it lets in. [Decision 0049](0049-dynamic-client-registration.md) let the conformance tenant's policy allow those types "the mark included"; this decision replaces that sentence. A registration policy may not name `token`, `id_token token`, `code token` or `code id_token token`, which is refused with `oauth.client_registration_policy_invalid`, and a registration or a change of one that names them is refused with `invalid_client_metadata`, as any member the policy does not allow is. A registration carries no `browser_access_tokens`. An administrator may still mark a registered client afterwards through the administration interface, like any other client, and it is then a finding of the posture. The Dynamic plan needs discovery to name `id_token token`, which it does whatever the policy says, and runs its tests with `code`.

## Consequences

- A tenant that never marks a client sees no change: discovery names the four new types, and the authorization endpoint refuses them to every client with `unauthorized_client`.
- The certification deployment and the conformance script mark their clients with one option of `hodor-cli client add`; the Implicit and Hybrid plans run every response type of their profile. The registration tenant of the certification deployment allows the response types that return no access token.
- No access token through the browser ever goes to a client nobody looked at.
- An administrator who marks a client sees it on the posture at once, and an auditor who cannot change clients sees it too.
- A request for a token type that names a resource server's scope the mark does not allow fails before the sign-in, where a cut token would have reached the resource server with less than the client asked and an audience it should not name.
- `/posture/findings` exists with one check. Each later check adds findings to it; its shape is the design's, so the console's screen reads it as it is.

## Alternatives considered

- **An operation of its own, `PUT` and `DELETE /clients/{client_id}/browser-access-tokens`.** Easy to find in the audit log and to hold to a stronger permission. Set aside: the mark and the types it allows would be set in two calls, the second refused until the first is made, and the events already tell the mark apart from other changes.
- **Cutting the scopes of the token to what the mark allows, instead of refusing the request.** Kinder to a client that asks for too much. Set aside: the audiences follow the scopes, and a token for a resource server it holds no scope of is a token that should not exist.
- **A finding stored when the mark is set, and removed with it.** Would carry a history. Set aside: the audit log already holds the history, and a finding computed when read can never outlive what it reports.
- **A registration policy that names the types, as the mark of the clients it lets register**, as Decision 0049 had it for the conformance tenant. Set aside: the mark would be given to clients nobody chose, and an open registration would let anyone obtain one.
- **Waiting for the whole posture resource.** Set aside: the issue asks that the mark be visible where a security engineer looks, and the design's resource can grow one check at a time.
