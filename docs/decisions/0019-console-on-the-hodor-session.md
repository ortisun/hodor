# Decision 0019: Until Hodor issues tokens, the admin console rides the administrator's Hodor session

Status: Accepted (requested by the project owner)

## Context

[Decision 0011](0011-frontends-bff.md) makes the admin console an ordinary OpenID Connect client of Hodor behind a backend-for-frontend: the browser holds a session cookie, the server holds the tokens, and no token ever reaches the page's scripts. Hodor's OAuth 2.0 and OpenID Connect server is Phase 2 and does not exist yet, so the console as decided cannot be built today.

What does exist is enough for a first console to be useful:

- the [administration interface](../api/admin-api.md): users, their sessions and the audit log, behind fixed roles;
- the sign-in of the [hosted pages](../architecture/hosted-pages.md), which leaves a session in an `HttpOnly` cookie, with a CSRF token derived from it;
- the design system on Astryx ([Decision 0018](0018-astryx-component-foundation.md)), with the shell, tables, dialogs and command palette a console needs.

The project owner asked for the control plane to be built now, on what is ready, and used in production.

## Decision

- **The admin console is built now**, as a third application of static files served by `hodor-server` on the tenant's origin, under `/t/{slug}/console`. It is specified in [the admin console](../architecture/admin-console.md).
- **It signs in with the administrator's Hodor session.** A person signs in on the hosted pages as anyone does; the console then works for those whose user holds a role. There is no access token in the browser, in a cookie or in the page.
- **The backend-for-frontend is the console interface**, mounted at `/t/{slug}/console/api`. It has the routes of the administration interface, one for one, answered by the same code, and differs only in how it knows who is asking: by the session cookie where the administration interface reads an access token. It is specified in [the console interface](../api/console-interface.md).
- **Cookies bring forgery with them, so the console interface carries the protections the interaction interface already has**: a request that changes something must come from this origin and must carry the session's CSRF token.
- **A console session is shorter than a session.** The console interface answers only while the sign-in is less than 12 hours old, whatever the tenant allows its users.
- **Permissions decide what the console shows, and the server decides what it does.** The console asks who the person is and what they may do, and offers only that; every request is checked again by the server against the same table of permissions as the administration interface.
- **The console shows only what the server can answer.** Screens whose resources do not exist yet (security posture, applications, signing keys, policies) are not in the navigation. Nothing is drawn from sample data.

When Hodor can issue tokens, the console interface changes how it authenticates, to OpenID Connect as Decision 0011 says, and nothing else: its routes, the console and its address stay.

## Consequences

- A tenant can be administered from a browser today, by people, with the dangerous action ladder in front of what is destructive.
- The administration interface is exercised by the product itself, which is what Decision 0011 wanted from the consoles.
- An administrator's sign-in is as strong as the tenant's sign-in: a password, until multi-factor authentication and passkeys arrive in Phase 4. A stolen session of an administrator is a stolen console for up to 12 hours. The [requirements of the console](../product/requirements.md#admin-console-admin-console) that this leaves unmet are listed, one by one, in [the admin console](../architecture/admin-console.md#what-is-not-built-yet).
- The session cookie is sent to every path of the tenant, so the console interface is reachable by any page of the tenant's origin. Every page there is Hodor's own, under a policy that lets no other script run.
- There are now two ways into the same administration code. One table of permissions and one set of handlers serve both, and a test holds the two lists of routes together.

## Alternatives considered

- **Wait for the OAuth server** (Decision 0011 as written): the cleanest, and it leaves tenants administered by `curl` for a whole phase.
- **Paste an access token into the console**: works with the administration interface as it is, and puts a privileged token in the page's memory, which is the one thing Decision 0011 exists to prevent.
- **Let the administration interface itself accept the session cookie**: one mount fewer, but an interface for programs that today has "no cookies, so nothing to forge" would gain forgery as a concern for every client.
