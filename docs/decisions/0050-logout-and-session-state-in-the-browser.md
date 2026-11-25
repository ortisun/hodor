# Decision 0050: Front-channel logout is a page of Hodor's that loads each client's address in a frame before it finishes, and session management reads a browser state that is not the session

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile). It sets aside the reason [Decision 0037](0037-back-channel-logout.md) gave for leaving front-channel logout out, for the profiles that need it.

## Context

Hodor tells applications that a session ended through [back-channel logout](../architecture/contexts/oauth.md#back-channel-logout), server to server. Two other specifications do it through the person's browser, and each is a certification profile of its own ([OpenID conformance](../operations/conformance.md#the-target)):

- **[OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html).** When a session ends, the provider's page loads, in an invisible frame, the `frontchannel_logout_uri` of every client the person signed in to, with `iss` and `sid`. The suite's plan requires `frontchannel_logout_supported` and `frontchannel_logout_session_supported`, and checks that the frame's address carries `iss` and the `sid` of the ID token.
- **[OpenID Connect Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html).** The authorization response carries `session_state`. The client's page loads the provider's `check_session_iframe` and asks it, by `postMessage`, whether the state changed. The iframe answers from a value the provider keeps in the browser, which its script must be able to read. The suite's plan checks that the iframe answers `unchanged` before logout and `changed` after.

A logout submission to the Foundation must hold the RP-Initiated OpenID Provider profile and at least one of Session, Front-Channel and Back-Channel, for every response type the provider supports ([connect_op_logout_testing](https://openid.net/certification/connect_op_logout_testing/)). Hodor's [end-session endpoint](../architecture/contexts/oauth.md#logout-initiated-by-the-relying-party) is built, but the suite's RP-Initiated plan does not run in continuous integration.

Both browser mechanisms live in frames of other sites. Browsers that block cookies of other sites in frames break session management, and some break front-channel logout for clients whose own session cookie is not sent in a frame. Session cookies of Hodor are `HttpOnly` and `SameSite=Lax`, and its pages refuse to be framed.

## Decision

### Front-channel logout happens on a page of Hodor's, before the request finishes

- **A client may register `frontchannel_logout_uri`**, one absolute HTTPS address checked as a redirect address is, and `frontchannel_logout_session_required`. Only a client with the authorization code or a response type that returns an ID token may have one.
- **When a session ends in the browser**, at the [finish](../architecture/contexts/oauth.md#finishing) of the end-session endpoint or when the person signs out from the account page, the browser is sent to `/t/{slug}/account/signed-out`, a page of the hosted pages that loads, each in an invisible frame, the address of every client of the session that has one, with `iss` and `sid` as that client knows the session (its pairwise identifier for a [pairwise client](../architecture/contexts/oauth.md#pairwise-subject-identifiers)). The clients are those [Decision 0037](0037-back-channel-logout.md) names: a grant made in the session with `openid`.
- **The page waits** until every frame has loaded or five seconds have passed, then goes on to the client's post-logout redirect address or to the sign-in page, as the finish does today. The list of addresses is made by the server for that one page, kept with the logout request, and never taken from the browser.
- **The page's content security policy** allows those addresses as frame sources and nothing else, for that answer only.
- **A session ended without the browser**, by an administrator, a password reset or deprovisioning, has no page to load frames in: such a client is told through back-channel logout, if it has an address for it, or not at all. The console says so beside the address.
- **Both kinds can be registered on one client.** Back-channel logout is still sent; a client handles two notices of one logout as it handles a repeated logout token.

### Session management reads a browser state, never the session

- **The browser state** is 32 random bytes kept in a cookie of its own, `hodor_browser_state`, per tenant, made when a session starts and replaced when it ends or its person changes. It is not the session token and grants nothing: it says only that the browser's session changed. It is `Secure`, `SameSite=None` so that the iframe can read it in a frame of another site, `Path=/t/{slug}`, and not `HttpOnly`, so that the iframe's script reads it.
- **`session_state`** in every authorization response, success or error, to a client that asks for it, is the SHA-256 of the client's identifier, the origin of its redirect address, the browser state and a salt of 16 random bytes, followed by `.` and the salt, as the specification describes.
- **The `check_session_iframe`** is `/t/{slug}/oauth2/check-session`, a static page with one script that answers `postMessage` from any origin by computing the same value. It may be framed by any site, unlike every other page of Hodor's, and holds nothing else. It answers `error` to a message that is not `client_id session_state`.
- **Discovery** names `check_session_iframe` only when the tenant turns session management on; it is off by default, since it needs a cookie readable by script and by frames of other sites.

### The RP-Initiated plan runs, and its pages are the ones there are

The suite's RP-Initiated plan joins continuous integration in this plan. Where it expects a page instead of a redirect, for a bad hint or an unregistered address, Hodor's own error page and question are what it gets, as the [end-session endpoint](../architecture/contexts/oauth.md#checking-the-request_1) already shows.

## Consequences

- The Front-Channel and Session OpenID Provider profiles can be certified, and a logout submission can name all four logout profiles.
- A person who signs out waits up to five seconds on a page while their applications are told. Back-channel logout is still what reaches clients when no browser is there.
- The browser state is a cookie a script can read. It tells only whether the session changed; a script that reads it learns no secret, and it is replaced at each change, so it cannot be used to follow a person across sessions. A tenant that does not turn session management on never sets it.
- Both mechanisms fail in browsers that block cookies of other sites in frames, for reasons outside Hodor. The guides say so, and recommend back-channel logout for applications that must be told.

## Alternatives considered

- **Leaving front-channel logout and session management out**, as Decision 0037 did. Set aside: the owner asked for every profile, and some relying parties, single-page applications without a server among them, can be told no other way.
- **Loading the clients' addresses from the end-session request itself, before the question.** One page less. Set aside: the session is not ended until the person answers, and a frame loaded before would tell clients of a logout that may not happen.
- **A browser state in the session cookie.** One cookie. Set aside: the session cookie must stay `HttpOnly` and `SameSite=Lax`; a script must never read it.
- **A partitioned cookie for the browser state.** Works where cookies of other sites are blocked. Set aside: a partitioned cookie set by Hodor's own pages is not the one the iframe sees in a client's page, so the iframe could never tell that the session changed.
