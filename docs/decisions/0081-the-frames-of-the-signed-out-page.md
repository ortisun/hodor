# Decision 0081: The frames of the signed-out page are kept on the server under a random handle, go only to a client's own sites, and are named in the page's policy by their sites

Status: Proposed

## Context

[Decision 0050](0050-logout-and-session-state-in-the-browser.md#front-channel-logout-happens-on-a-page-of-hodors-before-the-request-finishes) has Hodor's signed-out page load, in invisible frames, the `frontchannel_logout_uri` of every client of a session that ended in the browser, with `iss` and the `sid` that client knows. It says the list of addresses is "made by the server for that one page, kept with the logout request, and never taken from the browser", and that the page's content security policy "allows those addresses as frame sources and nothing else". Building it, Issue-139 found four questions the decision leaves open.

- **Where the list is kept.** The logout request is kept in a cookie, `__Secure-hodor_logout`, which the browser holds and sends back; Hodor checks it again when it is used. A list of frames in a cookie would be taken from the browser. A cookie holding the session's identifier, read back to make the list again, would let whoever knows a session's identifier, which every public client gets as `sid`, make Hodor's page show the pairwise `sid` of another person's session and the clients that person signed in to. And a session also ends on the account page, where there is no logout request at all.
- **Which addresses a client may register.** [Front-Channel Logout, section 2](https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout) requires that "the domain, port, and scheme of this URL MUST be the same as that of a registered Redirection URI value". Decision 0050 asks only that it be checked as a redirect address is.
- **How the policy names the frames.** A frame source may be a whole address without its query, or only its site. A front-channel logout address may be 2000 characters long and a session may have many clients; a response header of tens of kilobytes is refused by some proxies, which answer `502` in its place. Browsers also stop comparing the path of a frame source once the frame is redirected.
- **Where the page goes once it is done.** Decision 0050 says "to the client's post-logout redirect address or to the sign-in page, as the finish does today". The finish reads the logout request's cookie, which lives ten minutes, and a person who chose "Stay signed in" and then signs out from the account page within those minutes would be sent to an application that asked for nothing.

## Decision

- **The frames are kept in a row of their own, `oauth.frontchannel_logout`**, made when the session ends: its tenant, the session, the addresses with `iss` and `sid` already added, and the SHA-256 of a handle of 32 random bytes. The browser holds only the handle, in the cookie `__Secure-hodor_signed_out` (`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/t/{slug}`), and the row and the cookie live 120 seconds. The page reads its frames by the hash, in the tenant its address names. The row is not removed when it is read; the cleanup removes it once it has expired.
- **Every way a session ends in its own browser makes the row**: signing out through the interaction interface, from the account page or the sign-out page, ending the current session from the list of sessions, and the end-session endpoint ending a session at once. A sign-out with no client to frame makes no row and tells the browser to forget an older cookie.
- **A front-channel logout address shares its scheme, host and port with one of the client's redirect addresses**, as the specification requires, besides the rules of a redirect address but private-use schemes. It is checked at every change of the client, so a change of redirect addresses that leaves it on a site of no redirect address is refused.
- **The page's `frame-src` names the sites of its frames**, scheme, host and port, each once, for that answer only. Without frames there is no `frame-src` and `default-src 'none'` forbids every frame.
- **The frames are sandboxed with `allow-scripts allow-same-origin`**, invisible and without pointer events. A client's page may run its script against its own cookies and storage, which is what it needs to end its session, but cannot navigate Hodor's page, open a window or submit a form.
- **The page goes on to the finish only when its address says `continue=logout`**, which the end-session endpoint and the sign-out page give; from the account page it goes to the sign-in page, as signing out there always did. `continue` chooses between those two places of Hodor's own and never names an address.
- **A failure to make the frames does not undo the sign-out.** The session has ended by then; the failure is logged and the page loads no frame. Back-channel logout does not depend on it.

## Consequences

- Nothing the browser sends becomes a frame: a handle is a key to the row, and a handle that is unknown, expired, of another tenant or not one at all finds nothing. Knowing a session's identifier is of no use.
- One more tenant table, one more kind of row for the cleanup (`frontchannel_logouts`, retention 0), and one more cookie, which holds no secret of the session and grants nothing but reading, for two minutes, frames the person's own browser was about to load.
- A client cannot use Hodor's page to load a site that is not its own, and an address registered before the client had a redirect address on its site is refused when it is registered, not discovered when a person signs out. A single-page application that serves its logout page from another host than its callback must move one of them.
- The policy stays a few hundred bytes for any number of clients. It allows a whole site where the frame needs one page of it; the frames themselves still come only from the server's row.
- A client's logout page that relies on navigating the top window, or on opening a window, does not work inside Hodor's frame. The specification's frame is meant to be invisible and to end a session, not to show anything.
- A person who signs out waits up to five seconds on the page, as Decision 0050 says, and the page may be loaded again during the row's life, telling the clients again of a logout they already know of.

## Alternatives considered

- **The list in the logout request's cookie, signed by the server.** No table. Set aside: a cookie of a few kilobytes per client grows past what browsers keep, the account page has no logout request, and the list would still travel through the browser, which Decision 0050 rules out.
- **The session's identifier in the cookie, the list made again when the page asks.** No table. Set aside: anyone who learned a session's identifier could read the pairwise `sid` of that session's clients.
- **Whole addresses in the policy.** A tighter policy. Set aside: the header grows with every client and its address, until a proxy refuses the answer, and browsers ignore the path once a frame is redirected, so the gain holds only for a frame that is not.
- **Leaving the site of the address free**, as Decision 0050 read alone allows. Set aside: the specification requires the redirect address's site, and without it a tenant's administrator could make every person's sign-out load any site.
- **Removing the row when it is read.** A page loaded only once. Set aside: the policy and the page's own request each read it, a reload would leave the person on a page that loads nothing, and a repeated notice is harmless to a client that already ended its session.
