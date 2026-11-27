# Decision 0052: A client is held to a security profile, FAPI 1.0 Advanced, FAPI 2.0 Security Profile or FAPI 2.0 Message Signing, whose rules are checked when the client is saved and at every request; under FAPI 2.0 its refresh tokens are not rotated

Status: Proposed (requested by the project owner, who asked for every OpenID certification profile)

## Context

The FAPI profiles of the OpenID Foundation tighten OAuth and OpenID Connect for high-value data. Each is a certification programme of its own, with plans in the [OpenID conformance suite](../operations/conformance.md) (release 5.3.5, read in November 2026):

| Profile | What the authorization server must do, as the plan tests it |
|---|---|
| [FAPI 1.0 Advanced](https://openid.net/specs/openid-financial-api-part-2-1_0.html) (`fapi1-advanced-final-test-plan`) | A signed request object, with `exp` no more than 60 minutes after `nbf` and `nbf` no more than 60 minutes past; `code id_token` with `s_hash` and `c_hash`, or `code` with JARM; ID tokens and responses signed with `PS256` or `ES256`, never `RS256`; access tokens bound to the client's certificate, whatever the client authentication; `private_key_jwt` or mutual TLS; pushed requests with PKCE when used; TLS 1.2 or later with four cipher suites only |
| [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html) (`fapi2-security-profile-final-test-plan`) | Pushed authorization requests always, references living under 600 seconds; `code` only, PKCE with `S256`; `iss` in the response; tokens bound by DPoP or mutual TLS; `private_key_jwt` or mutual TLS; `PS256`, `ES256` or `EdDSA`; codes living 60 seconds at most; refresh token rotation only in extraordinary circumstances; TLS 1.2 or later with the cipher suites RFC 9325 recommends only |
| [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-message-signing-2_0-final.html) (`fapi2-message-signing-final-test-plan`) | The Security Profile, plus request objects signed and pushed, responses signed (JARM), `aud` the issuer, the 60-minute bounds of FAPI 1.0; JWT introspection responses ([RFC 9701](https://www.rfc-editor.org/rfc/rfc9701)) are in the specification and not tested by the suite |

Most of these are features this plan builds for every client: request objects and pushed requests ([Decision 0045](0045-request-objects-and-pushed-requests.md)), response types and JARM ([Decision 0046](0046-responses-through-the-browser.md)), DPoP ([Decision 0053](0053-dpop.md)), and mutual TLS with certificate-bound tokens, which [0.4.0 plans](../product/epics.md#slice-mutual-tls-epic-31) (Issues 107 and 108). What the profiles add is the obligation: a client of a profile may not do without them.

Hodor rotates every refresh token, with a short retry window ([refresh tokens](../architecture/contexts/oauth.md#refresh-tokens)). FAPI 2.0 asks a server not to rotate them except in extraordinary circumstances, since a client that loses an answer loses its grant.

The suite also checks the TLS of every endpoint it calls, and the address a client uses for mutual TLS (`mtls_endpoint_aliases` of RFC 8705). Hodor does not end TLS; the web server in front of it does.

## Decision

### A profile is a property of a client, with the tenant's default

- **A client is held to at most one profile:** `fapi1_advanced`, `fapi2_security` or `fapi2_message_signing`. A tenant may name a default for the clients made after it.
- **The profile is checked when the client is saved.** A client that could not keep it is refused, naming the rule: a secret method of authentication, `RS256` for its ID tokens, a response type other than those the profile allows, a client marked to receive tokens through the browser, a public client, unsigned request objects.
- **The profile is checked at every request.** Every rule below is a check of the authorization, pushed request and token endpoints, read from the client, so that a request that breaks one is refused even if the client was saved under an older rule.

### What each profile requires

| Rule | FAPI 1.0 Advanced | FAPI 2.0 Security Profile | FAPI 2.0 Message Signing |
|---|---|---|---|
| Client authentication | `private_key_jwt`, `tls_client_auth`, `self_signed_tls_client_auth` | The same | The same |
| Signing algorithms of the client and of Hodor | `PS256`, `ES256` | `PS256`, `ES256`, `EdDSA` | `PS256`, `ES256`, `EdDSA` |
| The request | A signed request object, by value or pushed | Pushed, request object optional | Pushed, as a signed request object |
| Request object lifetime | `exp` and `nbf` required, `exp` − `nbf` ≤ 60 minutes, `nbf` ≥ now − 60 minutes | — | As FAPI 1.0 |
| Response | `code id_token` with `s_hash`, or `code` with JARM | `code`, `iss` in the response | `code` with `iss`; JARM when the client asks |
| PKCE | `S256` when pushed | `S256` always | `S256` always |
| Bound tokens | Mutual TLS, always | DPoP or mutual TLS, as the client registers | DPoP or mutual TLS |
| Client assertion `aud` | The issuer or the token endpoint | The issuer only | The issuer only |
| Refresh tokens | Rotated, as today | **Not rotated** | **Not rotated** |
| Pushed reference lifetime | — | At most 600 seconds | At most 600 seconds |

- **Not rotating** means a client of FAPI 2.0 keeps one refresh token for its family's life. The token is bound to the client by its authentication and to its key or certificate by the binding, so a stolen copy alone gets nothing. Reuse detection still applies to every other client.
- **FAPI 2.0 for client credentials** is the same profile on a client of the client credentials grant: authentication and binding as above, nothing of the browser.
- **The assurance level that FAPI 1.0's tests ask for**, `urn:mace:incommon:iap:silver`, is not built in: the conformance tenant names one of its [assurance levels](../architecture/contexts/tenant.md#assurance-levels) so.

### Mutual TLS for clients that are not workloads

[Milestone 10](../product/epics.md#milestone-10-workloads-prove-who-they-are-with-their-certificates) accepts a client certificate forwarded by a trusted proxy, and checks it against a SPIFFE trust domain. A FAPI client is a company's server, not a workload of a mesh, so this plan adds:

- **certificate authorities of a tenant for client certificates**, outside any trust domain, uploaded by an administrator;
- **`tls_client_auth` with the metadata of RFC 8705**: the client names one of `tls_client_auth_subject_dn`, `_san_dns`, `_san_uri`, `_san_ip` or `_san_email`, and its certificate must chain to one of the tenant's authorities and match;
- **`self_signed_tls_client_auth`**: the certificate must be one of the client's registered keys, by its `x5c` or thumbprint;
- **`mtls_endpoint_aliases`**: when the operator gives Hodor a second public address where the web server asks for client certificates, discovery names the token, pushed request, revocation, introspection, UserInfo and backchannel authentication endpoints there.

### What the web server in front must do

The [certification deployment](../operations/certification.md) and the [installation pages](../operations/deployment.md) say how to set the web server in front of Hodor for a tenant with FAPI clients: TLS 1.2 and 1.3 only, 1.3 preferred, and on 1.2 only the cipher suites the profiles name; an RSA certificate for FAPI 1.0, whose suites are those of RSA; client certificates asked for on the alias address and forwarded to Hodor as Milestone 10 says. Hodor does not check what the web server negotiates; the suite does.

## Consequences

- A tenant can offer FAPI clients beside ordinary ones, each held to what its profile asks, and the three FAPI plans can be certified.
- A client of FAPI 2.0 that loses an answer to a refresh keeps its grant. A refresh token that leaks with its key or certificate is not detected by reuse, as it is for other clients; the binding is what protects it.
- Every endpoint reads the client's profile. The checks are a table of rules over what the endpoints already know, tested once per rule.
- The settings of the web server matter to the profile and are outside Hodor. The installation pages and the certification deployment carry them; a tenant whose web server does not keep them fails the suite's checks, not Hodor's.

## Alternatives considered

- **A profile per tenant rather than per client.** Simpler to explain. Set aside: a bank's tenant also serves its own web and mobile applications, which need neither mutual TLS nor pushed requests.
- **Rotating refresh tokens under FAPI 2.0 as for every client.** One rule. Set aside: FAPI 2.0 asks not to, the suite's flows may break on it, and the binding already does what rotation does for a client that keeps its key.
- **Making every client keep the strictest rules.** Simplest to reason about. Set aside: most clients cannot do mutual TLS or sign their requests, and OpenID Connect's own profiles need what FAPI forbids.
- **Ending TLS in Hodor for FAPI.** Hodor could check its own cipher suites. Set aside: [Milestone 10](../product/epics.md#explicitly-not-in-milestone-10) leaves TLS to the web server in front, and doing it for one feature would split how Hodor is deployed.
