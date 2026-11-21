# Decision 0011: Hosted user interface on an interaction API; consoles behind a backend-for-frontend

Status: Proposed

## Context

There are three React applications. The hosted login user interface handles credentials; the admin and account consoles are highly privileged. Tokens in browser storage are exposed to any script that runs on the page.

## Decision

- **`auth-ui`** is served by `hodor-server` on the tenant's origin and talks only to the Interaction API. It is a renderer for the step the flow engine returns; it holds no flow logic and never receives OAuth tokens. State is the server-side `AuthTransaction`, referenced by an `HttpOnly` cookie, with a CSRF token on every submission.
- **`admin-console` and `account-console`** are ordinary OpenID Connect clients of Hodor, using Authorization Code with PKCE through a backend-for-frontend built into `hodor-server`. The backend-for-frontend keeps tokens server-side and gives the browser a session cookie; the single-page application calls same-origin API routes.
- All three ship in the server image as static assets with a strict Content-Security-Policy (no inline script, no third-party origins), `frame-ancestors 'none'` and Trusted Types.
- Tenant theming is declarative: design tokens, logo, copy and locale. Tenant-supplied HTML, CSS files and JavaScript are not accepted.
- The consoles use only the public Admin and Account APIs. Anything the console can do, an API client can do.

## How it was built

`auth-ui` exists since Issue-31 and is described in [the hosted pages](../architecture/hosted-pages.md). Two choices made there narrow this decision:

- The static files are not compiled into the binary. They are built into a directory of the image, and `hodor-server` is told where it is. Building and testing the Rust workspace therefore needs no Node.js.
- The Content Security Policy carries `require-trusted-types-for 'script'` with no policy allowed at all, which is stricter than "Trusted Types": the pages have no way to turn text into markup.

The consoles and the backend-for-frontend do not exist yet.

## Consequences

- No token ever reaches browser JavaScript in first-party apps.
- The Admin API is exercised by the product itself, which keeps it complete.
- Custom login pages built by tenants are possible only through theming or, later, by building their own user interface against the Interaction API on their own origin (a deliberate, documented integration).
- The backend-for-frontend is extra server code, small and shared by both consoles.

## Alternatives considered

- **Single-page application holding tokens in memory or storage**: simpler, but exposes privileged tokens to XSS.
- **Server-rendered login pages (templates)**: smaller attack surface and no JavaScript requirement, but weaker for WebAuthn-heavy, multi-step flows and inconsistent with the chosen frontend stack. The Interaction API keeps this option open.
- **Free-form tenant themes (HTML templates)**: the main source of XSS in comparable products.
