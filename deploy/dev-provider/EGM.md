# dev-provider

## Overview

A development OpenID Connect identity provider in one file, `provider.mjs`, using only Node.js and its standard library (`node:crypto`, `node:http`). The header comment says it is "NOT FOR ANYTHING REAL": its sign-in page asks who you would like to be, so anyone signs in as anyone. It exists so that the development stack, the browser tests and the demonstration have an OpenID Connect provider to talk to. In the stack it is the `provider` service of [docker](../docker/EGM.md).

## Interface

Configuration, read from the environment at start:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `9400` | listening port |
| `ISSUER` | `http://provider:${PORT}` | the issuer it names itself, and where Hodor reaches it |
| `BROWSER_URL` | `http://localhost:${PORT}` | where a person's browser reaches it |
| `CLIENT_ID` | `hodor` | the only client it accepts |
| `CLIENT_SECRET` | `development-client-secret` | that client's secret |

Routes (`createServer` handler, matched on `${method} ${pathname}`):

| Route | Handler | Behavior |
| --- | --- | --- |
| `GET /health` | inline | `200 ok`, used by the compose health check |
| `GET /.well-known/openid-configuration` | inline | discovery document: `authorization_endpoint` on `BROWSER_URL`, `token_endpoint` and `jwks_uri` on `ISSUER`; `response_types_supported: ["code"]`, `id_token_signing_alg_values_supported: ["ES256"]`, `token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"]`, `code_challenge_methods_supported: ["S256"]` |
| `GET /keys` | inline | the JSON Web Key set holding the one public key, `kid: "development-key"` |
| `GET /authorize` | `authorize` | rejects with `400` unless `client_id` equals `CLIENT_ID` and `response_type` is `code`; otherwise an HTML form with fields `subject`, `email`, `email_verified` and `name`, carrying `redirect_uri`, `state`, `nonce`, `code_challenge` and `code_challenge_method` as hidden fields |
| `POST /authorize/decision` | `decide` | `303` back to `redirect_uri` with `state`; with `error=access_denied` unless `decision` is `allow`, otherwise with a new `code` |
| `POST /token` | `token` | exchanges a code for `{ token_type: "Bearer", access_token, expires_in: 60, id_token }` |
| anything else | inline | `404 not found` |

Internal functions: `idToken(claims)` signs a compact JSON Web Token with ES256; `clientOf(request, sent)` reads the client from an `Authorization: Basic` header or from `client_id` and `client_secret` form fields; `form(request)` reads a form body; `page`, `send`, `json`, `escape` render answers.

## Invariants

- The signing key is an elliptic curve P-256 key pair made by `generateKeyPairSync` at every start and never stored: a restart invalidates every token issued before it.
- Codes live in the in-memory `codes` map, expire 60 seconds after issue, and are deleted on the first `/token` call that presents them, whether or not the exchange succeeds ("Whatever happens next, the code is gone").
- `token` answers `401 invalid_client` unless the client identifier and secret both match, and `400 invalid_grant` unless `grant_type` is `authorization_code`, the code is known and unexpired, `redirect_uri` matches the one given at `/authorize`, and the SHA-256 of `code_verifier` (base64url) equals the stored `code_challenge`. Only the `S256` proof key for code exchange method is checked.
- The identity token carries `iss` (`ISSUER`), `aud` (`CLIENT_ID`), `iat`, `exp` (five minutes after issue), `sub` (default `development-subject`), `nonce`, and when given `email`, `email_verified` and `name`. `email_verified` is set only when an email address was sent.
- Form bodies over 64 kibibytes raise an error that the handler turns into `500`.
- Every answer carries `cache-control: no-store`; HTML output is escaped by `escape`.

## Side Effects

- Listens for HTTP on `PORT`; logs one line at start and errors to the console.
- Holds codes in memory only; nothing is written to disk.
- Closes the server and exits with status 0 on `SIGTERM` or `SIGINT`.

## Verification

No automated test lives in this directory. In the stack it runs as `node /provider.mjs` (`compose.yaml`, service `provider`) and is exercised by `.github/workflows/ci.yml` (job `pages`, step "Add the development identity provider to the tenant", then the browser tests and `python3 deploy/demo/external_identities.py`). With its defaults it also starts on its own:

```sh
node deploy/dev-provider/provider.mjs
```
