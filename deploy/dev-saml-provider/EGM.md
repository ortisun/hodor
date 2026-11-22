# dev-saml-provider

## Overview

A development SAML identity provider in one file, `saml-provider.mjs`, using only Node.js and its standard library (`node:crypto`, `node:fs`, `node:http`, `node:zlib`). The header comment says it is "NOT FOR ANYTHING REAL": its sign-in page asks who you would like to be, so anyone signs in as anyone, and its signing key is written in the repository beside it. It exists so that the development stack, the browser tests and the demonstration have a SAML identity provider that signs real responses. In the stack it is the `saml-provider` service of [docker](../docker/EGM.md).

The human-maintained [README](./README.md) of this directory describes the files and how the key and certificate were made.

## Interface

Files:

- `saml-provider.mjs`: the identity provider.
- `signing-key.pem`: an RSA private key, read at start as `KEY` and used to sign. It is a development key: anyone can sign with it, so nothing real may trust it.
- `certificate.pem`: a self-signed certificate for that key, read at start as `CERTIFICATE`. Its base64 body (`CERTIFICATE_BASE64`) is published in the metadata and in every signature's `KeyInfo`. The Milestone 2 demonstration and the continuous integration job pass this file to `hodor-cli provider add --kind saml --certificate`.

Configuration, read from the environment at start:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `9500` | listening port |
| `ENTITY_ID` | `urn:hodor:development-saml-provider` | the issuer of what it sends |
| `BROWSER_URL` | `http://localhost:${PORT}` | where a person's browser reaches it |
| `KEY_FILE` | `signing-key.pem` beside the script | the signing key |
| `CERTIFICATE_FILE` | `certificate.pem` beside the script | the certificate |

Routes (`createServer` handler, matched on `${method} ${pathname}`):

| Route | Handler | Behavior |
| --- | --- | --- |
| `GET /health` | inline | `200 ok`, used by the compose health check |
| `GET /metadata` | `metadata` | an `EntityDescriptor` with `entityID` `ENTITY_ID`, a signing `KeyDescriptor` holding the certificate, and one `SingleSignOnService` with the HTTP-Redirect binding at `${BROWSER_URL}/sso` |
| `GET /sso` | `signOn` | reads `SAMLRequest` with `requestOf`; `400` if it is not understood; otherwise an HTML form with fields `subject`, `email` and `name`, carrying `request_id`, `consumer`, `audience` and `relay_state` as hidden fields |
| `POST /sso/decision` | `decide` | `400` if the request fields are incomplete; otherwise a page whose form posts `SAMLResponse` (base64) and `RelayState` to the consumer address and submits itself with a script, as the HTTP-POST binding says |
| anything else | inline | `404 not found` |

Internal functions:

- `requestOf(encoded)`: base64-decodes and raw-inflates the request (at most 64 kibibytes), then reads `ID`, `AssertionConsumerServiceURL` and the `saml:Issuer` with regular expressions.
- `signedResponse({ request, subject, email, name })`: builds the assertion and its enveloped signature (RSA with SHA-256, SHA-256 digest, exclusive canonicalization) and wraps it with `samlResponse`.
- `samlResponse(request, status, assertion)`: the `samlp:Response` with `Destination` and `InResponseTo` from the request.
- `text`, `attribute`: escaping as canonical XML writes text and attribute values; `html`: escaping for the pages; `instant`, `identifier`, `page`, `send`, `htmlPage`, `form`.

## Invariants

- No XML library is used. The assertion is written already in its exclusive canonical form (attributes in sorted order, empty elements as start and end tags, each namespace on the element that first uses it), so the digest is taken over exactly the text that is sent. The digest covers the assertion without the signature element; the signature is inserted after `saml:Issuer`.
- `requestOf` and `decide` refuse a request without an identifier, without an audience, or whose consumer address does not start with `http://` or `https://`.
- A signed assertion carries: `saml:Issuer` `ENTITY_ID`; a persistent `NameID` (default `development-saml-subject`); a bearer `SubjectConfirmationData` with `InResponseTo` the request identifier, `Recipient` the consumer address and `NotOnOrAfter` five minutes ahead; `Conditions` from 30 seconds before to five minutes after issue with the request's issuer as `Audience`; an `AuthnStatement`; and the attributes `email` (default `saml-person@example.com`) and `name` (default `Development SAML Person`).
- When the decision is not `allow`, the response has status `urn:oasis:names:tc:SAML:2.0:status:Responder` and no assertion.
- Form bodies over 64 kibibytes raise an error that the handler turns into `500`. Every answer carries `cache-control: no-store`.
- The key and certificate are a pair: signatures are made with the key, while the certificate is what is published and what the demonstration and the continuous integration job register with Hodor. Replace both together, and register the new certificate again.

## Side Effects

- Reads `KEY_FILE` and `CERTIFICATE_FILE` from disk once at start; the process fails to start if either is missing.
- Listens for HTTP on `PORT`; logs one line at start and errors to the console.
- Keeps no state between requests: the request fields travel through the browser as hidden form fields.
- Closes the server and exits with status 0 on `SIGTERM` or `SIGINT`.

## Verification

No automated test lives in this directory. In the stack it runs as `node /saml-provider/saml-provider.mjs` with this directory mounted read-only (`compose.yaml`, service `saml-provider`) and is exercised by `.github/workflows/ci.yml` (job `pages`, step "Add the development SAML identity provider to the tenant", then the browser tests and `python3 deploy/demo/external_identities.py`, whose `a_tampered_response` step checks that a changed response is refused). With its defaults it also starts on its own:

```sh
node deploy/dev-saml-provider/saml-provider.mjs
```
