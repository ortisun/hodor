# browser-tests

## Overview

Playwright tests that drive the hosted pages in Chromium against a running
Hodor stack: the server with the pages, the worker, the development mail
server, and the development identity provider, directory and SAML identity
provider. `../playwright.config.ts` points here (`testDir: "browser-tests"`)
and runs `stack.ts` first as `globalSetup`. `support.ts` gives every test a
watched page and the steps a person repeats.

## Interface

- `stack.ts` - where the stack is, each value read from an environment
  variable with a default:

  | Constant | Variable | Default |
  | --- | --- | --- |
  | `SERVER` | `HODOR_URL` | `http://localhost:8080` |
  | `MAIL` | `HODOR_MAIL_URL` | `http://localhost:8025` |
  | `TENANT` | `HODOR_TENANT` | `acme` |
  | `PROVIDER` | `HODOR_PROVIDER` | `development` |
  | `DIRECTORY` | `HODOR_DIRECTORY` | `directory` |
  | `SAML_PROVIDER` | `HODOR_SAML_PROVIDER` | `corp` |

- `stack.ts:checkTheStack()` (default export, the global setup) - fails the
  run unless `{SERVER}/t/{TENANT}/account/sign-in` and `{MAIL}/api/v1/info`
  answer 200, `GET {SERVER}/t/{TENANT}/interaction/sign-in/providers` lists
  the aliases `PROVIDER`, `DIRECTORY` and `SAML_PROVIDER`, and a `POST
  {SERVER}/t/{TENANT}/interaction/recovery` is not answered 429. Each error
  includes the `HELP` text: the `docker compose -f deploy/docker/compose.yaml`
  and `hodor-cli server tenant create` / `server provider add` commands that
  set the stack up.
- `support.ts`:
  - `test` - Playwright's `test` extended with an automatic `misbehavior`
    fixture: a Content Security Policy violation (reported through a
    `securitypolicyviolation` listener added by `addInitScript`), a
    `pageerror`, or a console error other than `Failed to load resource`
    fails the test.
  - `expectAccessible(page)` - waits for running animations to finish, then
    runs `AxeBuilder` with the tags `wcag2a`, `wcag2aa`, `wcag21a`,
    `wcag21aa`, `wcag22aa` and expects no violations.
  - `messageTo(address, count = 1): Promise<Message>` - polls
    `{MAIL}/api/v1/search?query=to:"{address}"` for up to 20 seconds until
    `count` messages exist, reads `{MAIL}/api/v1/message/{ID}`, and returns
    `{ subject, text, link }`, where `link` is the path and `#token=` fragment
    of the first `https?://...#token=[0-9a-f]+` in the text.
  - `register(page, address, password = PASSWORD)` - registers through
    `register`, the message link and `complete-registration`, up to
    `en.noticeRegistered`.
  - `signIn(page, identifier, password)` - the identifier step and the
    password step of the sign-in page.
  - `signInThroughProvider(page, identity: Identity)` - leaves through
    `en.continueWith(PROVIDER_NAME)` and fills the development provider's
    page (`Subject`, `Email address`, "The provider vouches for this address",
    default vouched).
  - `at(page)` (path of a page of `TENANT`), `newAddress()`
    (`person-{uuid}@example.com`), `PASSWORD`, `PROVIDER_NAME`
    (`"Development provider"`), and re-exports `en`, `PROVIDER`, `TENANT`.
- Spec files (scenarios by `test(...)` title):
  - `pages.spec.ts` - a person registers, reads the message, signs in and
    signs out; the link in a message works once; a wrong password and an
    unknown address are refused in the same words; a person who forgot the
    password chooses a new one; asking to recover says the same for an
    address nobody has; a person signs in and out with the keyboard alone; a
    page is sent with the policy that keeps everything else out (checks
    `default-src 'none'`, `script-src 'self'`, `require-trusted-types-for
    'script'` and that an injected script does not run); and, under
    `test.describe("in Portuguese")` with locale `pt-BR`, the pages and the
    message speak the language of the browser.
  - `providers.spec.ts` (the OpenID Connect development provider) - a person
    signs in through an identity provider and is created on the first visit;
    a provider does not open an account that already exists with the same
    address; an address the provider does not vouch for creates nobody; a
    person who cancels at the provider is told so and can sign in another
    way; the code a provider sent does not stay in the address or work a
    second time; a person reaches the provider and comes back with the
    keyboard alone.
  - `directories.spec.ts` (the development directory, `"Company directory"`,
    person `dora` from `deploy/dev-directory/people.ldif`) - a person signs
    in through the directory without leaving the page; a wrong password at
    the directory is refused like any other.
  - `saml.spec.ts` (the development SAML identity provider, `"Development
    SAML provider"`) - a person signs in through a SAML identity provider and
    is the same person the next time; a person who cancels at the SAML
    identity provider is told it did not work.
  - `totp.spec.ts` - a person whose authenticator application an operator
    enrolled with `hodor-cli totp enroll` and `totp confirm` (run through
    `docker compose run … server`, honoring `COMPOSE_FILE` and
    `COMPOSE_PROJECT_NAME`) is asked for a code after the password, is
    refused with a wrong code, and signs in with the next one; the same with
    the keyboard alone. The codes are computed with `node:crypto` as RFC 6238
    says. With the recovery codes `totp confirm` prints, the person signs in
    with one of them, typed in lowercase with spaces, after a code that is
    not theirs is refused; the same code is refused the next time and
    `hodor-cli recovery-codes count` says nine are left; the switch to the
    recovery code form and back works with the keyboard alone.
  - `security.spec.ts` - people made through the development identity
    provider (`signInThroughProvider`), not by registering, since asking to
    register is limited by the one address all tests come from. On
    `/account/security`, reached from the account page's link: a person sets
    up an authenticator application, reading the key shown under the QR code
    and computing its code, keeps the recovery codes and is asked for a code
    after the provider at the next sign-in; is offered a new sign-in by
    `?continue=security` while signed in, adds a passkey through a virtual
    platform authenticator, generates new codes, renames and removes the
    passkey, which takes the codes with it; and works the page with the
    keyboard alone.
  - `consent.spec.ts` - an operator registers a third-party application
    and a public client with `hodor-cli application add` and `client add`
    (through `docker compose run … server`, as in `totp.spec.ts`); the
    application's site is answered by the test (`page.route`). A signed-in
    person sent to the authorization endpoint is asked on the consent page,
    which passes the accessibility check, allows with the keyboard alone,
    and the application gets a code with its state; the next request gets a
    code at once; withdrawing the application on the account page makes it
    ask again. A person who denies sends the application `access_denied`,
    and the consent page then has nothing to answer.
  - `webauthn.spec.ts` (a virtual authenticator of Chromium, added through
    the DevTools protocol) - a person registers, signs in with a password,
    registers a key through the interaction interface from a page of
    Hodor's origin, signs out, and signs in again with the password and the
    key; the session's methods are `password` and `webauthn`. With a
    virtual platform authenticator that verifies the person, a person
    registers a passkey, signs out and signs in with it alone: once with
    "sign in with a passkey", with the browser made to offer no passkey in
    the field (the virtual authenticator takes such an offer at once), and
    once through the offer in the identifier field; the session's methods
    are `passkey`, multi-factor.

## Invariants

- The stack must be running before `npm run browser-tests`: the server at
  `HODOR_URL`, the development mail server at `HODOR_MAIL_URL`, and a tenant
  `HODOR_TENANT` with open registration that offers the three development
  providers (commands in `stack.ts:HELP`). Otherwise `checkTheStack` stops
  the run before any test. `totp.spec.ts` and `consent.spec.ts` also need `docker compose` on the
  machine that runs the tests, to run `hodor-cli` in the stack.
- Tests run one at a time (`workers: 1`, `fullyParallel: false`), because
  the server limits attempts by the address requests come from and every test
  comes from the same one (comment in `../playwright.config.ts`).
  `retries: 0`; `forbidOnly` when `CI` is set.
- The base address is `HODOR_URL` (default `http://localhost:8080`), the
  browser locale `en-US`, the only project `chromium` (Desktop Chrome).
- Every test fails on any page misbehavior unless it empties `misbehavior`
  itself, as the policy test does after provoking a violation.
- Labels and button names come from `../src/messages/en.ts` (`en`) and
  `../src/messages/pt-BR.ts` (`ptBR`), so the tests follow the catalogs.

## Side Effects

- Registers new people, signs in and out, and asks for recovery links on the
  tenant under test, which makes the server send mail to the development mail
  server. `checkTheStack` itself sends one recovery request for a
  `nobody-{time}@example.com` address on every run.
- Repeated runs can exhaust the tenant's request limit; `checkTheStack`
  reports the `Retry-After` wait when that happens.
- Playwright writes its HTML report (`reporter: html`, `open: "never"`) and
  traces kept on failure (`trace: "retain-on-failure"`); the folders
  `playwright-report` and `test-results` are listed in `../.gitignore`.

## Verification

- With the stack running (see Invariants), run from `frontend/auth-ui`:
  `npm run browser-tests` (`playwright test`). `npm run typecheck` and `npm
  run lint` also cover this directory (`../tsconfig.json` includes
  `browser-tests`).
