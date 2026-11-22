# Signing in through identity providers

An identity provider is something outside Hodor that knows people and vouches for them. A tenant may trust up to twenty, of four kinds: `openid_connect`, `github`, `ldap` and `saml`. This example adds one of each to the tenant `acme` and signs in through them.

The development stack has a stand-in for three of the kinds, and each of them **lets anyone sign in as anyone**: they are there to be tried, and for nothing else. GitHub has no stand-in; the last section says what it takes to try it.

| Kind | On the stack | Where a person signs in |
|---|---|---|
| OpenID Connect | `provider`, `deploy/dev-provider/provider.mjs` | At the provider, <http://localhost:9400>, which sends them back |
| LDAP directory | `directory`, OpenLDAP with one person, `dora` | On Hodor's own sign-in page; Hodor asks the directory |
| SAML | `saml-provider`, `deploy/dev-saml-provider/saml-provider.mjs` | At the identity provider, <http://localhost:9500>, which posts a signed response back |
| GitHub | None | At GitHub, with an OAuth app you register there |

You need the stack running and the tenant `acme` of the [quick-start](../operations/quick-start.md#2-create-a-tenant). The rules behind every step are in [the federation context](../architecture/contexts/federation.md).

## 1. Add the providers

Each provider is added with `hodor-cli provider add`. Its **alias** is its name in addresses and never changes; its **name** is what the sign-in page shows. A client secret is read from `HODOR_PROVIDER_CLIENT_SECRET`, never from an argument, so that it shows neither in the list of processes nor in the shell's history. It is kept encrypted and is never shown again.

The OpenID Connect provider:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor -e HODOR_PROVIDER_CLIENT_SECRET=development-client-secret server provider add --tenant acme --alias development --name "Development provider" --issuer http://provider:9400 --client-id hodor
```

```text
created development enabled http://provider:9400 http://localhost:8080/t/acme/account/providers/development/callback
register this address at the provider: http://localhost:8080/t/acme/account/providers/development/callback
```

The second line is the address to register at a real provider as the place it sends people back to. The development provider accepts any.

The directory. Hodor binds as `cn=readonly`, whose password is the secret, searches under `ou=people` for the person whose `uid` is what they typed, then checks their password by binding as them. `--trust-email` says that the addresses in this directory are handed out by the organization itself:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor -e HODOR_PROVIDER_CLIENT_SECRET=readonly-password server provider add --tenant acme --alias directory --kind ldap --name "Company directory" --issuer ldap://directory:389 --client-id cn=readonly,dc=example,dc=org --base ou=people,dc=example,dc=org --filter "(uid={identifier})" --trust-email
```

The SAML identity provider. It has no secret: Hodor checks the signature of its responses against its certificate, which is not secret either:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server provider add --tenant acme --alias corp --kind saml --name "Development SAML provider" --issuer urn:hodor:development-saml-provider --sign-on-address http://localhost:9500/sso --certificate "$(cat deploy/dev-saml-provider/certificate.pem)" --trust-email
```

```text
created corp enabled urn:hodor:development-saml-provider http://localhost:8080/t/acme/interaction/sign-in/providers/corp/saml/metadata
give this metadata to the identity provider: http://localhost:8080/t/acme/interaction/sign-in/providers/corp/saml/metadata
```

The metadata address is what a real SAML identity provider is given: Hodor's entity identifier and where to post responses. Open it to see it.

List what the tenant now trusts:

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server provider list --tenant acme
```

```text
corp enabled urn:hodor:development-saml-provider http://localhost:8080/t/acme/interaction/sign-in/providers/corp/saml/metadata
development enabled http://provider:9400 http://localhost:8080/t/acme/account/providers/development/callback
directory enabled ldap://directory:389 -
```

The sign-in page of the tenant, <http://localhost:8080/t/acme/account/sign-in>, now offers the three under the form for a password:

![The sign-in page of the tenant acme: an email address or username, then a button for each identity provider](../images/sign-in.png)

Two settings of the stack make the development providers usable, and neither belongs anywhere real: `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` lets Hodor reach them at private addresses over plain HTTP and LDAP, and `HODOR_DIRECTORY_HOSTS` names the one directory the installation may use. See [outbound HTTP](../security/outbound-http.md#the-exception-for-development).

## 2. Sign in through OpenID Connect

If you are signed in from the quick-start, sign out first: <http://localhost:8080/t/acme/account> has the button.

1. On the sign-in page, choose **Continue with Development provider**. The browser goes to the provider, with a request that carries a `state`, a `nonce` and a PKCE challenge.
2. The provider asks who you would like to be: a subject, an address, whether it vouches for the address, and a name. Keep what it suggests and choose **Sign in**.
3. The browser comes back to Hodor, which exchanges the code, checks the ID token, and signs you in: *You are signed in*.

The first time a subject signs in, Hodor creates a user for it, with the address the provider vouched for, and links the two. The next time, the same subject is the same user. Hodor finds people by provider and subject only, never by address: a provider vouching for the address of someone who registered with a password does not let anyone into their account. [Who the person is](../architecture/contexts/federation.md#who-the-person-is) has the rules.

## 3. Sign in through the directory

Sign out, then:

1. Choose **Continue with Company directory**. Nobody leaves Hodor: the page asks for a username at the directory and a password.
2. Give `dora` and `dora-directory-password`, the person written in `deploy/dev-directory/people.ldif`, and choose **Sign in**.

Hodor searches the directory for `uid=dora`, binds as her with the password, and signs her in as *Dora Directory*, `dora@example.org`. Her identifier in the directory, `entryUUID`, is the subject: renaming her in the directory does not make her someone else.

## 4. Sign in through SAML

Sign out, then:

1. Choose **Continue with Development SAML provider**. The browser goes to <http://localhost:9500/sso> with a SAML request.
2. The identity provider suggests a name identifier, an address and a name. Choose **Sign in**.
3. It makes the browser post a signed response back to Hodor, which checks the signature against the certificate, the audience, the destination and that the response answers the request it sent. You are signed in.

[Signing in through a SAML identity provider](../architecture/contexts/federation.md#signing-in-through-a-saml-identity-provider) has every check, and [the SAML attack corpus](../security/saml-attack-corpus.md) the responses Hodor must refuse.

## 5. See what happened

Get an administrator's token, as in step 4 of the [quick-start](../operations/quick-start.md#4-make-an-administrator), and list the users:

```bash
curl -s http://localhost:8080/t/acme/api/v1/admin/users -H 'Authorization: Bearer <the token>'
```

Each sign-in through a new subject created one user: *Development Person* (`person@example.com`), *Dora Directory* (`dora@example.org`) and *Development SAML Person* (`saml-person@example.com`), next to the person who registered with a password. The audit log has, for each, `identity.user_created`, `federation.identity_linked`, `session.started` and `authentication.succeeded`, among others:

```bash
curl -s http://localhost:8080/t/acme/api/v1/admin/audit-records -H 'Authorization: Bearer <the token>'
```

The admin console shows the same, under **Identity providers** and **Audit records**.

## 6. GitHub

GitHub is not an OpenID Connect provider: it issues no ID token. A provider of the kind `github` asks GitHub's interface who the person is, by their number, never by their login name, which a person can change and another can take afterwards. [Signing in through GitHub](../architecture/contexts/federation.md#signing-in-through-github) has the details.

The stack has no stand-in for GitHub, so trying it takes an OAuth app registered at GitHub:

1. At GitHub, open **Settings → Developer settings → OAuth Apps → New OAuth App**. Give it a name, `http://localhost:8080` as the homepage, and this as the **Authorization callback URL**:

    ```text
    http://localhost:8080/t/acme/account/providers/github/callback
    ```

2. GitHub shows a client identifier. Generate a client secret beside it.

3. Add the provider, with the secret in `HODOR_PROVIDER_CLIENT_SECRET` and the identifier in `--client-id`. The issuer may be left out: it is `https://github.com` unless the provider is an installation of GitHub Enterprise Server.

    ```bash
    docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor -e HODOR_PROVIDER_CLIENT_SECRET=<the client secret> server provider add --tenant acme --alias github --kind github --name "GitHub" --client-id <the client identifier>
    ```

    ```text
    created github enabled https://github.com http://localhost:8080/t/acme/account/providers/github/callback
    register this address at the provider: http://localhost:8080/t/acme/account/providers/github/callback
    ```

4. The sign-in page offers **Continue with GitHub**, which sends the browser to `https://github.com/login/oauth/authorize` with the app's client identifier and the scopes `read:user user:email`.

Hodor takes the address that GitHub marks both primary and verified, or none.

The GitHub connector is built from GitHub's documentation and tested against answers shaped like GitHub's; [progress](../product/progress.md#known-gaps-in-what-is-done) records that no connector has yet been tried against the real provider.

## Turning a provider off

A disabled provider is not offered on the sign-in page and signs nobody in; the people it let in keep their accounts.

```bash
docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor server provider disable --tenant acme --alias development
```

`provider enable` with the same arguments turns it back on.
