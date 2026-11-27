# Keys in OpenBao

By default the tenants' signing keys are made and used inside Hodor, wrapped under the root keys of `HODOR_SECRET_KEYS` ([the local provider](../architecture/contexts/keys.md#the-local-provider)). Anyone who holds both the database and the server's configuration then holds every key. With the **OpenBao key provider**, the signing keys are made in [OpenBao](https://openbao.org)'s Transit secrets engine instead, are never exportable, and every signature is made by OpenBao: Hodor keeps a key's name and its public key, never the key.

The [certificate authority of a tenant](#the-certificate-authority-of-a-tenant) can only be created on such a provider ([Decision 0030](../decisions/0030-optional-certificate-authority.md#what-protects-the-key)). The tenants' token signing keys can be put there too, which this page describes.

What stays local: the data keys that seal the tenants' secrets, and the root keys that wrap them ([secrets at rest](../security/secrets-at-rest.md)). `HODOR_SECRET_KEYS` is still required.

## What it means for the installation

- **OpenBao signs every token.** Each token, ID token and logout token of a tenant whose keys are in OpenBao is a request to OpenBao. If OpenBao is down, sealed or unreachable, that tenant issues no token until it answers again, and nothing falls back to the local provider. Run OpenBao with the availability you expect of Hodor, and watch it.
- **OpenBao's keys are not in Hodor's backups.** Hodor's database holds the name of each key, not the key. Back up OpenBao as its own documentation says; a key lost from OpenBao cannot sign again, and its version must be [rotated and revoked](../architecture/contexts/keys.md#rotating-and-revoking-by-hand).
- **Only new keys go to OpenBao.** Keys already made locally keep signing locally until they are replaced. To move every tenant at once, rotate their keys after the switch, then revoke the versions that were replaced once their overlap has passed.
- **The same settings everywhere.** The server signs, the worker makes and rotates keys, and `hodor-cli keys` does both: all three need the same settings below.

## Preparing OpenBao

With the `bao` command line, as an administrator of OpenBao. The names `hodor-transit` and `hodor` are only conventions; use your own if you like, and say so in Hodor's settings.

1. **A Transit mount of Hodor's own.**

    ```bash
    bao secrets enable -path=hodor-transit transit
    ```

2. **Hodor's policy.** `deploy/openbao/hodor-policy.hcl`, shipped with Hodor, allows making signing keys, reading them and signing with them on that mount, and nothing else: it never lets Hodor read, export or back up a key, change a key's settings, rotate or delete one, encrypt, decrypt or reach any other path. If the mount is not `hodor-transit`, replace that name in the file first.

    ```bash
    bao policy write hodor deploy/openbao/hodor-policy.hcl
    ```

    The policy names the types of key Hodor makes: `ecdsa-p256`, `rsa-2048` and, since EdDSA was added, `ed25519`. An installation that wrote it before must write it again from the file of its new version; until then OpenBao refuses the first EdDSA key a client's tokens need, with `keys.provider_refused`, and nothing else changes.

3. **A way for Hodor to sign in**, one of these two.

    **Kubernetes authentication**, when Hodor runs on Kubernetes. Hodor presents a token of its service account, made for the audience `openbao` alone, which OpenBao checks with the cluster:

    ```bash
    bao auth enable kubernetes
    bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc
    bao write auth/kubernetes/role/hodor \
      bound_service_account_names=hodor \
      bound_service_account_namespaces=hodor \
      audience=openbao \
      token_policies=hodor token_ttl=1h token_max_ttl=4h
    ```

    `bound_service_account_names` is the service account of the release, the name of the release unless the chart's `serviceAccount.name` says otherwise. When OpenBao runs outside the cluster, its documentation says what else `auth/kubernetes/config` needs to reach the cluster.

    **An AppRole**, anywhere else:

    ```bash
    bao auth enable approle
    bao write auth/approle/role/hodor token_policies=hodor token_ttl=1h token_max_ttl=4h
    bao read -field=role_id auth/approle/role/hodor/role-id
    bao write -f -field=secret_id auth/approle/role/hodor/secret-id
    ```

    Keep the role identifier and the secret identifier with Hodor's other secrets.

Hodor signs in again before its token expires, and again at once if OpenBao refuses its token, so any token lifetime works; an hour is a reasonable one.

## Settings

Read by `hodor-server`, `hodor-worker` and `hodor-cli` from their environment.

| Variable | Default | Meaning |
|---|---|---|
| `HODOR_KEY_PROVIDER` | `local` | Where new signing keys are made: `local` or `openbao`. `openbao` requires `HODOR_OPENBAO_ADDRESS` |
| `HODOR_OPENBAO_ADDRESS` | Unset | OpenBao's address: `https://`, the name and the port, no path, such as `https://openbao.openbao.svc:8200`. Set, Hodor signs with the keys made in OpenBao whatever `HODOR_KEY_PROVIDER` says; unset, a key made there is refused with `keys.provider_not_configured` |
| `HODOR_OPENBAO_TRANSIT_MOUNT` | `hodor-transit` | The mount of step 1 |
| `HODOR_OPENBAO_AUTH_METHOD` | None, required with the address | `kubernetes` or `approle` |
| `HODOR_OPENBAO_AUTH_MOUNT` | `kubernetes` or `approle` | Where that method is mounted |
| `HODOR_OPENBAO_KUBERNETES_ROLE` | None, required for `kubernetes` | The role of step 3 |
| `HODOR_OPENBAO_KUBERNETES_TOKEN_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | The file of the service account's token. The chart mounts one made for OpenBao at `/var/run/secrets/openbao/token` |
| `HODOR_OPENBAO_APPROLE_ROLE_ID`, `HODOR_OPENBAO_APPROLE_SECRET_ID` | None, required for `approle` | The identifiers of step 3 |
| `HODOR_OPENBAO_CA_FILE` | Unset: the authorities the image trusts | A file of PEM certificates. When set, only these authorities are trusted for OpenBao's certificate |
| `HODOR_OPENBAO_TIMEOUT_MS` | `5000` | How long one request to OpenBao may take, 1 to 60 000 milliseconds. A signature waits for it |

A setting that cannot be used stops the process at startup with `keys.provider_settings_invalid`, naming the variable. Hodor does not call OpenBao when it starts: an OpenBao it cannot reach is found at the first key or signature.

Hodor calls OpenBao's address and nothing else, never through a proxy and without following redirects ([outbound HTTP](../security/outbound-http.md#what-does-not-go-through-this-client)). Plain HTTP is accepted, for a development stack; anywhere else use HTTPS, since the token and what is signed travel on that connection.

On Kubernetes, the chart's `keyProvider` values set all of this, mount the service account's token and the authority's certificate, and refuse `signingKeys: openbao` without OpenBao ([installing on Kubernetes](install-on-kubernetes.md#settings)). With Docker, set the variables in `.env` ([installing with Docker](install-with-docker.md)).

## The certificate authority of a tenant

`HODOR_CERTIFICATE_AUTHORITY`, read by `hodor-server`, turns on the [certificate authority of a tenant](../architecture/contexts/keys.md#the-certificate-authority-of-a-tenant):

| Value | Meaning |
|---|---|
| `off` (the default) | No authority: no route, no bundle endpoint, nothing in the administration interface's document |
| `on` | A tenant's administrator may create the tenant's authority. Its key is made in OpenBao whenever `HODOR_OPENBAO_ADDRESS` is set, whatever `HODOR_KEY_PROVIDER` says; without OpenBao, creating one is refused with `keys.authority_provider_unsuitable` |
| `development` | The same, and without OpenBao the key is made by the local provider, under the root keys of `HODOR_SECRET_KEYS`. Anyone holding the database and the configuration then holds the authority's key: every answer about such an authority says `for_development: true`, and its certificate's name ends in `(development)`. Never on an installation that serves anyone |

`on` and `development` need `HODOR_SECRET_KEYS`: the server refuses to start without it. On Kubernetes, the chart's `certificateAuthority.enabled` sets it to `on`, and `certificateAuthority.development` with it to `development` ([installing on Kubernetes](install-on-kubernetes.md#settings)); `hodor-cli` run in a server's pod reads the same setting.

The authority's key is named in Transit as a version's is, `tenant-<tenant>-version-<key identifier>`, and is used through the same policy: Hodor can make it and sign with it, never read its private part, export it or delete it. Removing a tenant's authority leaves its key in OpenBao; delete it there, as OpenBao's administrator, if it is to be gone. Back the Transit keys up with OpenBao: a lost authority key cannot sign again, and the tenant's meshes then need a new authority.

## How a key is kept

Each version of a tenant's key is a Transit key of its own, named `tenant-<tenant>-version-<version>` with both identifiers, of type `ecdsa-p256` for ES256, `rsa-2048` for RS256 and PS256, each with a key of its own, and `ed25519` for EdDSA. It is never rotated in OpenBao: rotating in Hodor makes a new version, and so a new key. Revoking a version in Hodor leaves its key in OpenBao, unused; deleting it is the administrator's, and Hodor's policy cannot.

A key Hodor finds under that name and did not make, one that is exportable, has a plaintext backup, was imported or rotated, is refused. The [keys context](../architecture/contexts/keys.md#the-openbao-provider) has the rest.

## Errors

| Code | Meaning | What to do |
|---|---|---|
| `keys.provider_unavailable` | OpenBao did not answer in time, could not be reached, or answered with a server error, a sealed OpenBao among them | Bring OpenBao back; nothing else signs in the meantime |
| `keys.provider_sign_in_refused` | OpenBao refused Hodor's sign-in | Check the role, its bound service account, namespace and audience, or the AppRole's identifiers |
| `keys.provider_refused` | Signed in, Hodor was still refused what it asked | Check the policy names Hodor's mount, and that the role gives that policy |
| `keys.provider_failed` | OpenBao answered something Hodor did not ask for: a key it did not make under the name of a version, a key deleted from OpenBao | Rotate the tenant's key, then revoke the version |
| `keys.provider_not_configured` | A version made in OpenBao, while `HODOR_OPENBAO_ADDRESS` is not set | Set the OpenBao settings again |

## In the development stack

The [development stack](quick-start.md) runs OpenBao 2.7.2 in development mode at <http://localhost:8200>, root token `development-root-token`, prepared by `deploy/openbao/setup.sh` exactly as above, with an AppRole whose identifiers are placeholders. The server and the worker are given its settings, and make their signing keys locally unless the stack is started with:

```bash
HODOR_KEY_PROVIDER=openbao docker compose -f deploy/docker/compose.yaml up --build --wait
```

OpenBao in development mode keeps everything in memory: removing its container loses the keys made there, and their versions stop signing. Start afresh with `docker compose -f deploy/docker/compose.yaml down --volumes`.

Continuous integration runs the provider's tests against OpenBao in a container, and runs [the demonstration of Milestone 3](quick-start.md#the-demonstration-of-milestone-3) a second time with the stack's signing keys in OpenBao, then finds the keys there.
