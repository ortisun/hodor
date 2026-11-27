# cert-manager's issuer: `hodor-cert-manager-issuer`

`hodor-cert-manager-issuer` lets [cert-manager](https://cert-manager.io/) keep the intermediates of a tenant's meshes current, signed by [the tenant's certificate authority](../architecture/contexts/keys.md#the-certificate-authority-of-a-tenant): Linkerd's identity issuer, Istio's `cacerts`, SPIRE's upstream authority. It is an outside issuer for cert-manager, a controller that signs the `CertificateRequest`s addressed to it by sending them to Hodor's [signing operation](../api/admin-api.md#intermediates), and only those that are approved and ask for an authority.

It is a binary of its own, in an image of its own, written with the Kubernetes client for Rust. It runs in each cluster whose meshes renew through Hodor, which need not be where Hodor runs, and holds no decision of its own: Hodor checks every request, as it does one an administrator sends, and records each signature with the issuer's service account as the actor. Why it is built this way is in [Decision 0030](../decisions/0030-optional-certificate-authority.md#how-a-mesh-gets-its-intermediate) and [Decision 0074](../decisions/0074-hodor-cert-manager-issuer.md).

```mermaid
sequenceDiagram
    participant Certificate as cert-manager
    participant Approver as Approver
    participant Issuer as hodor-cert-manager-issuer
    participant Hodor
    Certificate->>Certificate: a Certificate is due: a new key and a CertificateRequest
    Approver->>Certificate: Approved
    Issuer->>Issuer: its kind, approved, not denied, an authority?
    Issuer->>Hodor: POST /t/acme/oauth2/token, client credentials, by its key or its mesh identity
    Hodor-->>Issuer: an access token for urn:hodor:certificate-authority
    Issuer->>Hodor: POST /t/acme/api/v1/admin/certificate-authority/intermediates
    Hodor-->>Issuer: the intermediate and the chain, or a refusal with its code
    Issuer->>Certificate: status.certificate and status.ca, Ready; or Ready False with Hodor's reason
    Certificate->>Certificate: tls.crt, tls.key and ca.crt in the Secret
```

## Its kinds

The issuer defines two kinds in the group `hodor.ortisun.github.io`, version `v1alpha1`. A `Certificate` names one of them in its `issuerRef`:

| Kind | Serves | Typical use |
|---|---|---|
| `HodorIssuer` | The requests of its own namespace | One in `linkerd` for Linkerd's identity issuer, one in `istio-system` for Istio's `cacerts` |
| `HodorClusterIssuer` | The requests of every namespace | A cluster where every namespace may have an intermediate signed |

Their `spec` is empty: Hodor's address, the tenant and the client are [the issuer's own configuration](#configuration), so one installation of the issuer serves one tenant. The issuer sets their `Ready` condition: `True` when Hodor gave it an access token on its last try, every minute, and `False` with the reason otherwise.

```yaml
apiVersion: hodor.ortisun.github.io/v1alpha1
kind: HodorIssuer
metadata:
  name: hodor
  namespace: linkerd
spec: {}
```

## What it signs

The issuer watches every `CertificateRequest` of the cluster and takes only those whose `issuerRef` names `HodorIssuer` or `HodorClusterIssuer` in the group `hodor.ortisun.github.io`. Every other request is cert-manager's or another issuer's, and is never read further. Of its own, in this order:

| The request | What the issuer does | Sent to Hodor |
|---|---|---|
| Already finished: `Ready` is `True`, or `False` with the reason `Failed` or `Denied` | Nothing | No |
| Denied: its condition `Denied` is `True` | `Ready` `False`, reason `Denied`, and its failure time | No |
| Not approved: no condition `Approved` that is `True` | Nothing, until it is approved | No |
| Its issuer does not exist: no `HodorIssuer` of that name in the request's namespace, or no `HodorClusterIssuer` of that name | `Ready` `False`, reason `Pending`; looked at again later | No |
| Not for an authority: `spec.isCA` is not `true` | `Ready` `False`, reason `Failed`, and its failure time | No |
| Anything else | Sent, with its certificate signing request and its lifetime | Yes |

**The lifetime** is `spec.duration` in whole days, rounded down, at least one. A request without a duration is signed for the authority's bound on intermediates, 30 days unless the tenant set another. cert-manager gives a `Certificate` without `duration` 90 days, which is longer than the bound: set `duration` on each `Certificate`, as in the examples below.

**cert-manager must write the authority into the request.** Hodor signs only a certificate signing request that asks for an authority in its own basic constraints ([what a request must be](../architecture/contexts/keys.md#what-a-request-must-be)). cert-manager writes them only when its controller runs with the feature gate `UseCertificateRequestBasicConstraints`, which is off by default; without it, every request of a `Certificate` is refused with `keys.intermediate_not_an_authority`, and its condition says so. Install cert-manager with it on, as its chart takes it:

```bash
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager --namespace cert-manager --create-namespace \
  --set crds.enabled=true --set featureGates=UseCertificateRequestBasicConstraints=true
```

Hodor then checks the request as it checks any ([what a request must be](../architecture/contexts/keys.md#what-a-request-must-be)): its names within the authority's trust domains, a path length of zero, name constraints that only narrow, its key, its lifetime.

### What it writes back

| Hodor's answer | `Ready` | Reason | The request |
|---|---|---|---|
| `201`, signed | `True` | `Issued` | `status.certificate`: the intermediate followed by the chain above it, without its last certificate. `status.ca`: that last certificate, the tenant's root. The message names the intermediate's identifier and serial number |
| A refusal: `4xx` but `401`, `403`, `408` and `429` | `False` | `Failed` | The message names Hodor's code and its detail, such as `keys.intermediate_lifetime_invalid: the lifetime is longer than the authority's bound of 30 days`. Its failure time is set, and it is never sent again: cert-manager makes a new request after its own wait |
| No answer, an answer later than the timeout, `5xx`, `408`, `429`; the token endpoint refusing the client; `401` or `403` at the signing operation | `False` | `Pending` | The message says what failed. Looked at again after 10 seconds, then 20, doubling up to 5 minutes, until Hodor answers. A role given late, or Hodor coming back, lets the request through without anyone making it again |

cert-manager then writes the Secret of the `Certificate`: `tls.crt` from `status.certificate`, `ca.crt` from `status.ca`, and `tls.key`, the key it made, which never leaves the cluster.

## Who may have an intermediate signed

**Only approved requests are sent.** Approving a `CertificateRequest` is not the issuer's job: it is an approver's, which cert-manager asks for with the permission `approve` on the signers `hodorissuers.hodor.ortisun.github.io/<namespace>.<name>` and `hodorclusterissuers.hodor.ortisun.github.io/<name>`.

- **cert-manager's own approver** approves every request of an issuer it holds that permission for. The chart gives it that permission for Hodor's two kinds only with `certManagerIssuer.approveWithCertManager.enabled`. Then whoever can create a `CertificateRequest` that names a `HodorIssuer`, in its namespace, or a `HodorClusterIssuer`, anywhere, has an intermediate signed.
- **[approver-policy](https://cert-manager.io/docs/policy/approval/approver-policy/)** approves only the requests its policies allow, such as one common name, one namespace and a lifetime. It is the stricter choice.

Whatever is approved, Hodor signs only within the tenant's trust domains and for the bound, records every signature, and an administrator can [withdraw](../architecture/contexts/keys.md#withdrawing-an-intermediate) any intermediate at once. Prefer `HodorIssuer`, in the namespaces of the meshes, to `HodorClusterIssuer`.

## How it proves who it is to Hodor

The issuer asks the tenant's token endpoint for an access token with the client credentials grant:

```http
POST /t/acme/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=…&resource=urn%3Ahodor%3Acertificate-authority&scope=certificate-authority%3Asign
```

and keeps it until 30 seconds before it expires, or until the signing operation answers `401`, when it asks for another once. The token is good at the signing operation alone ([who may sign](../architecture/contexts/keys.md#who-may-sign)). Its client acts as a service account holding the built-in role `certificate_signer`, and proves who it is in one of two ways:

| `authentication.method` | The client uses | What the issuer holds |
|---|---|---|
| `forwarded` | `spiffe_x509`, `tls_client_auth` or `linkerd_identity`, bound to the identity of the issuer's pod in its mesh: `spiffe://cluster.local/ns/cert-manager/sa/hodor-cert-manager-issuer` in Istio, `hodor-cert-manager-issuer.cert-manager.serviceaccount.identity.linkerd.cluster.local` in Linkerd | Nothing. It sends `client_id` alone; its sidecar presents its certificate to Hodor's, and Hodor reads [the identity the proxy in front of it forwards](../api/api-spec.md#the-callers-identity-from-a-proxy). Hodor must run behind a proxy of the same mesh, with `HODOR_CLIENT_IDENTITY_HEADER` |
| `private_key_jwt` | `private_key_jwt`, with the public part of the issuer's key among its keys | An ECDSA P-256 key, in PEM (PKCS#8), mounted from a Secret. Each request carries an assertion signed with it: `iss` and `sub` the client, `aud` the tenant's issuer, a lifetime of one minute and a fresh `jti` |

`spiffe_jwt` is not offered: a JWT-SVID is used once, and Hodor refuses one seen before ([checking a JWT-SVID](../architecture/contexts/oauth.md#checking-a-jwt-svid)).

To make a key and the JSON Web Key Hodor keeps for it:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out issuer-key.pem
docker run --rm --volume "$PWD:/keys:ro" ghcr.io/ortisun/hodor-cert-manager-issuer:0.4.0 \
  jwk --key /keys/issuer-key.pem --key-id issuer-2026
kubectl create secret generic hodor-cert-manager-issuer-key --namespace cert-manager --from-file=key.pem=issuer-key.pem
```

`jwk` prints the public part alone, `{"kty":"EC","crv":"P-256","x":"…","y":"…","kid":"issuer-2026","use":"sig","alg":"ES256"}`, which is what `POST /clients/{client_id}/keys` takes.

### Setting it up in Hodor

For a tenant `acme` whose certificate authority is active for the trust domain `cluster.local`, with the administration interface and the command-line tool:

1. **Open the audience**, once per tenant: an application, for example "Certificate authority", with a resource server whose audience is `urn:hodor:certificate-authority` and whose one scope is `certificate-authority:sign`.
2. **A service account for the issuer**, `POST /service-accounts`, given the built-in role `certificate_signer`, which holds nothing but signing: `hodor-cli admin grant --tenant acme --user <its identifier> --role certificate_signer`.
3. **Its client**, in that application: a confidential client with the grant `client_credentials`, the service account as `principal`, `certificate-authority:sign` as its one scope, and either the method `spiffe_x509` (or `tls_client_auth`, or `linkerd_identity`) with the issuer's mesh identity, or the method `private_key_jwt` with the issuer's public key added afterwards.
4. **The issuer's configuration**, with the client's `client_id`.

## Configuration

The settings of the process are environment variables. The rest is one JSON file.

| Variable | Default | Meaning |
|---|---|---|
| `HODOR_CERT_MANAGER_ISSUER_CONFIG` | None | The configuration file. Required |
| `HODOR_OPS_ADDR` | `0.0.0.0:9090` | The operations port: `/startupz`, `/readyz` and `/livez` |
| `HODOR_LOG_FORMAT`, `HODOR_LOG_FILTER` | `json`, `info` | As for the server |
| `HODOR_OTLP_METRICS_ENDPOINT`, `HODOR_OTLP_TRACES_ENDPOINT` | Empty | As for the server |
| `KUBECONFIG` | Empty | Read only outside a cluster. Inside one, the issuer uses its pod's service account |

The file:

```json
{
  "hodor": {
    "url": "https://login.example.com",
    "tenant": "acme",
    "issuer": "https://login.example.com/t/acme",
    "timeout_milliseconds": 10000
  },
  "client": {
    "client_id": "0193f3c0-2d4e-7b1a-9c55-6b1f2c9d4e01",
    "authentication": {
      "method": "private_key_jwt",
      "key_file": "/etc/hodor-cert-manager-issuer/key/key.pem",
      "key_id": "issuer-2026"
    }
  }
}
```

| Field | Meaning |
|---|---|
| `hodor.url` | Where the issuer reaches Hodor, `http` or `https`, with no path. Inside a mesh, the plain address of Hodor's Service: the sidecar adds mutual TLS |
| `hodor.tenant` | The tenant's slug |
| `hodor.issuer` | The tenant's issuer, as tokens name it: Hodor's public address followed by `/t/<slug>`. An assertion names it as its audience. Default: `hodor.url` followed by `/t/<slug>`, right only when the two addresses are the same |
| `hodor.timeout_milliseconds` | How long one call to Hodor may take, from 1 to 60000, default 10000 |
| `client.client_id` | The client of [setting it up in Hodor](#setting-it-up-in-hodor) |
| `client.authentication.method` | `forwarded` or `private_key_jwt` |
| `client.authentication.key_file` | For `private_key_jwt`: the file holding the key, in PEM |
| `client.authentication.key_id` | For `private_key_jwt`, if wished: the `kid` of the key among the client's keys. Needed when the client has more than one |

The file is read once when the process starts, and so is the key. A file that does not read, or breaks a rule above, or a key that does not read, stops the process with a message saying why. A change takes a restart.

## What it may do in the cluster

The chart gives the issuer's Kubernetes service account one ClusterRole:

| Resources | Verbs | Why |
|---|---|---|
| `certificaterequests` of `cert-manager.io` | `get`, `list`, `watch` | To find the requests addressed to it |
| `certificaterequests/status` of `cert-manager.io` | `patch` | To write the certificate, or the reason it was not signed |
| `hodorissuers` and `hodorclusterissuers` of `hodor.ortisun.github.io` | `get`, `list`, `watch` | To find the issuer a request names |
| `hodorissuers/status` and `hodorclusterissuers/status` | `patch` | To say whether Hodor gives it a token |

It reads no Secret, and cannot create, change or approve a request. Each change of a request's status names the version it was read at, so a request changed since is read again rather than overwritten.

**One replica.** The issuer runs as a single pod, replaced with the `Recreate` strategy, so that no request is sent twice by two replicas at once. A renewal waits while the pod is replaced; intermediates are renewed long before they expire.

**Its log and metrics.** Each request it acts on is logged with its namespace, name and outcome, never the request or the certificate. The metric `hodor.cert_manager_issuer.requests` counts them by `outcome`: `issued`, `refused`, `denied`, `not_an_authority` and `pending`.

## The image and the chart

The image is `ghcr.io/ortisun/hodor-cert-manager-issuer:<version>`, published and signed with each release beside Hodor's own ([what a release publishes](../security/supply-chain.md#what-a-release-publishes)). It holds the one binary, distroless, as a user that is not root. To build it:

```bash
docker build --file deploy/docker/cert-manager-issuer.Dockerfile --tag registry.example.com/hodor-cert-manager-issuer:0.4.0 .
```

The chart installs it with `certManagerIssuer.enabled`, beside Hodor, or alone with `certManagerIssuer.only` in a cluster where Hodor does not run: the two kinds, a Deployment, its own Kubernetes service account, the ClusterRole above and its binding, and a ConfigMap with the configuration file written from the values. cert-manager must be installed first, with the feature gate of [what it signs](#what-it-signs). [Installing on Kubernetes](install-on-kubernetes.md#cert-managers-issuer) lists the values.

## For Linkerd and Istio

These follow Linkerd's and Istio's documentation on cert-manager, and [the demonstration of Milestone 12](quick-start.md#the-demonstration-of-milestone-12) runs them on kind, with Linkerd edge-26.10.2 and Istio 1.30.8.

Linkerd's identity issuer, for 2 days and renewed 25 hours before it expires, with the trust anchor in `ca.crt`, which Linkerd reads with `identity.externalCA`:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: linkerd-identity-issuer
  namespace: linkerd
spec:
  secretName: linkerd-identity-issuer
  duration: 48h
  renewBefore: 25h
  issuerRef:
    group: hodor.ortisun.github.io
    kind: HodorIssuer
    name: hodor
  commonName: identity.linkerd.cluster.local
  dnsNames:
    - identity.linkerd.cluster.local
  isCA: true
  privateKey:
    algorithm: ECDSA
  usages:
    - cert sign
    - crl sign
```

Istio's intermediate, in the Secret `cacerts`, for 30 days and renewed after 20:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: istio-intermediate
  namespace: istio-system
spec:
  secretName: cacerts
  duration: 720h
  renewBefore: 240h
  issuerRef:
    group: hodor.ortisun.github.io
    kind: HodorIssuer
    name: hodor
  commonName: Istio intermediate of cluster.local
  isCA: true
  privateKey:
    algorithm: ECDSA
    size: 256
  usages:
    - cert sign
    - crl sign
```

The tenant's authority must hold `cluster.local`, or whatever trust domain the mesh uses, among its trust domains.

What else each mesh needs:

- **Linkerd** is installed with `identity.externalCA=true` and `identity.issuer.scheme=kubernetes.io/tls`, so that it reads its issuer from the Secret cert-manager keeps, and reloads it when it is renewed. Its trust anchors are read from the ConfigMap `linkerd-identity-trust-roots`, key `ca-bundle.crt`, which nothing makes for it: fill it with the tenant's root, from the authority's bundle or from `ca.crt`, before Linkerd starts. Linkerd's proxy refuses every SPIFFE identity under an authority that constrains URIs: when a Linkerd mesh must accept the identities of the tenant's Istio meshes or SPIRE servers, create the authority with `uri_constraints` `false` ([Decision 0076](../decisions/0076-names-an-authority-leaves-to-its-meshes.md)). It also takes client certificates of ECDSA keys alone: give Istio's workloads ECDSA keys, with `ECC_SIGNATURE_ALGORITHM: ECDSA` in `meshConfig.defaultConfig.proxyMetadata`, or they present none to Linkerd.
- **Istio** signs istiod's own serving certificate with the intermediate, for `istiod.istio-system.svc` and `istio-pilot.istio-system.svc`: create the authority with `istio-system.svc`, or the namespace istiod runs in, among its `additional_dns_names`, or the Kubernetes interface and the sidecars refuse istiod ([Decision 0076](../decisions/0076-names-an-authority-leaves-to-its-meshes.md)). It reads `cacerts` as cert-manager writes it, `tls.crt`, `tls.key` and `ca.crt`, when istiod starts: restart istiod once the `Certificate` is ready, then the pods of the mesh, so that each takes a certificate under the tenant's root. A mesh that ran on a root of its own until then cannot reach the pods not yet restarted.

## What it does not do yet

| Missing | Until then |
|---|---|
| A JWT-SVID as its credential | It proves who it is with its mesh identity or its key |
| More than one replica, with a leader | One pod, replaced with `Recreate` |
| Hodor's address, tenant or client per issuer resource | One installation of the issuer per tenant |
