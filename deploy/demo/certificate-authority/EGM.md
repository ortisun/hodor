# demo/certificate-authority

## Overview

What `../certificate_authority.py`, the demonstration of Milestone 12, installs on its two kind clusters besides Hodor's chart, the charts of Istio, Linkerd and cert-manager, and the images. Nothing here is for anything real: OpenBao runs in development mode with a known root token, Hodor is reached over plain HTTP between the clusters of one machine, and every resource is small. The script applies or installs every file; none is applied by hand.

## Interface

- `kind-istio.yaml`, `kind-linkerd.yaml`: the two clusters, `hodor-milestone-12-istio` with pods on `10.244.0.0/16` and services on `10.96.0.0/16`, `hodor-milestone-12-linkerd` on `10.245.0.0/16` and `10.97.0.0/16`.
- `istiod-values.yaml`: values of the chart `istiod` 1.30.8: small requests, no autoscaling, `ENABLE_NATIVE_SIDECARS`, the trust domain `east.acme.example`, and ECDSA P-256 keys for the workloads (`ECC_SIGNATURE_ALGORITHM`), since Linkerd's proxy takes no RSA client certificate.
- `hodor-values.yaml`: values of `deploy/install/helm/hodor` for the namespace `hodor`, which Istio injects: `publicUrl` `http://hodor.hodor.svc:8080`, the Secret `hodor-evaluation` of `deploy/install/helm/evaluation.yaml`, `trustedProxies` `127.0.0.6`, `forwardedHeader` `none`, `clientIdentityHeader` `x-forwarded-client-cert`, one server and one worker. The image, the key provider and the certificate authority are given by the script, step by step.
- `forwarded-certificates.yaml`: an `EnvoyFilter` on the sidecar of Hodor's server (`app.kubernetes.io/component: server`), whose inbound HTTP connection manager forwards the caller's certificate with `SANITIZE_SET` and writes its `Subject`, `URI`, `DNS`, `Cert` and `Chain` into `X-Forwarded-Client-Cert`.
- `hodor-outside.yaml`: the Service `hodor-outside`, `NodePort` 30080 to the server's port 8080, where the Linkerd cluster's issuer reaches Hodor.
- `openbao.yaml`: the namespace `openbao` with OpenBao 2.7.2 (`openbao/openbao:2.7.2`, `server -dev`, root token `demonstration-root-token`) behind the Service `openbao` on port 8200, and its service account bound to `system:auth-delegator`, so that its Kubernetes authentication can review the tokens Hodor presents.
- `istio-workloads.yaml`: the namespace `payroll`, injected, with the service account `payroll` and the Deployment `payroll`, a container `app` (`curlimages/curl:8.23.0`, sleeping) that shares a volume with its sidecar, into which the sidecar writes `cert-chain.pem`, `key.pem` and `root-cert.pem` (`OUTPUT_CERTS`).
- `istio-intermediate.yaml`: the `HodorIssuer` `hodor` of `istio-system` and the `Certificate` `istio-intermediate`, kept in the Secret `cacerts`: an ECDSA P-256 authority for 720 hours, renewed after 480.
- `linkerd-intermediate.yaml`: the `HodorIssuer` `hodor` of `linkerd` and the `Certificate` `linkerd-identity-issuer`, kept in the Secret of that name: an ECDSA authority of `identity.linkerd.west.acme.example` for 48 hours, renewed 47 hours and 58 minutes before it expires, two minutes after it is signed; the script changes `renewBefore` to 25 hours once it has seen one renewal.
- `linkerd-workloads.yaml`: the namespace `ledger`, annotated for Linkerd's injection, with the service account `ledger` and the Deployment `ledger` (`traefik/whoami:v1.11.0` on port 8080, answering with the request's headers), behind the Service `ledger`, `NodePort` 30443.

## Invariants

- The identities the script checks follow from the names here: `spiffe://east.acme.example/ns/payroll/sa/payroll` from the trust domain of `istiod-values.yaml` and the namespace and service account of `istio-workloads.yaml`; `ledger.ledger.serviceaccount.identity.linkerd.west.acme.example` from the trust domain the script gives Linkerd and `linkerd-workloads.yaml`. Changing a name changes them.
- The two node ports, 30080 and 30443, are the constants `HODOR_NODE_PORT` and `LEDGER_NODE_PORT` of the script.
- Hodor's sidecar takes away any `X-Forwarded-Client-Cert` a caller sent and writes its own: the header is read from `127.0.0.6` alone.

## Verification

`.github/workflows/ci.yml`, job `certificate-authority`:

```sh
docker build --file deploy/docker/Dockerfile --tag hodor:milestone-12 .
docker build --file deploy/docker/cert-manager-issuer.Dockerfile --tag hodor-cert-manager-issuer:milestone-12 .
python3 deploy/demo/certificate_authority.py
```
