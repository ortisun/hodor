# demo/workload-identity

## Overview

What `../workload_identity.py`, the demonstration of Milestone 10, installs on its kind cluster besides Hodor's image. Nothing here is for anything real: the SPIRE agent trusts the kubelet without checking it, the SPIRE server keeps its keys on a small volume, and Hodor is given a private bundle endpoint through the development exception. The script applies or installs every file; none is applied by hand.

## Interface

- `spire.yaml`: the namespace `spire` with a SPIRE server 1.15.5 (`ghcr.io/spiffe/spire-server:1.15.5`, a StatefulSet with a volume) of the trust domain `workloads.example.org`, which attests agents with `k8s_psat` for the cluster named `hodor-milestone-10`, writes its bundle into the ConfigMap `spire-bundle` with the `k8sbundle` notifier, and serves its SPIFFE bundle endpoint with the `https_web` profile on port 8443 of the Service `spire-server` (`https://spire-server.spire.svc:8443`), with the certificate of the Secret `spire-bundle-endpoint`, which the script makes, read again every minute, and a refresh hint of one minute; JWT-SVIDs live five minutes. An agent on every node (DaemonSet `spire-agent`, host network and host process namespace) with the `k8s` workload attestor, its socket at `/run/spire/sockets/agent.sock` on the node. The namespace `elsewhere` with a second server, of `elsewhere.example.org`, with no agent, whose `jwt mint` gives a JWT-SVID of a trust domain no tenant trusts. Based on the Kubernetes quickstart of the SPIRE tutorials, with roles limited to what attestation and the notifier need.
- `istiod-values.yaml`: values of the chart `istiod` 1.30.8: small requests, no autoscaling, and `ENABLE_NATIVE_SIDECARS`, so that the sidecar is a Kubernetes sidecar container that starts before the pod's other containers, which the chart's migration job needs to reach the database through the mesh and to end.
- `hodor-values.yaml`: values of `deploy/install/helm/hodor` for the namespace `hodor`, which Istio injects: `publicUrl` `http://hodor.hodor.svc:8080`, the Secret `hodor-evaluation` of `deploy/install/helm/evaluation.yaml`, `trustedProxies` `127.0.0.6` (Istio's sidecar), `forwardedHeader` `none`, `clientIdentityHeader` `x-forwarded-client-cert`, `outboundAuthorities` the ConfigMap `hodor-outbound-authorities` the script makes, one server and one worker, both with `HODOR_OUTBOUND_DEVELOPMENT_HOSTS` `spire-server.spire.svc:8443`, and the worker with `HODOR_TRUST_BUNDLE_POLL_INTERVAL_MS` `1000`. The image is given by the script.
- `workloads.yaml`: the namespace `payroll`, injected, with the service account `payroll` and the Deployment `payroll`: a container `app` (`curlimages/curl:8.23.0`, sleeping) that calls Hodor, and a container `spiffe` (`ghcr.io/spiffe/spire-agent:1.15.5`, `spire-agent api watch`) with the agent's socket, where the script asks for JWT-SVIDs. The namespace `outside`, not injected, with the Deployment `outsider`, a container `app` with curl and nothing else.

## Invariants

- Istio's sidecar in front of Hodor connects to it from `127.0.0.6`, takes `X-Forwarded-Client-Cert` away from a request that came without a client certificate, and writes the `By`, `Hash`, `Subject` and `URI` of the caller's certificate into it for one that came with one. The demonstration checks each.
- SPIRE's trust domain and the identifiers the script binds, `spiffe://workloads.example.org/ns/payroll/sa/payroll` and `spiffe://cluster.local/ns/payroll/sa/payroll`, follow from the names here: changing a namespace, a service account or a trust domain changes them.

## Verification

`.github/workflows/ci.yml`, job `workload-identity`:

```sh
docker build --file deploy/docker/Dockerfile --tag hodor:milestone-10 .
python3 deploy/demo/workload_identity.py
```
