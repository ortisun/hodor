# demo/service-mesh

## Overview

What `../service_mesh.py`, the demonstration of Milestone 11, installs and applies on its two kind clusters besides Hodor's images, following [the service mesh guide](../../../docs/operations/service-mesh.md). Nothing here is for anything real: the stand-ins beside Hodor are those of the evaluation file, Linkerd's trust anchor and the certificate of Envoy Gateway's listener are made by the script with OpenSSL, and the key set Envoy Gateway checks tokens with is copied inline. The script applies or installs every file; none is applied by hand.

## Interface

- `istiod-values.yaml`: values of the chart `istiod` 1.30.8: small, no autoscaling, `ENABLE_NATIVE_SIDECARS`, and `meshConfig.extensionProviders` naming `hodor` as `envoyExtAuthzGrpc` at `hodor-ext-authz.hodor.svc.cluster.local:9191`, with a timeout of two seconds.
- `istio-gateway-values.yaml`: values of the chart `gateway` 1.30.8, installed as the release `istio-ingressgateway` in `istio-system`, whose pods run as the service account of the same name, labelled `istio: ingressgateway`: a Service of type `ClusterIP`, no autoscaling.
- `istio-routes.yaml`: the `Gateway` `istio-system/edge` on port 80 for `login.example.com` and `orders.example.com`, and the `VirtualService`s that send them to `hodor.hodor.svc.cluster.local:8080` and `orders.shop.svc.cluster.local:8080`.
- `istio-orders.yaml`: the `RequestAuthentication` `istio-system/edge` of the ingress gateway, which writes the claims into `x-hodor-token-claims` and forwards the token, and the `RequestAuthentication` and the `AuthorizationPolicy` of action `CUSTOM`, provider `hodor`, of the pods `app: orders`, as the guide writes them; `${issuer}` is filled in by the script.
- `envoy-gateway.yaml`: the `EnvoyProxy` `envoy-gateway-system/meshed`, which puts `envoy.filters.http.jwt_authn` before `envoy.filters.http.ext_authz` and whose proxies run as the Deployment, Service and service account `edge-gateway` with `linkerd.io/inject: enabled` and `config.linkerd.io/skip-inbound-ports: "8080,8443"`, the Service of type `ClusterIP`; the `GatewayClass` `meshed`; the `Gateway` `edge/edge` with the listener `login` (HTTP, 8080, `login.example.com`) and the listener `orders` (HTTPS, 8443, `orders.example.com`, the Secret `edge/orders-tls` the script makes); the `HTTPRoute`s `hodor/hodor` and `shop/orders`; and the `ReferenceGrant` in `hodor` that lets the `SecurityPolicy` of `shop` name the Service `hodor-ext-authz`.
- `envoy-gateway-orders.yaml`: the `SecurityPolicy` `shop/orders` on the route `orders`, with `jwt` (`${issuer}`, the audience `https://orders.example.com`, `localJWKS` of type `Inline` holding `${key_set}`) and `extAuth` to `hodor-ext-authz` on port 9191.
- `linkerd-server.yaml`: the `Server` `shop/orders-http` of the pods `app: orders` on the port `http`, the one `hodor-cli mesh linkerd-policy --server orders-http` writes its policy for.
- `hodor-common.yaml`: values of `deploy/install/helm/hodor` in both clusters: `publicUrl` `http://hodor.hodor.svc:8080`, the Secret `hodor-evaluation`, mail enabled, one small server and one small worker without disruption budgets. The images are given by the script.
- `hodor-istio.yaml`: `mesh.provider: istio`, `mesh.skipOutboundPorts: [1025]` for the stand-in mail server, which speaks first, `gatewayIdentities` `spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway`, the network policy on with `istio-system` and `shop` let in, and `shop` let in to `hodor-ext-authz`.
- `hodor-linkerd.yaml`: `mesh.provider: linkerd`, `mesh.skipOutboundPorts: [1025]`, `gatewayIdentities` `edge-gateway.envoy-gateway-system.serviceaccount.identity.linkerd.cluster.local`, the network policy on with `envoy-gateway-system` and `shop` let in, and `envoy-gateway-system` let in to `hodor-ext-authz`.
- `workloads.yaml`: in `shop`, which the script puts in the mesh, the Deployment and Service `orders` (`traefik/whoami:v1.11.0` on port 8080, named `http`, answering with the request's headers) and the Deployments `web` and `stranger`; in `outside`, the Deployments `visitor-a` and `visitor-b`. Each runs as a service account of its own name; every client is `python:3.13.9-alpine`, sleeping, its container named `app`.
- `client.py`: run by the script in a client's container with `python3 -` and one JSON document as its argument; prints one JSON document. `do` is `request` (a method, an address, headers, a JSON or form body), `sign_in` (a sign-in through `/t/{tenant}/interaction/sign-in` with the cookies and the token against forged requests kept as `deploy/demo/demo.py`'s `Browser` keeps them) or `fail_until_locked_out` (sign-ins with a wrong password, each for another identifier, until `429`, at most `most`). `resolve` maps a host name to the address to connect to, and `authority` is the PEM a gateway's certificate is checked against. Standard library only.

## Invariants

- The identities the script and the values name follow from the names here: Istio's `spiffe://cluster.local/ns/<namespace>/sa/<service account>` and Linkerd's `<service account>.<namespace>.serviceaccount.identity.linkerd.cluster.local`, for `orders`, `web`, `stranger`, `hodor-ext-authz` and the gateways. Changing a namespace or a service account changes them.
- `hodor`, the namespace of Hodor and of the stand-ins, has no label and no annotation: only the pods the chart's `mesh.provider` marks join the mesh.
- Envoy Gateway's listeners use ports of 1024 or more, so its proxies listen on the same ports, which `config.linkerd.io/skip-inbound-ports` names.

## Verification

`.github/workflows/ci.yml`, job `service-mesh`, once for each mesh:

```sh
docker build --file deploy/docker/Dockerfile --tag hodor:milestone-11 .
docker build --file deploy/docker/ext-authz.Dockerfile --tag hodor-ext-authz:milestone-11 .
HODOR_MESH=istio python3 deploy/demo/service_mesh.py
```
