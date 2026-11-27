#!/usr/bin/env python3
"""The demonstration of Milestone 11: Hodor in a service mesh.

Makes a kind cluster with Istio and its ingress gateway, and another with
Linkerd and Envoy Gateway in front, or takes the ones it made before, and
installs Hodor in each mesh with its chart, `mesh.provider` and
`hodor-ext-authz`. Then, in each, it does what the service mesh guide says
an operator does. An application, Orders, is protected by the proxy in
front of it, which checks the tenant's tokens and asks `hodor-ext-authz`:
a person who holds its role is let through, one who does not is refused,
and both decisions are in Hodor's record; with Hodor stopped, the call is
refused. Two clients behind the gateway fail passwords until one is locked
out, and the other still signs in; a workload that is not the gateway
writes a forwarded address, and it is ignored. With Linkerd, the policies
`hodor-cli mesh linkerd-policy` writes from Hodor's roles are applied, and
Linkerd itself refuses a workload whose service account holds no role.
Every answer is checked; the first one that is not what it should be stops
the demonstration with a non-zero exit status.

    python3 deploy/demo/service_mesh.py

It needs Python 3, Docker, kind, kubectl, Helm and OpenSSL, and nothing
outside the standard library. It never touches the current context of
kubectl or the repositories of Helm: both are given files of their own, in
a temporary directory. `HODOR_MESH` names one mesh, `istio` or `linkerd`,
for one cluster only. The clusters are left running, for a look and for
the next run; `kind delete cluster --name hodor-milestone-11-istio` and
`--name hodor-milestone-11-linkerd` remove them. See
docs/operations/quick-start.md.
"""

import base64
import json
import os
import string
import subprocess
import sys
import tempfile
import time
from pathlib import Path

IMAGE = os.environ.get("HODOR_IMAGE", "hodor:milestone-11")
EXT_AUTHZ_IMAGE = os.environ.get("HODOR_EXT_AUTHZ_IMAGE", "hodor-ext-authz:milestone-11")
MESHES = [mesh.strip() for mesh in os.environ.get("HODOR_MESH", "istio,linkerd").split(",") if mesh.strip()]
# Where the script reaches Hodor and the stand-in's mailbox, through
# `kubectl port-forward`: from outside the mesh, as an operator does.
PORT = int(os.environ.get("HODOR_PORT", "18111"))
MAIL_PORT = int(os.environ.get("HODOR_MAIL_PORT", "18112"))
SERVER = f"http://localhost:{PORT}"
# The helpers of the other demonstrations read where Hodor is when they are
# imported: this one's port forwards.
os.environ["HODOR_URL"] = SERVER
os.environ["HODOR_MAIL_URL"] = f"http://localhost:{MAIL_PORT}"

from demo import Browser, Failed, check, link_from_message, request, shown, step, until  # noqa: E402
from external_identities import completed, post_form, query_of  # noqa: E402
from strong_authentication import REDIRECT_URI, Application, decode  # noqa: E402
from workload_identity import Cluster, lines_of, released  # noqa: E402

HERE = Path(__file__).resolve().parent / "service-mesh"
REPOSITORY = Path(__file__).resolve().parent.parent.parent
CLIENT = (HERE / "client.py").read_text()
# Where the workloads of the cluster reach Hodor, and what every tenant's
# issuer starts with: publicUrl in hodor-common.yaml.
INSIDE = "http://hodor.hodor.svc:8080"

ISTIO_VERSION = "1.30.8"
ISTIO_CHARTS = "https://istio-release.storage.googleapis.com/charts"
LINKERD_VERSION = "2026.11.1"
LINKERD_CHARTS = "https://helm.linkerd.io/edge"
ENVOY_GATEWAY_VERSION = "1.10.0"
ENVOY_GATEWAY_CHART = "oci://docker.io/envoyproxy/gateway-helm"

API = "urn:hodor:authorization"
ORDERS = "https://orders.example.com"
PASSWORD = "correct horse battery staple"
FORGED_ADDRESS = "198.51.100.7"


class Mesh:
    """What differs between the two meshes."""

    def __init__(self, name):
        self.name = name
        self.istio = name == "istio"
        self.cluster = os.environ.get(f"HODOR_KIND_{name.upper()}_CLUSTER", f"hodor-milestone-11-{name}")
        self.proxy = "istio-proxy" if self.istio else "linkerd-proxy"
        self.method, self.identity_flag = (("spiffe_x509", "--spiffe-id") if self.istio
                                           else ("linkerd_identity", "--linkerd-identity"))
        self.gateway = ("Istio's ingress gateway" if self.istio else "Envoy Gateway")
        # Where the clients outside the mesh connect for login.example.com and
        # orders.example.com: the gateway's Service.
        self.gateway_service = ("istio-ingressgateway.istio-system.svc.cluster.local" if self.istio
                                else "edge-gateway.envoy-gateway-system.svc.cluster.local")
        self.login = "http://login.example.com" if self.istio else "http://login.example.com:8080"
        self.orders = "http://orders.example.com" if self.istio else "https://orders.example.com:8443"
        # What Envoy gives hodor-ext-authz as the destination of a check:
        # behind Istio, Orders' own identity, from its sidecar's certificate;
        # at Envoy Gateway, the certificate of the listener that received the
        # request.
        self.destination = self.identity("shop", "orders") if self.istio else "orders.example.com"

    def identity(self, namespace, account):
        if self.istio:
            return f"spiffe://cluster.local/ns/{namespace}/sa/{account}"
        return f"{account}.{namespace}.serviceaccount.identity.linkerd.cluster.local"


def payload_of(token):
    return token.split(".")[1]


def claims_of(token):
    return json.loads(decode(payload_of(token)))


# ---------------------------------------------------------------------------
# The cluster
# ---------------------------------------------------------------------------

def namespace(cluster, name, labels=None, annotations=None):
    cluster.apply(json.dumps({"apiVersion": "v1", "kind": "Namespace",
                              "metadata": {"name": name, "labels": labels or {},
                                           "annotations": annotations or {}}}))


def templated(name, **values):
    return string.Template((HERE / name).read_text()).substitute(values)


def in_pod(cluster, namespace_name, deployment, document, container="app"):
    """Runs client.py in a workload's own container, as that workload."""
    done = cluster.run("kubectl", "exec", "--stdin", "--namespace", namespace_name, f"deployment/{deployment}",
                       "--container", container, "--", "python3", "-", json.dumps(document), given=CLIENT)
    return json.loads(done.stdout.strip().splitlines()[-1])


def openssl(cluster, *arguments):
    cluster.run("openssl", *arguments)


def a_kind_cluster(cluster, mesh):
    step(f"A kind cluster, {mesh.cluster}, with Hodor's images")
    missing = [tool for tool in ("docker", "kind", "kubectl", "helm", "openssl")
               if subprocess.run(["which", tool], capture_output=True, check=False).returncode != 0]
    check(not missing, "Docker, kind, kubectl, Helm and OpenSSL are on the path"
          + (f" (missing: {', '.join(missing)})" if missing else ""))
    if mesh.cluster in cluster.run("kind", "get", "clusters").stdout.split():
        shown(f"using the cluster {mesh.cluster} made before")
    else:
        shown(f"making the cluster {mesh.cluster}")
        cluster.run("kind", "create", "cluster", "--name", mesh.cluster, "--kubeconfig", str(cluster.kubeconfig),
                    "--wait", "180s")
    cluster.kubeconfig.write_text(cluster.run("kind", "get", "kubeconfig", "--name", mesh.cluster).stdout)
    check(cluster.exists("nodes"), "the cluster answers, through a kubeconfig of this run alone")
    for image, dockerfile in ((IMAGE, "Dockerfile"), (EXT_AUTHZ_IMAGE, "ext-authz.Dockerfile")):
        if cluster.run("docker", "image", "inspect", image, allowed=(0, 1)).returncode != 0:
            shown(f"building {image} from this checkout; the first build takes several minutes")
            cluster.run("docker", "build", "--file", f"deploy/docker/{dockerfile}", "--tag", image, ".",
                        seconds=3600)
        cluster.run("kind", "load", "docker-image", image, "--name", mesh.cluster)
    shown(f"{IMAGE} and {EXT_AUTHZ_IMAGE} are on the cluster's node")


def istio(cluster):
    step(f"Istio {ISTIO_VERSION}, with hodor-ext-authz as a provider, and its ingress gateway")
    namespace(cluster, "istio-system")
    released(cluster, "istio-base", "istio-system", f"{ISTIO_CHARTS}/base-{ISTIO_VERSION}.tgz")
    released(cluster, "istiod", "istio-system", f"{ISTIO_CHARTS}/istiod-{ISTIO_VERSION}.tgz",
             "--values", str(HERE / "istiod-values.yaml"))
    released(cluster, "istio-ingressgateway", "istio-system", f"{ISTIO_CHARTS}/gateway-{ISTIO_VERSION}.tgz",
             "--values", str(HERE / "istio-gateway-values.yaml"))
    account = cluster.kubectl("get", "deployment", "--namespace", "istio-system", "istio-ingressgateway",
                              "--output", "jsonpath={.spec.template.spec.serviceAccountName}")
    check(account == "istio-ingressgateway",
          "the ingress gateway runs as spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway")


def envoy_gateway(cluster):
    step(f"Envoy Gateway {ENVOY_GATEWAY_VERSION}, with the Gateway API's definitions Linkerd needs")
    namespace(cluster, "envoy-gateway-system")
    released(cluster, "eg", "envoy-gateway-system", ENVOY_GATEWAY_CHART, "--version", ENVOY_GATEWAY_VERSION)
    check(cluster.exists("crd", "httproutes.gateway.networking.k8s.io"), "the Gateway API is defined")


def linkerd_certificates(cluster):
    """Linkerd's trust anchor and identity issuer, made with OpenSSL, as
    Linkerd's installation with Helm asks."""
    files = cluster.state / "linkerd"
    files.mkdir(exist_ok=True)
    (files / "extensions.cnf").write_text(
        "[req]\ndistinguished_name = name\n[name]\n"
        "[anchor]\nbasicConstraints = critical, CA:TRUE, pathlen:1\n"
        "keyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n"
        "[issuer]\nbasicConstraints = critical, CA:TRUE, pathlen:0\n"
        "keyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid\n")
    extensions = str(files / "extensions.cnf")
    for key in ("anchor.key", "issuer.key"):
        openssl(cluster, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(files / key))
    openssl(cluster, "req", "-new", "-x509", "-key", str(files / "anchor.key"), "-out", str(files / "anchor.crt"),
            "-days", "365", "-subj", "/CN=root.linkerd.cluster.local", "-config", extensions,
            "-extensions", "anchor")
    openssl(cluster, "req", "-new", "-key", str(files / "issuer.key"), "-out", str(files / "issuer.csr"),
            "-subj", "/CN=identity.linkerd.cluster.local", "-config", extensions)
    openssl(cluster, "x509", "-req", "-in", str(files / "issuer.csr"), "-CA", str(files / "anchor.crt"),
            "-CAkey", str(files / "anchor.key"), "-CAcreateserial", "-out", str(files / "issuer.crt"),
            "-days", "365", "-extfile", extensions, "-extensions", "issuer")
    return files


def linkerd(cluster):
    step(f"Linkerd {LINKERD_VERSION}, whose trust domain is cluster.local")
    namespace(cluster, "linkerd")
    released(cluster, "linkerd-crds", "linkerd", f"{LINKERD_CHARTS}/linkerd-crds-{LINKERD_VERSION}.tgz")
    found = cluster.run("helm", "status", "linkerd-control-plane", "--namespace", "linkerd", allowed=(0, 1))
    if found.returncode == 0 and "STATUS: deployed" in found.stdout:
        shown("Linkerd's control plane was installed before, with its trust anchor")
    else:
        files = linkerd_certificates(cluster)
        released(cluster, "linkerd-control-plane", "linkerd",
                 f"{LINKERD_CHARTS}/linkerd-control-plane-{LINKERD_VERSION}.tgz",
                 "--set-file", f"identityTrustAnchorsPEM={files / 'anchor.crt'}",
                 "--set-file", f"identity.issuer.tls.crtPEM={files / 'issuer.crt'}",
                 "--set-file", f"identity.issuer.tls.keyPEM={files / 'issuer.key'}")
    check(cluster.exists("--namespace", "linkerd", "deployment/linkerd-identity"), "Linkerd's control plane is ready")
    # Linkerd's injector lets a pod through unchanged while it cannot answer,
    # so its deployments being ready is not enough: wait until it injects a
    # pod asked for on a dry run.
    probe = json.dumps({"apiVersion": "v1", "kind": "Pod",
                        "metadata": {"name": "injected", "namespace": "default",
                                     "annotations": {"linkerd.io/inject": "enabled"}},
                        "spec": {"containers": [{"name": "app", "image": "python:3.13.9-alpine"}]}})

    def injects():
        done = cluster.run("kubectl", "create", "--dry-run=server", "--output", "json", "--filename", "-",
                           given=probe, allowed=(0, 1))
        if done.returncode != 0:
            return False
        spec = json.loads(done.stdout)["spec"]
        return any(container["name"] == "linkerd-proxy"
                   for container in spec.get("initContainers", []) + spec["containers"])

    until("Linkerd's proxy injector injecting pods", injects, seconds=180)
    shown("its proxy injector injects a pod asked for on a dry run")


def orders_certificate(cluster):
    """The certificate of Envoy Gateway's listener for orders.example.com,
    under an authority of the demonstration's own: answered in PEM."""
    files = cluster.state / "orders-tls"
    files.mkdir(exist_ok=True)
    (files / "extensions.cnf").write_text(
        "[req]\ndistinguished_name = name\n[name]\n"
        "[authority]\nbasicConstraints = critical, CA:TRUE, pathlen:0\n"
        "keyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n"
        "[listener]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\n"
        "extendedKeyUsage = serverAuth\nsubjectAltName = DNS:orders.example.com\n"
        "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n")
    extensions = str(files / "extensions.cnf")
    for key in ("authority.key", "listener.key"):
        openssl(cluster, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(files / key))
    openssl(cluster, "req", "-new", "-x509", "-key", str(files / "authority.key"), "-out",
            str(files / "authority.crt"), "-days", "30", "-subj", "/CN=Hodor demonstration authority",
            "-config", extensions, "-extensions", "authority")
    openssl(cluster, "req", "-new", "-key", str(files / "listener.key"), "-out", str(files / "listener.csr"),
            "-subj", "/CN=orders.example.com", "-config", extensions)
    openssl(cluster, "x509", "-req", "-in", str(files / "listener.csr"), "-CA", str(files / "authority.crt"),
            "-CAkey", str(files / "authority.key"), "-CAcreateserial", "-out", str(files / "listener.crt"),
            "-days", "30", "-extfile", extensions, "-extensions", "listener")
    cluster.apply(cluster.kubectl("create", "secret", "tls", "orders-tls", "--namespace", "edge",
                                  "--cert", str(files / "listener.crt"), "--key", str(files / "listener.key"),
                                  "--dry-run=client", "--output", "json"))
    return (files / "authority.crt").read_text()


def the_mesh(cluster, mesh):
    """The mesh, its gateway, and the namespaces of the demonstration."""
    authority = None
    if mesh.istio:
        istio(cluster)
        namespace(cluster, "shop", labels={"istio-injection": "enabled"})
    else:
        envoy_gateway(cluster)
        linkerd(cluster)
        namespace(cluster, "shop", annotations={"linkerd.io/inject": "enabled"})
        namespace(cluster, "edge")
        # A run before applied Orders' Server and its policies, which would
        # refuse Envoy Gateway and stranger from the start.
        cluster.kubectl("delete", "--namespace", "shop", "--ignore-not-found",
                        "authorizationpolicies.policy.linkerd.io,meshtlsauthentications.policy.linkerd.io,"
                        "servers.policy.linkerd.io", "--all")
    namespace(cluster, "outside")
    # No label and no annotation: mesh.provider puts Hodor's own pods in the
    # mesh, and the stand-ins beside them stay out.
    namespace(cluster, "hodor")
    if mesh.istio:
        cluster.apply((HERE / "istio-routes.yaml").read_text())
    else:
        step("Envoy Gateway in front of Linkerd, meshed")
        authority = orders_certificate(cluster)
        cluster.apply((HERE / "envoy-gateway.yaml").read_text())

        def made():
            return cluster.exists("--namespace", "envoy-gateway-system", "deployment/edge-gateway")

        until("the gateway's proxies", made, seconds=180)
        cluster.rolled_out("envoy-gateway-system", "deployment/edge-gateway")
        pod = json.loads(cluster.kubectl("get", "pods", "--namespace", "envoy-gateway-system", "--selector",
                                         "gateway.envoyproxy.io/owning-gateway-name=edge", "--output", "json"))
        found = pod["items"][0]
        spec = found["spec"]
        sidecars = [container["name"] for container in spec.get("initContainers", []) + spec["containers"]]
        check("linkerd-proxy" in sidecars and spec["serviceAccountName"] == "edge-gateway",
              "Envoy Gateway's proxy is meshed, as "
              "edge-gateway.envoy-gateway-system.serviceaccount.identity.linkerd.cluster.local"
              + ("" if "linkerd-proxy" in sidecars else
                 f" (its containers: {sidecars}; its account: {spec['serviceAccountName']}; "
                 f"its annotations: {found['metadata'].get('annotations')})"))
    cluster.apply((HERE / "workloads.yaml").read_text())
    for name, namespace_name in (("orders", "shop"), ("web", "shop"), ("stranger", "shop"),
                                 ("visitor-a", "outside"), ("visitor-b", "outside")):
        cluster.rolled_out(namespace_name, f"deployment/{name}")
    shown("orders, web and stranger in the mesh, in shop; visitor-a and visitor-b outside it")
    return authority


def proxied(cluster, selector, proxy):
    spec = json.loads(cluster.kubectl("get", "pods", "--namespace", "hodor", "--selector", selector,
                                      "--output", "json"))["items"][0]["spec"]
    return proxy in [container["name"] for container in spec.get("initContainers", []) + spec["containers"]]


def hodor(cluster, mesh, ext_authz=None):
    """Hodor's chart, in the mesh by mesh.provider; with hodor-ext-authz when
    its values are given."""
    if ext_authz is None:
        step(f"Hodor, installed with its chart, in {mesh.name} by mesh.provider")
        cluster.apply((REPOSITORY / "deploy/install/helm/evaluation.yaml").read_text(), namespace="hodor")
        cluster.rolled_out("hodor", "statefulset/hodor-evaluation-database")
        cluster.rolled_out("hodor", "deployment/hodor-evaluation-mail")
    else:
        step("hodor-ext-authz, beside Hodor and in the mesh with it")
    settings = []
    for name, image in (("hodor", IMAGE), ("ext-authz", EXT_AUTHZ_IMAGE)):
        repository, _, tag = image.rpartition(":")
        prefix = "" if name == "hodor" else "extAuthz."
        settings += ["--set", f"{prefix}image.repository={repository}", "--set", f"{prefix}image.tag={tag}"]
    image_id = cluster.run("docker", "image", "inspect", "--format", "{{.Id}}", IMAGE).stdout.strip()
    values = [str(HERE / "hodor-common.yaml"), str(HERE / f"hodor-{mesh.name}.yaml")]
    if ext_authz is not None:
        written = cluster.state / "ext-authz-values.json"
        written.write_text(json.dumps(ext_authz, indent=2))
        values.append(str(written))
    # The images' identifiers in an annotation restart the pods when an image
    # changed under the same tag.
    released(cluster, "hodor", "hodor", "deploy/install/helm/hodor",
             *[argument for path in values for argument in ("--values", path)], *settings,
             "--set", "image.pullPolicy=Never",
             "--set-string", f"server.podAnnotations.hodor\\.example/image={image_id}",
             "--set-string", f"worker.podAnnotations.hodor\\.example/image={image_id}")
    if ext_authz is None:
        check(proxied(cluster, "app.kubernetes.io/component=server", mesh.proxy),
              f"Hodor's server has {mesh.proxy}, with no label on its namespace")
        check(not proxied(cluster, "app.kubernetes.io/name=hodor-evaluation-database", mesh.proxy),
              "the stand-in database, beside it, stays out of the mesh")
    else:
        cluster.rolled_out("hodor", "deployment/hodor-ext-authz")
        check(proxied(cluster, "app.kubernetes.io/component=ext-authz", mesh.proxy),
              f"hodor-ext-authz has {mesh.proxy}: mesh.provider put it in the mesh")


class Forwards:
    """`kubectl port-forward` to Hodor and to the stand-in's mailbox."""

    def __init__(self, cluster):
        self.cluster = cluster
        self.processes = []

    def start(self):
        for service, local, remote in (("hodor", PORT, 8080), ("hodor-evaluation-mail", MAIL_PORT, 8025)):
            self.processes.append(subprocess.Popen(
                ["kubectl", "port-forward", "--namespace", "hodor", f"service/{service}", f"{local}:{remote}"],
                env=self.cluster.environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

        def answers():
            try:
                return request("GET", f"{SERVER}/t/system/.well-known/openid-configuration").status == 200
            except Failed:
                return False

        until(f"Hodor at {SERVER}", answers)

    def stop(self):
        for process in self.processes:
            process.terminate()
            process.wait()
        self.processes = []


# ---------------------------------------------------------------------------
# The tenant
# ---------------------------------------------------------------------------

class Administrator:
    """A tenant's first administrator, calling the administration interface
    from outside the cluster."""

    def __init__(self, tenant, token, user):
        self.tenant = tenant
        self.user = user
        self.headers = {"Authorization": f"Bearer {token}"}

    def call(self, method, path, body=None, expected=(200, 201, 202, 204)):
        answer = request(method, f"{SERVER}/t/{self.tenant}/api/v1/admin{path}", body, self.headers)
        if answer.status not in expected:
            raise Failed(f"{method} {path} answered {answer.status}: {answer.text}")
        return answer.json() if answer.text else {}


def a_tenant(cluster, tenant, suffix):
    step("A tenant, its administrator, and the mesh's trust domain")
    said = cluster.cli("tenant", "create", "--slug", tenant, "--name", "Acme", "--open-registration")
    check(said.startswith(f"created {tenant} "), f"the command-line tool created {tenant}")
    cluster.cli("keys", "rotate", "--tenant", tenant)
    said = lines_of(cluster.cli("admin", "bootstrap", "--tenant", tenant, "--email", f"operator-{suffix}@example.com"))
    check(said.get("role") == "tenant_administrator", f"operator-{suffix}@example.com administers {tenant}")
    admin = Administrator(tenant, said["token"], said["user"].split()[0])
    said = lines_of(cluster.cli("trust-domain", "add", "--tenant", tenant, "--name", "cluster.local", "--mesh"))
    check(said.get("source") == "mesh", "the tenant trusts cluster.local as checked by the mesh")
    return admin


def orders_in_hodor(cluster, mesh, admin):
    step("Orders in Hodor: its roles, hodor-ext-authz's client, and the workloads' service accounts")
    tenant = admin.tenant
    authorization = admin.call("POST", "/applications", {"name": "Authorization API", "first_party": True})
    admin.call("POST", "/resource-servers", {"application_id": authorization["id"], "audience": API,
                                             "name": "Authorization API",
                                             "scopes": [{"name": "authz:evaluate", "description": "Decisions"}]})
    orders = admin.call("POST", "/applications", {"name": "Orders", "first_party": True})["id"]
    server = admin.call("POST", "/resource-servers", {"application_id": orders, "audience": ORDERS, "name": "Orders",
                                                      "scopes": [{"name": "orders:read",
                                                                  "description": "Read your orders"}]})["id"]
    admin.call("PUT", f"/resource-servers/{server}/permissions/order:read", {"description": "Read an order"})
    admin.call("PUT", f"/resource-servers/{server}/roles/reader", {"permissions": [{"name": "order:read"}]})
    admin.call("PUT", f"/resource-servers/{server}/binding", {"engine": "native"})
    shown(f"the resource server {ORDERS}, whose role reader may read an order")

    def service_account(name, namespace_name, kubernetes_account, scope):
        account = admin.call("POST", "/service-accounts", {"name": name, "owners": [admin.user]})["id"]
        identity = mesh.identity(namespace_name, kubernetes_account)
        said = cluster.cli("client", "add", "--tenant", tenant, "--application", orders, "--name", name,
                           "--type", "confidential", "--grant", "client_credentials", "--scope", scope,
                           "--principal", account, "--method", mesh.method, mesh.identity_flag, identity)
        check("secret" not in said, f"{name}'s client is bound to {identity}, with no secret")
        return account, lines_of(said)["client"]

    _, ext_authz = service_account("hodor-ext-authz", "hodor", "hodor-ext-authz", "authz:evaluate")
    web, _ = service_account("Web", "shop", "web", "orders:read")
    service_account("Stranger", "shop", "stranger", "orders:read")
    admin.call("POST", "/role-assignments", {"principal": {"kind": "user", "id": web},
                                             "role": {"namespace": ORDERS, "name": "reader"}})
    shown("the service account Web holds reader; Stranger and hodor-ext-authz hold no role")
    said = lines_of(cluster.cli("client", "add", "--tenant", tenant, "--application", orders, "--name", "Orders web",
                                "--type", "confidential", "--grant", "authorization_code",
                                "--redirect-uri", REDIRECT_URI, "--scope", "openid", "--scope", "orders:read"))
    check("client" in said and "secret" in said, "Orders' own application signs people in with a client of its own")
    return {"application": orders, "ext_authz": ext_authz,
            "people": Application(tenant, said["client"], said["secret"])}


def a_person(cluster, admin, address):
    """Registers through the link Hodor mails, and signs in."""
    tenant = admin.tenant
    asked = request("POST", f"{SERVER}/t/{tenant}/interaction/registration", {"email": address})
    check(asked.status == 202, f"{tenant} accepted the request to register {address}")
    _, token = link_from_message(address, tenant)
    done = request("POST", f"{SERVER}/t/{tenant}/interaction/registration/complete",
                   {"token": token, "password": PASSWORD})
    check(done.status == 204, f"{address} registered with a password, from the link in the mailbox")
    browser = Browser()
    check(completed(browser.sign_in(tenant, address, PASSWORD)), f"{address} signs in")
    return browser, browser.call("GET", f"/t/{tenant}/interaction/session").json()["user_id"]


def access_token(application, browser):
    """An access token for Orders, from the authorization code a signed-in
    browser gets."""
    answer, parameters, verifier = application.authorize(browser, scope="openid orders:read")
    location = answer.headers.get("Location", "")
    back = query_of(location)
    check(answer.status in (302, 303) and location.startswith(REDIRECT_URI) and "code" in back,
          "the application gets a code at once: the session is enough and the application is the tenant's own")
    basic = base64.b64encode(f"{application.client_id}:{application.secret}".encode()).decode()
    answer = post_form(f"{SERVER}/t/{application.tenant}/oauth2/token",
                       {"grant_type": "authorization_code", "code": back["code"], "redirect_uri": REDIRECT_URI,
                        "code_verifier": verifier}, {"Authorization": f"Basic {basic}"})
    check(answer.status == 200, f"the code is exchanged for tokens (answered {answer.status})")
    token = answer.json()["access_token"]
    claims = claims_of(token)
    audiences = claims.get("aud") if isinstance(claims.get("aud"), list) else [claims.get("aud")]
    check(ORDERS in audiences and claims.get("iss") == f"{INSIDE}/t/{application.tenant}",
          f"the access token is for {ORDERS}, from the tenant's issuer")
    return token


def two_people(cluster, admin, suffix):
    step("Two people: Ana, who holds Orders' role, and Bruno, who holds none")
    people = {}
    for name in ("ana", "bruno"):
        browser, user = a_person(cluster, admin, f"{name}-{suffix}@example.com")
        people[name] = {"address": f"{name}-{suffix}@example.com", "user": user, "browser": browser}
    admin.call("POST", "/role-assignments", {"principal": {"kind": "user", "id": people["ana"]["user"]},
                                             "role": {"namespace": ORDERS, "name": "reader"}})
    shown(f"Ana is {people['ana']['user']} and holds reader; Bruno is {people['bruno']['user']}")
    return people


def their_tokens(setup, people):
    # Made just before they are used: an access token lives five minutes.
    step("Ana's and Bruno's access tokens for Orders, through Orders' own application")
    for person in people.values():
        person["token"] = access_token(setup["people"], person["browser"])


def another_tenants_token(cluster, other):
    """A token of another tenant, for its own resource server of the same
    audience as Orders'."""
    said = cluster.cli("tenant", "create", "--slug", other, "--name", "Globex")
    check(said.startswith(f"created {other} "), f"the command-line tool created {other}")
    cluster.cli("keys", "rotate", "--tenant", other)
    application = cluster.cli("application", "add", "--tenant", other, "--name", "Orders", "--first-party").split()[1]
    cluster.cli("resource-server", "add", "--tenant", other, "--application", application, "--audience", ORDERS,
                "--name", "Orders", "--scope", "orders:read=Read your orders")
    said = lines_of(cluster.cli("client", "add", "--tenant", other, "--application", application, "--name", "Batch",
                                "--type", "confidential", "--grant", "client_credentials", "--scope", "orders:read"))
    basic = base64.b64encode(f"{said['client']}:{said['secret']}".encode()).decode()
    answer = post_form(f"{SERVER}/t/{other}/oauth2/token", {"grant_type": "client_credentials",
                                                           "scope": "orders:read", "resource": ORDERS},
                       {"Authorization": f"Basic {basic}"})
    check(answer.status == 200, f"{other} gives its own client a token for {ORDERS} (answered {answer.status})")
    return answer.json()["access_token"]


# ---------------------------------------------------------------------------
# The demonstration
# ---------------------------------------------------------------------------

def ext_authz_values(mesh, admin, setup, cluster):
    image_id = cluster.run("docker", "image", "inspect", "--format", "{{.Id}}", EXT_AUTHZ_IMAGE).stdout.strip()
    return {"extAuthz": {
        "enabled": True, "replicas": 1, "tenant": admin.tenant,
        "token": {"header": "x-hodor-token-claims"},
        "podDisruptionBudget": {"enabled": False},
        "podAnnotations": {"hodor.example/image": image_id},
        "applications": [{
            "destination": mesh.destination, "clientId": setup["ext_authz"], "audience": ORDERS,
            "routes": [{"methods": ["GET"], "path": "/orders/{id}", "resourceType": "order", "action": "read"}],
        }],
    }}


def protected(cluster, mesh, admin):
    issuer = f"{INSIDE}/t/{admin.tenant}"
    if mesh.istio:
        step("Orders protected by its sidecar: RequestAuthentication, and an AuthorizationPolicy of action CUSTOM")
        cluster.apply(templated("istio-orders.yaml", issuer=issuer))
        shown(f"tokens of {issuer} for {ORDERS}, and every request asked of hodor-ext-authz")
    else:
        step("Orders protected by Envoy Gateway: one SecurityPolicy that checks the token and asks hodor-ext-authz")
        key_set = request("GET", f"{issuer.replace(INSIDE, SERVER)}/oauth2/jwks").text
        cluster.apply(templated("envoy-gateway-orders.yaml", issuer=issuer, key_set=json.dumps(key_set)))
        shown(f"tokens of {issuer} for {ORDERS}, the key set inline, and every request asked of hodor-ext-authz")


def at_orders(cluster, mesh, authority, token=None, claims=None, visitor="visitor-a"):
    """GET /orders/42 from a client outside the mesh, through the gateway."""
    # The host without its port: Envoy Gateway matches a route's host name
    # against the whole Host header, and its listeners are not on port 80.
    headers = {"Host": "orders.example.com"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if claims is not None:
        headers["x-hodor-token-claims"] = claims
    return in_pod(cluster, "outside", visitor, {
        "do": "request", "url": f"{mesh.orders}/orders/42", "headers": headers,
        "resolve": {"orders.example.com": mesh.gateway_service}, "authority": authority})


def last_decisions(admin):
    """What Hodor last decided, to say why a request was not let through."""
    items = admin.call("GET", "/decisions?limit=3")["items"]
    return [{key: item.get(key) for key in ("subject", "namespace", "action", "resource", "effect", "reason")}
            for item in items]


def through_the_gateway(cluster, mesh, admin, authority, people, other_token):
    step(f"Through {mesh.gateway}, Orders as a person who holds its role and as one who does not")
    ana, bruno = people["ana"]["token"], people["bruno"]["token"]
    # Envoy Gateway checks the token and forwards it, but writes no header of
    # its claims and sends hodor-ext-authz none of its metadata: the caller
    # sends the claims of the token it presents, which hodor-ext-authz
    # believes only when they are that token's own.
    ana_claims = None if mesh.istio else payload_of(ana)
    bruno_claims = None if mesh.istio else payload_of(bruno)

    def allowed():
        answer = at_orders(cluster, mesh, authority, ana, ana_claims)
        return answer if answer["status"] == 200 else None

    try:
        answer = until("Ana's request let through, once the proxy has the tenant's keys", allowed, seconds=120)
    except Failed as failure:
        answer = at_orders(cluster, mesh, authority, ana, ana_claims)
        raise Failed(f"{failure}: answered {answer['status']} {answer['text'][:300]}; Hodor's last decisions: "
                     f"{json.dumps(last_decisions(admin))}; Ana is {people['ana']['user']}, her token's sub "
                     f"{claims_of(ana).get('sub')}") from failure
    check("GET /orders/42" in answer["text"], "Ana reads order 42: hodor-ext-authz asked Hodor, which allowed")
    answer = at_orders(cluster, mesh, authority, bruno, bruno_claims)
    check(answer["status"] == 403, f"Bruno is refused with 403 (answered {answer['status']})")
    if mesh.istio:
        answer = at_orders(cluster, mesh, authority)
        check(answer["status"] == 403, f"with no token, the gateway's own identity is no subject Hodor knows: "
                                       f"403 (answered {answer['status']})")
    else:
        answer = at_orders(cluster, mesh, authority)
        check(answer["status"] == 401, f"with no token, Envoy Gateway refuses: 401 (answered {answer['status']})")
        answer = at_orders(cluster, mesh, authority, ana, bruno_claims)
        check(answer["status"] == 403, "Ana's token with Bruno's claims beside it: 403, the claims are not the "
                                       f"token's own (answered {answer['status']})")
    answer = at_orders(cluster, mesh, authority, other_token, None if mesh.istio else payload_of(other_token))
    check(answer["status"] == 401, f"a token of another tenant, for the same audience: 401, the proxy refuses its "
                                   f"issuer (answered {answer['status']})")


def the_record(admin, people):
    step("Both decisions in Hodor's record")
    for name, effect in (("ana", "allow"), ("bruno", "deny")):
        user = people[name]["user"]

        def recorded():
            items = admin.call("GET", f"/decisions?subject_id={user}&limit=20")["items"]
            return next((item for item in items if item["namespace"] == ORDERS and item["effect"] == effect), None)

        found = until(f"the decision about {name.capitalize()}", recorded)
        check(found["action"] == "read" and found["resource"] == {"type": "order", "id": "42"},
              f"{name.capitalize()}: {effect}, {found['reason']}, read on order 42")


def hodor_stopped(cluster, mesh, authority, people, forwards):
    step("Hodor stopped: the call is refused")
    forwards.stop()
    cluster.kubectl("scale", "deployment", "--namespace", "hodor", "hodor-server", "--replicas=0")

    def gone():
        return cluster.kubectl("get", "pods", "--namespace", "hodor", "--selector",
                               "app.kubernetes.io/component=server", "--output", "name").strip() == ""

    until("the server's pods stopped", gone, seconds=180)
    ana = people["ana"]["token"]
    answer = at_orders(cluster, mesh, authority, ana, None if mesh.istio else payload_of(ana))
    check(answer["status"] == 403, f"Ana, who was let through a moment ago, is refused: 403 (answered "
                                   f"{answer['status']})")
    cluster.kubectl("scale", "deployment", "--namespace", "hodor", "hodor-server", "--replicas=1")
    cluster.rolled_out("hodor", "deployment/hodor-server")
    forwards.start()
    shown("Hodor started again")


def pod_address(cluster, namespace_name, selector):
    return cluster.kubectl("get", "pods", "--namespace", namespace_name, "--selector", selector,
                           "--output", "jsonpath={.items[0].status.podIP}")


def sessions_of(admin, user):
    return admin.call("GET", f"/users/{user}/sessions")["items"]


def limited_apart(cluster, mesh, admin, people):
    step(f"Two clients behind {mesh.gateway}, limited apart")
    tenant = admin.tenant
    through = {"server": mesh.login, "tenant": tenant, "resolve": {"login.example.com": mesh.gateway_service},
               "headers": {"Host": "login.example.com"}}
    failed = in_pod(cluster, "outside", "visitor-a", {**through, "do": "fail_until_locked_out", "most": 80})
    check(failed.get("attempts") and failed["attempts"] > 5 and failed.get("code") == "authentication.too_many_attempts",
          f"visitor-a fails passwords until its address is locked out, after {failed.get('attempts')} attempts "
          f"of other identifiers each: the address, not an identifier ({failed})")
    ana = people["ana"]
    answer = in_pod(cluster, "outside", "visitor-a", {**through, "do": "sign_in", "identifier": ana["address"],
                                                       "password": PASSWORD})
    check(answer["status"] == 429, f"Ana, from visitor-a, is refused even with her password: {answer['status']}")
    answer = in_pod(cluster, "outside", "visitor-b", {**through, "do": "sign_in", "identifier": ana["address"],
                                                       "password": PASSWORD})
    check(answer["status"] == 200 and answer["body"].get("status") == "completed",
          f"Ana, from visitor-b behind the same gateway, signs in ({answer['status']})")
    address = pod_address(cluster, "outside", "app=visitor-b")
    addresses = [session["address"] for session in sessions_of(admin, ana["user"])]
    check(address in addresses, f"Hodor knows that session by visitor-b's own address, {address}, which the gateway "
                                f"forwarded and its identity vouched for")


def forwarded_ignored(cluster, mesh, admin, people):
    step("A forwarded address from a workload that is not the gateway, ignored")
    bruno = people["bruno"]
    answer = in_pod(cluster, "shop", "web", {"do": "sign_in", "server": INSIDE, "tenant": admin.tenant,
                                             "identifier": bruno["address"], "password": PASSWORD,
                                             "headers": {"X-Forwarded-For": FORGED_ADDRESS}})
    check(answer["status"] == 200 and answer["body"].get("status") == "completed",
          f"Bruno signs in from web, which writes X-Forwarded-For: {FORGED_ADDRESS}")
    proxy = "127.0.0.6" if mesh.istio else pod_address(cluster, "hodor", "app.kubernetes.io/component=server")
    newest = sessions_of(admin, bruno["user"])[0]["address"]
    check(newest == proxy, f"Hodor knows that session by the address of the proxy beside it, {proxy}, "
                           f"not {FORGED_ADDRESS}: web is not a gateway")


def linkerd_policies(cluster, admin, setup, suffix):
    step("Linkerd's policies, written from Hodor's roles, applied: Linkerd refuses a workload with no role")
    orders = "http://orders.shop.svc.cluster.local:8080/orders/42"
    answer = in_pod(cluster, "shop", "stranger", {"do": "request", "url": orders})
    stranger = "stranger.shop.serviceaccount.identity.linkerd.cluster.local"
    web = "web.shop.serviceaccount.identity.linkerd.cluster.local"
    check(answer["status"] == 200 and stranger in answer["text"],
          f"before any policy, stranger reaches Orders, whose proxy names it {stranger}")
    cluster.apply((HERE / "linkerd-server.yaml").read_text())
    shown("the Server orders-http: Orders' pods and port")

    # hodor-cli in a pod of its own, with the server's settings and a
    # directory it may write in; the server's own file system is read-only.
    template = json.loads(cluster.kubectl("get", "deployment", "--namespace", "hodor", "hodor-server",
                                          "--output", "json"))["spec"]["template"]["spec"]
    name = f"linkerd-policy-{suffix}"
    volume = {"name": "policies", "mountPath": "/policies"}
    cluster.apply(json.dumps({
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": "hodor"},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": template.get("securityContext", {}),
            "initContainers": [{
                "name": "cli", "image": IMAGE, "imagePullPolicy": "Never",
                "command": ["/usr/local/bin/hodor-cli", "mesh", "linkerd-policy", "--tenant", admin.tenant,
                            "--application", setup["application"], "--namespace", "shop", "--server", "orders-http",
                            "--output", "/policies/orders.yaml"],
                "env": template["containers"][0]["env"], "volumeMounts": [volume]}],
            "containers": [{"name": "files", "image": "python:3.13.9-alpine", "command": ["sleep", "infinity"],
                            "volumeMounts": [volume]}],
            "volumes": [{"name": "policies", "emptyDir": {}}]}}))
    waited = cluster.run("kubectl", "wait", "--namespace", "hodor", "--for=condition=Ready", f"pod/{name}",
                         "--timeout=180s", allowed=(0, 1))
    said = cluster.run("kubectl", "logs", "--namespace", "hodor", name, "--container", "cli", allowed=(0, 1)).stdout
    check(waited.returncode == 0, f"hodor-cli mesh linkerd-policy ran: {said.strip()}")
    shown(said.strip())
    policies = cluster.kubectl("exec", "--namespace", "hodor", name, "--container", "files", "--",
                               "cat", "/policies/orders.yaml")
    cluster.kubectl("delete", "pod", "--namespace", "hodor", name, "--wait=false")
    check(web in policies and stranger not in policies,
          f"the MeshTLSAuthentication names {web}, whose service account holds reader, and not stranger")
    cluster.apply(policies)
    shown("applied: the MeshTLSAuthentication and the AuthorizationPolicy")

    def refused():
        answer = in_pod(cluster, "shop", "stranger", {"do": "request", "url": orders})
        return answer if answer["status"] == 403 else None

    until("stranger refused by Linkerd", refused, seconds=60)
    check(True, "stranger, whose service account holds no role, is refused with 403 by Orders' own proxy")

    def let_in():
        answer = in_pod(cluster, "shop", "web", {"do": "request", "url": orders})
        return answer if answer["status"] == 200 else None

    answer = until("web let in by Linkerd", let_in, seconds=60)
    check(web in answer["text"], "web, whose service account holds reader, reaches Orders")


def the_audit_log(cluster, admin):
    step("The audit log")
    check(cluster.cli("audit", "verify", "--tenant", admin.tenant).startswith("intact: "),
          "the audit chain of the tenant is intact")


def in_one_mesh(name, state, suffix):
    mesh = Mesh(name)
    print(f"\n=== Hodor in {name.capitalize()}")
    folder = Path(state) / name
    folder.mkdir()
    cluster = Cluster(folder)
    forwards = Forwards(cluster)
    try:
        a_kind_cluster(cluster, mesh)
        authority = the_mesh(cluster, mesh)
        hodor(cluster, mesh)
        forwards.start()
        admin = a_tenant(cluster, f"acme-{suffix}", suffix)
        setup = orders_in_hodor(cluster, mesh, admin)
        people = two_people(cluster, admin, suffix)
        hodor(cluster, mesh, ext_authz_values(mesh, admin, setup, cluster))
        protected(cluster, mesh, admin)
        their_tokens(setup, people)
        other_token = another_tenants_token(cluster, f"globex-{suffix}")
        through_the_gateway(cluster, mesh, admin, authority, people, other_token)
        the_record(admin, people)
        hodor_stopped(cluster, mesh, authority, people, forwards)
        limited_apart(cluster, mesh, admin, people)
        forwarded_ignored(cluster, mesh, admin, people)
        if not mesh.istio:
            linkerd_policies(cluster, admin, setup, suffix)
        the_audit_log(cluster, admin)
    finally:
        forwards.stop()
    print(f"\nHodor in {name.capitalize()}: passed.")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    unknown = [mesh for mesh in MESHES if mesh not in ("istio", "linkerd")]
    if unknown or not MESHES:
        print(f"HODOR_MESH names istio, linkerd or both, not {', '.join(unknown) or 'nothing'}", file=sys.stderr)
        sys.exit(2)
    suffix = format(int(time.time() * 1000), "x")
    with tempfile.TemporaryDirectory(prefix="hodor-milestone-11-") as state:
        try:
            for name in MESHES:
                in_one_mesh(name, state, suffix)
        except Failed as failure:
            print(f"\nThe demonstration stopped: {failure}", file=sys.stderr)
            sys.exit(1)
    print("\nThe demonstration of Milestone 11 passed.")
    print("The clusters are still running; `kind delete cluster --name` "
          + " and ".join(f"`{Mesh(name).cluster}`" for name in MESHES) + " removes them.")


if __name__ == "__main__":
    main()
