#!/usr/bin/env python3
"""The demonstration of Milestone 12: an optional certificate authority per tenant.

Makes two kind clusters, one with Istio and one with Linkerd, and installs
Hodor with its chart in the Istio cluster's mesh; then does what an
operator, cert-manager and the workloads of two meshes would do. With the
authority off, nothing of it is routed, published or named; on with the
local key provider, creating one is refused. OpenBao is started and
prepared, Hodor's key provider pointed at it, and a tenant's authority
created for the trust domains of both meshes, its name constraints read.
`hodor-cert-manager-issuer` runs in each cluster, and cert-manager keeps
Istio's `cacerts` and Linkerd's identity issuer through it, renewing
Linkerd's with no one acting. A workload of the Istio cluster calls one of
the Linkerd cluster over mutual TLS, each trusting the other's certificate
under the one root. Requests for another tenant's trust domain, for a
certificate that is not an authority and for one past the bound are
refused; an intermediate is withdrawn and Hodor refuses its workloads on
the next request; every signature is in the audit log. Every answer is
checked; the first one that is not what it should be stops the
demonstration with a non-zero exit status.

    python3 deploy/demo/certificate_authority.py

It needs Python 3, Docker, kind, kubectl, Helm and OpenSSL, and nothing
outside the standard library. It never touches the current context of
kubectl or the repositories of Helm: both are given files of their own, in
a temporary directory. Each run starts from two new clusters, removing
those a run before left; they are left running for a look, and
`kind delete cluster --name hodor-milestone-12-istio` and
`--name hodor-milestone-12-linkerd` remove them. See
docs/operations/quick-start.md.
"""

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from demo import Failed, check, request, shown, step, until

HERE = Path(__file__).resolve().parent / "certificate-authority"
REPOSITORY = Path(__file__).resolve().parent.parent.parent
ISTIO_CLUSTER = os.environ.get("HODOR_KIND_ISTIO_CLUSTER", "hodor-milestone-12-istio")
LINKERD_CLUSTER = os.environ.get("HODOR_KIND_LINKERD_CLUSTER", "hodor-milestone-12-linkerd")
IMAGE = os.environ.get("HODOR_IMAGE", "hodor:milestone-12")
ISSUER_IMAGE = os.environ.get("HODOR_ISSUER_IMAGE", "hodor-cert-manager-issuer:milestone-12")
# Where the script reaches Hodor, through `kubectl port-forward`: from
# outside the mesh, as an operator does.
PORT = int(os.environ.get("HODOR_PORT", "18080"))
SERVER = f"http://localhost:{PORT}"
# Where the workloads and the issuers reach Hodor, and what every tenant's
# issuer starts with: publicUrl in hodor-values.yaml.
INSIDE = "http://hodor.hodor.svc:8080"
# The port of the Istio cluster's node where the Linkerd cluster reaches
# Hodor (hodor-outside.yaml), and the one of the Linkerd cluster's node
# where the Istio cluster reaches the ledger (linkerd-workloads.yaml).
HODOR_NODE_PORT = 30080
LEDGER_NODE_PORT = 30443

ISTIO_VERSION = "1.30.8"
ISTIO_CHARTS = "https://istio-release.storage.googleapis.com/charts"
CERT_MANAGER_VERSION = "v1.21.3"
CERT_MANAGER_CHART = "oci://quay.io/jetstack/charts/cert-manager"
LINKERD_VERSION = "2026.10.2"
LINKERD_CHARTS = "https://helm.linkerd.io/edge"
OPENBAO_TOKEN = "demonstration-root-token"

# The trust domains of the two meshes, both the tenant's authority's.
EAST = "east.acme.example"
WEST = "west.acme.example"
# The other tenant's.
GLOBEX_DOMAIN = "west.globex.example"
PAYROLL_ID = f"spiffe://{EAST}/ns/payroll/sa/payroll"
LEDGER_ID = f"ledger.ledger.serviceaccount.identity.linkerd.{WEST}"
LINKERD_ISSUER = f"identity.linkerd.{WEST}"
# Where istiod's own certificate, which Istio's intermediate signs, names it:
# istiod.istio-system.svc and istio-pilot.istio-system.svc.
ISTIO_CONTROL_PLANE = "istio-system.svc"

AUTHORITY_AUDIENCE = "urn:hodor:certificate-authority"
SIGN = "certificate-authority:sign"
PAYROLL = "https://payroll.example.com"


def lines_of(said):
    """The lines a command printed, as `name value`."""
    return dict(line.split(" ", 1) for line in said.splitlines() if " " in line)


def pem_certificates(text):
    """The certificates of a PEM text, in DER, in order."""
    return [base64.b64decode("".join(body.split()))
            for body in re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S)]


def to_pem(der):
    body = base64.b64encode(der).decode()
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(
        body[i:i + 64] for i in range(0, len(body), 64)) + "\n-----END CERTIFICATE-----\n"


def sha256(der):
    return hashlib.sha256(der).hexdigest()


# ---------------------------------------------------------------------------
# The clusters, through tools of their own
# ---------------------------------------------------------------------------

class Cluster:
    """A kind cluster, reached with a kubeconfig and Helm settings that
    belong to this run alone."""

    def __init__(self, state, name):
        self.name = name
        self.state = Path(state)
        self.kubeconfig = self.state / f"{name}.kubeconfig"
        self.environment = {
            **os.environ,
            "KUBECONFIG": str(self.kubeconfig),
            "HELM_CACHE_HOME": str(self.state / "helm" / "cache"),
            "HELM_CONFIG_HOME": str(self.state / "helm" / "config"),
            "HELM_DATA_HOME": str(self.state / "helm" / "data"),
        }

    def run(self, *arguments, given=None, allowed=(0,), seconds=900):
        done = subprocess.run(arguments, input=given, capture_output=True, text=True, check=False,
                              env=self.environment, cwd=REPOSITORY, timeout=seconds)
        if done.returncode not in allowed:
            said = (done.stderr.strip() or done.stdout.strip())[-2000:]
            raise Failed(f"{' '.join(arguments[:5])} … exited with {done.returncode}: {said}")
        return done

    def kubectl(self, *arguments, given=None, allowed=(0,)):
        return self.run("kubectl", *arguments, given=given, allowed=allowed).stdout

    def apply(self, manifest, namespace=None):
        within = ["--namespace", namespace] if namespace else []
        self.kubectl("apply", *within, "--filename", "-", given=manifest)

    def exists(self, *arguments):
        return self.run("kubectl", "get", *arguments, allowed=(0, 1)).returncode == 0

    def rolled_out(self, namespace, kind, seconds=300):
        self.kubectl("rollout", "status", "--namespace", namespace, kind, f"--timeout={seconds}s")

    def restarted(self, namespace, *kinds):
        """Replaces the pods of each, and waits for the new ones."""
        for kind in kinds:
            self.kubectl("rollout", "restart", "--namespace", namespace, kind)
        for kind in kinds:
            self.rolled_out(namespace, kind)

    def exec(self, namespace, target, container, *command, given=None, allowed=(0,)):
        interactive = ["--stdin"] if given is not None else []
        return self.run("kubectl", "exec", *interactive, "--namespace", namespace, target, "--container",
                        container, "--", *command, given=given, allowed=allowed)

    def cli(self, *arguments, given=None, allowed=(0,)):
        """`hodor-cli` in the server's pod, with the server's settings."""
        return self.exec("hodor", "deployment/hodor-server", "server", "/usr/local/bin/hodor-cli", *arguments,
                         given=given, allowed=allowed)

    def bao(self, *arguments, given=None, allowed=(0,)):
        """OpenBao's command line, in its pod, with the root token."""
        return self.exec("openbao", "deployment/openbao", "openbao", "env", "BAO_ADDR=http://127.0.0.1:8200",
                         f"BAO_TOKEN={OPENBAO_TOKEN}", "bao", *arguments, given=given, allowed=allowed)

    def secret(self, namespace, name, key):
        data = json.loads(self.kubectl("get", "secret", "--namespace", namespace, name, "--output", "json"))
        return base64.b64decode(data["data"][key]).decode()

    def node_address(self):
        return self.run("docker", "inspect", "--format", "{{.NetworkSettings.Networks.kind.IPAddress}}",
                        f"{self.name}-control-plane").stdout.strip()


def released(cluster, release, namespace, chart, *settings):
    """`helm upgrade --install`, after taking away what a run stopped in the
    middle of an installation left behind."""
    found = cluster.run("helm", "status", release, "--namespace", namespace, "--output", "json", allowed=(0, 1))
    if found.returncode == 0 and json.loads(found.stdout).get("info", {}).get("status", "").startswith("pending"):
        shown(f"taking away the release {release}, left unfinished by a run before")
        cluster.run("helm", "uninstall", release, "--namespace", namespace, "--wait")
    cluster.run("helm", "upgrade", "--install", release, chart, "--namespace", namespace, "--create-namespace",
                *settings, "--wait", "--timeout", "10m")


def namespace(cluster, name, labels=None):
    cluster.apply(json.dumps({"apiVersion": "v1", "kind": "Namespace",
                              "metadata": {"name": name, "labels": labels or {}}}))


class Forward:
    """`kubectl port-forward` to Hodor's service, started again whenever
    Hodor's server is replaced."""

    def __init__(self, cluster):
        self.cluster = cluster
        self.process = None

    def start(self):
        self.stop()
        self.process = subprocess.Popen(["kubectl", "port-forward", "--namespace", "hodor", "service/hodor",
                                         f"{PORT}:8080"], env=self.cluster.environment,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def answers():
            try:
                return request("GET", f"{SERVER}/t/system/.well-known/openid-configuration").status == 200
            except Failed:
                return False

        until(f"Hodor at {SERVER}", answers)

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            self.process.wait()
            self.process = None


# ---------------------------------------------------------------------------
# Setting the clusters up
# ---------------------------------------------------------------------------

def tools_present():
    missing = [tool for tool in ("docker", "kind", "kubectl", "helm", "openssl") if shutil.which(tool) is None]
    check(not missing, "Docker, kind, kubectl, Helm and OpenSSL are on the path"
          + (f" (missing: {', '.join(missing)})" if missing else ""))


def two_kind_clusters(istio, linkerd):
    step(f"Two new kind clusters, {ISTIO_CLUSTER} and {LINKERD_CLUSTER}, with Hodor's images")
    tools_present()
    known = istio.run("kind", "get", "clusters").stdout.split()
    for cluster, config in ((istio, "kind-istio.yaml"), (linkerd, "kind-linkerd.yaml")):
        if cluster.name in known:
            shown(f"removing the cluster {cluster.name} a run before left")
            cluster.run("kind", "delete", "cluster", "--name", cluster.name)
        cluster.run("kind", "create", "cluster", "--name", cluster.name, "--config", str(HERE / config),
                    "--kubeconfig", str(cluster.kubeconfig), "--wait", "180s")
        check(cluster.exists("nodes"), f"{cluster.name} answers, through a kubeconfig of this run alone")
    for image, dockerfile in ((IMAGE, "Dockerfile"), (ISSUER_IMAGE, "cert-manager-issuer.Dockerfile")):
        if istio.run("docker", "image", "inspect", image, allowed=(0, 1)).returncode != 0:
            shown(f"building {image} from this checkout; the first build takes several minutes")
            istio.run("docker", "build", "--file", f"deploy/docker/{dockerfile}", "--tag", image, ".",
                      seconds=3600)
    istio.run("kind", "load", "docker-image", IMAGE, ISSUER_IMAGE, "--name", istio.name)
    linkerd.run("kind", "load", "docker-image", ISSUER_IMAGE, "--name", linkerd.name)
    shown(f"{IMAGE} and {ISSUER_IMAGE} are on the nodes of the Istio cluster, {ISSUER_IMAGE} on the Linkerd one's")


def istio_mesh(cluster):
    step(f"Istio {ISTIO_VERSION}, whose trust domain is {EAST}, on its own root for now")
    released(cluster, "istio-base", "istio-system", f"{ISTIO_CHARTS}/base-{ISTIO_VERSION}.tgz")
    released(cluster, "istiod", "istio-system", f"{ISTIO_CHARTS}/istiod-{ISTIO_VERSION}.tgz",
             "--values", str(HERE / "istiod-values.yaml"))
    check(cluster.exists("--namespace", "istio-system", "deployment/istiod"), "Istio's control plane is ready")


def cert_manager(cluster):
    released(cluster, "cert-manager", "cert-manager", CERT_MANAGER_CHART, "--version", CERT_MANAGER_VERSION,
             "--set", "crds.enabled=true", "--set", "featureGates=UseCertificateRequestBasicConstraints=true")
    arguments = cluster.kubectl("get", "deployment", "--namespace", "cert-manager", "cert-manager", "--output",
                                "jsonpath={.spec.template.spec.containers[0].args}")
    check("UseCertificateRequestBasicConstraints=true" in arguments,
          f"cert-manager {CERT_MANAGER_VERSION} in {cluster.name}, its controller writing the authority into "
          f"each request it makes (UseCertificateRequestBasicConstraints)")


def hodor_settings(*settings):
    repository, _, tag = IMAGE.rpartition(":")
    return ["--values", str(HERE / "hodor-values.yaml"), "--set", f"image.repository={repository}",
            "--set", f"image.tag={tag}", "--set", "image.pullPolicy=Never", *settings]


def hodor(cluster, forward, *settings):
    """Hodor's chart with these settings, its pods replaced and the port
    forward started again."""
    released(cluster, "hodor", "hodor", "deploy/install/helm/hodor", *hodor_settings(*settings))
    cluster.rolled_out("hodor", "deployment/hodor-server")
    cluster.rolled_out("hodor", "deployment/hodor-worker")
    forward.start()


def hodor_in_the_mesh(cluster, forward):
    step("Hodor, installed with its chart, in the Istio cluster's mesh, the authority off")
    namespace(cluster, "hodor", {"istio-injection": "enabled"})
    cluster.apply((REPOSITORY / "deploy/install/helm/evaluation.yaml").read_text(), namespace="hodor")
    cluster.rolled_out("hodor", "statefulset/hodor-evaluation-database")
    hodor(cluster, forward)
    containers = cluster.kubectl("get", "pods", "--namespace", "hodor", "--selector",
                                 "app.kubernetes.io/component=server", "--output",
                                 "jsonpath={.items[*].spec.initContainers[*].name}")
    check("istio-proxy" in containers.split(), "Hodor's server has Istio's sidecar")
    cluster.apply((HERE / "forwarded-certificates.yaml").read_text())
    cluster.apply((HERE / "hodor-outside.yaml").read_text())
    cluster.apply((HERE / "istio-workloads.yaml").read_text())
    cluster.rolled_out("payroll", "deployment/payroll")
    shown("Hodor's sidecar forwards the caller's certificate and its chain; payroll is in the mesh")


# ---------------------------------------------------------------------------
# The demonstration
# ---------------------------------------------------------------------------

class Administrator:
    """A tenant's first administrator, calling the administration interface
    from outside the cluster."""

    def __init__(self, tenant, tenant_id, token, user):
        self.tenant = tenant
        self.tenant_id = tenant_id
        self.user = user
        self.headers = {"Authorization": f"Bearer {token}"}

    def answer(self, method, path, body=None):
        return request(method, f"{SERVER}/t/{self.tenant}/api/v1/admin{path}", body, self.headers)

    def call(self, method, path, body=None, expected=(200, 201, 202, 204)):
        answer = self.answer(method, path, body)
        if answer.status not in expected:
            raise Failed(f"{method} {path} answered {answer.status}: {answer.text}")
        return answer.json() if answer.text else {}


def two_tenants(cluster, tenant, other, suffix):
    step("Two tenants, and their administrators")
    admins = []
    for slug, name, address in [(tenant, "Acme", f"operator-{suffix}@example.com"),
                                (other, "Globex", f"operator-globex-{suffix}@example.com")]:
        said = cluster.cli("tenant", "create", "--slug", slug, "--name", name).stdout.strip()
        check(said.startswith(f"created {slug} "), f"the command-line tool created {slug}")
        cluster.cli("keys", "rotate", "--tenant", slug)
        made = lines_of(cluster.cli("admin", "bootstrap", "--tenant", slug, "--email", address).stdout)
        check(made.get("role") == "tenant_administrator", f"{address} is an administrator of {slug}")
        admins.append(Administrator(slug, said.split()[2], made["token"], made["user"].split()[0]))
    return admins


def mentions_the_authority(text):
    return "certificate-authority" in text or "certificate_authority" in text


def the_authority_off(cluster, admin):
    step("With the authority off, nothing of it")
    document = request("GET", f"{SERVER}/t/{admin.tenant}/api/v1/admin/openapi.json").json()
    paths = sorted(path for path in document.get("paths", {}) if mentions_the_authority(path))
    check(document.get("paths") and not paths,
          f"the administration interface's document names none of its operations, of {len(document['paths'])}")
    answer = admin.answer("POST", "/certificate-authority", {"kind": "root", "trust_domains": [EAST]})
    check(answer.status == 404, f"POST /certificate-authority is no route: {answer.status}")
    answer = request("GET", f"{SERVER}/t/{admin.tenant}/certificate-authority/bundle")
    check(answer.status == 404, f"no bundle is published: {answer.status}")
    discovery = request("GET", f"{SERVER}/t/{admin.tenant}/.well-known/openid-configuration")
    check(discovery.status == 200 and not mentions_the_authority(discovery.text),
          "the tenant's discovery document does not mention it")
    done = cluster.cli("authority", "intermediates", "--tenant", admin.tenant, allowed=(0, 1))
    check(done.returncode == 1 and "keys.authority_setting_invalid" in done.stderr + done.stdout,
          "hodor-cli authority refuses with keys.authority_setting_invalid")


def on_the_local_key_provider(cluster, forward, admin):
    step("Turned on, on the local key provider: refused")
    hodor(cluster, forward, "--set", "certificateAuthority.enabled=true")
    document = request("GET", f"{SERVER}/t/{admin.tenant}/api/v1/admin/openapi.json").json()
    operations = [f"{method.upper()} {path}" for path, methods in document["paths"].items()
                  if mentions_the_authority(path) for method in methods]
    check(len(operations) == 8, f"the document names its eight operations now: {', '.join(operations)}")
    answer = admin.answer("POST", "/certificate-authority", {"kind": "root", "trust_domains": [EAST, WEST]})
    check(answer.status == 409 and answer.code == "keys.authority_provider_unsuitable",
          f"creating one is refused: {answer.status} {answer.code}, the local provider keeps keys where Hodor "
          f"can read them")


def openbao(cluster, forward, admin):
    step("OpenBao, prepared for Hodor, and Hodor's key provider pointed at it")
    cluster.apply((HERE / "openbao.yaml").read_text())
    cluster.rolled_out("openbao", "deployment/openbao")
    until("OpenBao", lambda: cluster.bao("status", allowed=(0, 1, 2)).returncode == 0)
    if "hodor-transit/" not in cluster.bao("secrets", "list").stdout:
        cluster.bao("secrets", "enable", "-path=hodor-transit", "transit")
    cluster.bao("policy", "write", "hodor", "-", given=(REPOSITORY / "deploy/openbao/hodor-policy.hcl").read_text())
    if "kubernetes/" not in cluster.bao("auth", "list").stdout:
        cluster.bao("auth", "enable", "kubernetes")
    cluster.bao("write", "auth/kubernetes/config", "kubernetes_host=https://kubernetes.default.svc")
    cluster.bao("write", "auth/kubernetes/role/hodor", "bound_service_account_names=hodor",
                "bound_service_account_namespaces=hodor", "audience=openbao", "token_policies=hodor",
                "token_ttl=1h", "token_max_ttl=4h")
    shown("Transit at hodor-transit, Hodor's policy, and Kubernetes authentication for Hodor's service account")
    hodor(cluster, forward, "--set", "certificateAuthority.enabled=true", "--set", "keyProvider.signingKeys=openbao",
          "--set", "keyProvider.openbao.enabled=true",
          "--set", "keyProvider.openbao.address=http://openbao.openbao.svc:8200")
    said = cluster.cli("keys", "rotate", "--tenant", admin.tenant).stdout
    keys = json.loads(cluster.bao("list", "-format=json", "hodor-transit/keys").stdout)
    mine = [key for key in keys if key.startswith(f"tenant-{admin.tenant_id}-version-")]
    check(mine, f"the tenant's new signing key is made in OpenBao: {mine[0] if mine else said.strip()}")


def an_authority(cluster, admin):
    step(f"The tenant's authority, for {EAST} and {WEST}, its key in OpenBao")
    created = admin.call("POST", "/certificate-authority", {
        "kind": "root", "trust_domains": [EAST, WEST], "common_name": "Acme meshes",
        "intermediate_lifetime_days": 30, "uri_constraints": False,
        "additional_dns_names": [ISTIO_CONTROL_PLANE]})
    check(created["state"] == "active" and created["key"]["provider"] == "openbao"
          and created["for_development"] is False,
          f"a root, active at once, its key made by {created['key']['provider']}")
    constraints = created["name_constraints"]
    shown(f"name constraints: {json.dumps(constraints)}")
    check(constraints == {"permitted_uris": [], "permitted_dns_names": [EAST, WEST, ISTIO_CONTROL_PLANE],
                          "excluded_ip_ranges": ["0.0.0.0/0", "::/0"]},
          f"it permits the DNS names of both trust domains, and {ISTIO_CONTROL_PLANE}, where istiod serves "
          f"under Istio's intermediate, and excludes every address; URIs are left unconstrained, since "
          f"Linkerd's proxy refuses every SPIFFE identity under an authority that constrains them "
          f"(Decision 0076)")
    certificate = created["certificate"]
    read = cluster.run("openssl", "x509", "-noout", "-subject", "-ext", "basicConstraints,nameConstraints",
                       given=certificate).stdout
    shown(" ".join(read.split()))
    check(re.search(r"CA:TRUE, pathlen:1", read) and f"DNS:{EAST}" in read and f"DNS:{WEST}" in read
          and f"DNS:{ISTIO_CONTROL_PLANE}" in read and "URI:" not in read, "OpenSSL reads the same in its certificate, an authority of path length one")
    name = f"tenant-{admin.tenant_id}-version-{created['key']['id']}"
    key = json.loads(cluster.bao("read", "-format=json", f"hodor-transit/keys/{name}").stdout)["data"]
    check(key["type"] == "ecdsa-p256" and key["exportable"] is False and key["allow_plaintext_backup"] is False,
          f"OpenBao holds its key, {name}: ecdsa-p256, not exportable, no plaintext backup")
    bundle = request("GET", f"{SERVER}/t/{admin.tenant}/certificate-authority/bundle").json()
    root = base64.b64decode(bundle["keys"][0]["x5c"][0])
    check(root == pem_certificates(certificate)[0],
          f"its bundle is published under the tenant's issuer, {created['bundle_endpoint']}")
    domains = {item["name"]: item["source"] for item in admin.call("GET", "/trust-domains")["items"]}
    check(domains == {EAST: "authority", WEST: "authority"}, "Hodor trusts it for both trust domains")
    return to_pem(root)


def signing_clients(cluster, admin, state):
    step("A service account that signs, and a client of it for each cluster's issuer")
    application = admin.call("POST", "/applications", {"name": "Certificate authority", "first_party": True})["id"]
    admin.call("POST", "/resource-servers", {"application_id": application, "audience": AUTHORITY_AUDIENCE,
                                             "name": "Certificate authority",
                                             "scopes": [{"name": SIGN, "description": "Sign intermediates"}]})
    account = admin.call("POST", "/service-accounts", {"name": "cert-manager", "owners": [admin.user]})["id"]
    said = cluster.cli("admin", "grant", "--tenant", admin.tenant, "--user", account,
                       "--role", "certificate_signer").stdout
    check(said.startswith("granted certificate_signer"),
          f"the service account cert-manager, {account}, holds certificate_signer and nothing else")
    clients = {}
    for mesh in ("istio", "linkerd"):
        keys = Path(state) / f"issuer-{mesh}"
        keys.mkdir()
        key = keys / "key.pem"
        cluster.run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-out", str(key))
        key.chmod(0o644)
        keys.chmod(0o755)
        jwk = json.loads(cluster.run("docker", "run", "--rm", "--volume", f"{keys}:/keys:ro", ISSUER_IMAGE,
                                     "jwk", "--key", "/keys/key.pem", "--key-id", mesh).stdout)
        check(jwk.get("kid") == mesh and "d" not in jwk,
              f"hodor-cert-manager-issuer jwk prints the public part of the {mesh} issuer's key")
        client = admin.call("POST", f"/applications/{application}/clients", {
            "name": f"cert-manager of the {mesh} cluster", "type": "confidential", "principal": account,
            "grant_types": ["client_credentials"], "allowed_scopes": [SIGN],
            "authentication_method": "private_key_jwt"})["id"]
        admin.call("POST", f"/clients/{client}/keys", {"jwk": jwk})
        clients[mesh] = (client, key)
        shown(f"the {mesh} issuer's client, {client}, proves who it is with private_key_jwt")
    return account, clients


def issuer(cluster, admin, client, key, url):
    """`hodor-cert-manager-issuer`, from the chart alone, in the namespace
    of cert-manager, approved for by cert-manager's own approver."""
    secret = cluster.kubectl("create", "secret", "generic", "hodor-cert-manager-issuer-key", "--namespace",
                             "cert-manager", f"--from-file=key.pem={key}", "--dry-run=client", "--output", "json")
    cluster.apply(secret)
    repository, _, tag = ISSUER_IMAGE.rpartition(":")
    released(cluster, "hodor-issuer", "cert-manager", "deploy/install/helm/hodor",
             "--set", "certManagerIssuer.enabled=true", "--set", "certManagerIssuer.only=true",
             "--set", f"certManagerIssuer.image.repository={repository}",
             "--set", f"certManagerIssuer.image.tag={tag}", "--set", "image.pullPolicy=Never",
             "--set", f"certManagerIssuer.tenant={admin.tenant}", "--set", f"certManagerIssuer.hodorUrl={url}",
             "--set", f"certManagerIssuer.issuer={INSIDE}/t/{admin.tenant}",
             "--set", f"certManagerIssuer.clientId={client}",
             "--set", "certManagerIssuer.authentication.method=private_key_jwt",
             "--set", "certManagerIssuer.authentication.privateKeyJwt.secretName=hodor-cert-manager-issuer-key",
             "--set", "certManagerIssuer.approveWithCertManager.enabled=true")
    cluster.rolled_out("cert-manager", "deployment/hodor-issuer-cert-manager-issuer")


def issued(cluster, namespace_name, certificate):
    """Waits for a Certificate to be ready, and answers the message of the
    request that was signed for it."""
    cluster.kubectl("wait", "--namespace", namespace_name, f"certificate/{certificate}", "--for=condition=Ready",
                    "--timeout=180s")
    requests = json.loads(cluster.kubectl("get", "certificaterequests", "--namespace", namespace_name,
                                          "--output", "json"))["items"]
    mine = [item for item in requests
            if item["metadata"].get("annotations", {}).get("cert-manager.io/certificate-name") == certificate]
    newest = max(mine, key=lambda item: int(item["metadata"]["annotations"].get(
        "cert-manager.io/certificate-revision", "0")))
    ready = next(condition for condition in newest["status"]["conditions"] if condition["type"] == "Ready")
    return ready["message"]


def istio_on_the_root(cluster, forward, admin, root, state):
    step("cert-manager keeps Istio's cacerts through Hodor, and the mesh moves onto the tenant's root")
    message = issued(cluster, "istio-system", "istio-intermediate")
    shown(f"the request: {message}")
    check(cluster.secret("istio-system", "cacerts", "ca.crt") == root,
          "cacerts holds the tenant's root as ca.crt, and the key cert-manager made, which never left the cluster")
    intermediate = pem_certificates(cluster.secret("istio-system", "cacerts", "tls.crt"))[0]
    files = Path(state)
    (files / "root.pem").write_text(root)
    (files / "istio-intermediate.pem").write_text(to_pem(intermediate))
    verified = cluster.run("openssl", "verify", "-CAfile", str(files / "root.pem"),
                           str(files / "istio-intermediate.pem")).stdout.strip()
    check(verified.endswith(": OK"), f"OpenSSL verifies its intermediate under the root, name constraints too")
    signed = [line.split(" ", 4) for line in cluster.cli("authority", "intermediates", "--tenant",
                                                         admin.tenant).stdout.splitlines()]
    istio = next((row for row in signed if row[-1] == f"CN=Istio intermediate of {EAST}"), None)
    check(istio is not None and istio[1] == "active",
          f"hodor-cli authority intermediates lists it: {' '.join(istio or [])}")
    found = admin.call("GET", f"/certificate-authority/intermediates/{istio[0]}")
    check(found["certificate_sha256"] == sha256(intermediate), "it is the intermediate in cacerts")
    shown("istiod is restarted to sign with it, and every pod of the mesh to take a certificate under it")
    cluster.restarted("istio-system", "deployment/istiod")
    # The database first, so that Hodor's new pods find it in the mesh.
    cluster.restarted("hodor", "statefulset/hodor-evaluation-database", "deployment/hodor-evaluation-mail")
    cluster.restarted("hodor", "deployment/hodor-server", "deployment/hodor-worker")
    cluster.restarted("payroll", "deployment/payroll")
    forward.start()

    def output_certificates():
        done = cluster.exec("payroll", "deployment/payroll", "app", "cat", "/etc/istio-output-certs/root-cert.pem",
                            "/etc/istio-output-certs/cert-chain.pem", allowed=(0, 1))
        return pem_certificates(done.stdout) if done.returncode == 0 else None

    certificates = until("payroll's sidecar's certificates", output_certificates, seconds=120)
    check(certificates[0] == pem_certificates(root)[0], "payroll's sidecar trusts the tenant's root")
    leaf = cluster.run("openssl", "x509", "-noout", "-ext", "subjectAltName",
                       given=to_pem(certificates[1])).stdout
    check(PAYROLL_ID in leaf and intermediate in certificates[2:],
          f"and holds a certificate of {PAYROLL_ID} that Istio's intermediate signed")
    return istio[0], sha256(intermediate)


def linkerd_on_the_root(cluster, admin, root, state):
    step("cert-manager keeps Linkerd's identity issuer through Hodor, and Linkerd starts on the tenant's root")
    namespace(cluster, "linkerd")
    cluster.apply((HERE / "linkerd-intermediate.yaml").read_text())
    message = issued(cluster, "linkerd", "linkerd-identity-issuer")
    shown(f"the request: {message}")
    check(cluster.secret("linkerd", "linkerd-identity-issuer", "ca.crt") == root,
          "linkerd-identity-issuer holds the tenant's root as ca.crt")
    bundle = request("GET", f"{SERVER}/t/{admin.tenant}/certificate-authority/bundle").json()
    anchors = Path(state) / "trust-anchors.pem"
    anchors.write_text(to_pem(base64.b64decode(bundle["keys"][0]["x5c"][0])))
    roots = cluster.kubectl("create", "configmap", "linkerd-identity-trust-roots", "--namespace", "linkerd",
                            f"--from-file=ca-bundle.crt={anchors}", "--dry-run=client", "--output", "json")
    cluster.apply(roots)
    shown("Linkerd's trust anchors are the bundle Hodor publishes, in linkerd-identity-trust-roots")
    released(cluster, "linkerd-crds", "linkerd", f"{LINKERD_CHARTS}/linkerd-crds-{LINKERD_VERSION}.tgz")
    released(cluster, "linkerd-control-plane", "linkerd",
             f"{LINKERD_CHARTS}/linkerd-control-plane-{LINKERD_VERSION}.tgz",
             "--set", "identity.externalCA=true", "--set", "identity.issuer.scheme=kubernetes.io/tls",
             "--set", f"identityTrustDomain={WEST}", "--set-file", f"identityTrustAnchorsPEM={anchors}")
    check(cluster.exists("--namespace", "linkerd", "deployment/linkerd-identity"),
          f"Linkerd {LINKERD_VERSION}, whose trust domain is {WEST}, its issuer the one cert-manager keeps")
    # Linkerd's injector lets a pod through unchanged while it cannot answer,
    # so its deployments being ready is not enough: wait until it injects a
    # pod asked for on a dry run, before ledger's pods are made.
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
    cluster.apply((HERE / "linkerd-workloads.yaml").read_text())
    cluster.rolled_out("ledger", "deployment/ledger")
    containers = cluster.kubectl("get", "pods", "--namespace", "ledger", "--output",
                                 "jsonpath={.items[*].spec.initContainers[*].name}")
    check("linkerd-proxy" in containers.split(), f"ledger, in the mesh, is {LEDGER_ID}")


def linkerd_renewed(cluster, admin):
    step("cert-manager renews Linkerd's identity issuer through Hodor, with no one acting")

    def renewed():
        found = json.loads(cluster.kubectl("get", "certificate", "--namespace", "linkerd",
                                           "linkerd-identity-issuer", "--output", "json"))
        ready = any(condition["type"] == "Ready" and condition["status"] == "True"
                    for condition in found["status"].get("conditions", []))
        return found if ready and found["status"].get("revision", 0) >= 2 else None

    found = until("a renewal of Linkerd's identity issuer", renewed, seconds=300)
    cluster.kubectl("patch", "certificate", "--namespace", "linkerd", "linkerd-identity-issuer", "--type=merge",
                    "--patch", json.dumps({"spec": {"renewBefore": "25h"}}))
    shown(f"revision {found['status']['revision']}, valid until {found['status']['notAfter']}; from now on it is "
          f"renewed 25 hours before it expires")
    rows = [row for row in admin.call("GET", "/certificate-authority/intermediates")["items"]
            if row["subject"] == f"CN={LINKERD_ISSUER}"]
    check(len(rows) >= 2 and len({row["public_key_sha256"] for row in rows}) == len(rows),
          f"Hodor signed {len(rows)} intermediates of {LINKERD_ISSUER}, each for a new key")
    return rows


def the_call(istio, linkerd, linkerd_intermediates):
    step("payroll, of the Istio cluster, calls ledger, of the Linkerd cluster, over mutual TLS under the one root")
    address = linkerd.node_address()
    certificates = "/etc/istio-output-certs"

    def called():
        done = istio.exec("payroll", "deployment/payroll", "app", "curl", "--silent", "--show-error",
                          "--max-time", "20", "--cert", f"{certificates}/cert-chain.pem",
                          "--key", f"{certificates}/key.pem", "--cacert", f"{certificates}/root-cert.pem",
                          "--resolve", f"{LEDGER_ID}:{LEDGER_NODE_PORT}:{address}",
                          "--write-out", "\n%{certs}", f"https://{LEDGER_ID}:{LEDGER_NODE_PORT}/",
                          allowed=(0, 35, 56))
        return done if done.returncode == 0 else None

    done = until("ledger's answer", called, seconds=60)
    echoed = dict(line.split(": ", 1) for line in done.stdout.splitlines() if ": " in line and "-----" not in line)
    shown(f"ledger answered, from {echoed.get('Hostname', '?')}; L5d-Client-Id: {echoed.get('L5d-Client-Id')}")
    check(echoed.get("L5d-Client-Id") == PAYROLL_ID,
          f"Linkerd's proxy took payroll's Istio certificate under the tenant's root, and read {PAYROLL_ID}")
    chain = pem_certificates(done.stdout)
    signed = {row["certificate_sha256"]: row["serial_number"] for row in linkerd_intermediates}
    check(len(chain) >= 2 and sha256(chain[1]) in signed,
          f"curl took ledger's certificate with Istio's root, the same one: Linkerd's identity issuer signed it, "
          f"the intermediate of serial number {signed.get(sha256(chain[1]) if len(chain) >= 2 else '', '?')} "
          f"Hodor signed")


def refusals(cluster, admin, other, state):
    step("Requests for another tenant's trust domain, for no authority and past the bound: refused")
    theirs = other.call("POST", "/certificate-authority", {"kind": "root", "trust_domains": [GLOBEX_DOMAIN]})
    check(theirs["state"] == "active", f"{other.tenant} has an authority of its own, for {GLOBEX_DOMAIN}")
    files = Path(state) / "requests"
    files.mkdir()
    (files / "requests.cnf").write_text(
        "[req]\ndistinguished_name = name\n[name]\n"
        "[theirs]\nbasicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, keyCertSign, cRLSign\n"
        f"subjectAltName = URI:spiffe://{GLOBEX_DOMAIN}/ns/shop/sa/web\n"
        "[workload]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\n"
        f"subjectAltName = URI:spiffe://{EAST}/ns/shop/sa/web\n"
        "[authority]\nbasicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, keyCertSign, cRLSign\n")
    requests = {}
    for name in ("theirs", "workload", "authority"):
        key = files / f"{name}.key"
        cluster.run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
        requests[name] = cluster.run("openssl", "req", "-new", "-key", str(key), "-subj", f"/CN=A request {name}",
                                     "-config", str(files / "requests.cnf"), "-reqexts", name).stdout

    def sign(tenant, pem, *more):
        return cluster.cli("authority", "sign", "--tenant", tenant, "--request", "-", *more, given=pem,
                           allowed=(0, 1))

    for name, more, code, what in [
            ("theirs", (), "keys.intermediate_name_outside_trust_domains",
             f"an intermediate for spiffe://{GLOBEX_DOMAIN}, {other.tenant}'s trust domain"),
            ("workload", (), "keys.intermediate_not_an_authority", "a certificate that is not an authority"),
            ("authority", ("--lifetime-days", "31"), "keys.intermediate_lifetime_invalid",
             "an intermediate for 31 days, past the bound of 30")]:
        done = sign(admin.tenant, requests[name], *more)
        said = next((line.strip() for line in (done.stderr + done.stdout).splitlines() if code in line), "")
        check(done.returncode == 1 and said, f"{what}: {said or done.stderr.strip()}")
    done = sign(other.tenant, requests["theirs"])
    check(done.returncode == 0 and "signed " in done.stderr,
          f"the same request is signed by {other.tenant}'s own authority: {done.stderr.strip()}")
    too_long = {"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
                "metadata": {"name": "too-long", "namespace": "istio-system"},
                "spec": {"secretName": "too-long", "duration": "2400h", "isCA": True, "commonName": "Too long",
                         "issuerRef": {"group": "hodor.ortisun.github.io", "kind": "HodorIssuer", "name": "hodor"},
                         "privateKey": {"algorithm": "ECDSA", "size": 256}, "usages": ["cert sign", "crl sign"]}}
    cluster.apply(json.dumps(too_long))

    def failed():
        found = json.loads(cluster.kubectl("get", "certificaterequests", "--namespace", "istio-system",
                                           "--output", "json"))["items"]
        for item in found:
            if item["metadata"].get("annotations", {}).get("cert-manager.io/certificate-name") != "too-long":
                continue
            for condition in item.get("status", {}).get("conditions", []):
                if condition["type"] == "Ready" and condition.get("reason") == "Failed":
                    return condition["message"]
        return None

    message = until("the request for 100 days to fail", failed, seconds=120)
    check("keys.intermediate_lifetime_invalid" in message,
          f"through cert-manager, a Certificate of 100 days: Failed, {message}")
    cluster.kubectl("delete", "certificate", "--namespace", "istio-system", "too-long")


def payroll_client(cluster, admin):
    """A service account of payroll, and its client bound to payroll's
    identity in the Istio mesh, with no secret."""
    application = admin.call("POST", "/applications", {"name": "Payroll", "first_party": True})["id"]
    admin.call("POST", "/resource-servers", {"application_id": application, "audience": PAYROLL,
                                             "name": "Payroll",
                                             "scopes": [{"name": "payroll:read", "description": "Read"}]})
    account = admin.call("POST", "/service-accounts", {"name": "Payroll", "owners": [admin.user]})["id"]
    said = cluster.cli("client", "add", "--tenant", admin.tenant, "--application", application,
                       "--type", "confidential", "--grant", "client_credentials", "--scope", "payroll:read",
                       "--principal", account, "--name", "Payroll in the mesh", "--method", "spiffe_x509",
                       "--spiffe-id", PAYROLL_ID).stdout
    return lines_of(said)["client"]


def token_from_payroll(cluster, admin, client):
    done = cluster.exec("payroll", "deployment/payroll", "app", "curl", "--silent", "--max-time", "20",
                        "--output", "/dev/null", "--write-out", "%{http_code}",
                        "--data-urlencode", "grant_type=client_credentials", "--data-urlencode", f"client_id={client}",
                        "--data-urlencode", f"resource={PAYROLL}", "--data-urlencode", "scope=payroll:read",
                        f"{INSIDE}/t/{admin.tenant}/oauth2/token")
    return int(done.stdout.strip())


def withdrawal(cluster, admin, istio_intermediate):
    step("An intermediate withdrawn: Hodor stops trusting its workloads at once")
    client = payroll_client(cluster, admin)
    status = token_from_payroll(cluster, admin, client)
    check(status == 200, f"payroll gets a token with its client_id alone: its sidecar presents its certificate, "
                         f"which Hodor checks up to the tenant's root through Istio's intermediate ({status})")
    said = cluster.cli("authority", "withdraw", "--tenant", admin.tenant, "--intermediate", istio_intermediate,
                       "--reason", "the demonstration withdraws it").stdout.strip()
    check(said.startswith(f"withdrawn {istio_intermediate} withdrawn"), f"hodor-cli authority withdraw: {said}")
    status = token_from_payroll(cluster, admin, client)
    check(status == 401, f"payroll's next request is refused ({status}), its certificate under a withdrawn key")
    shown("Istio keeps signing with the intermediate until it expires: no revocation list is published")


def tenants_apart(admin, other, root):
    step("Tenants apart")
    theirs = request("GET", f"{SERVER}/t/{other.tenant}/certificate-authority/bundle").json()
    check(to_pem(base64.b64decode(theirs["keys"][0]["x5c"][0])) != root,
          f"{other.tenant} publishes a bundle of its own")
    names = {item["name"] for item in other.call("GET", "/trust-domains")["items"]}
    check(names == {GLOBEX_DOMAIN}, f"{other.tenant} trusts {GLOBEX_DOMAIN} alone, nothing of {admin.tenant}'s")
    mine = admin.call("GET", "/certificate-authority/intermediates")["items"]
    answer = other.answer("GET", f"/certificate-authority/intermediates/{mine[0]['id']}")
    check(answer.status == 404 and answer.code == "keys.intermediate_not_found",
          f"{other.tenant}'s administrator finds none of {admin.tenant}'s intermediates")


def the_audit_log(cluster, admin, account):
    step("The audit log")

    def records():
        items = admin.call("GET", "/audit-records?limit=200")["items"]
        return items if any(item["action"] == "keys.intermediate_withdrawn" for item in items) else None

    items = until("the audit records of the demonstration", records)
    created = next(item for item in items if item["action"] == "keys.authority_created")
    check(created["details"]["provider"] == "openbao" and created["details"]["uri_constraints"] is False,
          f"keys.authority_created: {json.dumps(created['details'])}")
    signed = [item for item in items if item["action"] == "keys.authority_signed"]
    by_issuers = [item for item in signed if item["details"]["signed"] == "intermediate_certificate"
                  and item["actor"].get("id") == account]
    by_tool = [item for item in signed if item["details"]["signed"] == "intermediate_certificate"
               and item["actor"].get("kind") == "system"]
    check(any(item["details"]["signed"] == "certificate" for item in signed),
          "keys.authority_signed of its own certificate")
    check(len(by_issuers) >= 3, f"keys.authority_signed of {len(by_issuers)} intermediates, the issuers' service "
                                f"account the actor, for {', '.join(sorted({d for item in by_issuers for d in item['details']['trust_domains']}))}")
    check(not by_tool, "none by hodor-cli: every request it was given was refused")
    withdrawn = [item for item in items if item["action"] == "keys.intermediate_withdrawn"]
    check(len(withdrawn) == 1, f"keys.intermediate_withdrawn, with its reason: {withdrawn[0]['details']['reason']}")
    check(cluster.cli("audit", "verify", "--tenant", admin.tenant).stdout.startswith("intact: "),
          "the audit chain is intact")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    started = time.monotonic()
    suffix = format(int(time.time() * 1000), "x")
    tenant, other = f"acme-{suffix}", f"globex-{suffix}"
    with tempfile.TemporaryDirectory(prefix="hodor-milestone-12-") as state:
        istio, linkerd = Cluster(state, ISTIO_CLUSTER), Cluster(state, LINKERD_CLUSTER)
        forward = Forward(istio)
        try:
            two_kind_clusters(istio, linkerd)
            istio_mesh(istio)
            step("cert-manager in both clusters")
            cert_manager(istio)
            cert_manager(linkerd)
            hodor_in_the_mesh(istio, forward)
            admin, other_admin = two_tenants(istio, tenant, other, suffix)
            the_authority_off(istio, admin)
            on_the_local_key_provider(istio, forward, admin)
            openbao(istio, forward, admin)
            root = an_authority(istio, admin)
            account, clients = signing_clients(istio, admin, state)
            step("hodor-cert-manager-issuer in both clusters")
            issuer(istio, admin, *clients["istio"], INSIDE)
            issuer(linkerd, admin, *clients["linkerd"], f"http://{istio.node_address()}:{HODOR_NODE_PORT}")
            shown(f"the Linkerd cluster's reaches Hodor at a port of the Istio cluster's node, {HODOR_NODE_PORT}")
            istio.apply((HERE / "istio-intermediate.yaml").read_text())
            istio_intermediate, _ = istio_on_the_root(istio, forward, admin, root, state)
            linkerd_on_the_root(linkerd, admin, root, state)
            linkerd_intermediates = linkerd_renewed(linkerd, admin)
            the_call(istio, linkerd, linkerd_intermediates)
            refusals(istio, admin, other_admin, state)
            withdrawal(istio, admin, istio_intermediate)
            tenants_apart(admin, other_admin, root)
            the_audit_log(istio, admin, account)
        except Failed as failure:
            print(f"\nThe demonstration stopped: {failure}", file=sys.stderr)
            sys.exit(1)
        finally:
            forward.stop()
    minutes = (time.monotonic() - started) / 60
    print(f"\nThe demonstration of Milestone 12 passed, in {minutes:.0f} minutes.")
    print(f"The clusters {ISTIO_CLUSTER} and {LINKERD_CLUSTER} are still running; `kind delete cluster --name` "
          f"each removes it.")


if __name__ == "__main__":
    main()
