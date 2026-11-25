#!/usr/bin/env python3
"""The demonstration of Milestone 10: workloads prove who they are with their certificates.

Makes a kind cluster, or takes the one it made before, with Istio and
SPIRE, and Hodor installed in the mesh with its chart; then does what an
operator and two workloads would do. A tenant trusts SPIRE's trust domain
by its bundle endpoint and Istio's as checked by the mesh, and binds a
service account's clients to one SPIFFE identifier of each. A workload gets
a token with a JWT-SVID from the SPIRE agent, then with no credential at
all, its sidecar presenting its certificate, and the bound token's `cnf`
is its certificate's thumbprint. The bound token is refused without the
certificate; a JWT-SVID presented twice, one of another trust domain and
one for another tenant are refused; `X-Forwarded-Client-Cert` sent from
outside the mesh is ignored. Every answer is checked; the first one that is
not what it should be stops the demonstration with a non-zero exit status.

    python3 deploy/demo/workload_identity.py

It needs Python 3, Docker, kind, kubectl, Helm and OpenSSL, and nothing
outside the standard library. It never touches the current context of
kubectl or the repositories of Helm: both are given files of their own, in
a temporary directory. The cluster is left running, for a look and for the
next run; `kind delete cluster --name hodor-milestone-10` removes it. See
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

from demo import Answer, Failed, check, request, shown, step, until
from external_identities import post_form
from strong_authentication import decode, verified

HERE = Path(__file__).resolve().parent / "workload-identity"
REPOSITORY = Path(__file__).resolve().parent.parent.parent
CLUSTER = os.environ.get("HODOR_KIND_CLUSTER", "hodor-milestone-10")
IMAGE = os.environ.get("HODOR_IMAGE", "hodor:milestone-10")
# Where the script reaches Hodor, through `kubectl port-forward`: from
# outside the mesh, as an operator does.
PORT = int(os.environ.get("HODOR_PORT", "18080"))
SERVER = f"http://localhost:{PORT}"
# Where the workloads of the cluster reach Hodor, and what every tenant's
# issuer starts with: publicUrl in hodor-values.yaml.
INSIDE = "http://hodor.hodor.svc:8080"

ISTIO_VERSION = "1.30.8"
ISTIO_CHARTS = "https://istio-release.storage.googleapis.com/charts"
SPIRE_DOMAIN = "workloads.example.org"
OTHER_DOMAIN = "elsewhere.example.org"
MESH_DOMAIN = "cluster.local"
BUNDLE_ENDPOINT = "https://spire-server.spire.svc:8443"
# The payroll workload: its SPIRE identity, and the identity of the
# certificate Istio gives its sidecar.
SPIRE_ID = f"spiffe://{SPIRE_DOMAIN}/ns/payroll/sa/payroll"
MESH_ID = f"spiffe://{MESH_DOMAIN}/ns/payroll/sa/payroll"
OTHER_ID = f"spiffe://{OTHER_DOMAIN}/ns/payroll/sa/payroll"
AGENT_ID = f"spiffe://{SPIRE_DOMAIN}/ns/spire/sa/spire-agent"
AGENT_SOCKET = "/run/spire/sockets/agent.sock"
# The name SPIRE's node attestation gives the cluster, in spire.yaml.
SPIRE_CLUSTER = "hodor-milestone-10"

API = "urn:hodor:authorization"
PAYROLL = "https://payroll.example.com"
JWT_SPIFFE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"


def lines_of(said):
    """The lines a command printed, as `name value`."""
    return dict(line.split(" ", 1) for line in said.splitlines() if " " in line)


def claims_of(token):
    return json.loads(decode(token.split(".")[1]))


# ---------------------------------------------------------------------------
# The cluster, through tools of its own
# ---------------------------------------------------------------------------

class Cluster:
    """The kind cluster, reached with a kubeconfig and Helm settings that
    belong to this run alone."""

    def __init__(self, state):
        self.state = Path(state)
        self.kubeconfig = self.state / "kubeconfig"
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
            raise Failed(f"{' '.join(arguments[:4])} … exited with {done.returncode}: {said}")
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

    def exec(self, namespace, target, container, *command, allowed=(0,)):
        return self.run("kubectl", "exec", "--namespace", namespace, target, "--container", container,
                        "--", *command, allowed=allowed)

    def cli(self, *arguments):
        """`hodor-cli` in the server's pod, with the server's settings."""
        return self.exec("hodor", "deployment/hodor-server", "server", "/usr/local/bin/hodor-cli",
                         *arguments).stdout.strip()

    def spire(self, *arguments, namespace="spire", target="statefulset/spire-server", allowed=(0,)):
        return self.exec(namespace, target, "spire-server", "/opt/spire/bin/spire-server", *arguments,
                         allowed=allowed)

    def curl(self, namespace, deployment, *arguments):
        """An HTTP request made by curl in a workload's own container."""
        done = self.exec(namespace, f"deployment/{deployment}", "app", "curl", "--silent", "--show-error",
                         "--include", "--max-time", "20", *arguments)
        # Read as text, the answer's line ends are already plain ones.
        head, _, body = done.stdout.partition("\n\n")
        lines = head.split("\n")
        status = int(lines[0].split()[1])
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        return Answer(status, headers, body.encode())


def form(fields):
    """Fields for curl, each encoded."""
    arguments = []
    for name, value in fields.items():
        arguments += ["--data-urlencode", f"{name}={value}"]
    return arguments


# ---------------------------------------------------------------------------
# Setting the cluster up
# ---------------------------------------------------------------------------

def tools_present():
    missing = [tool for tool in ("docker", "kind", "kubectl", "helm", "openssl") if shutil.which(tool) is None]
    check(not missing, "Docker, kind, kubectl, Helm and OpenSSL are on the path"
          + (f" (missing: {', '.join(missing)})" if missing else ""))


def a_kind_cluster(cluster):
    step(f"A kind cluster, {CLUSTER}, with Hodor's image")
    tools_present()
    known = cluster.run("kind", "get", "clusters").stdout.split()
    if CLUSTER in known:
        shown(f"using the cluster {CLUSTER} made before")
    else:
        shown(f"making the cluster {CLUSTER}")
        cluster.run("kind", "create", "cluster", "--name", CLUSTER, "--kubeconfig", str(cluster.kubeconfig),
                    "--wait", "180s")
    cluster.kubeconfig.write_text(cluster.run("kind", "get", "kubeconfig", "--name", CLUSTER).stdout)
    check(cluster.exists("nodes"), "the cluster answers, through a kubeconfig of this run alone")
    if cluster.run("docker", "image", "inspect", IMAGE, allowed=(0, 1)).returncode != 0:
        shown(f"building {IMAGE} from this checkout; the first build takes several minutes")
        cluster.run("docker", "build", "--file", "deploy/docker/Dockerfile", "--tag", IMAGE, ".", seconds=3600)
    cluster.run("kind", "load", "docker-image", IMAGE, "--name", CLUSTER)
    shown(f"{IMAGE} is on the cluster's node")


def released(cluster, release, namespace, chart, *settings):
    """`helm upgrade --install`, after taking away what a run stopped in the
    middle of an installation left behind."""
    found = cluster.run("helm", "status", release, "--namespace", namespace, "--output", "json", allowed=(0, 1))
    if found.returncode == 0 and json.loads(found.stdout).get("info", {}).get("status", "").startswith("pending"):
        shown(f"taking away the release {release}, left unfinished by a run before")
        cluster.run("helm", "uninstall", release, "--namespace", namespace, "--wait")
    cluster.run("helm", "upgrade", "--install", release, chart, "--namespace", namespace, *settings,
                "--wait", "--timeout", "10m")


def istio(cluster):
    step(f"Istio {ISTIO_VERSION}, whose trust domain is {MESH_DOMAIN}")
    namespace(cluster, "istio-system")
    released(cluster, "istio-base", "istio-system", f"{ISTIO_CHARTS}/base-{ISTIO_VERSION}.tgz")
    released(cluster, "istiod", "istio-system", f"{ISTIO_CHARTS}/istiod-{ISTIO_VERSION}.tgz",
             "--values", str(HERE / "istiod-values.yaml"))
    check(cluster.exists("--namespace", "istio-system", "deployment/istiod"), "Istio's control plane is ready")


def namespace(cluster, name, labels=None):
    cluster.apply(json.dumps({"apiVersion": "v1", "kind": "Namespace",
                              "metadata": {"name": name, "labels": labels or {}}}))


def an_authority(cluster):
    """The demonstration's own authority, and the certificate of SPIRE's
    bundle endpoint under it: the `https_web` profile wants a certificate a
    client can check, and a cluster on one machine has no public one."""
    if (cluster.exists("--namespace", "spire", "secret/spire-bundle-endpoint")
            and cluster.exists("--namespace", "hodor", "configmap/hodor-outbound-authorities")):
        shown("the authority and the bundle endpoint's certificate were made before")
        return
    files = cluster.state / "authority"
    files.mkdir()
    (files / "extensions.cnf").write_text(
        "[req]\ndistinguished_name = name\n[name]\n"
        "[authority]\nbasicConstraints = critical, CA:TRUE, pathlen:0\n"
        "keyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n"
        "[endpoint]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\n"
        "extendedKeyUsage = serverAuth\nsubjectAltName = DNS:spire-server.spire.svc\n"
        "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n")

    def openssl(*arguments):
        cluster.run("openssl", *arguments)

    extensions = str(files / "extensions.cnf")
    for key in ("authority.key", "endpoint.key"):
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(files / key))
    openssl("req", "-new", "-x509", "-key", str(files / "authority.key"), "-out", str(files / "authority.crt"),
            "-days", "365", "-subj", "/CN=Hodor demonstration authority", "-config", extensions,
            "-extensions", "authority")
    openssl("req", "-new", "-key", str(files / "endpoint.key"), "-out", str(files / "endpoint.csr"),
            "-subj", "/CN=spire-server.spire.svc", "-config", extensions)
    openssl("x509", "-req", "-in", str(files / "endpoint.csr"), "-CA", str(files / "authority.crt"),
            "-CAkey", str(files / "authority.key"), "-CAcreateserial", "-out", str(files / "endpoint.crt"),
            "-days", "365", "-extfile", extensions, "-extensions", "endpoint")
    secret = cluster.kubectl("create", "secret", "tls", "spire-bundle-endpoint", "--namespace", "spire",
                             "--cert", str(files / "endpoint.crt"), "--key", str(files / "endpoint.key"),
                             "--dry-run=client", "--output", "json")
    cluster.apply(secret)
    authorities = cluster.kubectl("create", "configmap", "hodor-outbound-authorities", "--namespace", "hodor",
                                  f"--from-file=authorities.pem={files / 'authority.crt'}",
                                  "--dry-run=client", "--output", "json")
    cluster.apply(authorities)
    # A SPIRE server already running reads the new certificate when it starts.
    if cluster.exists("--namespace", "spire", "statefulset/spire-server"):
        cluster.kubectl("rollout", "restart", "--namespace", "spire", "statefulset/spire-server")
    shown("made the demonstration's authority, and the bundle endpoint's certificate under it")


def spire(cluster):
    step(f"SPIRE, whose trust domain is {SPIRE_DOMAIN}, and another of {OTHER_DOMAIN}")
    namespace(cluster, "spire")
    namespace(cluster, "hodor", {"istio-injection": "enabled"})
    an_authority(cluster)
    cluster.apply((HERE / "spire.yaml").read_text())
    cluster.rolled_out("spire", "statefulset/spire-server")
    # The agents start before the server can attest them, and wait longer
    # after each failure: started again, they are attested at once.
    if cluster.run("kubectl", "rollout", "status", "--namespace", "spire", "daemonset/spire-agent",
                   "--timeout=10s", allowed=(0, 1)).returncode != 0:
        cluster.kubectl("delete", "pod", "--namespace", "spire", "--selector", "app=spire-agent", "--wait=false")
    cluster.rolled_out("spire", "daemonset/spire-agent")
    cluster.rolled_out("elsewhere", "deployment/spire-server")
    check(cluster.spire("healthcheck").returncode == 0, "the SPIRE server is healthy")
    # Which agents may give which identities: every agent of the cluster,
    # to the pods of the service account payroll of the namespace payroll.
    for entry in (["-node", "-spiffeID", AGENT_ID, "-selector", f"k8s_psat:cluster:{SPIRE_CLUSTER}",
                   "-selector", "k8s_psat:agent_ns:spire", "-selector", "k8s_psat:agent_sa:spire-agent"],
                  ["-parentID", AGENT_ID, "-spiffeID", SPIRE_ID, "-selector", "k8s:ns:payroll",
                   "-selector", "k8s:sa:payroll"]):
        made = cluster.spire("entry", "create", *entry, allowed=(0, 1))
        check(made.returncode == 0 or "AlreadyExists" in made.stdout + made.stderr,
              f"SPIRE gives {entry[entry.index('-spiffeID') + 1]} to its workloads")


def hodor(cluster):
    step("Hodor, installed with its chart, in the mesh")
    cluster.apply((REPOSITORY / "deploy/install/helm/evaluation.yaml").read_text(), namespace="hodor")
    cluster.rolled_out("hodor", "statefulset/hodor-evaluation-database")
    repository, _, tag = IMAGE.rpartition(":")
    image_id = cluster.run("docker", "image", "inspect", "--format", "{{.Id}}", IMAGE).stdout.strip()
    # The image's identifier in an annotation restarts the pods when the
    # image changed under the same tag.
    released(cluster, "hodor", "hodor", "deploy/install/helm/hodor",
             "--values", str(HERE / "hodor-values.yaml"), "--set", f"image.repository={repository}",
             "--set", f"image.tag={tag}", "--set", "image.pullPolicy=Never",
             "--set-string", f"server.podAnnotations.hodor\\.example/image={image_id}",
             "--set-string", f"worker.podAnnotations.hodor\\.example/image={image_id}")
    containers = cluster.kubectl("get", "pods", "--namespace", "hodor", "--selector",
                                 "app.kubernetes.io/component=server", "--output",
                                 "jsonpath={.items[*].spec.initContainers[*].name}")
    check("istio-proxy" in containers.split(), "Hodor's server has Istio's sidecar")
    cluster.apply((HERE / "workloads.yaml").read_text())
    cluster.rolled_out("payroll", "deployment/payroll")
    cluster.rolled_out("outside", "deployment/outsider")
    shown("payroll, in the mesh and under SPIRE; outsider, in neither")


def forwarded(cluster):
    """`kubectl port-forward` to Hodor's service, until the script ends."""
    process = subprocess.Popen(["kubectl", "port-forward", "--namespace", "hodor", "service/hodor",
                                f"{PORT}:8080"], env=cluster.environment, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)

    def answers():
        try:
            return request("GET", f"{SERVER}/t/system/.well-known/openid-configuration").status == 200
        except Failed:
            return False

    until(f"Hodor at {SERVER}", answers)
    return process


# ---------------------------------------------------------------------------
# The demonstration
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


def two_tenants(cluster, tenant, other, suffix):
    step("Two tenants, and their administrators")
    admins = []
    for slug, name, address in [(tenant, "Acme", f"operator-{suffix}@example.com"),
                                (other, "Globex", f"operator-globex-{suffix}@example.com")]:
        said = cluster.cli("tenant", "create", "--slug", slug, "--name", name)
        check(said.startswith(f"created {slug} "), f"the command-line tool created {slug}")
        cluster.cli("keys", "rotate", "--tenant", slug)
        said = lines_of(cluster.cli("admin", "bootstrap", "--tenant", slug, "--email", address))
        check(said.get("role") == "tenant_administrator", f"{address} is an administrator of {slug}")
        admins.append(Administrator(slug, said["token"], said["user"].split()[0]))
    return admins


def two_trust_domains(cluster, admin):
    step("Two trust domains: SPIRE's by its bundle endpoint, Istio's as checked by the mesh")
    tenant = admin.tenant
    said = lines_of(cluster.cli("trust-domain", "add", "--tenant", tenant, "--name", SPIRE_DOMAIN,
                                "--bundle-endpoint", BUNDLE_ENDPOINT))
    check(said.get("source") == "bundle_endpoint" and said.get("bundle-endpoint") == BUNDLE_ENDPOINT,
          f"hodor-cli trust-domain add: {SPIRE_DOMAIN}, fetched from {BUNDLE_ENDPOINT}")
    shown(f"sequence {said.get('sequence')}, refresh hint {said.get('refresh-hint')} seconds, "
          f"{said.get('x509-authorities')} authority of X509-SVIDs, {said.get('jwt-authorities')} of JWT-SVIDs")
    said = lines_of(cluster.cli("trust-domain", "add", "--tenant", tenant, "--name", MESH_DOMAIN, "--mesh"))
    check(said.get("source") == "mesh" and "bundle-sha256" not in said,
          f"hodor-cli trust-domain add: {MESH_DOMAIN}, checked by the mesh, with no bundle")
    listed = cluster.cli("trust-domain", "list", "--tenant", tenant).splitlines()
    check(len(listed) == 2 and f" {SPIRE_DOMAIN} bundle_endpoint fetched " in listed[0] + listed[1] + " ",
          "hodor-cli trust-domain list shows both, and the bundle endpoint's last fetch")

    items = {item["name"]: item for item in admin.call("GET", "/trust-domains")["items"]}
    fetched = items[SPIRE_DOMAIN]
    spire_bundle = json.loads(cluster.spire("bundle", "show", "-format", "spiffe").stdout)
    kids = sorted(key["kid"] for key in spire_bundle["keys"] if key.get("use") == "jwt-svid")
    check(kids and sorted(key["kid"] for key in fetched["bundle"]["keys"] if key["use"] == "jwt-svid") == kids,
          "the bundle Hodor keeps holds the keys SPIRE signs JWT-SVIDs with")
    return fetched


def a_service_account_and_two_clients(cluster, admin):
    step("A service account, and its clients bound to one SPIFFE identifier of each")
    tenant = admin.tenant
    authorization = admin.call("POST", "/applications", {"name": "Authorization API", "first_party": True})
    admin.call("POST", "/resource-servers", {"application_id": authorization["id"], "audience": API,
                                             "name": "Authorization API",
                                             "scopes": [{"name": "authz:evaluate", "description": "Decisions"}]})
    payroll = admin.call("POST", "/applications", {"name": "Payroll", "first_party": True})["id"]
    server = admin.call("POST", "/resource-servers", {"application_id": payroll, "audience": PAYROLL,
                                                      "name": "Payroll",
                                                      "scopes": [{"name": "payroll:read", "description": "Read"}]})["id"]
    admin.call("PUT", f"/resource-servers/{server}/permissions/invoice:approve", {"description": "Approve"})
    admin.call("PUT", f"/resource-servers/{server}/roles/approver", {"permissions": [{"name": "invoice:approve"}]})
    admin.call("PUT", f"/resource-servers/{server}/binding", {"engine": "native"})
    account = admin.call("POST", "/service-accounts", {"name": "Payroll", "owners": [admin.user]})["id"]
    admin.call("POST", "/role-assignments", {"principal": {"kind": "user", "id": account},
                                             "role": {"namespace": PAYROLL, "name": "approver"}})
    shown(f"the service account Payroll, {account}, may approve invoices")

    common = ["client", "add", "--tenant", tenant, "--application", payroll, "--type", "confidential",
              "--grant", "client_credentials", "--scope", "authz:evaluate", "--principal", account]
    said = cluster.cli(*common, "--name", "Payroll by its JWT-SVID", "--method", "spiffe_jwt",
                       "--spiffe-id", SPIRE_ID)
    by_svid = lines_of(said)["client"]
    check("secret" not in said, f"hodor-cli client add --method spiffe_jwt --spiffe-id {SPIRE_ID}: no secret")
    said = cluster.cli(*common, "--name", "Payroll in the mesh", "--method", "spiffe_x509",
                       "--spiffe-id", MESH_ID, "--bound-tokens")
    in_mesh = lines_of(said)["client"]
    check("secret" not in said,
          f"hodor-cli client add --method spiffe_x509 --spiffe-id {MESH_ID} --bound-tokens: no secret")
    read = admin.call("GET", f"/clients/{in_mesh}")
    check(read["spiffe_id"] == MESH_ID and read["tls_client_certificate_bound_access_tokens"] is True
          and read["principal"] == account, "the administration interface reads them as they were bound")
    return account, by_svid, in_mesh


def jwt_svid(cluster, audience):
    """A JWT-SVID of the payroll workload for `audience`, from the SPIRE
    agent on its node."""
    def fetched():
        done = cluster.exec("payroll", "deployment/payroll", "spiffe", "/opt/spire/bin/spire-agent", "api",
                            "fetch", "jwt", "-audience", audience, "-socketPath", AGENT_SOCKET,
                            "-output", "json", allowed=(0, 1))
        if done.returncode != 0:
            return None
        found = json.loads(done.stdout)
        return next((svid["svid"] for part in found for svid in part.get("svids", [])), None)

    return until("a JWT-SVID from the SPIRE agent", fetched, seconds=120)


def tenant_key_set(admin):
    return request("GET", f"{SERVER}/t/{admin.tenant}/oauth2/jwks").json().get("keys", [])


def signed_by(token, keys):
    """Whether an ES256 token is signed by one of `keys`, a list of JWKs."""
    header, payload, signature = token.split(".")
    kid = json.loads(decode(header)).get("kid")
    key = next((key for key in keys if key.get("kid") == kid and key.get("crv") == "P-256"), None)
    if key is None:
        return False
    public = (int.from_bytes(decode(key["x"]), "big"), int.from_bytes(decode(key["y"]), "big"))
    raw = decode(signature)
    return verified(public, f"{header}.{payload}".encode(), int.from_bytes(raw[:32], "big"),
                    int.from_bytes(raw[32:], "big"))


def evaluate_inside(cluster, namespace, deployment, tenant, token, account):
    return cluster.curl(namespace, deployment, f"{INSIDE}/t/{tenant}/api/v1/authorization/evaluate",
                        "--header", f"Authorization: Bearer {token}", "--header", "Content-Type: application/json",
                        "--data", json.dumps({"subject": {"type": "user", "id": account},
                                              "resource": {"type": "invoice", "id": "invoice-42"},
                                              "action": "approve"}))


def allowed(answer, what):
    body = answer.json()
    check(answer.status == 200 and body.get("decision") == "ALLOW",
          what + ("" if answer.status == 200 else f" (answered {answer.status} {answer.text})"))
    shown(f"{body.get('decision')} {body.get('reason')}")


def a_token_with_a_jwt_svid(cluster, admin, account, client, bundle):
    step("A token with a JWT-SVID")
    tenant = admin.tenant
    issuer = f"{INSIDE}/t/{tenant}"
    svid = jwt_svid(cluster, issuer)
    claims = claims_of(svid)
    check(claims.get("sub") == SPIRE_ID and claims.get("aud") in ([issuer], issuer),
          f"the SPIRE agent gives payroll a JWT-SVID of {SPIRE_ID} for the tenant's issuer, {issuer}")
    check(signed_by(svid, [key for key in bundle["bundle"]["keys"] if key["use"] == "jwt-svid"]),
          "signed by a key of the bundle Hodor fetched from SPIRE")
    fields = {"grant_type": "client_credentials", "client_id": client, "client_assertion_type": JWT_SPIFFE,
              "client_assertion": svid, "resource": API, "scope": "authz:evaluate"}
    answer = cluster.curl("payroll", "payroll", f"{INSIDE}/t/{tenant}/oauth2/token", *form(fields))
    check(answer.status == 200, "payroll gets a token with it, as its client assertion"
          + ("" if answer.status == 200 else f" (answered {answer.status} {answer.text})"))
    token = answer.json()["access_token"]
    claims = claims_of(token)
    check(claims.get("sub") == account and claims.get("principal_kind") == "service_account"
          and "cnf" not in claims and signed_by(token, tenant_key_set(admin)),
          "the token names the service account, is signed by the tenant, and is bound to nothing")
    allowed(evaluate_inside(cluster, "outside", "outsider", tenant, token, account),
            "with it, the service account may approve an invoice, asked from anywhere")
    return svid, fields


def sidecar_thumbprint(cluster):
    """The SHA-256 of the certificate payroll's sidecar presents, as
    `x5t#S256` writes it: read from the sidecar's own configuration."""
    dump = json.loads(cluster.exec("payroll", "deployment/payroll", "istio-proxy", "pilot-agent", "request",
                                   "GET", "config_dump?resource=dynamic_active_secrets").stdout)
    for config in dump.get("configs", []):
        secret = config.get("secret", {})
        if secret.get("name") == "default" and "tls_certificate" in secret:
            chain = base64.b64decode(secret["tls_certificate"]["certificate_chain"]["inline_bytes"]).decode()
            leaf = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", chain, re.S).group(1)
            der = base64.b64decode("".join(leaf.split()))
            return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode()
    raise Failed("payroll's sidecar holds no certificate")


def a_token_with_no_credential(cluster, admin, account, client):
    step("A token with no credential at all, the sidecar presenting its certificate")
    tenant = admin.tenant
    fields = {"grant_type": "client_credentials", "client_id": client, "resource": API, "scope": "authz:evaluate"}
    answer = cluster.curl("payroll", "payroll", f"{INSIDE}/t/{tenant}/oauth2/token", *form(fields))
    check(answer.status == 200, f"payroll gets a token with its client_id alone, over the mesh's mutual TLS"
          + ("" if answer.status == 200 else f" (answered {answer.status} {answer.text})"))
    token = answer.json()["access_token"]
    claims = claims_of(token)
    check(claims.get("sub") == account and signed_by(token, tenant_key_set(admin)),
          "the token names the service account, and is signed by the tenant")
    bound = claims.get("cnf", {}).get("x5t#S256")
    shown(f"cnf {json.dumps(claims.get('cnf'))}")
    check(bound == sidecar_thumbprint(cluster),
          "its cnf is the SHA-256 of the certificate payroll's sidecar presented")
    allowed(evaluate_inside(cluster, "payroll", "payroll", tenant, token, account),
            "the bound token is taken from payroll, whose sidecar presents the certificate")
    introspected = cluster.curl("payroll", "payroll", f"{INSIDE}/t/{tenant}/oauth2/introspect",
                                *form({"token": token, "client_id": client}))
    body = introspected.json()
    check(introspected.status == 200 and body.get("active") is True and body.get("cnf") == claims["cnf"],
          "introspection answers it active, with its cnf")
    return token, fields


def the_bound_token_without_its_certificate(cluster, admin, account, token):
    step("The bound token without its certificate")
    tenant = admin.tenant
    answer = evaluate_inside(cluster, "outside", "outsider", tenant, token, account)
    check(answer.status == 401 and "invalid_token" in answer.headers.get("www-authenticate", ""),
          f"from outsider, outside the mesh: {answer.status}, {answer.headers.get('www-authenticate')}")
    answer = request("POST", f"{SERVER}/t/{tenant}/api/v1/authorization/evaluate",
                     {"subject": {"type": "user", "id": account}, "resource": {"type": "invoice", "id": "invoice-42"},
                      "action": "approve"}, {"Authorization": f"Bearer {token}"})
    check(answer.status == 401, f"from this machine, through the port forward: {answer.status}")


def refused_client(answer, what):
    check(answer.status == 401 and answer.json().get("error") == "invalid_client",
          what + ("" if answer.status == 401 else f" (answered {answer.status} {answer.text})"))


def jwt_svids_refused(cluster, admin, other, fields):
    step("A JWT-SVID twice, one of another trust domain and one for another tenant: all refused")
    tenant = admin.tenant
    token_endpoint = f"{INSIDE}/t/{tenant}/oauth2/token"
    refused_client(cluster.curl("payroll", "payroll", token_endpoint, *form(fields)),
                   "the same JWT-SVID, presented a second time: invalid_client")
    elsewhere = cluster.spire("jwt", "mint", "-spiffeID", OTHER_ID, "-audience", f"{INSIDE}/t/{tenant}",
                              "-ttl", "300s", namespace="elsewhere", target="deployment/spire-server").stdout.strip()
    check(claims_of(elsewhere).get("sub") == OTHER_ID,
          f"the SPIRE server of {OTHER_DOMAIN} mints a JWT-SVID of {OTHER_ID} for the tenant's issuer")
    refused_client(cluster.curl("payroll", "payroll", token_endpoint,
                                *form({**fields, "client_assertion": elsewhere})),
                   f"presented for payroll's client: invalid_client, the tenant does not trust {OTHER_DOMAIN}")
    for_other = jwt_svid(cluster, f"{INSIDE}/t/{other.tenant}")
    check(claims_of(for_other).get("sub") == SPIRE_ID,
          f"the SPIRE agent gives payroll a JWT-SVID of its own for {other.tenant}'s issuer")
    refused_client(cluster.curl("payroll", "payroll", token_endpoint,
                                *form({**fields, "client_assertion": for_other})),
                   f"presented to {tenant}: invalid_client")


def forged_header(cluster, admin, fields):
    step("X-Forwarded-Client-Cert sent from outside the mesh, ignored")
    tenant = admin.tenant
    forged = (f"By=spiffe://{MESH_DOMAIN}/ns/hodor/sa/hodor;Hash={'ab' * 32};Subject=\"\";URI={MESH_ID}")
    answer = cluster.curl("outside", "outsider", f"{INSIDE}/t/{tenant}/oauth2/token",
                          "--header", f"X-Forwarded-Client-Cert: {forged}", *form(fields))
    refused_client(answer, f"outsider names payroll's identity in the header: invalid_client, "
                           f"Hodor's sidecar took the header away")
    answer = post_form(f"{SERVER}/t/{tenant}/oauth2/token", fields, {"X-Forwarded-Client-Cert": forged})
    refused_client(answer, "sent through the port forward, from an address Hodor does not trust: invalid_client")


def the_bundle_kept_current(cluster, admin, added):
    step("The worker keeps SPIRE's bundle current")
    before = added["refresh"]["fetched_at"]

    def fetched_again():
        items = admin.call("GET", "/trust-domains")["items"]
        found = next(item for item in items if item["name"] == SPIRE_DOMAIN)
        refresh = found["refresh"]
        return found if refresh["fetched_at"] != before and refresh["failing_since"] is None else None

    found = until("a fetch of SPIRE's bundle by the worker", fetched_again, seconds=180)
    check(found["bundle"]["keys"], f"the worker fetched it again at {found['refresh']['fetched_at']}, "
                                   f"after the refresh hint SPIRE gives")
    said = lines_of(cluster.cli("trust-domain", "show", "--tenant", admin.tenant, "--name", SPIRE_DOMAIN))
    shown(f"fetched {said.get('fetched')}, next {said.get('next-fetch')}")


def tenants_apart(cluster, admin, other, account, token, in_mesh, spire_domain):
    step("Tenants apart")
    check(other.call("GET", "/trust-domains")["items"] == [], f"{other.tenant} trusts no trust domain")
    answer = request("GET", f"{SERVER}/t/{other.tenant}/api/v1/admin/trust-domains/{spire_domain}",
                     headers=other.headers)
    check(answer.status == 404 and answer.code == "keys.trust_domain_not_found",
          f"the administrator of {other.tenant} finds no trust domain of {admin.tenant}'s identifier")
    answer = evaluate_inside(cluster, "payroll", "payroll", other.tenant, token, account)
    check(answer.status == 401, f"the bound token is refused by {other.tenant}, even with its certificate")
    fields = {"grant_type": "client_credentials", "client_id": in_mesh}
    refused_client(cluster.curl("payroll", "payroll", f"{INSIDE}/t/{other.tenant}/oauth2/token", *form(fields)),
                   f"and payroll's certificate gets no token from {other.tenant}")


def the_audit_log(cluster, admin):
    step("The audit log")
    wanted = {"keys.trust_domain_added", "oauth.client_created"}

    def records():
        items = admin.call("GET", "/audit-records?limit=200")["items"]
        return items if wanted <= {item["action"] for item in items} else None

    items = until("the audit records of the demonstration", records)
    added = sorted(item["details"].get("name") for item in items if item["action"] == "keys.trust_domain_added")
    check(added == sorted([SPIRE_DOMAIN, MESH_DOMAIN]), f"both trust domains were added: {', '.join(added)}")
    check(cluster.cli("audit", "verify", "--tenant", admin.tenant).startswith("intact: "),
          "the audit chain is intact")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    suffix = format(int(time.time() * 1000), "x")
    tenant, other = f"acme-{suffix}", f"globex-{suffix}"
    forward = None
    with tempfile.TemporaryDirectory(prefix="hodor-milestone-10-") as state:
        cluster = Cluster(state)
        try:
            a_kind_cluster(cluster)
            istio(cluster)
            spire(cluster)
            hodor(cluster)
            forward = forwarded(cluster)
            admin, other_admin = two_tenants(cluster, tenant, other, suffix)
            spire_domain = two_trust_domains(cluster, admin)
            account, by_svid, in_mesh = a_service_account_and_two_clients(cluster, admin)
            _, svid_fields = a_token_with_a_jwt_svid(cluster, admin, account, by_svid, spire_domain)
            token, mesh_fields = a_token_with_no_credential(cluster, admin, account, in_mesh)
            the_bound_token_without_its_certificate(cluster, admin, account, token)
            jwt_svids_refused(cluster, admin, other_admin, svid_fields)
            forged_header(cluster, admin, mesh_fields)
            the_bundle_kept_current(cluster, admin, spire_domain)
            tenants_apart(cluster, admin, other_admin, account, token, in_mesh, spire_domain["id"])
            the_audit_log(cluster, admin)
        except Failed as failure:
            print(f"\nThe demonstration stopped: {failure}", file=sys.stderr)
            sys.exit(1)
        finally:
            if forward is not None:
                forward.terminate()
                forward.wait()
    print("\nThe demonstration of Milestone 10 passed.")
    print(f"The cluster {CLUSTER} is still running; `kind delete cluster --name {CLUSTER}` removes it.")


if __name__ == "__main__":
    main()
