#!/usr/bin/env python3
"""The demonstration of Milestone 5: the authorization engine.

Runs against the development stack and does what an administrator, an
operator and an application would do: permissions and roles for a resource
server, a role given to a person and to a client, decisions asked for with
an access token, a condition that changes the answer, a resource server
bound to Open Policy Agent with policies published, simulated and rolled
back, a stopped instance whose decisions are never allowed, the record of
decisions, and a token of one tenant refused by another. Every answer is
checked; the first one that is not what it should be stops the
demonstration with a non-zero exit status.

    docker compose -f deploy/docker/compose.yaml up --build --wait
    python3 deploy/demo/authorization.py

It needs Python 3 and Docker, and nothing outside the standard library. It
starts an Open Policy Agent instance of its own next to the stack, and
removes it at the end. See docs/operations/quick-start.md.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from demo import SERVER, Failed, check, cli, compose, request, shown, step, until
from external_identities import post_form

POLICY_AGENT_IMAGE = "openpolicyagent/opa:1.10.1"
API = "urn:hodor:authorization"
PAYROLL = "https://payroll.example.com"
LEDGER = "https://ledger.example.com"
REPOSITORY = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Administrator:
    """The tenant's first administrator, calling the administration interface."""

    def __init__(self, tenant, token):
        self.tenant = tenant
        self.headers = {"Authorization": f"Bearer {token}"}

    def call(self, method, path, body=None, expected=(200, 201, 202, 204)):
        answer = request(method, f"{SERVER}/t/{self.tenant}/api/v1/admin{path}", body, self.headers)
        if answer.status not in expected:
            raise Failed(f"{method} {path} answered {answer.status}: {answer.text}")
        return answer.json() if answer.text else {}


def token_for(tenant, client, scope):
    """An access token for the Authorization API, by client credentials."""
    basic = base64.b64encode(f"{client['id']}:{client['secret']}".encode()).decode()
    answer = post_form(f"{SERVER}/t/{tenant}/oauth2/token",
                       {"grant_type": "client_credentials", "resource": API, "scope": scope},
                       {"Authorization": f"Basic {basic}"})
    check(answer.status == 200, f"the client gets a token for the Authorization API (answered {answer.status})")
    return answer.json()["access_token"]


def evaluate(tenant, token, subject, action, resource):
    answer = request("POST", f"{SERVER}/t/{tenant}/api/v1/authorization/evaluate", {
        "subject": subject,
        "resource": resource,
        "action": action,
    }, {"Authorization": f"Bearer {token}"})
    return answer


def decided(answer, decision, reason, what):
    body = answer.json() if answer.text else {}
    check(answer.status == 200 and body.get("decision") == decision and body.get("reason") == reason,
          f"{what}: {decision} with {reason}"
          + ("" if answer.status == 200 and body.get("decision") == decision else f" (answered {answer.status} {body})"))
    shown(f"{body.get('decision')} {body.get('reason')}"
          + (f" by {body.get('engine')} at revision {body.get('policy_version')}"
             if body.get("policy_version") else ""))
    return body


def application(admin, name, audience, scopes):
    created = admin.call("POST", "/applications", {"name": name, "first_party": True})
    server = admin.call("POST", "/resource-servers", {
        "application_id": created["id"],
        "audience": audience,
        "name": name,
        "scopes": [{"name": scope, "description": scope} for scope in scopes],
    })
    return created["id"], server["id"]


def service_client(admin, application_id):
    client = admin.call("POST", f"/applications/{application_id}/clients", {
        "name": "Service",
        "type": "confidential",
        "grant_types": ["client_credentials"],
        "allowed_scopes": ["authz:evaluate", "authz:simulate", "authz:explain"],
    })
    return {"id": client["id"], "secret": client["client_secret"]}


# ---------------------------------------------------------------------------
# Open Policy Agent, next to the stack
# ---------------------------------------------------------------------------

def stack_network():
    """The network the stack's server is on, for the instance to join."""
    found = subprocess.run([*compose(), "ps", "-q", "server"], capture_output=True, text=True, check=False)
    container = found.stdout.strip().splitlines()[:1]
    check(container, "the stack's server is running")
    inspected = subprocess.run(
        ["docker", "inspect", container[0], "--format",
         "{{range $name, $network := .NetworkSettings.Networks}}{{$name}} {{end}}"],
        capture_output=True, text=True, check=False)
    return inspected.stdout.split()[0]


class PolicyAgent:
    """An Open Policy Agent instance shared by the tenants, as an operator runs one."""

    def __init__(self, name, directory):
        self.name = name
        self.directory = directory
        self.container = f"hodor-demonstration-{name}"

    def start(self, network):
        subprocess.run(["docker", "rm", "-f", self.container], capture_output=True, check=False)
        done = subprocess.run([
            "docker", "run", "-d", "--rm", "--name", self.container,
            "--network", network, "--network-alias", "policy-agent",
            "-v", f"{self.directory}:/configuration:ro",
            POLICY_AGENT_IMAGE, "run", "--server", "--addr", "0.0.0.0:8181",
            "--config-file", "/configuration/config.yaml",
            "/configuration/decision-log-mask.rego",
        ], capture_output=True, text=True, check=False)
        check(done.returncode == 0, f"the instance {self.name} starts" + (f": {done.stderr}" if done.returncode else ""))

    def stop(self):
        subprocess.run(["docker", "stop", "-t", "1", self.container], capture_output=True, check=False)


def configuration(credential, bundle, public_key):
    """The instance's configuration: where its bundle is and who signs it."""
    indented = "\n".join(f"      {line}" for line in public_key.strip().splitlines())
    return f"""services:
  hodor:
    url: http://server:8080/opa
    credentials:
      bearer:
        token: {credential}
bundles:
  {bundle}:
    service: hodor
    resource: bundles/{bundle}
    polling:
      min_delay_seconds: 1
      max_delay_seconds: 2
    signing:
      keyid: hodor
keys:
  hodor:
    algorithm: ES256
    key: |
{indented}
status:
  service: hodor
decision_logs:
  service: hodor
  reporting:
    min_delay_seconds: 1
    max_delay_seconds: 2
"""


def policy(package, deletes):
    rules = 'decision := {"allow": true} if input.action == "read"\n'
    if deletes:
        rules += 'decision := {"allow": true} if input.action == "delete"\n'
    return (f"package {package}\n\ndefault decision := {{\"allow\": false}}\n\n{rules}",
            f"package {package}\n\ntest_reading_is_allowed if decision.allow with input as {{\"action\": \"read\"}}\n")


# ---------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------

def two_tenants(tenant, other, operator):
    step("Two tenants, and an administrator")
    for slug, name in [(tenant, "Acme"), (other, "Globex")]:
        said = cli("tenant", "create", "--slug", slug, "--name", name)
        check(slug in said, f"the command-line tool created {slug}")
        cli("keys", "rotate", "--tenant", slug)
    said = dict(line.split(" ", 1) for line in
                cli("admin", "bootstrap", "--tenant", tenant, "--email", operator).splitlines())
    check(said.get("role") == "tenant_administrator", f"{operator} is an administrator of {tenant}")
    return Administrator(tenant, said["token"])


def roles_and_who_holds_them(admin, ana):
    step("Permissions and roles of a resource server, given to a person and a client")
    application(admin, "Authorization API", API, ["authz:evaluate", "authz:simulate", "authz:explain"])
    payroll, payroll_server = application(admin, "Payroll", PAYROLL, ["payroll:read"])
    client = service_client(admin, payroll)
    for name, description in [("invoice:read", "Read an invoice"), ("invoice:approve", "Approve an invoice")]:
        admin.call("PUT", f"/resource-servers/{payroll_server}/permissions/{name}", {"description": description})
    admin.call("PUT", f"/resource-servers/{payroll_server}/roles/clerk",
               {"permissions": [{"name": "invoice:read"}]})
    approver = admin.call("PUT", f"/resource-servers/{payroll_server}/roles/approver", {
        "permissions": [{"name": "invoice:approve"}],
        "includes": [{"namespace": PAYROLL, "name": "clerk"}],
    })
    check(approver["includes"] == [{"namespace": PAYROLL, "name": "clerk"}], "an approver is also a clerk")
    admin.call("POST", "/role-assignments", {
        "principal": {"kind": "user", "id": ana},
        "role": {"namespace": PAYROLL, "name": "approver"},
    })
    admin.call("POST", "/role-assignments", {
        "principal": {"kind": "client", "id": client["id"]},
        "role": {"namespace": PAYROLL, "name": "clerk"},
        "application_id": payroll,
    })
    held = admin.call("GET", f"/users/{ana}/role-assignments")["items"]
    check([item["role"]["name"] for item in held] == ["approver"], "the person holds the approver role")
    admin.call("PUT", f"/resource-servers/{payroll_server}/binding", {"engine": "native"})
    shown("Payroll is answered by the native engine")
    return payroll_server, client


def decisions_by_role(tenant, client, ana):
    step("The application asks, with its token")
    token = token_for(tenant, client, "authz:evaluate authz:explain")
    invoice = {"type": "invoice", "id": "invoice-42", "attributes": {"amount": 5000}}
    decided(evaluate(tenant, token, {"type": "user", "id": ana}, "approve", invoice),
            "ALLOW", "matching_role", "the approver may approve")
    decided(evaluate(tenant, token, {"type": "client", "id": client["id"]}, "approve", invoice),
            "DENY", "no_matching_role", "the client, a clerk, may not approve")
    decided(evaluate(tenant, token, {"type": "client", "id": client["id"]}, "read", invoice),
            "ALLOW", "matching_role", "the client may read, for its own application")
    return token


def a_condition(admin, tenant, token, payroll_server, ana):
    step("A condition changes the answer")
    admin.call("PUT", f"/resource-servers/{payroll_server}/roles/approver", {
        "permissions": [{"name": "invoice:approve", "condition": "resource.attributes.amount <= 1000"}],
        "includes": [{"namespace": PAYROLL, "name": "clerk"}],
    })
    refused = request("PUT", f"{SERVER}/t/{tenant}/api/v1/admin/resource-servers/{payroll_server}/roles/approver",
                      {"permissions": [{"name": "invoice:approve", "condition": "resource.attributes.amount <="}]},
                      admin.headers)
    check(refused.status == 422 and refused.code == "authorization.condition_invalid",
          "a condition that does not compile is refused when the role is saved")
    person = {"type": "user", "id": ana}
    decided(evaluate(tenant, token, person, "approve",
                     {"type": "invoice", "id": "invoice-42", "attributes": {"amount": 5000}}),
            "DENY", "condition_not_met", "an approver may no longer approve 5000")
    decided(evaluate(tenant, token, person, "approve",
                     {"type": "invoice", "id": "invoice-43", "attributes": {"amount": 500}}),
            "ALLOW", "matching_role", "an approver still approves 500")


def waited(admin, number, state):
    def look():
        version = admin.call("GET", f"/policy-versions/{number}")
        if version["state"] == "rejected":
            raise Failed(f"version {number} was rejected: {version.get('report')}")
        return version if version["state"] == state else None
    return until(f"version {number} to be {state}", look, seconds=120)


def checked_and_tested(admin, number):
    admin.call("POST", f"/policy-versions/{number}:validate")
    waited(admin, number, "validated")
    admin.call("POST", f"/policy-versions/{number}:test")
    version = waited(admin, number, "tested")
    shown(f"version {number} is tested: {len(version['report']['tests'])} test passed")


def running(admin, instance, revision):
    def look():
        status = admin.call("GET", "/policy-status")
        latest = status.get("latest") or {}
        mine = [item for item in status["instances"] if item["instance"] == instance]
        return status if latest.get("revision") == revision and mine and mine[0]["current"] else None
    until(f"{instance} to run revision {revision}", look, seconds=90)
    shown(f"{instance} runs revision {revision}")


def open_policy_agent(admin, tenant, suffix, directory):
    step("A resource server bound to Open Policy Agent")
    ledger, ledger_server = application(admin, "Ledger", LEDGER, ["ledger:read"])
    client = service_client(admin, ledger)
    keys = cli("policy-agent", "signing-key")
    private = keys[:keys.index("-----BEGIN PUBLIC KEY-----")]
    public = keys[keys.index("-----BEGIN PUBLIC KEY-----"):]
    with open(os.path.join(directory, "signing.pem"), "w", encoding="utf-8") as file:
        file.write(private)
    os.chmod(os.path.join(directory, "signing.pem"), 0o644)
    name = f"shared-{suffix}"
    registered = cli("policy-agent", "instance", "add", "--name", name).splitlines()
    credential = registered[-1].strip()
    check(credential.startswith("hodor_pa_"), "the instance gets a credential of its own, shown once")
    bundle = cli("policy-agent", "bundle-name", "--tenant", tenant)
    package = cli("policy-agent", "bundle-name", "--tenant", tenant, "--namespace", LEDGER)
    with open(os.path.join(directory, "config.yaml"), "w", encoding="utf-8") as file:
        file.write(configuration(credential, bundle, public))
    shutil.copy(os.path.join(REPOSITORY, "deploy", "open-policy-agent", "decision-log-mask.rego"), directory)
    for name in ("config.yaml", "decision-log-mask.rego"):
        os.chmod(os.path.join(directory, name), 0o644)
    agent = PolicyAgent(name, directory)
    agent.start(stack_network())
    admin.call("PUT", f"/resource-servers/{ledger_server}/binding",
               {"engine": "open_policy_agent", "time_limit_milliseconds": 1000})
    signing = {"volumes": [f"{directory}:/operator:ro"],
               "environment": ["HODOR_OPEN_POLICY_AGENT_SIGNING_KEY_FILE=/operator/signing.pem"]}

    def drafted(deletes):
        files = os.path.join(directory, f"policy-{'deletes' if deletes else 'reads'}")
        os.makedirs(os.path.join(files, "ledger"), mode=0o755, exist_ok=True)
        os.chmod(files, 0o755)
        os.chmod(os.path.join(files, "ledger"), 0o755)
        module, test = policy(package, deletes)
        for path, text in [("ledger/policy.rego", module), ("ledger/policy_test.rego", test)]:
            with open(os.path.join(files, path), "w", encoding="utf-8") as file:
                file.write(text)
            os.chmod(os.path.join(files, path), 0o644)
        said = cli("policy", "draft", "--tenant", tenant, "--directory", "/policy", "--written-by", "operator",
                   volumes=[f"{files}:/policy:ro"])
        return int(said.splitlines()[-1].split()[0])

    first = drafted(deletes=False)
    checked_and_tested(admin, first)
    said = cli("policy", "publish", "--tenant", tenant, "--version", str(first), **signing)
    shown(said)
    running(admin, name, 1)
    token = token_for(tenant, client, "authz:evaluate")
    entry = {"type": "entry", "id": "entry-7"}
    service = {"type": "client", "id": client["id"]}
    decided(evaluate(tenant, token, service, "read", entry), "ALLOW", "policy_allowed",
            "the published policy allows reading")
    decided(evaluate(tenant, token, service, "delete", entry), "DENY", "policy_denied",
            "and denies deleting")

    step("A draft simulated, published, rolled back")
    second = drafted(deletes=True)
    admin.call("POST", f"/policy-versions/{second}:validate")
    waited(admin, second, "validated")
    simulation = admin.call("POST", f"/policy-versions/{second}/simulations", {
        "resource_server_id": ledger_server,
        "inputs": [{"action": "read"}, {"action": "delete"}],
    })

    def simulated():
        found = admin.call("GET", f"/policy-simulations/{simulation['simulation_id']}")
        return found if found["state"] != "waiting" else None

    result = until("the simulation", simulated, seconds=120)
    check(result["state"] == "done" and [answer["differs"] for answer in result["results"]] == [False, True],
          "the simulation shows the draft would allow deleting, which the published version denies")
    admin.call("POST", f"/policy-versions/{second}:test")
    waited(admin, second, "tested")
    shown(cli("policy", "publish", "--tenant", tenant, "--version", str(second), **signing))
    running(admin, name, 2)
    decided(evaluate(tenant, token, service, "delete", entry), "ALLOW", "policy_allowed",
            "revision 2 allows deleting")
    shown(cli("policy", "rollback", "--tenant", tenant, "--revision", "1", **signing))
    running(admin, name, 3)
    decided(evaluate(tenant, token, service, "delete", entry), "DENY", "policy_denied",
            "the rollback, revision 3, denies deleting again")

    step("A stopped instance is never an allow")
    agent.stop()
    answer = evaluate(tenant, token, service, "read", entry)
    body = answer.json()
    check(answer.status == 200 and body.get("decision") == "INDETERMINATE"
          and body.get("reason", "").startswith("policy_engine_"),
          f"with the instance stopped, reading is indeterminate, which denies: {body}")
    shown(f"{body['decision']} {body['reason']}")
    return token


def the_record(admin, ana):
    step("The record of decisions")
    wanted = {(PAYROLL, "allow", "matching_role"), (PAYROLL, "deny", "condition_not_met"),
              (LEDGER, "allow", "policy_allowed"), (LEDGER, "deny", "policy_denied")}

    def records():
        items = admin.call("GET", "/decisions?limit=200")["items"]
        found = {(item["namespace"], item["effect"], item["reason"]) for item in items}
        stopped = any(item["namespace"] == LEDGER and item["effect"] == "indeterminate" for item in items)
        return items if wanted <= found and stopped else None

    items = until("the recorded decisions", records)
    check(any(item["subject"] == {"kind": "user", "id": ana} for item in items),
          "the person's decisions are recorded under their identifier")
    shown(f"{len(items)} decisions recorded, from both engines, the stopped instance's among them")


def tenants_apart(other, token):
    step("A token of one tenant evaluates nothing in another")
    answer = evaluate(other, token, {"type": "user", "id": "0193f1c4-0000-7000-8000-000000000001"},
                      "read", {"type": "invoice", "id": "invoice-42"})
    check(answer.status == 401, f"the token is refused by {other}: {answer.status}")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    suffix = format(int(time.time() * 1000), "x")
    tenant, other = f"acme-{suffix}", f"globex-{suffix}"
    directory = tempfile.mkdtemp(prefix="hodor-authorization-")
    # The containers run as users of their own, which must read what is
    # mounted from here: the key that signs bundles, the policy files and
    # the instance's configuration. They are this run's and nobody else's,
    # and are removed at the end.
    os.chmod(directory, 0o755)
    agent = PolicyAgent(f"shared-{suffix}", directory)
    try:
        admin = two_tenants(tenant, other, f"operator-{suffix}@example.com")
        ana = admin.call("POST", "/users", {"email": f"ana-{suffix}@example.com"})["id"]
        payroll_server, client = roles_and_who_holds_them(admin, ana)
        token = decisions_by_role(tenant, client, ana)
        a_condition(admin, tenant, token, payroll_server, ana)
        open_policy_agent(admin, tenant, suffix, directory)
        the_record(admin, ana)
        tenants_apart(other, token)
    except Failed as failure:
        print(f"\nThe demonstration stopped: {failure}", file=sys.stderr)
        sys.exit(1)
    finally:
        agent.stop()
        shutil.rmtree(directory, ignore_errors=True)
    print("\nThe demonstration of Milestone 5 passed.")


if __name__ == "__main__":
    main()
