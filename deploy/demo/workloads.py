#!/usr/bin/env python3
"""The demonstration of Milestone 8: workloads, agents and webhooks.

Runs against the development stack and does what an administrator, an
operator, a service, an agent, a person and a receiver of webhooks would
do: a service account with a client, an API key and a role, allowed by the
Authorization API with its token and with its key; an agent that exchanges
a person's token for one it holds on their behalf, whose `act` claim and
audit record name it, and an exchange for a wider scope refused; a webhook
endpoint that receives the event of a sign-in, signed, then, while it is
stopped, retries, a delivery set aside and delivered again; and a key and a
webhook of one tenant refused by another. Every answer is checked; the
first one that is not what it should be stops the demonstration with a
non-zero exit status.

    docker compose -f deploy/docker/compose.yaml up --build --wait
    python3 deploy/demo/workloads.py

It needs Python 3 and Docker, and nothing outside the standard library. It
stops the stack's receiver of webhooks for a while and starts it again. Run
it before the demonstration of Milestone 6, whose second worker removes the
delivered messages this one reads. See docs/operations/quick-start.md.
"""

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import urllib.parse

from authorization import API, Administrator, application, decided, evaluate
from demo import SERVER, Browser, Failed, check, cli, compose, link_from_message, request, shown, step, until
from external_identities import completed, post_form, query_of
from strong_authentication import REDIRECT_URI, Application

RECEIVER = os.environ.get("HODOR_WEBHOOK_RECEIVER_URL", "http://localhost:9600")
# Where Hodor reaches the receiver, inside the stack.
RECEIVER_INSIDE = "http://webhook-receiver:9600"
# The worker of the development stack sets a delivery aside after this many attempts.
ATTEMPTS = 3
PASSWORD = "a password for the demonstration of milestone eight"
PAYROLL = "https://payroll.example.com"
ASSISTANT = "https://assistant.example.com"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def basic(client_id, secret):
    pair = f"{urllib.parse.quote(client_id)}:{urllib.parse.quote(secret)}"
    return {"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()}


def lines_of(said):
    """The lines a command printed, as `name value`."""
    return dict(line.split(" ", 1) for line in said.splitlines() if " " in line)


def audiences(claims):
    """The audiences of a token, one or several."""
    found = claims.get("aud")
    return found if isinstance(found, list) else [found]


def refused(answer, status, code, what):
    check(answer.status == status and answer.code == code,
          f"{what}: {status} {code}" + ("" if answer.status == status else f" (answered {answer.status} {answer.text})"))


def bootstrap(tenant, operator):
    said = lines_of(cli("admin", "bootstrap", "--tenant", tenant, "--email", operator))
    check(said.get("role") == "tenant_administrator", f"{operator} is an administrator of {tenant}")
    return Administrator(tenant, said["token"])


def a_person(admin, address):
    """A person of the tenant, with a password chosen from a recovery link."""
    person = admin.call("POST", "/users", {"email": address, "display_name": "Ana"})["id"]
    asked = request("POST", f"{SERVER}/t/{admin.tenant}/interaction/recovery", {"email": address})
    check(asked.status == 202, f"{address} asks for a link to choose a password")
    _, token = link_from_message(address, admin.tenant)
    done = request("POST", f"{SERVER}/t/{admin.tenant}/interaction/recovery/complete",
                   {"token": token, "password": PASSWORD})
    check(done.status == 204, f"{address} chose a password")
    return person


def signed_in(tenant, address):
    browser = Browser()
    check(completed(browser.sign_in(tenant, address, PASSWORD)), f"{address} signed in with the password")
    return browser


# ---------------------------------------------------------------------------
# The receiver of webhooks, as the tenant's own system would be
# ---------------------------------------------------------------------------

def received(path, webhook_id=None):
    query = {"path": path, **({"webhook-id": webhook_id} if webhook_id else {})}
    answer = request("GET", f"{RECEIVER}/received?" + urllib.parse.urlencode(query))
    if answer.status != 200:
        raise Failed(f"the receiver at {RECEIVER} answered {answer.status}")
    return answer.json()["items"]


def signed_with(delivery, secret):
    """Checks a delivery as Standard Webhooks say a receiver checks one."""
    headers = delivery["headers"]
    content = f"{headers['webhook-id']}.{headers['webhook-timestamp']}.{delivery['body']}".encode()
    key = base64.b64decode(secret.removeprefix("whsec_"))
    expected = base64.b64encode(hmac.new(key, content, hashlib.sha256).digest()).decode()
    signatures = [value.split(",", 1)[1] for value in headers["webhook-signature"].split() if value.startswith("v1,")]
    fresh = abs(time.time() - int(headers["webhook-timestamp"])) < 300
    return fresh and any(hmac.compare_digest(expected, signature) for signature in signatures)


def receiver(action):
    """Stops or starts the stack's receiver of webhooks."""
    done = subprocess.run([*compose(), action, "webhook-receiver"], capture_output=True, text=True, check=False)
    check(done.returncode == 0, f"the receiver was told to {action}"
          + ("" if done.returncode == 0 else f": {done.stderr.strip()}"))


def receiver_answers():
    try:
        return request("GET", f"{RECEIVER}/health").status == 200
    except Exception:  # noqa: BLE001 - not answering yet is what is waited for
        return False


# ---------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------

def two_tenants(tenant, other, suffix):
    step("Two tenants, and their administrators")
    identifiers = {}
    for slug, name in [(tenant, "Acme"), (other, "Globex")]:
        said = cli("tenant", "create", "--slug", slug, "--name", name)
        check(said.startswith(f"created {slug} "), f"the command-line tool created {slug}")
        identifiers[slug] = said.split()[2]
        cli("keys", "rotate", "--tenant", slug)
    return (bootstrap(tenant, f"operator-{suffix}@example.com"),
            bootstrap(other, f"operator-globex-{suffix}@example.com"),
            identifiers[tenant])


def a_service_account(admin, owner):
    step("A service account, its client, its key and its role")
    tenant = admin.tenant
    application(admin, "Authorization API", API, ["authz:evaluate"])
    payroll, payroll_server = application(admin, "Payroll", PAYROLL, ["payroll:read", "payroll:approve"])
    admin.call("PUT", f"/resource-servers/{payroll_server}/permissions/invoice:approve",
               {"description": "Approve an invoice"})
    admin.call("PUT", f"/resource-servers/{payroll_server}/roles/approver",
               {"permissions": [{"name": "invoice:approve"}]})
    admin.call("PUT", f"/resource-servers/{payroll_server}/binding", {"engine": "native"})
    account = admin.call("POST", "/service-accounts", {"name": "Nightly export", "owners": [owner]})
    check(account["status"] == "active" and account["owners"] == [owner],
          "the service account is active, and owned by a person of the tenant")
    client = admin.call("POST", f"/applications/{payroll}/clients", {
        "name": "Nightly export",
        "type": "confidential",
        "grant_types": ["client_credentials"],
        "allowed_scopes": ["authz:evaluate"],
        "principal": account["id"],
    })
    check(client["principal"] == account["id"], "a client of Payroll acts as the service account")
    admin.call("POST", "/role-assignments", {
        "principal": {"kind": "user", "id": account["id"]},
        "role": {"namespace": PAYROLL, "name": "approver"},
    })
    held = admin.call("GET", f"/users/{account['id']}/role-assignments")["items"]
    check([item["role"]["name"] for item in held] == ["approver"], "the service account holds the approver role")
    said = lines_of(cli("service-account", "key", "create", "--tenant", tenant, "--id", account["id"],
                        "--name", "Payroll checks", "--scope", "authz:evaluate", "--application", payroll))
    key = said.get("api-key", "")
    check(key.startswith("hodor_ak_") and len(key) == 73, "the command-line tool printed the key once")
    shown(f"key {said.get('key')}, …{key[-4:]}, expires {said.get('expires')}")
    listed = admin.call("GET", f"/service-accounts/{account['id']}/api-keys")["items"]
    check([item["hint"] for item in listed] == ["…" + key[-4:]] and key not in json.dumps(listed),
          "the administration interface lists the key by its last four characters, never the key")
    return account["id"], {"id": client["id"], "secret": client["client_secret"]}, key


def evaluated_with_its_token_and_its_key(tenant, account, client, key):
    step("Evaluated with its token and with its key")
    answer = post_form(f"{SERVER}/t/{tenant}/oauth2/token",
                       {"grant_type": "client_credentials", "resource": API, "scope": "authz:evaluate"},
                       basic(client["id"], client["secret"]))
    check(answer.status == 200, f"the client gets a token by client credentials (answered {answer.status})")
    token = answer.json()["access_token"]
    claims = Application(tenant, client["id"], client["secret"]).checked(token, "the access token")
    check(claims.get("sub") == account and claims.get("principal_kind") == "service_account",
          "the token names the service account in sub, with principal_kind")
    subject = {"type": "user", "id": account}
    invoice = {"type": "invoice", "id": "invoice-42"}
    decided(evaluate(tenant, token, subject, "approve", invoice), "ALLOW", "matching_role",
            "with its token, the service account may approve")
    decided(evaluate(tenant, key, subject, "approve", invoice), "ALLOW", "matching_role",
            "and with its key")
    forged = key[:-1] + ("0" if key[-1] != "0" else "1")
    answer = evaluate(tenant, forged, subject, "approve", invoice)
    check(answer.status == 401, f"the same key with one character changed is refused: {answer.status}")


def an_agent_acts_for_a_person(admin, owner, address):
    step("An agent acts for a person, through token exchange")
    tenant = admin.tenant
    assistant, _ = application(admin, "Assistant", ASSISTANT, ["payroll:read"])
    web = admin.call("POST", f"/applications/{assistant}/clients", {
        "name": "Assistant web",
        "type": "confidential",
        "grant_types": ["authorization_code"],
        "redirect_uris": [REDIRECT_URI],
        "allowed_scopes": ["openid", "payroll:read"],
    })
    agent = admin.call("POST", "/agents", {"name": "Payroll assistant", "owners": [owner]})["id"]
    client = admin.call("POST", f"/applications/{assistant}/clients", {
        "name": "Payroll assistant",
        "type": "confidential",
        "grant_types": ["client_credentials", TOKEN_EXCHANGE],
        "allowed_scopes": ["payroll:read", "payroll:approve"],
        "principal": agent,
        "exchange_rules": [{"subject_audience": ASSISTANT, "audience": PAYROLL}],
    })
    check(client["exchange_rules"] == [{"subject_audience": ASSISTANT, "audience": PAYROLL}],
          "the agent's client may exchange a token for the assistant for one for Payroll")

    # The person signs in to the assistant, which gets a token for itself.
    portal = Application(tenant, web["id"], web["client_secret"])
    browser = signed_in(tenant, address)
    answer, parameters, verifier = portal.authorize(browser, scope="openid payroll:read", resource=ASSISTANT)
    back = query_of(answer.headers.get("Location", ""))
    check(answer.status in (302, 303) and back.get("state") == parameters["state"] and "code" in back,
          "the assistant gets a code at once: it is the tenant's own application")
    redeemed = post_form(f"{SERVER}/t/{tenant}/oauth2/token",
                         {"grant_type": "authorization_code", "code": back["code"],
                          "redirect_uri": REDIRECT_URI, "code_verifier": verifier},
                         basic(web["id"], web["client_secret"]))
    check(redeemed.status == 200, "the assistant redeems the code"
          + ("" if redeemed.status == 200 else f" (answered {redeemed.status} {redeemed.text})"))
    subject = redeemed.json()["access_token"]
    person_token = portal.checked(subject, "the person's access token")
    check(ASSISTANT in audiences(person_token) and "payroll:read" in person_token.get("scope", "").split(),
          "the person's token is for the assistant, with payroll:read")

    own = post_form(f"{SERVER}/t/{tenant}/oauth2/token", {"grant_type": "client_credentials"},
                    basic(client["id"], client["client_secret"]))
    check(own.status == 200, f"the agent's client gets the agent's own token by client credentials ({own.status})")
    actor = own.json()["access_token"]

    def exchange(**extra):
        return post_form(f"{SERVER}/t/{tenant}/oauth2/token", {
            "grant_type": TOKEN_EXCHANGE,
            "subject_token": subject,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "actor_token": actor,
            "actor_token_type": ACCESS_TOKEN_TYPE,
            **extra,
        }, basic(client["id"], client["client_secret"]))

    exchanged = exchange(audience=PAYROLL, scope="payroll:read")
    good = exchanged.status == 200 and exchanged.json().get("issued_token_type") == ACCESS_TOKEN_TYPE
    check(good, "the agent exchanges the person's token for one for Payroll"
          + ("" if good else f" (answered {exchanged.status} {exchanged.text})"))
    held = Application(tenant, client["id"], client["client_secret"]).checked(
        exchanged.json()["access_token"], "the exchanged token")
    shown(f"sub {held.get('sub')}, act {json.dumps(held.get('act'))}, aud {held.get('aud')}")
    check(held.get("sub") == person_token.get("sub") and audiences(held) == [PAYROLL],
          "it names the person in sub, for Payroll")
    check(held.get("act") == {"sub": agent, "principal_kind": "agent"}, "and the agent in act")
    check("refresh_token" not in exchanged.json(), "an exchange never gives a refresh token")
    return agent, person_token.get("sub"), exchange


def a_wider_exchange_refused(exchange):
    step("An exchange for a wider scope, or another audience, refused")
    wider = exchange(audience=PAYROLL, scope="payroll:read payroll:approve")
    check(wider.status == 400 and wider.json().get("error") == "invalid_scope",
          f"payroll:approve, which the person's token does not hold, is refused: invalid_scope ({wider.status})")
    elsewhere = exchange(audience=API, scope="authz:evaluate")
    check(elsewhere.status == 400 and elsewhere.json().get("error") == "invalid_target",
          f"an audience no exchange rule allows is refused: invalid_target ({elsewhere.status})")


def a_webhook_endpoint(admin, tenant_id, address):
    step("A webhook endpoint, and a sign-in that arrives signed")
    tenant = admin.tenant
    path = f"/{tenant}"
    said = cli("webhook", "add", "--tenant", tenant, "--url", f"{RECEIVER_INSIDE}{path}",
               "--event", "session.started", "--description", "The demonstration's receiver")
    first = said.splitlines()[0].split()
    check(first[0] == "created" and first[2] == f"{RECEIVER_INSIDE}{path}",
          "the command-line tool registered the endpoint")
    endpoint = first[1]
    secret = lines_of(said).get("secret", "")
    check(secret.startswith("whsec_"), "and printed its secret, once")
    listed = cli("webhook", "list", "--tenant", tenant)
    check(listed == f"{endpoint} {RECEIVER_INSIDE}{path} session.started" and secret not in listed,
          "the endpoint is listed, without its secret")

    signed_in(tenant, address)
    deliveries = until("the delivery of the sign-in", lambda: received(path))
    delivery = deliveries[0]
    body = json.loads(delivery["body"])
    shown(f"webhook-id {delivery['headers']['webhook-id']}, {body.get('type')}")
    check(signed_with(delivery, secret), "the signature checks with the secret, as Standard Webhooks say")
    check(body.get("type") == "session.started" and body.get("tenant_id") == tenant_id
          and body.get("id") == delivery["headers"]["webhook-id"] and "session_id" in body.get("data", {}),
          "the body is the event of the sign-in, in this tenant, with its session")
    # The endpoint answers before the worker records the delivery: wait for
    # the record rather than read it at once.
    def recorded():
        listed = admin.call("GET", f"/webhook-deliveries?endpoint_id={endpoint}")["items"]
        pairs = [(item["status"], item["event_id"]) for item in listed]
        return pairs if pairs == [("delivered", body["id"])] else None
    until("the delivery to be recorded as delivered", recorded)
    check(True, "the administration interface says it was delivered")
    return endpoint, secret, path


def retried_set_aside_and_delivered_again(admin, endpoint, secret, path, address):
    step("The endpoint stopped: retries, set aside, delivered again")
    tenant = admin.tenant
    receiver("stop")
    try:
        signed_in(tenant, address)

        def set_aside():
            items = admin.call("GET", f"/webhook-deliveries?endpoint_id={endpoint}&status=set_aside")["items"]
            return items or None

        delivery = until("a delivery set aside", set_aside, seconds=90)[0]
        shown(f"{delivery['attempts']} attempts, last: {delivery['last_error']}")
        check(delivery["attempts"] == ATTEMPTS and delivery["next_attempt_at"] is None,
              f"the delivery was tried {ATTEMPTS} times and set aside")
        said = cli("webhook", "deliveries", "--tenant", tenant, "--endpoint", endpoint, "--status", "set_aside")
        check(said.split()[:3] == [delivery["id"], "set_aside", str(ATTEMPTS)],
              "the command-line tool lists it as set aside")
    finally:
        receiver("start")
    until("the receiver to answer again", receiver_answers)
    again = admin.call("POST", f"/webhook-deliveries/{delivery['id']}:redeliver")
    check(again["status"] == "pending", "the administration interface puts it back, to be delivered again")
    arrived = until("the delivery asked for again", lambda: received(path, delivery["event_id"]))[0]
    check(arrived["headers"]["webhook-id"] == delivery["event_id"] and signed_with(arrived, secret),
          "the event arrives with the same webhook-id, signed")

    def delivered():
        items = admin.call("GET", f"/webhook-deliveries?endpoint_id={endpoint}&status=delivered")["items"]
        return items if len(items) == 2 else None

    until("both deliveries delivered", delivered)
    return delivery["id"]


def tenants_apart(other_admin, account, key, endpoint, delivery):
    step("A key and a webhook of one tenant refused by another")
    other = other_admin.tenant
    answer = evaluate(other, key, {"type": "user", "id": account}, "approve", {"type": "invoice", "id": "invoice-42"})
    check(answer.status == 401, f"the key is refused by the Authorization API of {other}: {answer.status}")
    answer = request("GET", f"{SERVER}/t/{other}/api/v1/admin/users", headers={"Authorization": f"Bearer {key}"})
    refused(answer, 401, "admin.not_authenticated", f"and by the administration interface of {other}")
    found = request("GET", f"{SERVER}/t/{other}/api/v1/admin/webhook-endpoints/{endpoint}", headers=other_admin.headers)
    refused(found, 404, "webhooks.endpoint_not_found", f"the administrator of {other} finds no such endpoint")
    listed = other_admin.call("GET", f"/webhook-deliveries?endpoint_id={endpoint}")["items"]
    check(listed == [], "nor any of its deliveries")
    again = request("POST", f"{SERVER}/t/{other}/api/v1/admin/webhook-deliveries/{delivery}:redeliver",
                    headers=other_admin.headers)
    refused(again, 404, "webhooks.delivery_not_found", "and cannot deliver one again")


def the_audit_log(admin, agent, person):
    step("The audit log")
    wanted = {"credential.api_key_created", "oauth.token_exchanged", "webhooks.endpoint_registered",
              "webhooks.delivery_set_aside", "webhooks.redelivery_requested"}

    def records():
        items = admin.call("GET", "/audit-records?limit=200")["items"]
        return items if wanted <= {item["action"] for item in items} else None

    items = until("the audit records of the demonstration", records)
    for action in sorted(wanted):
        shown(action)
    exchanged = next(item for item in items if item["action"] == "oauth.token_exchanged")
    check(exchanged["actor"].get("id") == agent, "the exchange was done by the agent")
    check(exchanged["details"].get("subject_id") == person and exchanged["details"].get("actors") == [agent],
          "for the person, with the agent as the one actor of the chain")
    check(cli("audit", "verify", "--tenant", admin.tenant).startswith("intact: "), "the audit chain is intact")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    suffix = format(int(time.time() * 1000), "x")
    tenant, other = f"acme-{suffix}", f"globex-{suffix}"
    address = f"ana-{suffix}@example.com"
    try:
        check(receiver_answers(), f"the stack's receiver of webhooks answers at {RECEIVER}")
        admin, other_admin, tenant_id = two_tenants(tenant, other, suffix)
        person = a_person(admin, address)
        account, client, key = a_service_account(admin, person)
        evaluated_with_its_token_and_its_key(tenant, account, client, key)
        agent, subject, exchange = an_agent_acts_for_a_person(admin, person, address)
        a_wider_exchange_refused(exchange)
        endpoint, secret, path = a_webhook_endpoint(admin, tenant_id, address)
        delivery = retried_set_aside_and_delivered_again(admin, endpoint, secret, path, address)
        tenants_apart(other_admin, account, key, endpoint, delivery)
        the_audit_log(admin, agent, subject)
    except Failed as failure:
        print(f"\nThe demonstration stopped: {failure}", file=sys.stderr)
        sys.exit(1)
    print("\nThe demonstration of Milestone 8 passed.")


if __name__ == "__main__":
    main()
