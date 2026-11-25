#!/usr/bin/env python3
"""The demonstration of Milestone 9: what 0.2.0 left out.

Runs against the development stack and does what an administrator, an
operator, two applications of different sectors, a person and a receiver of
logout tokens would do: one person signs in to both applications, which know
her by two different `sub`; a claim mapper puts a group into the ID token;
signing out at Hodor sends each application a logout token; a code and then
a link sent by email sign her in, each refused the second time; under the
second factor policy a person who has none sets up an authenticator
application from its QR code during the sign-in and finishes; and a
document shared with a group through an access control list is allowed for
a member and denied to someone else. Every answer is checked; the first one
that is not what it should be stops the demonstration with a non-zero exit
status.

    docker compose -f deploy/docker/compose.yaml up --build --wait
    python3 deploy/demo/what_was_left_out.py

It needs Python 3 and Docker, and nothing outside the standard library. The
two applications are played by the script: they register redirect addresses
nobody listens on, and read where the browser is sent; their back-channel
logout addresses are at the stack's receiver of webhooks, which keeps what
it gets. Run it before the demonstration of Milestone 6, whose second worker
removes the delivered messages this one reads. See
docs/operations/quick-start.md.
"""

import base64
import json
import os
import re
import secrets
import sys
import time
import urllib.parse

from authorization import API, Administrator, application, decided, evaluate
from demo import MAIL, SERVER, Browser, Failed, check, cli, link_from_message, request, shown, step, until
from external_identities import completed, post_form, query_of, rejected
from strong_authentication import Application, AuthenticatorApplication, decode, encode, sha256

RECEIVER = os.environ.get("HODOR_WEBHOOK_RECEIVER_URL", "http://localhost:9600")
# Where Hodor reaches the receiver, inside the stack.
RECEIVER_INSIDE = "http://webhook-receiver:9600"
PASSWORD = "a password for the demonstration of milestone nine"
DOCUMENTS = "https://documents.example.com"
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class SectorApplication(Application):
    """An application of the tenant whose redirect address, and so whose
    sector, is its own."""

    def __init__(self, tenant, name, client_id, secret, redirect_uri):
        super().__init__(tenant, client_id, secret)
        self.name = name
        self.redirect_uri = redirect_uri

    def basic(self):
        pair = f"{urllib.parse.quote(self.client_id)}:{urllib.parse.quote(self.secret)}"
        return {"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()}

    def signed_in(self, browser):
        """Sends a signed-in browser to the authorization endpoint, takes the
        code from where it is sent back, and redeems it: the token response
        with the checked claims of the ID token."""
        verifier = encode(secrets.token_bytes(32))
        parameters = {
            "response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_uri,
            "scope": "openid", "state": encode(secrets.token_bytes(12)), "nonce": encode(secrets.token_bytes(12)),
            "code_challenge": encode(sha256(verifier.encode())), "code_challenge_method": "S256",
        }
        answer = browser.call("GET", f"/t/{self.tenant}/oauth2/authorize?" + urllib.parse.urlencode(parameters))
        location = answer.headers.get("Location", "")
        back = query_of(location)
        check(answer.status in (302, 303) and location.startswith(self.redirect_uri)
              and back.get("state") == parameters["state"] and "code" in back,
              f"{self.name} gets a code at once: the session is enough and the application is the tenant's own")
        answer = post_form(f"{SERVER}/t/{self.tenant}/oauth2/token",
                           {"grant_type": "authorization_code", "code": back["code"],
                            "redirect_uri": self.redirect_uri, "code_verifier": verifier}, self.basic())
        check(answer.status == 200, f"{self.name} redeems the code (answered {answer.status})")
        tokens = answer.json()
        identity = self.checked(tokens["id_token"], f"the ID token of {self.name}")
        check(identity.get("nonce") == parameters["nonce"] and identity.get("aud") in (self.client_id, [self.client_id]),
              f"the ID token is for {self.name}, with its nonce")
        return tokens, identity


def bootstrap(tenant, operator):
    said = dict(line.split(" ", 1) for line in
                cli("admin", "bootstrap", "--tenant", tenant, "--email", operator).splitlines())
    check(said.get("role") == "tenant_administrator", f"{operator} is an administrator of {tenant}")
    return Administrator(tenant, said["token"])


def refused(answer, status, code, what):
    check(answer.status == status and answer.code == code,
          f"{what}: {status} {code}" + ("" if answer.status == status else f" (answered {answer.status} {answer.text})"))


def a_person(admin, address, name):
    """A person of the tenant, with a password chosen from a recovery link."""
    person = admin.call("POST", "/users", {"email": address, "display_name": name})["id"]
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
# The mailbox and the receiver
# ---------------------------------------------------------------------------

def message_ids(address):
    query = urllib.parse.quote(f'to:"{address}"')
    return [summary["ID"] for summary in request("GET", f"{MAIL}/api/v1/search?query={query}").json().get("messages", [])]


def a_new_message(address, before, pattern):
    """Waits for a message to `address` that was not among `before` and
    matches `pattern`; answers the first group of the match."""

    def look():
        for identifier in message_ids(address):
            if identifier in before:
                continue
            text = request("GET", f"{MAIL}/api/v1/message/{identifier}").json().get("Text", "")
            found = re.search(pattern, text, re.MULTILINE)
            if found:
                return found.group(1)
        return None

    return until(f"a new message to {address}", look)


def received(path):
    answer = request("GET", f"{RECEIVER}/received?" + urllib.parse.urlencode({"path": path}))
    if answer.status != 200:
        raise Failed(f"the receiver at {RECEIVER} answered {answer.status}")
    return answer.json()["items"]


def receiver_answers():
    try:
        return request("GET", f"{RECEIVER}/health").status == 200
    except Exception:  # noqa: BLE001 - a receiver that does not answer is what is checked
        return False


# ---------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------

def two_tenants(tenant, other, suffix):
    step("Two tenants, and their administrators")
    for slug, name in [(tenant, "Acme"), (other, "Globex")]:
        said = cli("tenant", "create", "--slug", slug, "--name", name)
        check(slug in said, f"the command-line tool created {slug}")
        cli("keys", "rotate", "--tenant", slug)
    return (bootstrap(tenant, f"operator-{suffix}@example.com"),
            bootstrap(other, f"operator-globex-{suffix}@example.com"))


def two_applications_of_two_sectors(admin, suffix):
    step("Two applications of two sectors")
    applications = []
    for name, host in [("Travel", f"travel-{suffix}.example.com"), ("Payroll", f"payroll-{suffix}.example.com")]:
        created = admin.call("POST", "/applications", {"name": name, "first_party": True})
        redirect_uri = f"https://{host}/callback"
        client = admin.call("POST", f"/applications/{created['id']}/clients", {
            "name": f"{name} web",
            "type": "confidential",
            "grant_types": ["authorization_code"],
            "redirect_uris": [redirect_uri],
            "allowed_scopes": ["openid"],
            "subject_type": "pairwise",
            "backchannel_logout_uri": f"{RECEIVER_INSIDE}/{admin.tenant}/{name.lower()}",
            "backchannel_logout_session_required": True,
        })
        check(client["subject_type"] == "pairwise" and client["backchannel_logout_uri"].startswith(RECEIVER_INSIDE),
              f"{name} is pairwise, of the sector {host}, and told at the receiver when a session ends")
        applications.append(SectorApplication(admin.tenant, name, client["id"], client["client_secret"], redirect_uri))
    return applications


def the_same_person_by_two_subs(tenant, address, person, travel, payroll):
    step("One person, two sectors, two subjects")
    browser = signed_in(tenant, address)
    travel_tokens, at_travel = travel.signed_in(browser)
    _, at_payroll = payroll.signed_in(browser)
    shown(f"Travel knows her as {at_travel['sub']}")
    shown(f"Payroll knows her as {at_payroll['sub']}")
    check(at_travel["sub"] != at_payroll["sub"], "the two applications are given two different sub")
    check(person not in (at_travel["sub"], at_payroll["sub"]), "and neither is her user identifier")
    check(at_travel.get("sid") != at_payroll.get("sid"), "the session, too, has an identifier per sector")
    again = signed_in(tenant, address)
    _, later = travel.signed_in(again)
    check(later["sub"] == at_travel["sub"], "signed in again, Travel is given the same sub")
    answer = request("GET", f"{SERVER}/t/{tenant}/oauth2/userinfo",
                     headers={"Authorization": f"Bearer {travel_tokens['access_token']}"})
    check(answer.status == 200 and answer.json().get("sub") == at_travel["sub"],
          "UserInfo answers Travel with the sub of its ID token")
    return browser, at_payroll


def a_claim_mapper(admin, travel, browser, person):
    step("A claim mapper puts a group into the ID token")
    finance = admin.call("POST", "/groups", {"name": "finance"})["id"]
    admin.call("POST", f"/groups/{finance}/members", {"kind": "user", "id": person})
    mappers = f"{SERVER}/t/{admin.tenant}/api/v1/admin/clients/{travel.client_id}/claim-mappers"
    reserved = request("POST", mappers, {"claim": "sub", "targets": ["id_token"], "source": {"kind": "groups"}},
                       admin.headers)
    refused(reserved, 422, "oauth.claim_mapper_name_reserved", "a mapper that would name sub is refused")
    mapper = admin.call("POST", f"/clients/{travel.client_id}/claim-mappers", {
        "claim": "teams",
        "targets": ["id_token", "userinfo"],
        "source": {"kind": "groups"},
    })
    check(mapper["claim"] == "teams", "a mapper of Travel writes the person's groups as teams")
    tokens, identity = travel.signed_in(browser)
    shown(f"teams {identity.get('teams')}")
    check(identity.get("teams") == [finance], "the ID token carries her group, finance, by its identifier")
    answer = request("GET", f"{SERVER}/t/{admin.tenant}/oauth2/userinfo",
                     headers={"Authorization": f"Bearer {tokens['access_token']}"})
    check(answer.status == 200 and answer.json().get("teams") == [finance], "and UserInfo the same")
    return finance, mapper["id"], identity


def logout_tokens(tenant, applications, browser, identities):
    step("Signed out at Hodor: each application receives a logout token")
    check(receiver_answers(), f"the stack's receiver answers at {RECEIVER}")
    session = browser.call("GET", f"/t/{tenant}/interaction/session")
    check(session.status == 200, "the person is signed in")
    ended = browser.call("DELETE", f"/t/{tenant}/interaction/session")
    check(ended.status == 204, "she signs out at Hodor, as the account page does")
    check(browser.call("GET", f"/t/{tenant}/interaction/session").status != 200, "her session has ended")
    for application in applications:
        path = f"/{tenant}/{application.name.lower()}"
        delivery = until(f"the logout token of {application.name}", lambda path=path: received(path))[0]
        fields = urllib.parse.parse_qs(delivery["body"])
        check(delivery["headers"]["content-type"].startswith("application/x-www-form-urlencoded")
              and list(fields) == ["logout_token"], f"{application.name} got a form with a logout_token")
        token = fields["logout_token"][0]
        check(json.loads(decode(token.split(".")[0])).get("typ") == "logout+jwt", "its type is logout+jwt")
        claims = application.checked(token, f"the logout token of {application.name}")
        identity = identities[application.name]
        shown(f"{application.name}: sub {claims.get('sub')}, sid {claims.get('sid')}")
        check(claims.get("aud") in (application.client_id, [application.client_id])
              and claims.get("iss") == identity.get("iss")
              and BACKCHANNEL_LOGOUT_EVENT in claims.get("events", {}) and "nonce" not in claims,
              f"it is from the tenant, for {application.name}, and says a session ended")
        check(claims.get("sub") == identity["sub"] and claims.get("sid") == identity["sid"],
              f"it names the person and the session by the sub and sid of {application.name}'s ID token")


def by_email(tenant, address, person):
    step("A code, then a link, sent by email")
    said = cli("tenant", "email-sign-in", "--slug", tenant, "--code", "on", "--link", "on")
    check(said.endswith("email-sign-in code on link on"), f"{tenant} lets people sign in with a code or a link")
    offered = Browser().call("GET", f"/t/{tenant}/interaction/sign-in/alternatives").json().get("alternatives", [])
    check({"email_code", "email_link"} <= set(offered), f"the sign-in page is told it may offer both: {offered}")
    base = f"/t/{tenant}/interaction/sign-in"

    def ask(browser, kind):
        before = set(message_ids(address))
        check(browser.call("POST", base).status == 201, "a sign-in starts")
        asked = browser.call("POST", f"{base}/steps/{kind}/send", {"email": address})
        what = "a code" if kind == "email_code" else "a link"
        check(asked.status == 202, f"she asks for {what}, which is accepted whoever the address is")
        return before

    browser = Browser()
    before = ask(browser, "email_code")
    code = a_new_message(address, before, r"^\s*(\d{6})\s*$")
    shown(f"the message holds the code {code}")
    done = browser.call("POST", f"{base}/steps/email_code", {"code": code})
    check(completed(done), "the code signs her in")
    who = browser.call("GET", f"/t/{tenant}/interaction/session").json()
    check(who.get("user_id") == person and who.get("methods") == ["email_code"],
          f"the session is hers, by {who.get('methods')}")
    again = Browser()
    again.call("POST", base)
    check(rejected(again.call("POST", f"{base}/steps/email_code", {"code": code})),
          "the same code is refused the second time")

    browser = Browser()
    before = ask(browser, "email_link")
    token = a_new_message(address, before, r"https?://\S+/t/" + re.escape(tenant) + r"/account/sign-in-link#token=([0-9a-f]{64})")
    shown("the message holds a link to /account/sign-in-link")
    elsewhere = Browser()
    elsewhere.call("POST", base)
    check(rejected(elsewhere.call("POST", f"{base}/steps/email_link", {"token": token}))
          and "__Secure-hodor_session" not in elsewhere.cookies,
          "opened in another browser, the link signs nothing in")
    done = browser.call("POST", f"{base}/steps/email_link", {"token": token})
    check(completed(done), "in the browser that asked, the link signs her in")
    who = browser.call("GET", f"/t/{tenant}/interaction/session").json()
    check(who.get("user_id") == person and who.get("methods") == ["email_link"],
          f"the session is hers, by {who.get('methods')}")
    again = Browser()
    again.call("POST", base)
    check(rejected(again.call("POST", f"{base}/steps/email_link", {"token": token})),
          "the same link is refused the second time")


def enrolled_during_the_sign_in(admin, address, travel):
    step("Under the second factor policy, a factor set up during the sign-in")
    tenant = admin.tenant
    said = cli("tenant", "second-factor", "--slug", tenant, "--policy", "required")
    check(said.endswith("second-factor required"), f"{tenant} now requires a second factor")
    bob = a_person(admin, address, "Bob")
    base = f"/t/{tenant}/interaction/sign-in"

    abandoned = Browser()
    waiting = abandoned.sign_in(tenant, address, PASSWORD)
    check(waiting.status == 200 and waiting.json().get("status") == "pending"
          and waiting.json().get("step") == "enrollment",
          "the password is right, and the sign-in waits for a second factor to be set up")
    check(abandoned.call("GET", f"/t/{tenant}/interaction/session").status != 200
          and "__Secure-hodor_session" not in abandoned.cookies,
          "leaving it there signs nobody in")

    browser = Browser()
    browser.sign_in(tenant, address, PASSWORD)
    kinds = browser.call("GET", f"{base}/steps/enrollment/kinds").json().get("kinds", [])
    check("authenticator_application" in kinds, f"what can be set up: {kinds}")
    begun = browser.call("POST", f"{base}/steps/enrollment/options", {"kind": "authenticator_application"})
    uri = begun.json().get("uri", "")
    check(begun.status == 200 and uri.startswith("otpauth://totp/"),
          "the page is given the address its QR code shows")
    shown(uri.split("?")[0] + "?secret=…")
    secret = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(uri).query))["secret"]
    phone = AuthenticatorApplication(secret)
    done = browser.call("POST", f"{base}/steps/enrollment", {"code": phone.code()})
    codes = done.json().get("recovery_codes", [])
    check(completed(done) and len(codes) == 10,
          "the code the application shows confirms it and finishes the sign-in, with ten recovery codes")
    who = browser.call("GET", f"/t/{tenant}/interaction/session").json()
    check(who.get("methods") == ["password", "enrollment"] and who.get("assurance") == "multi_factor",
          f"the session holds {who.get('methods')}, at {who.get('assurance')}")
    _, identity = travel.signed_in(browser)
    shown(f"acr {identity.get('acr')}, amr {identity.get('amr')}")
    check(identity.get("amr") == ["pwd", "mfa"], "Travel's ID token says a password and multi-factor")

    later = Browser()
    waiting = later.sign_in(tenant, address, PASSWORD)
    check(waiting.json().get("step") == "totp", "the next sign-in asks for the code of the application")
    check(completed(later.call("POST", f"{base}/steps/totp", {"code": phone.code()})), "which signs him in")
    return bob


def a_document_shared_with_a_group(admin, finance, member, someone_else):
    step("A document shared with a group, through an access control list")
    tenant = admin.tenant
    application(admin, "Authorization API", API, ["authz:evaluate"])
    documents, server = application(admin, "Documents", DOCUMENTS, ["documents:read"])
    admin.call("PUT", f"/resource-servers/{server}/permissions/document:read", {"description": "Read a document"})
    admin.call("PUT", f"/resource-servers/{server}/binding", {"engine": "native"})
    client = admin.call("POST", f"/applications/{documents}/clients", {
        "name": "Documents back end",
        "type": "confidential",
        "grant_types": ["client_credentials"],
        "allowed_scopes": ["authz:evaluate"],
    })
    basic = base64.b64encode(f"{client['id']}:{client['client_secret']}".encode()).decode()
    answer = post_form(f"{SERVER}/t/{tenant}/oauth2/token",
                       {"grant_type": "client_credentials", "resource": API, "scope": "authz:evaluate"},
                       {"Authorization": f"Basic {basic}"})
    check(answer.status == 200, f"the back end gets a token for the Authorization API ({answer.status})")
    token = answer.json()["access_token"]
    budget = {"type": "document", "id": "budget-2027"}
    decided(evaluate(tenant, token, {"type": "user", "id": member}, "read", budget), "DENY", "no_matching_role",
            "before anything is shared, the member may not read the budget")
    entry = admin.call("POST", f"/resource-servers/{server}/access-entries", {
        "permission": "document:read",
        "resource_id": "budget-2027",
        "principal": {"kind": "group", "id": finance},
    })
    check(entry["principal"] == {"kind": "group", "id": finance}, "finance may read budget-2027")
    decided(evaluate(tenant, token, {"type": "user", "id": member}, "read", budget),
            "ALLOW", "matching_entry", "a member of finance may read it")
    decided(evaluate(tenant, token, {"type": "user", "id": someone_else}, "read", budget),
            "DENY", "no_matching_role", "someone else may not")
    decided(evaluate(tenant, token, {"type": "user", "id": member}, "read", {"type": "document", "id": "salaries"}),
            "DENY", "no_matching_role", "and the member may not read another document")
    return entry["id"]


def tenants_apart(other_admin, travel, mapper, entry):
    step("Tenants apart")
    other = other_admin.tenant
    found = request("GET", f"{SERVER}/t/{other}/api/v1/admin/clients/{travel.client_id}/claim-mappers/{mapper}",
                    headers=other_admin.headers)
    refused(found, 404, "oauth.client_not_found", f"the administrator of {other} finds neither the client nor its mapper")
    found = request("GET", f"{SERVER}/t/{other}/api/v1/admin/access-entries/{entry}", headers=other_admin.headers)
    refused(found, 404, "authorization.access_entry_not_found", "nor the entry of the access control list")


def the_audit_log(admin):
    step("The audit log")
    wanted = {"oauth.claim_mapper_created", "authentication.email_sign_in_sent",
              "authentication.second_factor_enrolled", "authorization.access_entry_granted"}

    def records():
        items, cursor = [], None
        while True:
            page = admin.call("GET", "/audit-records?limit=200" + (f"&cursor={cursor}" if cursor else ""))
            items += page.get("items", [])
            cursor = page.get("next_cursor")
            if not cursor or not page.get("items"):
                break
        return items if wanted <= {item["action"] for item in items} else None

    until("the audit records of the demonstration", records)
    for action in sorted(wanted):
        shown(action)
    check(cli("audit", "verify", "--tenant", admin.tenant).startswith("intact: "), "the audit chain is intact")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    suffix = format(int(time.time() * 1000), "x")
    tenant, other = f"acme-{suffix}", f"globex-{suffix}"
    ana, bob = f"ana-{suffix}@example.com", f"bob-{suffix}@example.com"
    try:
        check(receiver_answers(), f"the stack's receiver answers at {RECEIVER}")
        admin, other_admin = two_tenants(tenant, other, suffix)
        person = a_person(admin, ana, "Ana")
        travel, payroll = two_applications_of_two_sectors(admin, suffix)
        browser, at_payroll = the_same_person_by_two_subs(tenant, ana, person, travel, payroll)
        finance, mapper, at_travel = a_claim_mapper(admin, travel, browser, person)
        logout_tokens(tenant, [travel, payroll], browser, {"Travel": at_travel, "Payroll": at_payroll})
        by_email(tenant, ana, person)
        someone_else = enrolled_during_the_sign_in(admin, bob, travel)
        entry = a_document_shared_with_a_group(admin, finance, person, someone_else)
        tenants_apart(other_admin, travel, mapper, entry)
        the_audit_log(admin)
    except Failed as failure:
        print(f"\nThe demonstration stopped: {failure}", file=sys.stderr)
        sys.exit(1)
    print("\nThe demonstration of Milestone 9 passed.")


if __name__ == "__main__":
    main()
