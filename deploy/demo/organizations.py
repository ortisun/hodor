#!/usr/bin/env python3
"""The demonstration of Milestone 7: groups, organizations and SCIM.

Runs against the development stack and does what an administrator, a person
invited by email, an application and the SCIM client of a directory would
do: a group inside another group and a cycle refused, an organization with a
department and an invitation accepted from the link in the message, a role
given to a group and evaluated for a member until the member is taken out, a
sign-in for the organization whose tokens carry `org_id`, a user and a group
provisioned and changed through SCIM, the user deactivated and their session
and refresh token ended, and a group, an organization and a SCIM token of
one tenant refused by another. Every answer is checked; the first one that
is not what it should be stops the demonstration with a non-zero exit
status.

    docker compose -f deploy/docker/compose.yaml up --build --wait
    python3 deploy/demo/organizations.py

It needs Python 3 and Docker, and nothing outside the standard library. Run
it before the demonstration of Milestone 6, whose second worker removes the
delivered messages this one reads. See docs/operations/quick-start.md.
"""

import base64
import sys
import time
import urllib.parse

from authorization import API, Administrator, application, decided, evaluate, service_client, token_for
from demo import SERVER, Browser, Failed, check, cli, link_from_message, request, shown, step, until
from external_identities import completed, post_form, query_of
from strong_authentication import REDIRECT_URI, Application

PASSWORD = "a password for the demonstration of milestone seven"
PAYROLL = "https://payroll.example.com"
SCIM = "urn:hodor:scim"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
ENTERPRISE_SCHEMA = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


class Portal(Application):
    """The tenant's own application, which signs people in and keeps their
    refresh token."""

    def basic(self):
        pair = f"{urllib.parse.quote(self.client_id)}:{urllib.parse.quote(self.secret)}"
        return {"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()}

    def signed_in(self, browser, **extra):
        """A code for a signed-in person, redeemed: the token response with
        the checked claims of both tokens."""
        answer, parameters, verifier = self.authorize(browser, **extra)
        location = answer.headers.get("Location", "")
        check(answer.status in (302, 303) and location.startswith(REDIRECT_URI),
              "the application gets a code at once: the session is enough and the application is the tenant's own")
        back = query_of(location)
        check(back.get("state") == parameters["state"] and "code" in back,
              "the browser was sent back to the application with a code and its state")
        answer = post_form(f"{SERVER}/t/{self.tenant}/oauth2/token",
                           {"grant_type": "authorization_code", "code": back["code"],
                            "redirect_uri": REDIRECT_URI, "code_verifier": verifier}, self.basic())
        check(answer.status == 200, f"the code was exchanged for tokens (answered {answer.status})")
        tokens = answer.json()
        identity = self.checked(tokens["id_token"], "the ID token")
        access = self.checked(tokens["access_token"], "the access token")
        check(identity.get("nonce") == parameters["nonce"], "the ID token carries the nonce the application sent")
        return tokens, identity, access

    def refresh(self, token):
        return post_form(f"{SERVER}/t/{self.tenant}/oauth2/token",
                         {"grant_type": "refresh_token", "refresh_token": token}, self.basic())


class Directory:
    """The SCIM client of a directory, with the token it got for itself."""

    def __init__(self, tenant, token):
        self.tenant = tenant
        self.headers = {"Authorization": f"Bearer {token}"}

    def call(self, method, path, body=None, tenant=None):
        return request(method, f"{SERVER}/t/{tenant or self.tenant}/scim/v2{path}", body, self.headers)


def bootstrap(tenant, operator):
    said = dict(line.split(" ", 1) for line in
                cli("admin", "bootstrap", "--tenant", tenant, "--email", operator).splitlines())
    check(said.get("role") == "tenant_administrator", f"{operator} is an administrator of {tenant}")
    return Administrator(tenant, said["token"])


def refused(answer, status, code, what):
    check(answer.status == status and answer.code == code,
          f"{what}: {status} {code}" + ("" if answer.status == status else f" (answered {answer.status} {answer.text})"))


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


def a_group_inside_another(admin):
    step("A group inside another group, and a cycle refused")
    staff = admin.call("POST", "/groups", {"name": "staff", "description": "Everyone who works here"})["id"]
    finance = admin.call("POST", "/groups", {"name": "finance"})["id"]
    admin.call("POST", f"/groups/{staff}/members", {"kind": "group", "id": finance})
    members = admin.call("GET", f"/groups/{staff}/members")["items"]
    check([(member["kind"], member["id"]) for member in members] == [("group", finance)],
          "finance is a member of staff")
    cycle = request("POST", f"{SERVER}/t/{admin.tenant}/api/v1/admin/groups/{finance}/members",
                    {"kind": "group", "id": staff}, admin.headers)
    refused(cycle, 409, "identity.group_cycle", "putting staff inside finance would make a cycle, and is refused")
    return staff, finance


def an_organization_and_an_invitation(admin, address):
    step("An organization with a department, and a person invited by email")
    tenant = admin.tenant
    organization = admin.call("POST", "/organizations", {"name": "Initech"})["id"]
    department = admin.call("POST", f"/organizations/{organization}/units",
                            {"parent_id": None, "name": "Engineering", "kind": "department"})
    check(department["kind"] == "department", "Initech has a department, Engineering")
    admin.call("POST", f"/organizations/{organization}/invitations",
               {"email": address, "unit_ids": [department["id"]]})
    pending = admin.call("GET", f"/organizations/{organization}/invitations")["items"]
    check([item["email"] for item in pending] == [address], f"{address} is invited, and the invitation waits")
    link, token = link_from_message(address, tenant)
    shown(f"link: {link[:link.index('#token=') + 15]}…")
    described = request("POST", f"{SERVER}/t/{tenant}/interaction/invitations/describe", {"token": token})
    check(described.status == 200 and described.json().get("organization_name") == "Initech"
          and described.json().get("has_account") is False,
          "the link says it is for Initech, and that the address has no account yet")
    accept = {"token": token, "password": PASSWORD, "display_name": "Bia"}
    accepted = request("POST", f"{SERVER}/t/{tenant}/interaction/invitations/accept", accept)
    check(accepted.status == 204, "accepting with a password made the account and the membership")
    again = request("POST", f"{SERVER}/t/{tenant}/interaction/invitations/accept", accept)
    refused(again, 404, "identity.invitation_invalid", "the same link does not work a second time")
    members = admin.call("GET", f"/organizations/{organization}/members")["items"]
    check(len(members) == 1 and members[0]["unit_ids"] == [department["id"]],
          "the person is a member of Initech, in Engineering")
    return organization, members[0]["user_id"]


def a_role_through_a_group(admin, staff, finance, person):
    step("A role given to a group, and evaluated for a member")
    tenant = admin.tenant
    application(admin, "Authorization API", API, ["authz:evaluate", "authz:simulate", "authz:explain"])
    payroll, payroll_server = application(admin, "Payroll", PAYROLL, ["payroll:read"])
    admin.call("PUT", f"/resource-servers/{payroll_server}/permissions/invoice:read", {"description": "Read an invoice"})
    admin.call("PUT", f"/resource-servers/{payroll_server}/roles/reader", {"permissions": [{"name": "invoice:read"}]})
    admin.call("PUT", f"/resource-servers/{payroll_server}/binding", {"engine": "native"})
    admin.call("POST", "/role-assignments", {
        "principal": {"kind": "group", "id": staff},
        "role": {"namespace": PAYROLL, "name": "reader"},
    })
    held = admin.call("GET", f"/groups/{staff}/role-assignments")["items"]
    check([item["role"]["name"] for item in held] == ["reader"], "staff holds the reader role")
    admin.call("POST", f"/groups/{finance}/members", {"kind": "user", "id": person})
    groups = {item["id"]: item["direct"] for item in admin.call("GET", f"/users/{person}/groups")["items"]}
    check(groups == {finance: True, staff: False}, "the person is in finance, and through it in staff")
    token = token_for(tenant, service_client(admin, payroll), "authz:evaluate")
    subject = {"type": "user", "id": person}
    invoice = {"type": "invoice", "id": "invoice-42"}
    decided(evaluate(tenant, token, subject, "read", invoice), "ALLOW", "matching_role",
            "the person may read an invoice, through finance and staff")
    admin.call("POST", f"/groups/{finance}/members:remove", {"kind": "user", "id": person})
    shown("the person is taken out of finance")
    decided(evaluate(tenant, token, subject, "read", invoice), "DENY", "no_matching_role",
            "the next decision denies")


def a_portal(tenant):
    """The tenant's own application, registered with the command-line tool."""
    said = cli("application", "add", "--tenant", tenant, "--name", "Portal", "--first-party")
    application_id = said.split()[1]
    added = dict(line.split(" ", 1) for line in cli(
        "client", "add", "--tenant", tenant, "--application", application_id, "--name", "Portal web",
        "--type", "confidential", "--grant", "authorization_code", "--grant", "refresh_token",
        "--redirect-uri", REDIRECT_URI, "--scope", "openid", "--scope", "offline_access").splitlines())
    check("client" in added and "secret" in added, f"the application of {tenant} has a client and a secret")
    return Portal(tenant, added["client"], added["secret"])


def signed_in_for_the_organization(admin, organization, address):
    step("Signed in from the application, for the organization")
    portal = a_portal(admin.tenant)
    browser = Browser()
    check(completed(browser.sign_in(admin.tenant, address, PASSWORD)), f"{address} signed in with the password")
    _, identity, access = portal.signed_in(browser, organization=organization)
    shown(f"org_id {access.get('org_id')}")
    check(identity.get("org_id") == organization and access.get("org_id") == organization,
          "the ID token and the access token carry the organization in org_id")
    elsewhere = admin.call("POST", "/organizations", {"name": "Umbrella"})["id"]
    answer, _, _ = portal.authorize(browser, organization=elsewhere)
    location = answer.headers.get("Location", "")
    check(location.startswith(REDIRECT_URI) and query_of(location).get("error") == "access_denied"
          and "code" not in query_of(location),
          "for an organization the person is not a member of, the application is answered access_denied")
    return portal


def a_directory(admin):
    step("A directory provisions a user and a group through SCIM")
    tenant = admin.tenant
    scim_application, _ = application(admin, "SCIM", SCIM, ["scim"])
    client = admin.call("POST", f"/applications/{scim_application}/clients", {
        "name": "Directory",
        "type": "confidential",
        "grant_types": ["client_credentials"],
        "allowed_scopes": ["scim"],
    })
    basic = base64.b64encode(f"{client['id']}:{client['client_secret']}".encode()).decode()
    answer = post_form(f"{SERVER}/t/{tenant}/oauth2/token",
                       {"grant_type": "client_credentials", "resource": SCIM, "scope": "scim"},
                       {"Authorization": f"Basic {basic}"})
    check(answer.status == 200, "the SCIM client gets a token with the scope scim for itself")
    return Directory(tenant, answer.json()["access_token"]), client["id"]


def provisioned(directory, address):
    made = directory.call("POST", "/Users", {
        "schemas": [USER_SCHEMA],
        "userName": address,
        "name": {"givenName": "Carla", "familyName": "Lima"},
        "emails": [{"value": address, "type": "work", "primary": True}],
        "active": True,
    })
    check(made.status == 201 and made.json().get("active") is True, f"the directory created {address}, active")
    person = made.json()["id"]
    group = directory.call("POST", "/Groups", {
        "schemas": [GROUP_SCHEMA],
        "displayName": "contractors",
        "members": [{"value": person}],
    })
    check(group.status == 201 and [member["value"] for member in group.json().get("members", [])] == [person],
          "and the group contractors, with the person in it")
    group_id = group.json()["id"]

    changed = directory.call("PATCH", f"/Users/{person}", {
        "schemas": [PATCH_SCHEMA],
        "Operations": [
            {"op": "replace", "path": "name.familyName", "value": "Souza"},
            {"op": "add", "path": f"{ENTERPRISE_SCHEMA}:department", "value": "Finance"},
        ],
    })
    body = changed.json()
    check(changed.status == 200 and body.get("name", {}).get("familyName") == "Souza"
          and body.get(ENTERPRISE_SCHEMA, {}).get("department") == "Finance",
          "a PATCH changed the person's family name and set their department")
    shown(f"version {made.json()['meta']['version']} became {body['meta']['version']}")
    renamed = directory.call("PATCH", f"/Groups/{group_id}", {
        "schemas": [PATCH_SCHEMA],
        "Operations": [{"op": "replace", "path": "displayName", "value": "vendors"}],
    })
    check(renamed.status == 200 and renamed.json().get("displayName") == "vendors"
          and [member["value"] for member in renamed.json().get("members", [])] == [person],
          "a PATCH renamed the group to vendors, and kept its member")
    return person, group_id


def deactivated(directory, portal, person, address):
    step("The person deactivated through SCIM, and their session and refresh token ended")
    tenant = directory.tenant
    asked = request("POST", f"{SERVER}/t/{tenant}/interaction/recovery", {"email": address})
    check(asked.status == 202, "the provisioned person asks for a link to choose a password")
    _, token = link_from_message(address, tenant)
    done = request("POST", f"{SERVER}/t/{tenant}/interaction/recovery/complete", {"token": token, "password": PASSWORD})
    check(done.status == 204, "the address SCIM set is verified, so the link arrives and the password is set")
    browser = Browser()
    check(completed(browser.sign_in(tenant, address, PASSWORD)), f"{address} signed in")
    tokens, _, _ = portal.signed_in(browser, scope="openid offline_access")
    check("refresh_token" in tokens, "the application holds a refresh token")
    refreshed = portal.refresh(tokens["refresh_token"])
    check(refreshed.status == 200, "the refresh token works")
    refresh_token = refreshed.json()["refresh_token"]

    found = directory.call("GET", "/Users?filter=" + urllib.parse.quote(f'userName eq "{address}"'))
    check(found.status == 200 and [item["id"] for item in found.json().get("Resources", [])] == [person],
          "the directory finds the person by a filter on userName")
    answer = directory.call("PATCH", f"/Users/{person}", {
        "schemas": [PATCH_SCHEMA],
        "Operations": [{"op": "replace", "path": "active", "value": False}],
    })
    check(answer.status == 200 and answer.json().get("active") is False, "the directory set active to false")
    session = browser.call("GET", f"/t/{tenant}/interaction/session")
    check(session.status == 401, "the person's session ended at once")
    again = portal.refresh(refresh_token)
    check(again.status == 400 and again.json().get("error") == "invalid_grant",
          "the refresh token is refused: invalid_grant")
    signing_in = Browser().sign_in(tenant, address, PASSWORD)
    check(not completed(signing_in), "the password no longer signs the person in"
          + f" ({signing_in.status} {signing_in.json().get('status') or signing_in.code})")


def tenants_apart(other_admin, directory, staff, organization):
    step("A group, an organization and a SCIM token of one tenant refused by another")
    other = other_admin.tenant
    group = request("GET", f"{SERVER}/t/{other}/api/v1/admin/groups/{staff}", headers=other_admin.headers)
    refused(group, 404, "identity.group_not_found", f"the administrator of {other} finds no such group")
    found = request("GET", f"{SERVER}/t/{other}/api/v1/admin/organizations/{organization}",
                    headers=other_admin.headers)
    refused(found, 404, "identity.organization_not_found", "nor such an organization")
    answer = directory.call("GET", "/Users", tenant=other)
    check(answer.status == 401 and answer.headers.get("WWW-Authenticate", "").startswith("Bearer"),
          f"the SCIM token of {directory.tenant} is refused by the SCIM server of {other}: 401")


def the_audit_log(admin, scim_client):
    step("The audit log")

    def records():
        items = admin.call("GET", "/audit-records?limit=200")["items"]
        actions = {item["action"] for item in items}
        wanted = {"identity.group_member_added", "identity.invitation_accepted", "identity.user_deactivated"}
        return items if wanted <= actions else None

    items = until("the audit records of the demonstration", records)
    for action in ("identity.group_member_added", "identity.invitation_accepted"):
        check(any(item["action"] == action for item in items), f"the log of {admin.tenant} has {action}")
    deactivation = next(item for item in items if item["action"] == "identity.user_deactivated")
    check(deactivation["actor"] == {"kind": "client", "id": scim_client},
          "identity.user_deactivated was done by the SCIM client")
    check(cli("audit", "verify", "--tenant", admin.tenant).startswith("intact: "), "the audit chain is intact")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    suffix = format(int(time.time() * 1000), "x")
    tenant, other = f"acme-{suffix}", f"globex-{suffix}"
    try:
        admin, other_admin = two_tenants(tenant, other, suffix)
        staff, finance = a_group_inside_another(admin)
        organization, person = an_organization_and_an_invitation(admin, f"bia-{suffix}@example.com")
        a_role_through_a_group(admin, staff, finance, person)
        portal = signed_in_for_the_organization(admin, organization, f"bia-{suffix}@example.com")
        directory, scim_client = a_directory(admin)
        person, _ = provisioned(directory, f"carla-{suffix}@example.com")
        deactivated(directory, portal, person, f"carla-{suffix}@example.com")
        tenants_apart(other_admin, directory, staff, organization)
        the_audit_log(admin, scim_client)
    except Failed as failure:
        print(f"\nThe demonstration stopped: {failure}", file=sys.stderr)
        sys.exit(1)
    print("\nThe demonstration of Milestone 7 passed.")


if __name__ == "__main__":
    main()
