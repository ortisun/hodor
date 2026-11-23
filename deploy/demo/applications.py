#!/usr/bin/env python3
"""The demonstration of Milestone 3: applications ask Hodor who someone is.

Runs against the development stack and does what an operator, a person and
a third-party application would do: the application is registered with the
command-line tool, the person is asked once whether it may have what it asks
for, and the application signs the person in with a code and PKCE. Then the
tokens are used as an application uses them: the ID token and UserInfo, a
refresh token that moves at every use and ends when an old one comes back, a
token a service gets for itself, revocation and introspection, and the
tenant's key rotated while the old key stays published. Last, a code, a token
and a client of one tenant are presented to another, which refuses them.
Every answer is checked; the first one that is not what it should be stops
the demonstration with a non-zero exit status.

    docker compose -f deploy/docker/compose.yaml up --build --wait
    python3 deploy/demo/applications.py

It needs Python 3 and Docker, and nothing outside the standard library. Every
token's signature is checked against the tenant's published key set with the
P-256 arithmetic of the Milestone 4 demonstration.
See docs/operations/quick-start.md.
"""

import base64
import json
import sys
import time
import urllib.parse

from demo import SERVER, Browser, Failed, check, cli, link_from_message, request, shown, step
from external_identities import post_form, query_of
from strong_authentication import REDIRECT_URI, Application, decode

PASSWORD = "correct horse battery staple"
AUDIENCE = "https://api.billing.example.com"
SCOPES = "openid email offline_access invoices:read"
# What the person agreed to: `offline_access` is asked for every time.
AGREED = "openid email invoices:read"
# The development stack's window for a retried refresh, HODOR_REFRESH_RETRY_SECONDS.
RETRY_WINDOW_SECONDS = 10


class ThirdPartyApplication(Application):
    """The application of the demonstration, with what Milestone 3 lets it do
    beyond signing a person in."""

    def basic(self):
        pair = f"{urllib.parse.quote(self.client_id)}:{urllib.parse.quote(self.secret)}"
        return {"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()}

    def endpoint(self, name, fields):
        return post_form(f"{SERVER}/t/{self.tenant}/oauth2/{name}", fields, self.basic())

    def exchange(self, location, parameters, verifier):
        """Redeems the code where the browser was sent back, and answers the
        token response with the checked claims of both tokens."""
        back = query_of(location)
        check(location.startswith(REDIRECT_URI) and back.get("state") == parameters["state"] and "code" in back,
              "the browser was sent back to the application with a code and its state")
        answer = self.endpoint("token", {"grant_type": "authorization_code", "code": back["code"],
                                         "redirect_uri": REDIRECT_URI, "code_verifier": verifier})
        check(answer.status == 200, "the code was exchanged for tokens")
        tokens = answer.json()
        identity = self.checked(tokens["id_token"], "the ID token")
        access = self.checked(tokens["access_token"], "the access token")
        check(identity.get("nonce") == parameters["nonce"], "the ID token carries the nonce the application sent")
        return tokens, identity, access

    def code_at_once(self, browser):
        """A code for a person who has agreed already: no page is shown."""
        answer, parameters, verifier = self.authorize(browser, scope=AGREED)
        check(answer.status in (302, 303) and answer.headers.get("Location", "").startswith(REDIRECT_URI),
              "the application gets a code at once: the person agreed before")
        return answer.headers["Location"], parameters, verifier

    def active(self, token):
        answer = self.endpoint("introspect", {"token": token})
        check(answer.status == 200, "introspection answered")
        return answer.json()


def userinfo(tenant, access):
    return request("GET", f"{SERVER}/t/{tenant}/oauth2/userinfo", headers={"Authorization": f"Bearer {access}"})


def key_identifier(token):
    return json.loads(decode(token.split(".")[0]))["kid"]


def published_keys(tenant):
    return {key["kid"] for key in request("GET", f"{SERVER}/t/{tenant}/oauth2/jwks").json().get("keys", [])}


# ---------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------

def two_tenants_and_a_person(tenant, other, address):
    step("Two tenants, and a person in one of them")
    for slug, name in [(tenant, "Acme"), (other, "Globex")]:
        said = cli("tenant", "create", "--slug", slug, "--name", name, "--open-registration")
        check(slug in said, f"the command-line tool created {slug}")
    asked = request("POST", f"{SERVER}/t/{tenant}/interaction/registration", {"email": address})
    check(asked.status == 202, f"{tenant} accepted the request to register {address}")
    _, token = link_from_message(address, tenant)
    done = request("POST", f"{SERVER}/t/{tenant}/interaction/registration/complete",
                   {"token": token, "password": PASSWORD})
    check(done.status == 204, f"{address} registered with a password")


def a_third_party_application(tenant):
    step("A third-party application, registered with the command-line tool")
    said = cli("application", "add", "--tenant", tenant, "--name", "Billing")
    application = said.split()[1]
    listed = cli("application", "list", "--tenant", tenant)
    check(application in listed and "third-party" in listed, f"Billing is a third-party application of {tenant}")
    said = cli("resource-server", "add", "--tenant", tenant, "--application", application, "--audience", AUDIENCE,
               "--name", "Invoices", "--scope", "invoices:read=Read your invoices")
    check(AUDIENCE in said, f"its resource server is {AUDIENCE}, with the scope invoices:read")
    added = dict(line.split(" ", 1) for line in cli(
        "client", "add", "--tenant", tenant, "--application", application, "--name", "Billing web",
        "--type", "confidential", "--grant", "authorization_code", "--grant", "refresh_token",
        "--grant", "client_credentials", "--redirect-uri", REDIRECT_URI,
        "--scope", "openid", "--scope", "email", "--scope", "offline_access",
        "--scope", "invoices:read").splitlines())
    check("client" in added and "secret" in added, "its client has an identifier and a secret, shown once")
    shown(f"client {added['client']}")
    return ThirdPartyApplication(tenant, added["client"], added["secret"])


def asked_once(tenant, address, application):
    step("Signed in from the application, and asked once")
    browser = Browser()
    check(browser.sign_in(tenant, address, PASSWORD).json().get("status") == "completed",
          f"{address} signed in to {tenant}")
    answer, parameters, verifier = application.authorize(browser, scope=SCOPES)
    check(answer.status in (302, 303) and answer.headers.get("Location") == f"/t/{tenant}/account/consent",
          "the application does not get a code yet: the browser is sent to the consent page")
    question = browser.call("GET", f"/t/{tenant}/interaction/consent")
    check(question.status == 200, "the consent page asks what the application asks for")
    described = question.json()
    shown(f"{described['application']} asks for {[scope['scope'] for scope in described['scopes']]}, "
          f"and to keep access: {described['offline_access']}")
    check(described["application"] == "Billing" and described["offline_access"]
          and {"scope": "invoices:read", "kind": "resource", "description": "Read your invoices",
               "resource_server": "Invoices"} in described["scopes"],
          "the page names the application, each scope in plain words, and access kept when the person is away")
    answered = browser.call("POST", f"/t/{tenant}/interaction/consent", {"decision": "allow"})
    check(answered.status == 200, "the person allowed it")
    resumed = browser.call("GET", answered.json()["continue"])
    check(resumed.status in (302, 303), "the authorization went on")
    tokens, identity, access = application.exchange(resumed.headers["Location"], parameters, verifier)
    shown(f"the ID token: sub {identity['sub']}, aud {identity['aud']}, amr {identity.get('amr')}")
    check(identity["aud"] == application.client_id and "refresh_token" in tokens,
          "the ID token is for the application, and a refresh token came with the tokens")
    check(AUDIENCE in access.get("aud", []) and "invoices:read" in access.get("scope", "").split(),
          "the access token is for the resource server, with invoices:read")
    again, _, _ = application.authorize(browser, scope=SCOPES)
    check(again.headers.get("Location") == f"/t/{tenant}/account/consent",
          "asked again with offline_access, the person is asked again: keeping access is never agreed to for good")
    application.code_at_once(browser)
    return browser, tokens, identity


def userinfo_answers(tenant, tokens, identity, address):
    step("UserInfo")
    answer = userinfo(tenant, tokens["access_token"])
    check(answer.status == 200, "UserInfo answered the access token")
    claims = answer.json()
    shown(f"UserInfo: {claims}")
    check(claims.get("sub") == identity["sub"] and claims.get("email") == address,
          "it names the same person as the ID token, with the email address the scope email allows")


def a_refresh_token(application, tokens):
    step("A refresh token moves at every use, and ends when an old one comes back")
    first = tokens["refresh_token"]
    answer = application.endpoint("token", {"grant_type": "refresh_token", "refresh_token": first})
    check(answer.status == 200 and answer.json().get("refresh_token") not in (None, first),
          "a refresh gave a new access token and the next refresh token")
    application.checked(answer.json()["access_token"], "the refreshed access token")
    second = answer.json()["refresh_token"]
    shown(f"waiting {RETRY_WINDOW_SECONDS + 1} seconds, past the window in which a retried refresh is answered again")
    time.sleep(RETRY_WINDOW_SECONDS + 1)
    again = application.endpoint("token", {"grant_type": "refresh_token", "refresh_token": first})
    check(again.status == 400 and again.json().get("error") == "invalid_grant",
          "the first refresh token, presented again, is refused: it was used before")
    after = application.endpoint("token", {"grant_type": "refresh_token", "refresh_token": second})
    check(after.status == 400 and after.json().get("error") == "invalid_grant",
          "and the newest one is refused too: reuse ended the whole family")
    check(application.active(second) == {"active": False}, "introspection says the newest one is not active")


def a_token_for_itself(tenant, application):
    step("A token a service gets for itself")
    answer = application.endpoint("token", {"grant_type": "client_credentials", "scope": "invoices:read"})
    check(answer.status == 200 and "refresh_token" not in answer.json(),
          "the client got an access token with its own credentials, and no refresh token")
    claims = application.checked(answer.json()["access_token"], "the access token")
    check(claims.get("sub") == application.client_id and AUDIENCE in claims.get("aud", []),
          "its subject is the client itself, and it is for the resource server")
    return answer.json()["access_token"]


def revocation_and_introspection(tenant, application, browser):
    step("Revocation and introspection")
    location, parameters, verifier = application.code_at_once(browser)
    tokens, _, _ = application.exchange(location, parameters, verifier)
    access = tokens["access_token"]
    said = application.active(access)
    check(said.get("active") is True and said.get("client_id") == application.client_id,
          "introspection says the access token is active, and whose it is")
    revoked = application.endpoint("revoke", {"token": access, "token_type_hint": "access_token"})
    check(revoked.status == 200, "the application revoked the access token")
    check(application.active(access) == {"active": False}, "introspection now says it is not active, and no more")
    check(userinfo(tenant, access).status == 401, "UserInfo refuses it at once, long before it expires")


def a_rotated_key(tenant, application, browser, identity_token):
    step("The tenant's key is rotated")
    before = key_identifier(identity_token)
    check(before in published_keys(tenant), f"the key that signed the tokens so far, {before}, is published")
    said = cli("keys", "rotate", "--tenant", tenant)
    shown(said)
    location, parameters, verifier = application.code_at_once(browser)
    tokens, _, _ = application.exchange(location, parameters, verifier)
    after = key_identifier(tokens["id_token"])
    check(after != before and after in said, "new tokens are signed with the new key")
    keys = published_keys(tenant)
    check(before in keys and after in keys,
          "the old key stays in the key set, so that tokens it signed can still be checked until they expire")
    application.checked(identity_token, "the ID token signed before the rotation")


def tenants_apart(tenant, other, application, browser, client_token):
    step("Tenants apart")
    location, parameters, verifier = application.code_at_once(browser)
    code = query_of(location)["code"]
    elsewhere = Browser()
    answer = elsewhere.call("GET", f"/t/{other}/oauth2/authorize?" + urllib.parse.urlencode(
        parameters))
    check(answer.status == 400 and "Location" not in answer.headers,
          f"the client of {tenant} is no client in {other}: an error page, and nothing sent to its address")
    there = ThirdPartyApplication(other, application.client_id, application.secret)
    redeemed = there.endpoint("token", {"grant_type": "authorization_code", "code": code,
                                        "redirect_uri": REDIRECT_URI, "code_verifier": verifier})
    check(redeemed.status == 401 and redeemed.json().get("error") == "invalid_client",
          f"a code of {tenant} is refused by {other}, where its client is unknown")
    check(userinfo(other, client_token).status == 401, f"an access token of {tenant} is refused by {other}'s UserInfo")
    itself = there.endpoint("token", {"grant_type": "client_credentials", "scope": "invoices:read"})
    check(itself.status == 401 and itself.json().get("error") == "invalid_client",
          f"the client's secret means nothing in {other}")
    tokens, _, _ = application.exchange(location, parameters, verifier)
    check("access_token" in tokens, f"the code still redeems in {tenant}, where it belongs")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    suffix = format(int(time.time() * 1000), "x")
    tenant, other = f"acme-{suffix}", f"globex-{suffix}"
    address = f"ana-{suffix}@example.com"
    try:
        two_tenants_and_a_person(tenant, other, address)
        application = a_third_party_application(tenant)
        browser, tokens, identity = asked_once(tenant, address, application)
        userinfo_answers(tenant, tokens, identity, address)
        a_refresh_token(application, tokens)
        client_token = a_token_for_itself(tenant, application)
        revocation_and_introspection(tenant, application, browser)
        a_rotated_key(tenant, application, browser, tokens["id_token"])
        tenants_apart(tenant, other, application, browser, client_token)
    except Failed as failure:
        print(f"\nThe demonstration stopped: {failure}", file=sys.stderr)
        sys.exit(1)
    print("\nThe demonstration passed.")


if __name__ == "__main__":
    main()
