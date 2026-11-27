#!/usr/bin/env python3
"""The demonstration of Milestone 13: requests that say what they need.

Runs against the development stack and does what an administrator, three
applications and two people would do: a person gives her names, her
telephone number and her postal address on the account page; an
application sends its request as a request object signed with its own key
and reads, in the ID token, the claims it asked for through `claims`; it
pushes a request first and sends the browser with the reference alone,
which works once; it keeps a request object at an address of its own,
which Hodor fetches; an object signed by another application's key, a
reference pushed by another application and a reference of another tenant
are refused; a third-party application asks through `claims` for a claim of
a scope the person did not agree to, and does not get it; an essential
`acr` steps the person up; and the ID token of one person, as the hint of a
request in a browser signed in as another, is answered `login_required`.
Every answer is checked; the first one that is not what it should be stops
the demonstration with a non-zero exit status.

    docker compose -f deploy/docker/compose.yaml up --build --wait
    python3 deploy/demo/requests_and_claims.py

It needs Python 3 and Docker, and nothing outside the standard library. The
applications are played by the script, as in the demonstration of
Milestone 4: they register redirect addresses nobody listens on, and read
where the browser is sent. Their keys are P-256 keys made here, with the
arithmetic done by hand, for this demonstration only. The address where one
keeps its request objects is a path of the stack's receiver of webhooks,
which answers what the script puts there. See
docs/operations/quick-start.md.
"""

import base64
import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from applications import ThirdPartyApplication, userinfo
from demo import OPENER, SERVER, Answer, Failed, check, cli, request, shown, step
from external_identities import completed, post_form, query_of
from strong_authentication import (
    G,
    MULTI_FACTOR,
    N,
    REDIRECT_URI,
    Application,
    an_authenticator_application,
    encode,
    point_multiply,
    sha256,
    sign,
)
from what_was_left_out import RECEIVER, RECEIVER_INSIDE, a_person, bootstrap, signed_in

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


# ---------------------------------------------------------------------------
# Signing, as an application does with its own key
# ---------------------------------------------------------------------------

def raw_signature(der):
    """The `r` and `s` of a DER-encoded ECDSA signature, as JSON Web
    Signatures write them: 32 bytes each."""
    length_r = der[3]
    r = int.from_bytes(der[4:4 + length_r], "big")
    s = int.from_bytes(der[6 + length_r:], "big")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class Key:
    """A P-256 key of an application, kept in memory while the script runs."""

    def __init__(self, kid):
        self.kid = kid
        self.private = secrets.randbelow(N - 1) + 1
        x, y = point_multiply(self.private, G)
        self.jwk = {"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
                    "x": encode(x.to_bytes(32, "big")), "y": encode(y.to_bytes(32, "big"))}

    def signed(self, claims, kind="JWT"):
        """`claims` as a JSON Web Token of the type `kind`, signed with
        ES256 under this key's `kid`."""
        header = encode(json.dumps({"alg": "ES256", "kid": self.kid, "typ": kind}).encode())
        payload = encode(json.dumps(claims).encode())
        signature = raw_signature(sign(self.private, f"{header}.{payload}".encode()))
        return f"{header}.{payload}.{encode(signature)}"


class SigningApplication(Application):
    """A client of the tenant that proves who it is with `private_key_jwt`
    and signs its request objects, both with its own key."""

    def __init__(self, tenant, issuer, name, client_id, key):
        super().__init__(tenant, client_id, None)
        self.issuer = issuer
        self.name = name
        self.key = key

    def assertion(self):
        now = int(time.time())
        return self.key.signed({"iss": self.client_id, "sub": self.client_id, "aud": self.issuer,
                                "iat": now, "exp": now + 60, "jti": encode(secrets.token_bytes(16))})

    def authenticated(self, fields):
        return {**fields, "client_assertion_type": ASSERTION_TYPE, "client_assertion": self.assertion()}

    def parameters(self, **extra):
        """The parameters of a request, with PKCE: the parameters and the verifier."""
        verifier = encode(secrets.token_bytes(32))
        return {
            "response_type": "code", "client_id": self.client_id, "redirect_uri": REDIRECT_URI,
            "scope": "openid", "state": encode(secrets.token_bytes(12)), "nonce": encode(secrets.token_bytes(12)),
            "code_challenge": encode(sha256(verifier.encode())), "code_challenge_method": "S256", **extra,
        }, verifier

    def request_object(self, parameters, key=None):
        """The parameters as a request object for the tenant, signed with
        this application's key unless another is given."""
        return (key or self.key).signed({"iss": self.client_id, "aud": self.issuer,
                                         "exp": int(time.time()) + 300, **parameters},
                                        kind="oauth-authz-req+jwt")

    def push(self, parameters):
        return post_form(f"{SERVER}/t/{self.tenant}/oauth2/par", self.authenticated(parameters))

    def tokens(self, location, parameters, verifier):
        """Redeems the code where the browser was sent back, proving who the
        application is with an assertion: the tokens and the checked claims
        of the ID token."""
        back = query_of(location)
        check(location.startswith(REDIRECT_URI) and back.get("state") == parameters["state"] and "code" in back,
              f"the browser was sent back to {self.name} with a code and the state of the request")
        answer = post_form(f"{SERVER}/t/{self.tenant}/oauth2/token", self.authenticated({
            "grant_type": "authorization_code", "code": back["code"],
            "redirect_uri": REDIRECT_URI, "code_verifier": verifier}))
        check(answer.status == 200, f"{self.name} redeems the code, proving who it is with its key"
                                    + ("" if answer.status == 200 else f" (answered {answer.status} {answer.text})"))
        tokens = answer.json()
        identity = self.checked(tokens["id_token"], f"the ID token of {self.name}")
        check(identity.get("nonce") == parameters["nonce"] and identity.get("aud") in (self.client_id, [self.client_id]),
              f"the ID token is for {self.name}, with the nonce of the request")
        return tokens, identity


def authorize(browser, tenant, parameters):
    answer = browser.call("GET", f"/t/{tenant}/oauth2/authorize?" + urllib.parse.urlencode(parameters))
    return answer, answer.headers.get("Location", "")


def refused_at_the_client(location, error, what):
    back = query_of(location)
    check(location.startswith(REDIRECT_URI) and back.get("error") == error and "code" not in back,
          f"{what}: {error} at the application's redirect address" + ("" if back.get("error") == error
                                                                       else f" (sent to {location})"))


def keep_at_the_receiver(path, content):
    """Puts `content` at `path` of the stack's receiver, which answers it
    to every `GET` of that path from then on."""
    call = urllib.request.Request(f"{RECEIVER}{path}", data=content.encode(), method="PUT",
                                  headers={"Content-Type": "application/oauth-authz-req+jwt"})
    try:
        with OPENER.open(call, timeout=30) as response:
            answer = Answer(response.status, response.headers, response.read())
    except urllib.error.HTTPError as error:
        answer = Answer(error.code, error.headers, error.read())
    except urllib.error.URLError as error:
        raise Failed(f"{RECEIVER} could not be reached: {error.reason}") from error
    check(answer.status == 204, f"the application keeps its object at {RECEIVER_INSIDE}{path}")


def fetched(path):
    """The fetches of `path` the stack's receiver answered."""
    return request("GET", f"{RECEIVER}/fetched?path={urllib.parse.quote(path)}").json().get("items", [])


# ---------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------

def two_tenants_and_two_people(tenant, other, suffix, ana, bruno):
    step("Two tenants, their administrators, and two people")
    administrators = []
    for slug, name in [(tenant, "Acme"), (other, "Globex")]:
        said = cli("tenant", "create", "--slug", slug, "--name", name)
        check(slug in said, f"the command-line tool created {slug}")
        cli("keys", "rotate", "--tenant", slug)
        administrators.append(bootstrap(slug, f"operator-{suffix}@{slug}.example.com"))
    admin, other_admin = administrators
    a_person(admin, ana, "Ana")
    a_person(admin, bruno, "Bruno")
    return admin, other_admin


def what_discovery_says(tenant):
    step("What discovery says a request may say")
    said = request("GET", f"{SERVER}/t/{tenant}/.well-known/openid-configuration").json()
    issuer = said["issuer"]
    check(said.get("request_parameter_supported") is True
          and "ES256" in said.get("request_object_signing_alg_values_supported", []),
          "request objects by value, signed with ES256 among others")
    check(said.get("pushed_authorization_request_endpoint") == f"{issuer}/oauth2/par"
          and said.get("require_pushed_authorization_requests") is False,
          "the pushed request endpoint, which this tenant does not require")
    check(said.get("request_uri_parameter_supported") is True and said.get("require_request_uri_registration") is True,
          "request objects at a client's address, registered first")
    check(said.get("claims_parameter_supported") is True
          and {"address", "phone"} <= set(said.get("scopes_supported", [])),
          "the claims parameter, and the scopes address and phone")
    return issuer


def her_claims_on_the_account_page(tenant, ana):
    step("Her standard claims, on the account page")
    browser = signed_in(tenant, ana)
    browser.call("GET", f"/t/{tenant}/interaction/session")
    changed = browser.call("PUT", f"/t/{tenant}/interaction/profile", {
        "display_name": "Ana Lima",
        "claims": {
            "given_name": "Ana", "family_name": "Lima", "phone_number": "+55 (11) 91234-5678",
            "address": {"street_address": "Avenida Paulista, 1000", "locality": "São Paulo",
                        "postal_code": "01310-100", "country": "BR"},
        },
    })
    check(changed.status == 200, "the profile page kept them"
          + ("" if changed.status == 200 else f" (answered {changed.status} {changed.text})"))
    claims = changed.json()["claims"]
    shown(f"kept: {claims}")
    check(claims.get("phone_number") == "+5511912345678" and claims.get("phone_number_verified") is False,
          "the number is kept as E.164, and not verified: she cannot vouch for it herself")
    return browser


def two_applications_that_sign(admin, issuer, suffix):
    step("Two applications that sign their requests")
    made = []
    for name in ["Billing", "Payroll"]:
        application = admin.call("POST", "/applications", {"name": name, "first_party": True})
        client = admin.call("POST", f"/applications/{application['id']}/clients", {
            "name": f"{name} web", "type": "confidential", "authentication_method": "private_key_jwt",
            "grant_types": ["authorization_code"], "redirect_uris": [REDIRECT_URI],
            "allowed_scopes": ["openid", "profile", "phone", "address", "email"],
            "request_object_signing_alg": "ES256",
            "request_uris": [f"{RECEIVER_INSIDE}/request-objects/{suffix}/{name.lower()}/"],
        })
        key = Key(f"{name.lower()}-1")
        keyed = admin.call("POST", f"/clients/{client['id']}/keys", {"jwk": key.jwk})
        check(keyed.get("request_object_signing_alg") == "ES256" and len(keyed.get("request_uris", [])) == 1,
              f"{name} signs its request objects with ES256, keeps them under one address of its own, "
              f"and has one key")
        made.append(SigningApplication(admin.tenant, issuer, name, client["id"], key))
    return made


def a_signed_request_object(browser, billing):
    step("A request object, signed")
    asked = {"id_token": {"given_name": {"essential": True}, "family_name": None,
                          "phone_number": None, "address": None}}
    parameters, verifier = billing.parameters(scope="openid profile phone address", claims=asked)
    shown(f"claims: {json.dumps(asked)}")
    _, location = authorize(browser, billing.tenant, {
        "client_id": billing.client_id, "response_type": "code", "scope": parameters["scope"],
        "request": billing.request_object(parameters)})
    tokens, identity = billing.tokens(location, parameters, verifier)
    shown(f"the ID token: given_name {identity.get('given_name')}, family_name {identity.get('family_name')}, "
          f"phone_number {identity.get('phone_number')}, address {identity.get('address')}")
    check(identity.get("given_name") == "Ana" and identity.get("family_name") == "Lima"
          and identity.get("phone_number") == "+5511912345678"
          and identity.get("address", {}).get("locality") == "São Paulo",
          "the ID token holds the claims the object asked for, under their own names")
    return tokens["id_token"]


def a_pushed_request(browser, billing):
    step("A pushed request")
    parameters, verifier = billing.parameters()
    pushed = billing.push(parameters)
    check(pushed.status == 201 and pushed.json().get("request_uri", "").startswith("urn:ietf:params:oauth:request_uri:"),
          f"{billing.name} pushed its request, proving who it is, and got a reference"
          + ("" if pushed.status == 201 else f" (answered {pushed.status} {pushed.text})"))
    reference, lifetime = pushed.json()["request_uri"], pushed.json().get("expires_in")
    shown(f"{reference}, for {lifetime} seconds")
    brought = {"client_id": billing.client_id, "request_uri": reference}
    _, location = authorize(browser, billing.tenant, brought)
    billing.tokens(location, parameters, verifier)
    _, location = authorize(browser, billing.tenant, {**brought, "redirect_uri": REDIRECT_URI})
    refused_at_the_client(location, "invalid_request_uri", "the same reference brought again")


def a_request_object_at_its_address(browser, billing, suffix):
    step("A request object at the application's own address")
    parameters, verifier = billing.parameters()
    content = billing.request_object(parameters)
    path = f"/request-objects/{suffix}/billing/sign-in"
    keep_at_the_receiver(path, content)
    address = f"{RECEIVER_INSIDE}{path}#{encode(sha256(content.encode()))}"
    _, location = authorize(browser, billing.tenant, {"client_id": billing.client_id, "request_uri": address})
    billing.tokens(location, parameters, verifier)
    seen = fetched(path)
    check(len(seen) == 1 and "application/oauth-authz-req+jwt" in (seen[0].get("accept") or ""),
          "Hodor fetched it once, for this request, and the hash after # was the content's")

    # Under Payroll's address, which Billing did not register: never fetched.
    elsewhere = f"/request-objects/{suffix}/payroll/sign-in"
    keep_at_the_receiver(elsewhere, content)
    _, location = authorize(browser, billing.tenant, {
        "client_id": billing.client_id, "request_uri": f"{RECEIVER_INSIDE}{elsewhere}", "redirect_uri": REDIRECT_URI})
    refused_at_the_client(location, "invalid_request_uri", "an address Billing did not register")
    check(fetched(elsewhere) == [], "and it was never fetched")
    _, location = authorize(browser, billing.tenant, {
        "client_id": billing.client_id, "request_uri": f"{RECEIVER_INSIDE}{path}#{encode(sha256(b'other'))}",
        "redirect_uri": REDIRECT_URI})
    refused_at_the_client(location, "invalid_request_uri", "its own address with the hash of other content")


def what_must_be_refused(browser, billing, payroll, other_admin, other_issuer):
    step("What must be refused, refused")
    parameters, _ = billing.parameters()
    _, location = authorize(browser, billing.tenant, {
        "client_id": billing.client_id, "response_type": "code", "scope": "openid", "redirect_uri": REDIRECT_URI,
        "request": billing.request_object(parameters, key=payroll.key)})
    refused_at_the_client(location, "invalid_request_object", "Billing's request signed by Payroll's key")

    parameters, _ = payroll.parameters()
    pushed = payroll.push(parameters)
    check(pushed.status == 201, "Payroll pushed a request of its own")
    _, location = authorize(browser, billing.tenant, {
        "client_id": billing.client_id, "request_uri": pushed.json()["request_uri"], "redirect_uri": REDIRECT_URI})
    refused_at_the_client(location, "invalid_request_uri", "Payroll's reference, brought for Billing")

    # The other tenant's own application, with a secret.
    application = other_admin.call("POST", "/applications", {"name": "Billing", "first_party": True})
    client = other_admin.call("POST", f"/applications/{application['id']}/clients", {
        "name": "Billing web", "type": "confidential", "grant_types": ["authorization_code"],
        "redirect_uris": [REDIRECT_URI], "allowed_scopes": ["openid"]})
    elsewhere = Application(other_admin.tenant, client["id"], client["client_secret"])
    verifier = encode(secrets.token_bytes(32))
    pushed = post_form(f"{SERVER}/t/{other_admin.tenant}/oauth2/par", {
        "response_type": "code", "redirect_uri": REDIRECT_URI, "scope": "openid",
        "code_challenge": encode(sha256(verifier.encode())), "code_challenge_method": "S256"},
        {"Authorization": basic(elsewhere.client_id, elsewhere.secret)})
    check(pushed.status == 201, f"the application of {other_admin.tenant} pushed a request there, at {other_issuer}")
    _, location = authorize(browser, billing.tenant, {
        "client_id": billing.client_id, "request_uri": pushed.json()["request_uri"], "redirect_uri": REDIRECT_URI})
    refused_at_the_client(location, "invalid_request_uri",
                          f"a reference of {other_admin.tenant}, brought to {billing.tenant} for Billing")


def basic(client_id, secret):
    pair = f"{urllib.parse.quote(client_id)}:{urllib.parse.quote(secret)}"
    return "Basic " + base64.b64encode(pair.encode()).decode()


def a_claim_she_did_not_agree_to(admin, browser):
    step("A claim of a scope she did not agree to")
    tenant = admin.tenant
    application = admin.call("POST", "/applications", {"name": "Travel", "first_party": False})
    client = admin.call("POST", f"/applications/{application['id']}/clients", {
        "name": "Travel web", "type": "confidential", "grant_types": ["authorization_code"],
        "redirect_uris": [REDIRECT_URI], "allowed_scopes": ["openid", "email"]})
    travel = ThirdPartyApplication(tenant, client["id"], client["client_secret"])
    asked = {"id_token": {"email": {"essential": True}}, "userinfo": {"email": {"essential": True}}}
    shown(f"Travel, an application of another company, asks for the scope openid and claims {json.dumps(asked)}")
    answer, parameters, verifier = travel.authorize(browser, claims=json.dumps(asked))
    check(answer.headers.get("Location") == f"/t/{tenant}/account/consent", "she is asked for her consent")
    question = browser.call("GET", f"/t/{tenant}/interaction/consent").json()
    check([scope["scope"] for scope in question.get("scopes", [])] == ["openid"],
          "the page asks about openid alone: claims choose where a claim goes, never widen what is given")
    answered = browser.call("POST", f"/t/{tenant}/interaction/consent", {"decision": "allow"})
    resumed = browser.call("GET", answered.json()["continue"])
    tokens, identity, _ = travel.exchange(resumed.headers["Location"], parameters, verifier)
    check("email" not in identity, "the ID token holds no email address, though it was asked for as essential")
    answered = userinfo(tenant, tokens["access_token"])
    shown(f"UserInfo: {answered.json()}")
    check(answered.status == 200 and "email" not in answered.json() and answered.json().get("sub") == identity["sub"],
          "nor does UserInfo: she agreed to openid alone")


def an_essential_acr(browser, billing):
    step("An essential acr steps her up")
    tenant = billing.tenant
    authenticator, _ = an_authenticator_application(browser, tenant)
    asked = {"id_token": {"acr": {"essential": True, "values": [MULTI_FACTOR]}}}
    parameters, verifier = billing.parameters(claims=asked)
    _, location = authorize(browser, tenant, {
        "client_id": billing.client_id, "response_type": "code", "scope": "openid",
        "request": billing.request_object(parameters)})
    check("/account/sign-in" in location, "the session of a password is not enough: she is sent to sign in")
    waiting = browser.call("GET", f"/t/{tenant}/interaction/sign-in").json()
    check(waiting.get("step") == "totp", "only the code of her authenticator application is asked for")
    done = browser.call("POST", f"/t/{tenant}/interaction/sign-in/steps/totp", {"code": authenticator.code()})
    check(completed(done), "the code completed the step-up")
    resumed = browser.call("GET", done.json()["continue"])
    _, identity = billing.tokens(resumed.headers["Location"], parameters, verifier)
    shown(f"the ID token: acr {identity.get('acr')}, amr {identity.get('amr')}")
    check(identity.get("acr") == MULTI_FACTOR and "otp" in identity.get("amr", []),
          "the ID token says the multi-factor level, reached with a one-time code")


def a_hint_of_another_person(browser, tenant, bruno, billing, identity_token):
    step("The ID token of another person, as a hint")
    parameters, verifier = billing.parameters(prompt="none", id_token_hint=identity_token)
    _, location = authorize(browser, tenant, parameters)
    billing.tokens(location, parameters, verifier)
    shown("in Ana's own browser, her ID token as the hint is answered with a code, asking nothing")
    someone_else = signed_in(tenant, bruno)
    parameters, _ = billing.parameters(prompt="none", id_token_hint=identity_token)
    _, location = authorize(someone_else, tenant, parameters)
    refused_at_the_client(location, "login_required",
                          "her ID token as the hint, with prompt=none, in a browser signed in as Bruno")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    suffix = format(int(time.time() * 1000), "x")
    tenant, other = f"acme-{suffix}", f"globex-{suffix}"
    ana, bruno = f"ana-{suffix}@example.com", f"bruno-{suffix}@example.com"
    try:
        check(request("GET", f"{RECEIVER}/health").status == 200, f"the stack's receiver answers at {RECEIVER}")
        admin, other_admin = two_tenants_and_two_people(tenant, other, suffix, ana, bruno)
        issuer = what_discovery_says(tenant)
        other_issuer = request("GET", f"{SERVER}/t/{other}/.well-known/openid-configuration").json()["issuer"]
        browser = her_claims_on_the_account_page(tenant, ana)
        billing, payroll = two_applications_that_sign(admin, issuer, suffix)
        identity_token = a_signed_request_object(browser, billing)
        a_pushed_request(browser, billing)
        a_request_object_at_its_address(browser, billing, suffix)
        what_must_be_refused(browser, billing, payroll, other_admin, other_issuer)
        a_claim_she_did_not_agree_to(admin, browser)
        an_essential_acr(browser, billing)
        a_hint_of_another_person(browser, tenant, bruno, billing, identity_token)
    except Failed as failure:
        print(f"\nThe demonstration stopped: {failure}", file=sys.stderr)
        sys.exit(1)
    print("\nThe demonstration of Milestone 13 passed.")


if __name__ == "__main__":
    main()
