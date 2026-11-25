#!/usr/bin/env python3
"""The demonstration of Milestone 4: strong authentication.

Runs against the development stack and does what a person, an application
and an administrator would do: a code from an authenticator application,
recovery codes, a tenant that requires a second factor, a passkey that signs
in on its own, an application that asks for a higher assurance in the middle
of a session, and an administrator who removes a person's factors. Every
answer is checked; the first one that is not what it should be stops the
demonstration with a non-zero exit status.

    docker compose -f deploy/docker/compose.yaml up --build --wait
    python3 deploy/demo/strong_authentication.py

It needs Python 3 and Docker, and nothing outside the standard library. The
passkey is a software authenticator written here, with the P-256 arithmetic
of the WebAuthn specification done by hand: it is for this demonstration
only, and keeps its private key in memory for as long as the script runs.
See docs/operations/quick-start.md.
"""

import base64
import hashlib
import hmac
import json
import secrets
import struct
import sys
import time
import urllib.parse

from demo import (
    SERVER,
    Browser,
    Failed,
    check,
    cli,
    link_from_message,
    request,
    shown,
    step,
    until,
)
from external_identities import completed, post_form, query_of, rejected

PASSWORD = "correct horse battery staple"
REDIRECT_URI = "http://127.0.0.1:8765/callback"
PHISHING_RESISTANT = "urn:example:acr:phishing-resistant"
MULTI_FACTOR = "urn:hodor:acr:mfa"
SINGLE_FACTOR = "urn:hodor:acr:single-factor"


# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------

def encode(data):
    """Base64url without padding, as WebAuthn and JSON Web Tokens write bytes."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sha256(data):
    return hashlib.sha256(data).digest()


def cbor_bytes(value):
    if len(value) < 24:
        head = bytes([0x40 | len(value)])
    elif len(value) < 256:
        head = bytes([0x58, len(value)])
    else:
        head = bytes([0x59]) + struct.pack(">H", len(value))
    return head + value


def cbor_text(value):
    data = value.encode()
    return bytes([0x60 | len(data)]) + data


# ---------------------------------------------------------------------------
# P-256, for the passkey's signatures and for checking tokens
# ---------------------------------------------------------------------------

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def point_add(first, second):
    if first is None:
        return second
    if second is None:
        return first
    (x1, y1), (x2, y2) = first, second
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if first == second:
        slope = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def point_multiply(scalar, point):
    result = None
    while scalar:
        if scalar & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        scalar >>= 1
    return result


def on_curve(point):
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


def sign(private, message):
    """An ECDSA signature with SHA-256, DER encoded, as an authenticator gives it."""
    digest = int.from_bytes(sha256(message), "big")
    while True:
        nonce = secrets.randbelow(N - 1) + 1
        r = point_multiply(nonce, G)[0] % N
        s = pow(nonce, -1, N) * (digest + r * private) % N
        if r and s:
            break

    def integer(value):
        data = value.to_bytes(32, "big").lstrip(b"\0")
        if data[0] & 0x80:
            data = b"\0" + data
        return bytes([0x02, len(data)]) + data

    body = integer(r) + integer(s)
    return bytes([0x30, len(body)]) + body


def verified(public, message, r, s):
    """Whether (r, s) is an ECDSA signature with SHA-256 of `message` by `public`."""
    if not (0 < r < N and 0 < s < N) or not on_curve(public):
        return False
    digest = int.from_bytes(sha256(message), "big")
    inverse = pow(s, -1, N)
    point = point_add(point_multiply(digest * inverse % N, G), point_multiply(r * inverse % N, public))
    return point is not None and point[0] % N == r


class Passkey:
    """A software authenticator holding one passkey.

    It answers as a platform authenticator does after the person unlocked it:
    present and verified. It makes its key pair when it is first asked to
    register, and counts its signatures as an authenticator must.
    """

    def __init__(self, origin):
        self.origin = origin
        self.private = secrets.randbelow(N - 1) + 1
        self.public = point_multiply(self.private, G)
        self.credential_id = secrets.token_bytes(32)
        self.counter = 0
        self.user_handle = None

    def _client_data(self, kind, challenge):
        return json.dumps({"type": kind, "challenge": challenge, "origin": self.origin,
                           "crossOrigin": False}).encode()

    def _authenticator_data(self, rp_id, attested):
        # Present, verified, and with attested credential data at registration.
        flags = 0x01 | 0x04 | (0x40 if attested else 0)
        data = sha256(rp_id.encode()) + bytes([flags]) + struct.pack(">I", self.counter)
        self.counter += 1
        if attested:
            x, y = self.public
            key = (bytes([0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]) + cbor_bytes(x.to_bytes(32, "big"))
                   + bytes([0x22]) + cbor_bytes(y.to_bytes(32, "big")))
            data += bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id + key
        return data

    def register(self, options):
        self.user_handle = options["user"]["id"]
        authenticator_data = self._authenticator_data(options["rp"]["id"], attested=True)
        attestation = (bytes([0xA3]) + cbor_text("fmt") + cbor_text("none") + cbor_text("attStmt")
                       + bytes([0xA0]) + cbor_text("authData") + cbor_bytes(authenticator_data))
        return {
            "client_data": encode(self._client_data("webauthn.create", options["challenge"])),
            "attestation_object": encode(attestation),
            "transports": ["internal"],
            "discoverable": True,
            "name": "Demonstration passkey",
        }

    def answer(self, options):
        client_data = self._client_data("webauthn.get", options["challenge"])
        authenticator_data = self._authenticator_data(options["rpId"], attested=False)
        return {
            "credential_id": encode(self.credential_id),
            "client_data": encode(client_data),
            "authenticator_data": encode(authenticator_data),
            "signature": encode(sign(self.private, authenticator_data + sha256(client_data))),
            "user_handle": self.user_handle,
        }


# ---------------------------------------------------------------------------
# An authenticator application
# ---------------------------------------------------------------------------

class AuthenticatorApplication:
    """What an authenticator application does with the secret it was given.

    A code is good once: the server refuses a code it has seen. The
    application therefore never gives a time step twice, and waits for the
    clock when the next step is not yet within the server's window of one
    step either way.
    """

    def __init__(self, secret):
        self.key = base64.b32decode(secret + "=" * (-len(secret) % 8))
        self.last_step = None

    def code(self):
        now = int(time.time()) // 30
        wanted = now if self.last_step is None else max(now, self.last_step + 1)
        while wanted > int(time.time()) // 30 + 1:
            shown("waiting for the authenticator application's next code")
            time.sleep(30 - time.time() % 30 + 0.5)
        self.last_step = wanted
        digest = hmac.new(self.key, struct.pack(">Q", wanted), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        return f"{value % 1_000_000:06d}"


# ---------------------------------------------------------------------------
# An application, as Milestone 3 lets one sign a person in
# ---------------------------------------------------------------------------

class Application:
    def __init__(self, tenant, client_id, secret):
        self.tenant = tenant
        self.client_id = client_id
        self.secret = secret

    def authorize(self, browser, **extra):
        """Sends the browser to the authorization endpoint, with PKCE."""
        verifier = encode(secrets.token_bytes(32))
        parameters = {
            "response_type": "code", "client_id": self.client_id, "redirect_uri": REDIRECT_URI,
            "scope": "openid", "state": encode(secrets.token_bytes(12)), "nonce": encode(secrets.token_bytes(12)),
            "code_challenge": encode(sha256(verifier.encode())), "code_challenge_method": "S256", **extra,
        }
        answer = browser.call("GET", f"/t/{self.tenant}/oauth2/authorize?" + urllib.parse.urlencode(parameters))
        return answer, parameters, verifier

    def tokens(self, location, parameters, verifier):
        """Takes the code from where the browser was sent back and redeems it."""
        back = query_of(location)
        check(location.startswith(REDIRECT_URI) and back.get("state") == parameters["state"] and "code" in back,
              "the browser was sent back to the application with a code and its state")
        basic = base64.b64encode(
            f"{urllib.parse.quote(self.client_id)}:{urllib.parse.quote(self.secret)}".encode()).decode()
        answer = post_form(f"{SERVER}/t/{self.tenant}/oauth2/token",
                           {"grant_type": "authorization_code", "code": back["code"],
                            "redirect_uri": REDIRECT_URI, "code_verifier": verifier},
                           {"Authorization": f"Basic {basic}"})
        check(answer.status == 200 and "id_token" in answer.json(), "the code was exchanged for tokens")
        identity = self.checked(answer.json()["id_token"], "the ID token")
        access = self.checked(answer.json()["access_token"], "the access token")
        check(identity.get("nonce") == parameters["nonce"], "the ID token carries the nonce the application sent")
        return identity, access

    def checked(self, token, what):
        """Checks a token's signature against the tenant's published key set."""
        header, payload, signature = token.split(".")
        kid = json.loads(decode(header))["kid"]
        keys = request("GET", f"{SERVER}/t/{self.tenant}/oauth2/jwks").json().get("keys", [])
        key = next((key for key in keys if key.get("kid") == kid), None)
        check(key is not None and key.get("crv") == "P-256", f"{what} names a key of the published key set")
        public = (int.from_bytes(decode(key["x"]), "big"), int.from_bytes(decode(key["y"]), "big"))
        raw = decode(signature)
        check(verified(public, f"{header}.{payload}".encode(), int.from_bytes(raw[:32], "big"),
                       int.from_bytes(raw[32:], "big")),
              f"the signature of {what} is good")
        return json.loads(decode(payload))


def show_levels(claims, what):
    shown(f"{what}: acr {claims.get('acr')}, amr {claims.get('amr')}")


# ---------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------

def a_tenant_and_a_person(tenant, other, address):
    step("A tenant, and a person in it")
    for slug, name in [(tenant, "Acme"), (other, "Globex")]:
        said = cli("tenant", "create", "--slug", slug, "--name", name, "--open-registration")
        check(slug in said, f"the command-line tool created {slug}")
    cli("keys", "rotate", "--tenant", tenant)
    check(any(request("GET", f"{SERVER}/t/{tenant}/oauth2/jwks").json().get("keys", [])),
          f"{tenant} has a signing key, published")
    said = cli("tenant", "assurance-levels", "--slug", tenant,
               "--level", f"{SINGLE_FACTOR}=single_factor", "--level", f"{MULTI_FACTOR}=multi_factor",
               "--level", f"{PHISHING_RESISTANT}=phishing_resistant")
    check(PHISHING_RESISTANT in said, f"{tenant} names three assurance levels, one of them phishing-resistant")
    asked = request("POST", f"{SERVER}/t/{tenant}/interaction/registration", {"email": address})
    check(asked.status == 202, f"{tenant} accepted the request to register {address}")
    _, token = link_from_message(address, tenant)
    done = request("POST", f"{SERVER}/t/{tenant}/interaction/registration/complete",
                   {"token": token, "password": PASSWORD})
    check(done.status == 204, f"{address} registered with a password")


def an_application(tenant):
    step("An application")
    said = cli("application", "add", "--tenant", tenant, "--name", "Billing", "--first-party")
    application = said.split()[1]
    said = dict(line.split(" ", 1) for line in cli(
        "client", "add", "--tenant", tenant, "--application", application, "--name", "Billing web",
        "--type", "confidential", "--grant", "authorization_code", "--redirect-uri", REDIRECT_URI,
        "--scope", "openid").splitlines())
    check("client" in said and "secret" in said, f"the application of {tenant} has a client and a secret")
    return Application(tenant, said["client"], said["secret"])


def a_password_session(tenant, address, application):
    step("Signed in with a password")
    browser = Browser()
    check(completed(browser.sign_in(tenant, address, PASSWORD)), f"{address} signed in with the password alone")
    session = browser.call("GET", f"/t/{tenant}/interaction/session").json()
    shown(f"the session holds {session.get('methods')}")
    answer, parameters, verifier = application.authorize(browser)
    check(answer.status in (302, 303), "the application gets a code at once: the session is enough")
    identity, access = application.tokens(answer.headers["Location"], parameters, verifier)
    show_levels(identity, "the ID token")
    show_levels(access, "the access token")
    check(identity.get("amr") == ["pwd"] and identity.get("acr") == SINGLE_FACTOR,
          "the tokens say a password, and the single-factor level")
    return browser, session["user_id"]


def an_authenticator_application(browser, tenant):
    step("An authenticator application")
    begun = browser.call("POST", f"/t/{tenant}/interaction/factors/authenticator-application")
    check(begun.status == 201 and begun.json().get("uri", "").startswith("otpauth://totp/"),
          "the person was given a secret, as text and as the address a QR code shows")
    application = AuthenticatorApplication(begun.json()["secret"])
    confirmed = browser.call("POST", f"/t/{tenant}/interaction/factors/authenticator-application/confirmation",
                             {"code": application.code()})
    codes = confirmed.json().get("recovery_codes", [])
    check(confirmed.status == 200 and len(codes) == 10, "a code confirmed it, and ten recovery codes came with it")
    shown(f"the first recovery code: {codes[0]}")
    listed = browser.call("GET", f"/t/{tenant}/interaction/factors").json()
    check(listed["authenticator_application"]["in_use"] and listed["recovery_codes"]["remaining"] == 10,
          "the person's factors list the application and ten recovery codes")
    return application, codes


def a_step_up(browser, tenant, application, authenticator):
    step("A step-up")
    answer, parameters, verifier = application.authorize(browser, acr_values=MULTI_FACTOR)
    location = answer.headers.get("Location", "")
    check(answer.status in (302, 303) and "/account/sign-in" in location,
          "the application asked for multi-factor: the person is sent to sign in, the session is not enough")
    asked = browser.call("GET", f"/t/{tenant}/interaction/sign-in").json()
    check(asked.get("step") == "totp", "only the code of the application is asked: not the identifier, not the password")
    done = browser.call("POST", f"/t/{tenant}/interaction/sign-in/steps/totp", {"code": authenticator.code()})
    check(completed(done) and done.json().get("continue", "").endswith("/oauth2/authorize/resume"),
          "the code completed the step-up, which goes back to the application's request")
    resumed = browser.call("GET", done.json()["continue"])
    check(resumed.status in (302, 303), "the request went on")
    identity, access = application.tokens(resumed.headers["Location"], parameters, verifier)
    show_levels(identity, "the ID token")
    show_levels(access, "the access token")
    check(set(identity.get("amr", [])) == {"pwd", "otp", "mfa"} and identity.get("acr") == MULTI_FACTOR,
          "the tokens say a password, a one-time code and multi-factor")
    check(access.get("acr") == MULTI_FACTOR and set(access.get("amr", [])) == {"pwd", "otp", "mfa"},
          "the access token says the same")


def a_tenant_that_requires_it(tenant, address, authenticator):
    step("A tenant that requires a second factor")
    said = cli("tenant", "second-factor", "--slug", tenant, "--policy", "required")
    check(said.endswith("second-factor required"), f"{tenant} now requires a second factor")
    browser = Browser()
    answer = browser.sign_in(tenant, address, PASSWORD)
    check(answer.status == 200 and answer.json().get("status") == "pending" and answer.json().get("step") == "totp",
          "the password alone does not complete the sign-in: the code is asked for")
    done = browser.call("POST", f"/t/{tenant}/interaction/sign-in/steps/totp", {"code": authenticator.code()})
    check(completed(done), "the code completed it")
    methods = browser.call("GET", f"/t/{tenant}/interaction/session").json().get("methods")
    check(methods == ["password", "totp"], f"the session holds {methods}")


def a_recovery_code(tenant, address, codes):
    step("A recovery code")
    browser = Browser()
    check(browser.sign_in(tenant, address, PASSWORD).json().get("step") == "totp", "the code is asked for")
    done = browser.call("POST", f"/t/{tenant}/interaction/sign-in/steps/recovery_code", {"code": codes[0].lower()})
    check(completed(done), "a recovery code stood in for it, written in lower case")
    methods = browser.call("GET", f"/t/{tenant}/interaction/session").json().get("methods")
    check(methods == ["password", "recovery_code"], f"the session holds {methods}")
    again = Browser()
    again.sign_in(tenant, address, PASSWORD)
    used = again.call("POST", f"/t/{tenant}/interaction/sign-in/steps/recovery_code", {"code": codes[0]})
    check(rejected(used) and used.json().get("step") == "totp", "the same recovery code is refused the second time")
    listed = browser.call("GET", f"/t/{tenant}/interaction/factors").json()
    check(listed["recovery_codes"]["remaining"] == 9, "nine recovery codes are left")
    return browser


def a_passkey(browser, tenant, application):
    step("A passkey")
    passkey = Passkey(SERVER)
    begun = browser.call("POST", f"/t/{tenant}/interaction/webauthn/registrations", {"passkey": True})
    options = begun.json().get("public_key", {})
    check(begun.status == 201 and options.get("authenticatorSelection", {}).get("residentKey") == "required",
          "registering a passkey asks for a discoverable credential and a verified person")
    finished = browser.call("POST", f"/t/{tenant}/interaction/webauthn/registrations/{begun.json()['registration_id']}",
                            passkey.register(options))
    check(finished.status == 201, f"the passkey is registered as {finished.json().get('name')}")

    alone = Browser()
    started = alone.call("POST", f"/t/{tenant}/interaction/sign-in")
    check(started.json().get("step") == "identifier", "a new sign-in waits for an identifier")
    challenge = alone.call("POST", f"/t/{tenant}/interaction/sign-in/steps/passkey/options").json()["public_key"]
    check(challenge.get("allowCredentials") == [] and challenge.get("userVerification") == "required",
          "the passkey's challenge names no credential and requires a verified person")
    done = alone.call("POST", f"/t/{tenant}/interaction/sign-in/steps/passkey", passkey.answer(challenge))
    check(completed(done), "the passkey alone signed the person in, with no identifier and no password")
    methods = alone.call("GET", f"/t/{tenant}/interaction/session").json().get("methods")
    check(methods == ["passkey"], f"the session holds {methods}, which the tenant's policy accepts")
    answer, parameters, verifier = application.authorize(alone, acr_values=PHISHING_RESISTANT)
    check(answer.status in (302, 303) and answer.headers.get("Location", "").startswith(REDIRECT_URI),
          "asked for the phishing-resistant level, the application gets a code at once")
    identity, _ = application.tokens(answer.headers["Location"], parameters, verifier)
    show_levels(identity, "the ID token")
    check(set(identity.get("amr", [])) == {"pop", "user", "mfa"} and identity.get("acr") == PHISHING_RESISTANT,
          "the tokens say a key held by the person, a verified person, multi-factor, and phishing-resistant")
    return passkey


def tenants_apart(other, passkey):
    step("Tenants apart")
    browser = Browser()
    browser.call("POST", f"/t/{other}/interaction/sign-in")
    challenge = browser.call("POST", f"/t/{other}/interaction/sign-in/steps/passkey/options").json()["public_key"]
    answer = browser.call("POST", f"/t/{other}/interaction/sign-in/steps/passkey", passkey.answer(challenge))
    check(rejected(answer), f"the same passkey is refused by {other}: the credential is unknown there")


def an_administrator(tenant, other, user_id, address):
    step("An administrator removes the person's factors")
    operator = f"operator-{address}"
    said = dict(line.split(" ", 1) for line in
                cli("admin", "bootstrap", "--tenant", tenant, "--email", operator).splitlines())
    check(said.get("role") == "tenant_administrator", f"{operator} is an administrator of {tenant}")
    headers = {"Authorization": f"Bearer {said['token']}"}
    administrator = said["user"].split()[0]
    base = f"{SERVER}/t/{tenant}/api/v1/admin/users/{user_id}/factors"
    factors = request("GET", base, headers=headers).json()
    check(factors["authenticator_application"]["in_use"] and len(factors["keys"]) == 1
          and factors["second_factor_required"],
          "the administrator sees an application, one passkey and the tenant's policy, and no secret")
    there = request("GET", f"{SERVER}/t/{other}/api/v1/admin/users/{user_id}/factors", headers=headers)
    check(there.status == 401 and there.code == "admin.not_authenticated",
          f"the administrator's token is refused by {other}")
    removed = request("DELETE", f"{base}/keys/{factors['keys'][0]['id']}", headers=headers)
    check(removed.status == 204, "the passkey is removed")
    removed = request("DELETE", f"{base}/authenticator-application", headers=headers)
    check(removed.status == 204, "the application is removed, though the tenant requires a second factor")
    factors = request("GET", base, headers=headers).json()
    check(not factors["authenticator_application"]["in_use"] and not factors["keys"]
          and factors["recovery_codes"]["remaining"] == 0,
          "nothing is left, and the recovery codes went with the last second factor")
    failed = Browser()
    answer = failed.sign_in(tenant, address, PASSWORD)
    said = answer.json()
    check(said.get("status") == "pending" and said.get("step") == "enrollment"
          and "__Secure-hodor_session" not in failed.cookies,
          "with no second factor, the password alone no longer signs the person in: the sign-in waits for one to be set up")

    def records():
        items, cursor = [], None
        while True:
            page = request("GET", f"{SERVER}/t/{tenant}/api/v1/admin/audit-records?limit=200"
                           + (f"&cursor={cursor}" if cursor else ""), headers=headers).json()
            items += page.get("items", [])
            cursor = page.get("next_cursor")
            if not cursor or not page.get("items"):
                break
        found = {item["action"]: item for item in items if item["actor"].get("id") == administrator}
        return found if {"credential.webauthn_removed", "credential.totp_removed"} <= found.keys() else None

    found = until("the audit records of the removals", records)
    for action in ("credential.webauthn_removed", "credential.totp_removed"):
        check(action in found, f"the log has {action}, with the administrator as the actor")
    said = cli("audit", "verify", "--tenant", tenant)
    check(said.startswith("intact: "), f"the chain of {tenant} is {said}")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    suffix = format(int(time.time() * 1000), "x")
    tenant, other = f"acme-{suffix}", f"globex-{suffix}"
    address = f"ana-{suffix}@example.com"
    try:
        a_tenant_and_a_person(tenant, other, address)
        application = an_application(tenant)
        browser, user_id = a_password_session(tenant, address, application)
        authenticator, codes = an_authenticator_application(browser, tenant)
        a_step_up(browser, tenant, application, authenticator)
        a_tenant_that_requires_it(tenant, address, authenticator)
        fresh = a_recovery_code(tenant, address, codes)
        passkey = a_passkey(fresh, tenant, application)
        tenants_apart(other, passkey)
        an_administrator(tenant, other, user_id, address)
    except Failed as failure:
        print(f"\nThe demonstration stopped: {failure}", file=sys.stderr)
        sys.exit(1)
    print("\nThe demonstration passed.")


if __name__ == "__main__":
    main()
