#!/usr/bin/env python3
"""The demonstration of Milestone 2: signing in with external identities.

Runs against the development stack and does what a person would do in a
browser, through the development providers of the stack: an OpenID Connect
provider, an LDAP directory and a SAML identity provider. Every answer is
checked; the first one that is not what it should be stops the
demonstration with a non-zero exit status.

    docker compose -f deploy/docker/compose.yaml up --build --wait
    python3 deploy/demo/external_identities.py

It needs Python 3 and Docker, and nothing outside the standard library.
See docs/operations/quick-start.md.
"""

import base64
import html
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from demo import (
    CLI_DATABASE_URL,
    compose,
    MAIL,
    SERVER,
    Browser,
    Failed,
    OPENER,
    Answer,
    check,
    link_from_message,
    request,
    shown,
    step,
    until,
)

SAML_PROVIDER = os.environ.get("HODOR_SAML_PROVIDER_URL", "http://localhost:9500")
SAML_CERTIFICATE = Path(__file__).resolve().parent.parent / "dev-saml-provider" / "certificate.pem"
SAML_ENTITY_ID = "urn:hodor:development-saml-provider"

PASSWORD = "correct horse battery staple"
# The one person of the development directory, deploy/dev-directory/people.ldif.
DORA = ("dora", "dora-directory-password")


def cli(*arguments, environment=()):
    """Runs `hodor-cli` in the stack, as an operator would, with extra
    environment variables such as the client secret."""
    extra = [part for name, value in environment for part in ("-e", f"{name}={value}")]
    command = [
        *compose(), "run", "--rm", "--no-deps", "-T",
        "--entrypoint", "/usr/local/bin/hodor-cli",
        "-e", f"HODOR_DATABASE_URL={CLI_DATABASE_URL}", *extra,
        "server", *arguments,
    ]
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise Failed(f"hodor-cli {' '.join(arguments)} failed:\n{done.stdout}{done.stderr}")
    return done.stdout.strip()


def post_form(url, fields, headers=None):
    """Posts a form, as a page of another site makes a browser do."""
    data = urllib.parse.urlencode(fields).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}
    call = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with OPENER.open(call, timeout=30) as response:
            return Answer(response.status, response.headers, response.read())
    except urllib.error.HTTPError as error:
        return Answer(error.code, error.headers, error.read())
    except urllib.error.URLError as error:
        raise Failed(f"{url} could not be reached: {error.reason}") from error


def hidden_fields(page):
    """The hidden fields of the form on a page, and where it is posted."""
    fields = {
        name: html.unescape(value)
        for name, value in re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)">', page)
    }
    action = re.search(r'<form method="post" action="([^"]+)"', page)
    return fields, html.unescape(action.group(1)) if action else None


def query_of(address):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(address).query))


def completed(answer):
    return answer.status == 200 and answer.json().get("status") == "completed"


def rejected(answer):
    return answer.status == 200 and answer.json().get("status") == "rejected"


def leave(browser, tenant, alias):
    """Starts a sign-in and chooses a provider: the address to go to."""
    started = browser.call("POST", f"/t/{tenant}/interaction/sign-in")
    if started.status != 201:
        raise Failed(f"a sign-in could not be started in {tenant}: {started.status}")
    chosen = browser.call("POST", f"/t/{tenant}/interaction/sign-in/providers/{alias}")
    if chosen.status != 200:
        raise Failed(f"{alias} could not be chosen in {tenant}: {chosen.status} {chosen.text}")
    return chosen.json()["redirect"]


def through_openid(browser, tenant, subject, email, vouched=True):
    """A whole sign-in through the development OpenID Connect provider."""
    address = leave(browser, tenant, "development")
    sent = query_of(address)
    authorize = request("GET", address)
    check(authorize.status == 200 and "Development provider" in authorize.text,
          "the browser is at the provider's sign-in page")
    provider = address.split("/authorize", 1)[0]
    decided = post_form(f"{provider}/authorize/decision", {
        **{name: sent[name] for name in ("redirect_uri", "state", "nonce", "code_challenge",
                                          "code_challenge_method")},
        "subject": subject,
        "email": email,
        "email_verified": "true" if vouched else "false",
        "name": "Bia Example",
        "decision": "allow",
    })
    back = decided.headers.get("Location", "")
    answer = query_of(back)
    check(decided.status == 303 and back.startswith(sent["redirect_uri"]) and "code" in answer,
          "the provider sends the browser back to Hodor's page with a code")
    return browser.call("POST", f"/t/{tenant}/interaction/sign-in/providers/development/callback",
                        {"code": answer["code"], "state": answer["state"]})


def through_saml(browser, tenant, subject, email, tamper=None):
    """A whole sign-in through the development SAML identity provider.
    `tamper`, if given, changes the signed response on its way back."""
    address = leave(browser, tenant, "corp")
    sent = query_of(address)
    check(address.startswith(f"{SAML_PROVIDER}/sso?") and "SAMLRequest" in sent and "RelayState" in sent,
          "the browser is sent to the SAML identity provider with a request and a relay state")
    page = request("GET", address)
    fields, _ = hidden_fields(page.text)
    decided = post_form(f"{SAML_PROVIDER}/sso/decision", {
        **fields, "subject": subject, "email": email, "name": "Sam Example", "decision": "allow",
    })
    posted, consumer = hidden_fields(decided.text)
    check(decided.status == 200 and "SAMLResponse" in posted and consumer,
          "the identity provider gives the browser a signed response to post to Hodor")
    response = posted["SAMLResponse"]
    if tamper is not None:
        xml = base64.b64decode(response).decode()
        changed = tamper(xml)
        check(changed != xml, "on its way, the signed response is changed")
        response = base64.b64encode(changed.encode()).decode()
    # The identity provider's page makes the browser post it: from its own
    # site, so no cookie of Hodor's goes with it.
    arrived = post_form(consumer, {"SAMLResponse": response, "RelayState": posted["RelayState"]},
                        headers={"Origin": SAML_PROVIDER})
    back = arrived.headers.get("Location", "")
    carried = query_of(back)
    check(arrived.status == 303 and carried.get("binding") == "saml" and "receipt" in carried,
          "Hodor keeps the response unread and sends the browser to its page with a receipt")
    return browser.call("POST", f"/t/{tenant}/interaction/sign-in/providers/corp/callback",
                        {"state": carried["state"], "receipt": carried["receipt"]})


def who(browser, tenant):
    answer = browser.call("GET", f"/t/{tenant}/interaction/session")
    return answer.json().get("user_id") if answer.status == 200 else None


def a_provider(tenant):
    step("A provider")
    said = cli("tenant", "create", "--slug", tenant, "--name", "Acme", "--open-registration")
    check(said.startswith(f"created {tenant} "), f"the command-line tool created {tenant}")
    said = cli("provider", "add", "--tenant", tenant, "--alias", "development",
               "--name", "Development provider", "--issuer", "http://provider:9400", "--client-id", "hodor",
               environment=[("HODOR_PROVIDER_CLIENT_SECRET", "development-client-secret")])
    check(said.startswith("created development enabled"), "the command-line tool added the OpenID Connect provider")
    shown(said.splitlines()[-1])
    offered = request("GET", f"{SERVER}/t/{tenant}/interaction/sign-in/providers").json().get("providers", [])
    check([provider["alias"] for provider in offered] == ["development"],
          "the sign-in page offers it")


def the_first_sign_in(tenant, subject, email):
    step("The first sign-in")
    browser = Browser()
    answer = through_openid(browser, tenant, subject, email)
    check(completed(answer), f"{email} signed in through the provider and was created")
    user = who(browser, tenant)
    check(user is not None, "the server says who is signed in")
    shown(f"user {user}")
    return user


def the_second_sign_in(tenant, subject, email, user):
    step("The second sign-in")
    browser = Browser()
    answer = through_openid(browser, tenant, subject, email)
    check(completed(answer) and who(browser, tenant) == user, "the same external identity is the same user")


def no_takeover(tenant):
    step("No takeover")
    address = f"ana-{int(time.time() * 1000):x}@example.com"
    asked = request("POST", f"{SERVER}/t/{tenant}/interaction/registration", {"email": address})
    check(asked.status == 202, f"{address} asks to register with a password")
    _, token = link_from_message(address, tenant)
    done = request("POST", f"{SERVER}/t/{tenant}/interaction/registration/complete",
                   {"token": token, "password": PASSWORD})
    check(done.status == 204, f"{address} has an account with a password")
    answer = through_openid(Browser(), tenant, "someone-else", address)
    check(rejected(answer), "someone at the provider with the same address, vouched for, is refused")
    own = Browser().sign_in(tenant, address, PASSWORD)
    check(completed(own), f"{address} still signs in with the password")


def tenants_apart(tenant, other):
    step("Tenants apart")
    said = cli("tenant", "create", "--slug", other, "--name", "Globex")
    check(said.startswith(f"created {other} "), f"a second tenant, {other}")
    offered = request("GET", f"{SERVER}/t/{other}/interaction/sign-in/providers").json().get("providers", [])
    check(offered == [], f"{other} offers no provider")
    browser = Browser()
    browser.call("POST", f"/t/{other}/interaction/sign-in")
    chosen = browser.call("POST", f"/t/{other}/interaction/sign-in/providers/development")
    check(chosen.status == 404 and chosen.code == "federation.provider_not_found",
          f"the provider of {tenant} does not exist in {other}")


def a_directory(tenant):
    step("A directory")
    said = cli("provider", "add", "--tenant", tenant, "--alias", "directory", "--kind", "ldap",
               "--name", "Company directory", "--issuer", "ldap://directory:389",
               "--client-id", "cn=readonly,dc=example,dc=org", "--base", "ou=people,dc=example,dc=org",
               "--filter", "(uid={identifier})", "--trust-email",
               environment=[("HODOR_PROVIDER_CLIENT_SECRET", "readonly-password")])
    check(said.startswith("created directory enabled"), "the command-line tool added the directory")
    browser = Browser()
    browser.call("POST", f"/t/{tenant}/interaction/sign-in")
    wrong = browser.call("POST", f"/t/{tenant}/interaction/sign-in/providers/directory/password",
                         {"identifier": DORA[0], "password": "not her password"})
    check(rejected(wrong), "a wrong password at the directory is refused")
    right = browser.call("POST", f"/t/{tenant}/interaction/sign-in/providers/directory/password",
                         {"identifier": DORA[0], "password": DORA[1]})
    check(completed(right), f"{DORA[0]} signs in through the directory")


def a_saml_identity_provider(tenant):
    step("A SAML identity provider")
    certificate = SAML_CERTIFICATE.read_text()
    said = cli("provider", "add", "--tenant", tenant, "--alias", "corp", "--kind", "saml",
               "--name", "Development SAML provider", "--issuer", SAML_ENTITY_ID,
               "--sign-on-address", f"{SAML_PROVIDER}/sso", "--certificate", certificate, "--trust-email")
    check(said.startswith("created corp enabled"), "the command-line tool added the SAML identity provider")
    metadata = request("GET", f"{SERVER}/t/{tenant}/interaction/sign-in/providers/corp/saml/metadata")
    check(metadata.status == 200 and "entityID=" in metadata.text,
          "Hodor's metadata for it is at its address")
    browser = Browser()
    email = f"sam-{int(time.time() * 1000):x}@example.com"
    answer = through_saml(browser, tenant, f"saml-{email}", email)
    check(completed(answer), f"{email} signed in through the SAML identity provider")
    check(who(browser, tenant) is not None, "the server says who is signed in")


def a_tampered_response(tenant, administrator_email):
    step("A tampered response")
    email = f"mallory-{int(time.time() * 1000):x}@example.com"
    answer = through_saml(
        Browser(), tenant, f"saml-{email}", email,
        tamper=lambda xml: re.sub(r"(<saml:NameID[^>]*>)[^<]*", r"\1somebody-else", xml, count=1),
    )
    check(rejected(answer), "a response whose subject was changed after signing is refused")
    said = dict(line.split(" ", 1)
                for line in cli("admin", "bootstrap", "--tenant", tenant, "--email", administrator_email).splitlines())
    headers = {"Authorization": f"Bearer {said['token']}"}

    def refusal():
        items = request("GET", f"{SERVER}/t/{tenant}/api/v1/admin/audit-records?limit=200",
                        headers=headers).json().get("items", [])
        found = [item for item in items if item["action"] == "federation.sign_in_refused"
                 and item["details"].get("reason") == "digest"]
        return found or None

    found = until("the refusal in the audit log", refusal)
    check(bool(found), "the audit log says why: the digest of what was signed does not match")
    shown(f"{found[-1]['action']} reason {found[-1]['details']['reason']}")


def main():
    suffix = format(int(time.time()), "x")
    tenant, other = f"initech-{suffix}", f"umbrella-{suffix}"
    subject, email = f"subject-{suffix}", f"bia-{suffix}@example.com"

    a_provider(tenant)
    user = the_first_sign_in(tenant, subject, email)
    the_second_sign_in(tenant, subject, email, user)
    no_takeover(tenant)
    tenants_apart(tenant, other)
    a_directory(tenant)
    a_saml_identity_provider(tenant)
    a_tampered_response(tenant, email)

    print("\nThe demonstration passed.\n")
    print(f"   The sign-in page of the tenant   {SERVER}/t/{tenant}/account/sign-in")
    print(f"   The messages that were sent      {MAIL}")


if __name__ == "__main__":
    # Each line is written as it is said, so that a log shows the steps in order.
    sys.stdout.reconfigure(line_buffering=True)
    try:
        main()
    except Failed as failure:
        print(f"\nThe demonstration stopped: {failure}", file=sys.stderr)
        sys.exit(1)
