#!/usr/bin/env python3
"""The demonstration of Milestone 1.

Runs against the development stack and shows, step by step, that a person
registers, verifies an address and signs in to a tenant, and that tenants
are kept apart. Every answer is checked; the first one that is not what it
should be stops the demonstration with a non-zero exit status.

    docker compose -f deploy/docker/compose.yaml up --build --wait
    python3 deploy/demo/demo.py

It needs Python 3 and Docker, and nothing outside the standard library.
See docs/operations/quick-start.md.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SERVER = os.environ.get("HODOR_URL", "http://localhost:8080")
MAIL = os.environ.get("HODOR_MAIL_URL", "http://localhost:8025")
METRICS = os.environ.get("HODOR_METRICS_URL", "http://localhost:8428")
TRACES = os.environ.get("HODOR_TRACES_URL", "http://localhost:10428")

COMPOSE_FILE = Path(__file__).resolve().parent.parent / "docker" / "compose.yaml"
# The command-line tool connects as the server does. These are the
# placeholder credentials of the development stack.
CLI_DATABASE_URL = "postgres://hodor_server:dev-server@postgres:5432/hodor"

PASSWORD_AT_FIRST = "correct horse battery staple"
PASSWORD_AT_SECOND = "an entirely different passphrase"


class Failed(Exception):
    """A step did not go as it should."""


def step(title):
    print(f"\n== {title}")


def shown(text):
    print(f"   {text}")


def check(condition, what):
    """States a fact the demonstration relies on, and stops if it is not one."""
    if not condition:
        raise Failed(what)
    print(f"   ok  {what}")


class Answer:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.text = body.decode("utf-8", errors="replace")

    def json(self):
        try:
            return json.loads(self.text)
        except ValueError:
            return {}

    @property
    def code(self):
        """The `code` of a problem document, if the answer is one."""
        return self.json().get("code")


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


OPENER = urllib.request.build_opener(NoRedirects)


def request(method, url, body=None, headers=None):
    data = None
    headers = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    call = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with OPENER.open(call, timeout=30) as response:
            return Answer(response.status, response.headers, response.read())
    except urllib.error.HTTPError as error:
        return Answer(error.code, error.headers, error.read())
    except urllib.error.URLError as error:
        raise Failed(f"{url} could not be reached: {error.reason}") from error


class Browser:
    """A browser, as far as the demonstration needs one.

    It keeps the cookies the server sets and sends them back to whatever
    path it is asked to call. A real browser would not send one tenant's
    cookie to another; the demonstration does so on purpose.
    """

    def __init__(self):
        self.cookies = {}
        self.csrf_token = None

    def call(self, method, path, body=None):
        headers = {}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies.items())
        if self.csrf_token and method != "GET":
            headers["X-CSRF-Token"] = self.csrf_token
        answer = request(method, SERVER + path, body, headers)
        for cookie in answer.headers.get_all("Set-Cookie") or []:
            name, _, value = cookie.split(";")[0].partition("=")
            if "Max-Age=0" in cookie:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value
        token = answer.json().get("csrf_token") if answer.text else None
        if token:
            self.csrf_token = token
        return answer

    def sign_in(self, tenant, identifier, password):
        """One sign-in from start to the answer to the password."""
        base = f"/t/{tenant}/interaction/sign-in"
        started = self.call("POST", base)
        if started.status != 201:
            return started
        named = self.call("POST", f"{base}/steps/identifier", {"identifier": identifier})
        if named.status != 200:
            return named
        return self.call("POST", f"{base}/steps/password", {"password": password})


def cli(*arguments):
    """Runs `hodor-cli` in the stack, as an operator would."""
    command = [
        "docker", "compose", "-f", str(COMPOSE_FILE), "run", "--rm", "--no-deps", "-T",
        "--entrypoint", "/usr/local/bin/hodor-cli",
        "-e", f"HODOR_DATABASE_URL={CLI_DATABASE_URL}",
        "server", *arguments,
    ]
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise Failed(f"hodor-cli {' '.join(arguments)} failed:\n{done.stdout}{done.stderr}")
    return done.stdout.strip()


def until(what, attempt, seconds=60):
    """Waits for something that arrives a little later, such as a message."""
    deadline = time.monotonic() + seconds
    while True:
        found = attempt()
        if found:
            return found
        if time.monotonic() > deadline:
            raise Failed(f"{what} did not arrive within {seconds} seconds")
        time.sleep(1)


def link_from_message(address, tenant):
    """Reads the mailbox of `address` and returns the link made for `tenant`."""

    def look():
        query = urllib.parse.quote(f'to:"{address}"')
        found = request("GET", f"{MAIL}/api/v1/search?query={query}").json()
        for summary in found.get("messages", []):
            text = request("GET", f"{MAIL}/api/v1/message/{summary['ID']}").json().get("Text", "")
            match = re.search(r"https?://\S+/t/" + re.escape(tenant) + r"/account/\S+#token=([0-9a-f]+)", text)
            if match:
                return match.group(0), match.group(1)
        return None

    return until(f"the message to {address} for {tenant}", look)


def the_stack_answers():
    step("The stack")
    for name, url in [
        ("Hodor", f"{SERVER}/t/system/account/sign-in"),
        ("the mail server", f"{MAIL}/api/v1/info"),
        ("VictoriaMetrics", f"{METRICS}/health"),
        ("VictoriaTraces", f"{TRACES}/health"),
    ]:
        check(request("GET", url).status == 200, f"{name} answers at {url}")


def two_tenants(first, second):
    step("Two tenants")
    for slug, name in [(first, "Acme"), (second, "Globex")]:
        said = cli("tenant", "create", "--slug", slug, "--name", name, "--open-registration")
        check(said.startswith(f"created {slug} "), f"the command-line tool created {slug}")


def the_same_person_in_both(first, second, address):
    step("The same person in both")
    tokens = {}
    for tenant in (first, second):
        asked = request("POST", f"{SERVER}/t/{tenant}/interaction/registration", {"email": address})
        check(asked.status == 202, f"{tenant} accepted the request to register {address}")
    for tenant in (first, second):
        link, tokens[tenant] = link_from_message(address, tenant)
        shown(f"link for {tenant}: {link[:link.index('#token=') + 15]}…")
    check(tokens[first] != tokens[second], "each tenant sent its own link")
    return tokens


def the_link(first, second, tokens):
    step("The link")
    complete = "/interaction/registration/complete"
    crossed = request("POST", f"{SERVER}/t/{second}{complete}",
                      {"token": tokens[first], "password": PASSWORD_AT_SECOND})
    check(crossed.status == 404 and crossed.code == "authentication.verification_token_invalid",
          f"the link of {first} is refused by {second}")
    for tenant, password in [(first, PASSWORD_AT_FIRST), (second, PASSWORD_AT_SECOND)]:
        done = request("POST", f"{SERVER}/t/{tenant}{complete}", {"token": tokens[tenant], "password": password})
        check(done.status == 204, f"the link of {tenant} finished the registration there")
    again = request("POST", f"{SERVER}/t/{first}{complete}",
                    {"token": tokens[first], "password": PASSWORD_AT_FIRST})
    check(again.status == 404, "a link that was used does not work a second time")


def signing_in(first, address):
    step("Signing in")
    browser = Browser()
    answer = browser.sign_in(first, address, PASSWORD_AT_FIRST)
    check(answer.status == 200 and answer.json().get("status") == "completed",
          f"{address} signed in to {first}")
    check("__Secure-hodor_session" in browser.cookies, "the browser was given a session cookie")
    session = browser.call("GET", f"/t/{first}/interaction/session")
    check(session.status == 200, "the server says who is signed in")
    shown(f"user {session.json()['user_id']}, signed in with {', '.join(session.json()['methods'])}")
    listed = browser.call("GET", f"/t/{first}/interaction/sessions").json().get("sessions", [])
    check(len(listed) == 1 and listed[0]["current"], "the person has one session, this one")
    return browser, session.json()["user_id"]


def the_pages(first):
    step("The pages")
    page = request("GET", f"{SERVER}/t/{first}/account/sign-in")
    policy = page.headers.get("Content-Security-Policy", "")
    check(page.status == 200 and "<div id=\"root\">" in page.text, "the sign-in page is served")
    check("script-src 'self'" in policy and "require-trusted-types-for 'script'" in policy,
          "with a Content Security Policy that keeps everything else out")
    shown(f"open {SERVER}/t/{first}/account/sign-in in a browser to see it")


def tenants_apart_session(browser, first, second):
    step("Tenants apart: the session")
    here = browser.call("GET", f"/t/{first}/interaction/session")
    there = browser.call("GET", f"/t/{second}/interaction/session")
    check(here.status == 200, f"the session cookie works in {first}")
    check(there.status == 401 and there.code == "session.not_authenticated",
          f"the same cookie is refused by {second}")


def tenants_apart_password(first, second, address):
    step("Tenants apart: the password")
    answer = Browser().sign_in(second, address, PASSWORD_AT_FIRST)
    check(answer.status == 200 and answer.json().get("status") == "rejected",
          f"the password of {first} does not sign in to {second}")
    return 1


def lockout(first, second, address, failures_so_far):
    step("Lockout")
    for attempt in range(failures_so_far + 1, 6):
        answer = Browser().sign_in(second, address, "a wrong guess")
        check(answer.status == 200 and answer.json().get("status") == "rejected",
              f"wrong password number {attempt} in {second} is rejected")
    locked = Browser().sign_in(second, address, PASSWORD_AT_SECOND)
    check(locked.status == 429 and locked.code == "authentication.too_many_attempts",
          f"after five, even the right password is refused in {second}")
    shown(f"the server says to wait {locked.headers.get('Retry-After')} seconds")
    free = Browser().sign_in(first, address, PASSWORD_AT_FIRST)
    check(free.status == 200 and free.json().get("status") == "completed",
          f"the same address still signs in to {first}")


def an_administrator(first, address, user_id):
    step("An administrator")
    said = dict(line.split(" ", 1) for line in cli("admin", "bootstrap", "--tenant", first, "--email", address).splitlines())
    check(said.get("role") == "tenant_administrator" and said.get("user", "").startswith(user_id),
          f"the command-line tool made {address} an administrator of {first}")
    token = said["token"]
    shown(f"token {token[:17]}…, good until {said.get('expires')}")
    users = request("GET", f"{SERVER}/t/{first}/api/v1/admin/users", headers={"Authorization": f"Bearer {token}"})
    check(users.status == 200 and len(users.json().get("items", [])) == 1,
          f"the token lists the users of {first}: one")
    nobody = request("GET", f"{SERVER}/t/{first}/api/v1/admin/users")
    check(nobody.status == 401, "without a token the list is refused")
    return token


def tenants_apart_token(second, token):
    step("Tenants apart: the token")
    for path in ("users", "audit-records"):
        there = request("GET", f"{SERVER}/t/{second}/api/v1/admin/{path}", headers={"Authorization": f"Bearer {token}"})
        check(there.status == 401 and there.code == "admin.not_authenticated",
              f"the administrator's token is refused by {second} for {path}")


def the_audit_log(first, second, token):
    step("The audit log")
    headers = {"Authorization": f"Bearer {token}"}

    def records():
        answer = request("GET", f"{SERVER}/t/{first}/api/v1/admin/audit-records?limit=200", headers=headers)
        items = answer.json().get("items", [])
        actions = [item["action"] for item in items]
        # The worker writes the log shortly after each change.
        return items if "authentication.succeeded" in actions and "credential.access_token_issued" in actions else None

    items = until("the audit records of the sign-in", records)
    for item in items:
        actor = item["actor"]
        shown(f"{item['sequence']:>3}  {item['action']:<42} by {actor['kind']} {actor.get('id', '')}")
    actions = [item["action"] for item in items]
    for action in ("identity.user_created", "authentication.registration_completed",
                   "session.started", "authentication.succeeded"):
        check(action in actions, f"the log of {first} has {action}")
    check("authentication.locked_out" not in actions,
          f"the lockout in {second} is not in the log of {first}")
    said = cli("audit", "verify", "--tenant", first)
    check(said.startswith("intact: "), f"the chain of {first} is {said}")


def metrics():
    step("Metrics")

    def arrived():
        query = urllib.parse.quote('{__name__=~"hodor.*"}')
        series = request("GET", f"{METRICS}/api/v1/series?match[]={query}").json().get("data", [])
        return sorted({entry["__name__"] for entry in series})

    names = until("the metrics", arrived, seconds=120)
    for name in names:
        shown(name)
    check(any("outbox" in name for name in names), "the worker's metrics arrived in VictoriaMetrics")


def a_trace(first):
    step("A trace")
    wanted = f"/t/{first}/interaction/sign-in/steps/password"

    def arrived():
        query = urllib.parse.urlencode({"service": "hodor-server", "limit": "200", "lookback": "1h"})
        traces = request("GET", f"{TRACES}/select/jaeger/api/traces?{query}").json().get("data") or []
        for trace in traces:
            for span in trace.get("spans", []):
                if any(tag.get("value") == wanted for tag in span.get("tags", [])):
                    return trace
        return None

    trace = until("the trace of the sign-in", arrived, seconds=120)
    spans = trace["spans"]
    check(len(spans) >= 1, f"the trace of the sign-in arrived in VictoriaTraces: {len(spans)} spans")
    for span in sorted(spans, key=lambda span: span["startTime"])[:12]:
        shown(f"{span['duration'] / 1000:>9.2f} ms  {span['operationName']}")
    shown(f"trace {trace['traceID']}")


def main():
    suffix = format(int(time.time()), "x")
    first, second = f"acme-{suffix}", f"globex-{suffix}"
    address = f"ana-{suffix}@example.com"

    the_stack_answers()
    two_tenants(first, second)
    tokens = the_same_person_in_both(first, second, address)
    the_link(first, second, tokens)
    browser, user_id = signing_in(first, address)
    the_pages(first)
    tenants_apart_session(browser, first, second)
    failures = tenants_apart_password(first, second, address)
    lockout(first, second, address, failures)
    token = an_administrator(first, address, user_id)
    tenants_apart_token(second, token)
    the_audit_log(first, second, token)
    metrics()
    a_trace(first)

    print("\nThe demonstration passed.\n")
    print(f"   The pages of the first tenant   {SERVER}/t/{first}/account")
    print(f"   The messages that were sent     {MAIL}")
    print(f"   Metrics                         {METRICS}/vmui")
    print(f"   Traces                          {TRACES}/select/vmui")
    print(f"\n   {address} signs in to {first} with the password: {PASSWORD_AT_FIRST}")


if __name__ == "__main__":
    # Each line is written as it is said, so that a log shows the steps in order.
    sys.stdout.reconfigure(line_buffering=True)
    try:
        main()
    except Failed as failure:
        print(f"\nThe demonstration stopped: {failure}", file=sys.stderr)
        sys.exit(1)
