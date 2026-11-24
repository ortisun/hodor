#!/usr/bin/env python3
"""The demonstration of Milestone 6.

Runs against the development stack, through `edge`, the web server in front
of it, and shows that each client behind a load balancer has a limit of its
own, that a forged address does not help, and that the worker removes what
stopped being useful without touching the audit log.

    docker compose -f deploy/docker/compose.yaml up --build --wait
    python3 deploy/demo/operations.py

It needs Python 3 and Docker, and nothing outside the standard library.
See docs/operations/quick-start.md.
"""

import os
import secrets
import subprocess
import sys
import urllib.parse

from demo import (
    METRICS,
    SERVER,
    Browser,
    Failed,
    check,
    cli,
    compose,
    link_from_message,
    request,
    shown,
    step,
    until,
)

EDGE = os.environ.get("HODOR_EDGE_URL", "http://localhost:8081")
# The worker's platform role sees every tenant: the script counts rows with
# it, as an operator would. A placeholder credential of the stack.
PLATFORM_DATABASE_URL = "postgres://hodor_worker_platform:dev-worker@postgres:5432/hodor"
PASSWORD = "a password for the demonstration of milestone six"
CLEANUP_WORKER = "hodor-demonstration-cleanup"


def through_edge(client, path, body):
    """A request a load balancer passes on for `client`: it names the client
    in `X-Forwarded-For`, and `edge` adds the address it received it from."""
    return request("POST", EDGE + path, body, {"X-Forwarded-For": client})


def count(query):
    """Runs a query that counts rows, in the database of the stack."""
    done = subprocess.run(
        [*compose(), "exec", "-T", "postgres", "psql", PLATFORM_DATABASE_URL, "-At", "-c", query],
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        raise Failed(f"the query could not be run:\n{done.stderr}")
    return int(done.stdout.strip() or 0)


def a_tenant(slug):
    step("A tenant behind a web server")
    said = cli("tenant", "create", "--slug", slug, "--name", "Initech", "--open-registration")
    check(said.startswith(f"created {slug} "), f"the command-line tool created {slug}")
    found = request("GET", f"{EDGE}/t/{slug}/account/sign-in")
    check(found.status == 200, f"{slug} answers through the web server at {EDGE}")
    return said.split()[2]


def ask(slug, client, number):
    return through_edge(client, f"/t/{slug}/interaction/registration", {"email": f"person{number}@{slug}.example"})


def a_limit_per_client(slug):
    step("Each client has a limit of its own")
    asked = 0
    while True:
        asked += 1
        if asked > 200:
            raise Failed("the client was never limited")
        answer = ask(slug, "203.0.113.7", asked)
        if answer.status == 429:
            break
        if answer.status != 202:
            raise Failed(f"asking to register was answered {answer.status}: {answer.text}")
    check(answer.code == "authentication.too_many_attempts",
          f"the client at 203.0.113.7 is limited after {asked - 1} requests")
    shown(f"the server says to wait {answer.headers.get('Retry-After')} seconds")
    other = ask(slug, "203.0.113.8", asked + 1)
    check(other.status == 202, "a client at 203.0.113.8, behind the same web server, is still answered")
    direct = request("POST", f"{SERVER}/t/{slug}/interaction/registration",
                     {"email": f"direct@{slug}.example"})
    check(direct.status == 202, "and so is this machine, straight to the server")
    return asked + 2


def a_forged_address(slug, asked):
    step("A forged address does not help")
    forged = ask(slug, "198.51.100.1, 203.0.113.7", asked)
    check(forged.status == 429,
          "203.0.113.7, writing 198.51.100.1 at the start of its header, is still limited")


def a_person_signs_out(slug):
    step("A person signs in and out")
    address = f"ana@{slug}.example"
    asked = request("POST", f"{SERVER}/t/{slug}/interaction/registration", {"email": address})
    check(asked.status == 202, f"{slug} accepted the request to register {address}")
    _, token = link_from_message(address, slug)
    done = request("POST", f"{SERVER}/t/{slug}/interaction/registration/complete",
                   {"token": token, "password": PASSWORD})
    check(done.status == 204, "the link finished the registration")
    browser = Browser()
    signed_in = browser.sign_in(slug, address, PASSWORD)
    check(signed_in.json().get("status") == "completed", f"{address} signed in")
    # The session's own CSRF token, which the requests that change it carry.
    browser.call("GET", f"/t/{slug}/interaction/session")
    out = browser.call("DELETE", f"/t/{slug}/interaction/session")
    check(out.status == 204, f"{address} signed out, and the session ended")


def the_cleanup(slug, tenant_id):
    step("What stopped being useful is removed")
    in_tenant = f"tenant_id = '{tenant_id}'"
    until("every message of the tenant to be delivered",
          lambda: count(f"SELECT count(*) FROM notification.message WHERE {in_tenant} AND status = 'pending'") == 0)
    sessions = count(f"SELECT count(*) FROM session.session WHERE {in_tenant} AND revoked_at IS NOT NULL")
    messages = count(f"SELECT count(*) FROM notification.message WHERE {in_tenant}")
    check(sessions == 1 and messages > 0,
          f"{slug} holds {sessions} ended session and {messages} delivered messages")

    subprocess.run(["docker", "rm", "-f", CLEANUP_WORKER], capture_output=True, check=False)
    started = subprocess.run(
        [*compose(), "run", "-d", "--no-deps", "--name", CLEANUP_WORKER,
         "-e", "HODOR_CLEANUP_RETENTION_DAYS=sessions=0,messages=0",
         "-e", "HODOR_CLEANUP_INTERVAL_MS=1000",
         "worker"],
        capture_output=True, text=True, check=False,
    )
    if started.returncode != 0:
        raise Failed(f"the second worker did not start:\n{started.stderr}")
    shown("a second worker keeps ended sessions and delivered messages for 0 days")
    try:
        until("the ended session to be removed",
              lambda: count(f"SELECT count(*) FROM session.session WHERE {in_tenant}") == 0)
        check(True, "the ended session is gone")
        until("the delivered messages to be removed",
              lambda: count(f"SELECT count(*) FROM notification.message WHERE {in_tenant}") == 0)
        check(True, "the delivered messages are gone")

        # The second worker sends its metrics now and then: it is stopped
        # only once they arrived.
        def removed_sessions():
            query = urllib.parse.quote('max({__name__="hodor.cleanup.removed",job="sessions"})')
            found = request("GET", f"{METRICS}/api/v1/query?query={query}").json()
            results = found.get("data", {}).get("result", [])
            return results and float(results[0]["value"][1]) > 0

        until("the metric of the cleanup", removed_sessions, seconds=120)
        check(True, "VictoriaMetrics counts the sessions the worker removed, under hodor.cleanup.removed")
    finally:
        subprocess.run(["docker", "rm", "-f", CLEANUP_WORKER], capture_output=True, check=False)

    left = count(f"SELECT count(*) FROM audit.record WHERE {in_tenant}")
    check(left > 0, f"the audit log of {slug} keeps its {left} records")
    said = cli("audit", "verify", "--tenant", slug)
    check(said.startswith("intact: "), f"the chain of {slug} is {said}")


def main():
    slug = f"initech-{secrets.token_hex(3)}"
    try:
        tenant_id = a_tenant(slug)
        asked = a_limit_per_client(slug)
        a_forged_address(slug, asked)
        a_person_signs_out(slug)
        the_cleanup(slug, tenant_id)
    except Failed as failure:
        print(f"\nThe demonstration of Milestone 6 failed: {failure}", file=sys.stderr)
        return 1
    print("\nThe demonstration of Milestone 6 passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
