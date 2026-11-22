#!/usr/bin/env python3
"""Seeds a test environment: a tenant, a person with a password, an
administrator, and, in the Docker environment, the three development
identity providers.

NOT FOR ANYTHING REAL: every password used here is written in the
repository. Run by deploy/test-environment/docker.sh and kubernetes.sh;
see docs/development/test-environments.md.

It does what a person and an operator would do, through the same doors,
checks every answer, and skips what already exists, so that it can run
again and again.

    python3 deploy/test-environment/seed.py          seed, then print a token
    python3 deploy/test-environment/seed.py token    print a new token only

Where the environment is comes from the environment: HODOR_URL and
HODOR_MAIL_URL; HODOR_TEST_PROVIDERS=1 to add the development providers;
HODOR_TEST_KUBERNETES_CONTEXT to run the command-line tool in the
Kubernetes environment's server pod instead of through Compose.
"""

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "demo"))

from demo import (  # noqa: E402
    CLI_DATABASE_URL,
    COMPOSE_FILE,
    SERVER,
    Browser,
    Failed,
    check,
    link_from_message,
    request,
    shown,
    step,
)

TENANT = os.environ.get("HODOR_TEST_TENANT", "test")
PERSON = "tester@example.com"
PASSWORD = "test-environment-password"
WITH_PROVIDERS = os.environ.get("HODOR_TEST_PROVIDERS") == "1"
KUBERNETES_CONTEXT = os.environ.get("HODOR_TEST_KUBERNETES_CONTEXT")
SAML_PROVIDER = os.environ.get("HODOR_SAML_PROVIDER_URL", "http://localhost:9500")
SAML_CERTIFICATE = Path(__file__).resolve().parent.parent / "dev-saml-provider" / "certificate.pem"


def cli(*arguments, environment=()):
    """Runs `hodor-cli` where the environment runs Hodor."""
    if KUBERNETES_CONTEXT:
        # The server's pod has the database and the keys in its environment.
        if environment:
            raise Failed("the Kubernetes environment has no development providers to add")
        command = [
            "kubectl", "--context", KUBERNETES_CONTEXT, "--namespace", "hodor",
            "exec", "deployment/hodor-server", "--", "/usr/local/bin/hodor-cli", *arguments,
        ]
    else:
        extra = [part for name, value in environment for part in ("-e", f"{name}={value}")]
        command = [
            "docker", "compose", "-f", str(COMPOSE_FILE), "run", "--rm", "--no-deps", "-T",
            "--entrypoint", "/usr/local/bin/hodor-cli",
            "-e", f"HODOR_DATABASE_URL={CLI_DATABASE_URL}", *extra,
            "server", *arguments,
        ]
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise Failed(f"hodor-cli {' '.join(arguments[:3])} … failed:\n{done.stdout}{done.stderr}")
    return done.stdout.strip()


def the_tenant():
    step(f"The tenant {TENANT}")
    if request("GET", f"{SERVER}/t/{TENANT}/account/sign-in").status == 200:
        shown("it is there already")
        return
    said = cli("tenant", "create", "--slug", TENANT, "--name", "Test", "--open-registration")
    check(said.startswith(f"created {TENANT} "), f"the command-line tool created {TENANT}")


def the_providers():
    step("The development identity providers")
    listed = cli("provider", "list", "--tenant", TENANT)
    present = {line.split(" ", 1)[0] for line in listed.splitlines() if line}
    wanted = [
        ("development", [
            "--name", "Development provider", "--issuer", "http://provider:9400", "--client-id", "hodor",
        ], [("HODOR_PROVIDER_CLIENT_SECRET", "development-client-secret")]),
        ("directory", [
            "--kind", "ldap", "--name", "Company directory", "--issuer", "ldap://directory:389",
            "--client-id", "cn=readonly,dc=example,dc=org", "--base", "ou=people,dc=example,dc=org",
            "--filter", "(uid={identifier})", "--trust-email",
        ], [("HODOR_PROVIDER_CLIENT_SECRET", "readonly-password")]),
        ("corp", [
            "--kind", "saml", "--name", "Development SAML provider",
            "--issuer", "urn:hodor:development-saml-provider",
            "--sign-on-address", f"{SAML_PROVIDER}/sso",
            "--certificate", SAML_CERTIFICATE.read_text(), "--trust-email",
        ], []),
    ]
    for alias, arguments, environment in wanted:
        if alias in present:
            shown(f"{alias} is there already")
            continue
        said = cli("provider", "add", "--tenant", TENANT, "--alias", alias, *arguments, environment=environment)
        check(said.startswith(f"created {alias} enabled"), f"the command-line tool added {alias}")


def the_person():
    step(f"The person {PERSON}")
    if Browser().sign_in(TENANT, PERSON, PASSWORD).json().get("status") == "completed":
        shown("they are there already, and sign in with their password")
        return
    asked = request("POST", f"{SERVER}/t/{TENANT}/interaction/registration", {"email": PERSON})
    check(asked.status == 202, f"{PERSON} asked to register")
    _, token = link_from_message(PERSON, TENANT)
    done = request("POST", f"{SERVER}/t/{TENANT}/interaction/registration/complete",
                   {"token": token, "password": PASSWORD, "display_name": "Test Person"})
    check(done.status == 204, f"{PERSON} chose a password")
    signed_in = Browser().sign_in(TENANT, PERSON, PASSWORD)
    check(signed_in.json().get("status") == "completed", f"{PERSON} signs in with it")


def a_token():
    said = dict(line.split(" ", 1)
                for line in cli("admin", "bootstrap", "--tenant", TENANT, "--email", PERSON).splitlines())
    check(said.get("role") == "tenant_administrator", f"{PERSON} is an administrator of {TENANT}")
    return said["token"], said.get("expires", "")


def main():
    if sys.argv[1:] == ["token"]:
        token, expires = a_token()
        print(f"\n{token}\n\ngood until {expires}")
        return
    the_tenant()
    if WITH_PROVIDERS:
        the_providers()
    the_person()
    step("The administrator")
    token, expires = a_token()

    print("\nThe test environment is ready.\n")
    print(f"   The pages of the tenant          {SERVER}/t/{TENANT}/account")
    print(f"   A person with a password         {PERSON} / {PASSWORD}")
    print(f"   The administration interface     {SERVER}/t/{TENANT}/api/v1/admin/")
    print(f"   An administrator's token         {token}")
    print(f"                                    good until {expires}")


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    try:
        main()
    except Failed as failure:
        print(f"\nThe seeding stopped: {failure}", file=sys.stderr)
        sys.exit(1)
