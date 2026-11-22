#!/usr/bin/env bash
# The Docker test environment: the development stack as the Compose project
# hodor-test, on ports of its own, seeded with a tenant, a person, an
# administrator and the three development providers.
#
# NOT FOR ANYTHING REAL: every password and key in it is written in the
# repository. See docs/development/test-environments.md.
#
#   deploy/test-environment/docker.sh up | token | status | logs | down | reset | demonstrate

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
compose_file="$root/deploy/docker/compose.yaml"

# A name and ports of its own, so that it never meets the development stack
# or anything else running on the machine.
export COMPOSE_PROJECT_NAME=hodor-test
export HODOR_HTTP_PORT=38080
export HODOR_OPS_PORT=39090
export HODOR_VM_PORT=38428
export HODOR_MAIL_PORT=38025
export HODOR_TRACES_PORT=31428
export HODOR_PROVIDER_PORT=39400
export HODOR_SAML_PROVIDER_PORT=39500

# Where the seeding and the demonstrations find the environment.
export HODOR_URL="http://localhost:$HODOR_HTTP_PORT"
export HODOR_MAIL_URL="http://localhost:$HODOR_MAIL_PORT"
export HODOR_METRICS_URL="http://localhost:$HODOR_VM_PORT"
export HODOR_TRACES_URL="http://localhost:$HODOR_TRACES_PORT"
export HODOR_SAML_PROVIDER_URL="http://localhost:$HODOR_SAML_PROVIDER_PORT"
export HODOR_TEST_PROVIDERS=1

compose() {
  docker compose -f "$compose_file" "$@"
}

seed() {
  python3 -B "$here/seed.py" "$@"
}

usage() {
  echo "usage: $0 up | token | status | logs | down | reset | demonstrate" >&2
  exit 2
}

[ $# -eq 1 ] || usage

case "$1" in
  up)
    compose up --build --wait
    seed
    ;;
  token)
    seed token
    ;;
  status)
    compose ps
    ;;
  logs)
    compose logs --follow server worker
    ;;
  down)
    compose down
    ;;
  reset)
    compose down --volumes
    compose up --build --wait
    seed
    ;;
  demonstrate)
    python3 -B "$root/deploy/demo/demo.py"
    python3 -B "$root/deploy/demo/external_identities.py"
    ;;
  *)
    usage
    ;;
esac
