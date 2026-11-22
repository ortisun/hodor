#!/usr/bin/env bash
# The Kubernetes test environment: a kind cluster named hodor-test, with
# Hodor installed by its Helm chart and the evaluation stand-ins for the
# database and the mail server, forwarded to ports of its own and seeded
# with a tenant, a person and an administrator.
#
# NOT FOR ANYTHING REAL: every password and key in it is written in the
# repository. See docs/development/test-environments.md.
#
#   deploy/test-environment/kubernetes.sh up | upgrade | token | status | down | delete

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
state="$here/.local/kubernetes"

cluster=hodor-test
context="kind-$cluster"
namespace=hodor
http_port=48080
mail_port=48025

export HODOR_URL="http://localhost:$http_port"
export HODOR_MAIL_URL="http://localhost:$mail_port"
export HODOR_TEST_KUBERNETES_CONTEXT="$context"

k() {
  kubectl --context "$context" --namespace "$namespace" "$@"
}

seed() {
  python3 -B "$here/seed.py" "$@"
}

usage() {
  echo "usage: $0 up | upgrade | token | status | down | delete" >&2
  exit 2
}

# Builds the image from the checkout under a tag of its own, and loads it
# into the cluster, which pulls nothing.
build_and_load() {
  local tag="test-$(date +%s)"
  docker build --file "$root/deploy/docker/Dockerfile" --tag "hodor:$tag" "$root" >&2
  kind load docker-image "hodor:$tag" --name "$cluster" >&2
  echo "$tag"
}

install() {
  local tag="$1"
  helm upgrade --install hodor "$root/deploy/install/helm/hodor" \
    --kube-context "$context" --namespace "$namespace" \
    --set image.repository=hodor --set image.tag="$tag" \
    --set publicUrl="$HODOR_URL" \
    --set secret.name=hodor-evaluation \
    --set mail.enabled=true --set mail.from="Hodor <no-reply@hodor.localhost>" \
    --wait --timeout 10m
}

stop_forwarding() {
  for pid_file in "$state"/*.pid; do
    [ -e "$pid_file" ] || continue
    kill "$(cat "$pid_file")" 2>/dev/null || true
    rm -f "$pid_file"
  done
}

# Forwards one port of the cluster in the background, unless it already is.
forward() {
  local name="$1" target="$2" ports="$3"
  local pid_file="$state/$name.pid"
  if [ -e "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
    return
  fi
  mkdir -p "$state"
  k port-forward "$target" "$ports" >"$state/$name.log" 2>&1 &
  echo $! >"$pid_file"
}

# Waits until Hodor answers through the forwarded port.
wait_for_hodor() {
  for _ in $(seq 1 60); do
    if curl --silent --output /dev/null "$HODOR_URL/t/system/account/sign-in"; then
      return
    fi
    sleep 1
  done
  echo "Hodor did not answer at $HODOR_URL; see $state/hodor.log" >&2
  exit 1
}

[ $# -eq 1 ] || usage

case "$1" in
  up)
    if ! kind get clusters 2>/dev/null | grep --quiet --line-regexp "$cluster"; then
      kind create cluster --name "$cluster"
    fi
    kubectl --context "$context" create namespace "$namespace" --dry-run=client --output yaml \
      | kubectl --context "$context" apply --filename -
    k apply --filename "$root/deploy/install/helm/evaluation.yaml"
    k rollout status statefulset/hodor-evaluation-database --timeout 5m
    if ! helm status hodor --kube-context "$context" --namespace "$namespace" >/dev/null 2>&1; then
      install "$(build_and_load)"
    fi
    forward hodor service/hodor "$http_port:8080"
    forward mail service/hodor-evaluation-mail "$mail_port:8025"
    wait_for_hodor
    seed
    ;;
  upgrade)
    install "$(build_and_load)"
    # The pods behind the services changed: forward again.
    stop_forwarding
    forward hodor service/hodor "$http_port:8080"
    forward mail service/hodor-evaluation-mail "$mail_port:8025"
    wait_for_hodor
    ;;
  token)
    seed token
    ;;
  status)
    k get pods
    helm status hodor --kube-context "$context" --namespace "$namespace"
    ;;
  down)
    stop_forwarding
    ;;
  delete)
    stop_forwarding
    kind delete cluster --name "$cluster"
    ;;
  *)
    usage
    ;;
esac
