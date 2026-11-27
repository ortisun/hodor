#!/bin/sh
# Prepares the OpenBao of the development stack for Hodor, as an operator would prepare their own
# (docs/operations/keys-in-openbao.md): Transit mounted at hodor-transit, Hodor's policy, and an AppRole that
# gives it. The role and secret identifiers are fixed placeholders, like every credential of the stack; never
# use them anywhere real. Running it again changes nothing.
set -eu

until bao status > /dev/null 2>&1; do sleep 1; done

bao secrets list | grep -q '^hodor-transit/' || bao secrets enable -path=hodor-transit transit
bao policy write hodor /openbao-setup/hodor-policy.hcl
bao auth list | grep -q '^approle/' || bao auth enable approle
bao write auth/approle/role/hodor token_policies=hodor token_ttl=1h token_max_ttl=4h \
  secret_id_ttl=0 secret_id_num_uses=0
bao write auth/approle/role/hodor/role-id role_id=development-hodor-role
bao list auth/approle/role/hodor/secret-id 2> /dev/null | grep -q . ||
  bao write auth/approle/role/hodor/custom-secret-id secret_id=development-hodor-secret
echo "OpenBao is ready for Hodor"
