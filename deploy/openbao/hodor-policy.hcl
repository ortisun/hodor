# Hodor's policy in OpenBao: make signing keys, read their public keys and sign with them, on Hodor's own
# Transit mount, and nothing else. Nothing here reads, exports or backs up a key, changes a key's settings,
# rotates or deletes a key, encrypts or decrypts, or reaches any other path.
#
# The mount is `hodor-transit`. An installation that mounts Transit elsewhere replaces `hodor-transit` below
# with its mount, the value of HODOR_OPENBAO_TRANSIT_MOUNT. See docs/operations/keys-in-openbao.md.

# Make a key, and read what OpenBao says of it: its type, its settings and its public key. A key is made with
# its type alone, so it is never exportable and has no plaintext backup. `+` is one segment of the path, so
# `keys/<name>/config`, `keys/<name>/rotate` and the other paths under a key are not reached.
path "hodor-transit/keys/+" {
  capabilities = ["update", "read"]
  allowed_parameters = {
    "type" = ["ecdsa-p256", "rsa-2048"]
  }
}

# Sign with a key.
path "hodor-transit/sign/+" {
  capabilities = ["update"]
}
