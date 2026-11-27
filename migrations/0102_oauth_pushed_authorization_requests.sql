-- Pushed authorization requests (RFC 9126): a request a client pushes is
-- kept as a pending authorization request, found by the SHA-256 of its
-- reference instead of the hash of a browser's secret, and a client may be
-- required to push every request.
-- See docs/architecture/contexts/oauth.md, "Pushed authorization requests".

-- Whether every request of the client must be pushed first; false for every
-- client made before it.
ALTER TABLE oauth.client
    ADD COLUMN require_pushed_authorization_requests boolean NOT NULL DEFAULT false;

-- A pending request is bound to a browser by the hash of its secret, or,
-- pushed and waiting for its browser, found by the hash of its reference:
-- exactly one of the two. The reference itself is stored nowhere. A pushed
-- request lives ten minutes at most.
ALTER TABLE oauth.authorization_request
    ALTER COLUMN secret_hash DROP NOT NULL,
    ADD COLUMN reference_hash bytea,
    ADD CONSTRAINT authorization_request_reference_is_sha256 CHECK (
        reference_hash IS NULL OR octet_length(reference_hash) = 32),
    ADD CONSTRAINT authorization_request_bound_once CHECK (
        (secret_hash IS NULL) <> (reference_hash IS NULL)),
    ADD CONSTRAINT authorization_request_pushed_short_lived CHECK (
        reference_hash IS NULL OR expires_at <= received_at + interval '600 seconds'),
    ADD CONSTRAINT authorization_request_pushed_waits_for_nobody CHECK (
        reference_hash IS NULL OR consent_user_id IS NULL);

-- A reference names one request of its tenant.
CREATE UNIQUE INDEX authorization_request_reference_idx
    ON oauth.authorization_request (tenant_id, reference_hash)
    WHERE reference_hash IS NOT NULL;

-- The pushed requests of a client, oldest first, when a sixth arrives.
CREATE INDEX authorization_request_pushed_client_idx
    ON oauth.authorization_request (tenant_id, client_id, received_at)
    WHERE reference_hash IS NOT NULL;
