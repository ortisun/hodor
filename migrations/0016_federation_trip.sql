-- The federation context: the trip of a sign-in to a provider and back.
-- See docs/architecture/contexts/federation.md, "The trip".

CREATE TABLE federation.trip (
    tenant_id      uuid        NOT NULL,
    -- A sign-in in progress of the authentication context; deliberately
    -- not a foreign key. One trip per sign-in.
    transaction_id uuid        NOT NULL,
    provider_id    uuid        NOT NULL,
    -- SHA-256 of the state sent to the provider. The state itself is
    -- stored nowhere.
    state_hash     bytea       NOT NULL,
    nonce          text        NOT NULL,
    -- The PKCE verifier, sealed. See docs/security/secrets-at-rest.md.
    code_verifier  bytea       NOT NULL,
    redirect_uri   text        NOT NULL,
    expires_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id),
    CONSTRAINT trip_provider_fk
        FOREIGN KEY (tenant_id, provider_id)
        REFERENCES federation.identity_provider (tenant_id, id),
    CONSTRAINT trip_state_hash_is_sha256 CHECK (octet_length(state_hash) = 32),
    CONSTRAINT trip_verifier_is_sealed CHECK (octet_length(code_verifier) > 0)
);

SELECT platform.enable_tenant_rls('federation.trip');
