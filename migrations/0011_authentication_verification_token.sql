-- The authentication context: verification tokens, which the links of
-- registration and password recovery carry.
-- See docs/architecture/contexts/authentication.md.

CREATE TABLE authentication.verification_token (
    tenant_id   uuid        NOT NULL,
    id          uuid        NOT NULL,
    purpose     text        NOT NULL,
    -- SHA-256 of the token. The token itself is stored nowhere.
    token_hash  bytea       NOT NULL,
    -- The normalized address the link was sent to.
    email       text        NOT NULL,
    -- A user of the identity context; deliberately not a foreign key.
    user_id     uuid,
    locale      text        NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    replaced_at timestamptz,
    PRIMARY KEY (tenant_id, id),
    -- A token is looked up by tenant and hash together, so a token
    -- presented to another tenant finds nothing.
    CONSTRAINT verification_token_hash_unique UNIQUE (tenant_id, token_hash),
    CONSTRAINT verification_token_hash_is_sha256 CHECK (octet_length(token_hash) = 32),
    CONSTRAINT verification_token_purpose_known
        CHECK (purpose IN ('registration', 'password_recovery')),
    CONSTRAINT verification_token_recovery_has_a_user
        CHECK ((purpose = 'password_recovery') = (user_id IS NOT NULL))
);

SELECT platform.enable_tenant_rls('authentication.verification_token');

-- Replacing the earlier tokens of an address when a new one is made.
CREATE INDEX verification_token_unused_idx
    ON authentication.verification_token (tenant_id, purpose, email)
    WHERE used_at IS NULL AND replaced_at IS NULL;
