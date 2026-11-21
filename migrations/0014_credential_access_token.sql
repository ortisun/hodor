-- The credential context: access tokens, which let a program act as a
-- user on the administration interface.
-- See docs/architecture/contexts/credential.md, "Access tokens".

CREATE TABLE credential.access_token (
    tenant_id   uuid        NOT NULL,
    id          uuid        NOT NULL,
    -- A user of the identity context; deliberately not a foreign key.
    user_id     uuid        NOT NULL,
    -- SHA-256 of the token. The token itself is stored nowhere.
    token_hash  bytea       NOT NULL,
    description text        NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    PRIMARY KEY (tenant_id, id),
    -- A token is looked up by tenant and hash together, so a token
    -- presented to another tenant finds nothing.
    CONSTRAINT access_token_hash_unique UNIQUE (tenant_id, token_hash),
    CONSTRAINT access_token_hash_is_sha256 CHECK (octet_length(token_hash) = 32),
    -- There is no token that does not expire.
    CONSTRAINT access_token_expires CHECK (expires_at > created_at)
);

SELECT platform.enable_tenant_rls('credential.access_token');

CREATE INDEX access_token_user_idx ON credential.access_token (tenant_id, user_id);
