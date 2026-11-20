-- The session context: browser sessions.
-- See docs/architecture/contexts/session.md.

CREATE SCHEMA session;
GRANT USAGE ON SCHEMA session TO hodor_app, hodor_platform;

-- `user_id` refers to a user of the identity context but is deliberately
-- not a foreign key: contexts do not reference each other's tables.
CREATE TABLE session.session (
    tenant_id            uuid        NOT NULL,
    id                   uuid        NOT NULL,
    user_id              uuid        NOT NULL,
    token_hash           bytea       NOT NULL,
    signed_in_at         timestamptz NOT NULL,
    assurance            text        NOT NULL,
    methods              text[]      NOT NULL,
    started_at           timestamptz NOT NULL,
    last_activity_at     timestamptz NOT NULL,
    idle_timeout_seconds integer     NOT NULL,
    absolute_expires_at  timestamptz NOT NULL,
    client_address       text,
    client_description   text,
    revoked_at           timestamptz,
    revocation_reason    text,
    PRIMARY KEY (tenant_id, id),
    -- A token is looked up by tenant and hash together, so a token
    -- presented to another tenant finds nothing.
    CONSTRAINT session_token_hash_unique UNIQUE (tenant_id, token_hash),
    CONSTRAINT session_token_hash_is_sha256 CHECK (octet_length(token_hash) = 32),
    CONSTRAINT session_assurance_known CHECK (assurance IN ('single_factor', 'multi_factor')),
    CONSTRAINT session_idle_timeout_positive CHECK (idle_timeout_seconds > 0)
);

SELECT platform.enable_tenant_rls('session.session');

CREATE INDEX session_user_idx ON session.session (tenant_id, user_id, started_at DESC);
