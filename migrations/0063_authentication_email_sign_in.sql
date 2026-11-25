-- The authentication context: what is sent to sign in by email, a code or
-- a link, one row per sign-in that asked.
-- See docs/architecture/contexts/authentication.md, "Signing in with a
-- code or a link by email", and Decision 0036.

CREATE TABLE authentication.email_sign_in (
    tenant_id      uuid        NOT NULL,
    -- The sign-in that asked; deliberately not a foreign key, so that the
    -- cleanup of each table goes its own way.
    transaction_id uuid        NOT NULL,
    method         text        NOT NULL,
    -- SHA-256 of the code or of the link's token. Neither is stored.
    secret_hash    bytea       NOT NULL,
    -- SHA-256 of the address asked about, normalized as the identifier
    -- step normalizes it: what attempts are counted by.
    identifier_key bytea       NOT NULL,
    -- A user of the identity context, or null when the address belongs
    -- to nobody who may sign in; deliberately not a foreign key.
    user_id        uuid,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    -- Asking again replaces the row: only the newest is good.
    PRIMARY KEY (tenant_id, transaction_id),
    CONSTRAINT email_sign_in_method_known CHECK (method IN ('email_code', 'email_link')),
    CONSTRAINT email_sign_in_secret_is_sha256 CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT email_sign_in_identifier_is_sha256 CHECK (octet_length(identifier_key) = 32),
    CONSTRAINT email_sign_in_lifetime CHECK (expires_at > created_at),
    -- Only something sent to a person can be used.
    CONSTRAINT email_sign_in_used_by_someone CHECK (used_at IS NULL OR user_id IS NOT NULL)
);

SELECT platform.enable_tenant_rls('authentication.email_sign_in');

-- Finding the tenants with expired rows, for the cleanup.
CREATE INDEX email_sign_in_expires_idx ON authentication.email_sign_in (expires_at);
