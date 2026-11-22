-- The authentication context: counting failed attempts.
-- See docs/architecture/contexts/authentication.md.

CREATE SCHEMA authentication;
GRANT USAGE ON SCHEMA authentication TO hodor_app, hodor_platform;

-- Attempts counted against a login identifier or a network address. Only
-- a digest of the subject is stored, never the identifier or the address.
CREATE TABLE authentication.attempt_counter (
    tenant_id         uuid        NOT NULL,
    subject_kind      text        NOT NULL,
    subject_key       bytea       NOT NULL,
    failures          integer     NOT NULL,
    window_started_at timestamptz NOT NULL,
    lockouts          integer     NOT NULL,
    locked_until      timestamptz,
    PRIMARY KEY (tenant_id, subject_kind, subject_key),
    CONSTRAINT attempt_counter_kind_known CHECK (subject_kind IN ('identifier', 'address')),
    CONSTRAINT attempt_counter_key_is_sha256 CHECK (octet_length(subject_key) = 32)
);

SELECT platform.enable_tenant_rls('authentication.attempt_counter');
