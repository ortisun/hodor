-- The credential context: passwords.
-- See docs/architecture/contexts/credential.md.

CREATE SCHEMA credential;
GRANT USAGE ON SCHEMA credential TO hodor_app, hodor_platform;

-- One password per user. `user_id` refers to a user of the identity
-- context but is deliberately not a foreign key: contexts do not reference
-- each other's tables.
CREATE TABLE credential.password (
    tenant_id     uuid        NOT NULL,
    user_id       uuid        NOT NULL,
    password_hash text        NOT NULL,
    must_change   boolean     NOT NULL,
    changed_at    timestamptz NOT NULL,
    version       integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, user_id)
);

SELECT platform.enable_tenant_rls('credential.password');

-- Previous hashes, newest first by `position`, kept to refuse reuse.
CREATE TABLE credential.password_history (
    tenant_id     uuid        NOT NULL,
    id            uuid        NOT NULL,
    user_id       uuid        NOT NULL,
    position      smallint    NOT NULL,
    password_hash text        NOT NULL,
    replaced_at   timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, user_id)
        REFERENCES credential.password (tenant_id, user_id) ON DELETE CASCADE,
    CONSTRAINT password_history_position_unique UNIQUE (tenant_id, user_id, position)
);

SELECT platform.enable_tenant_rls('credential.password_history');
