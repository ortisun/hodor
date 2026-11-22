-- The identity context: users and their login identifiers.
-- See docs/architecture/contexts/identity.md.

CREATE SCHEMA identity;
GRANT USAGE ON SCHEMA identity TO hodor_app, hodor_platform;

CREATE TABLE identity."user" (
    tenant_id     uuid        NOT NULL,
    id            uuid        NOT NULL,
    kind          text        NOT NULL,
    status        text        NOT NULL,
    status_reason text,
    display_name  text,
    locale        text,
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL,
    version       integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT user_kind_known CHECK (kind IN ('human', 'service_account', 'agent')),
    CONSTRAINT user_status_known CHECK (
        status IN ('pending', 'active', 'suspended', 'deactivated', 'deleted')
    )
);

SELECT platform.enable_tenant_rls('identity."user"');

CREATE TABLE identity.user_identifier (
    tenant_id        uuid        NOT NULL,
    id               uuid        NOT NULL,
    user_id          uuid        NOT NULL,
    kind             text        NOT NULL,
    value_normalized text        NOT NULL,
    value_display    text        NOT NULL,
    verified_at      timestamptz,
    is_primary       boolean     NOT NULL,
    created_at       timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES identity."user" (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT user_identifier_kind_known CHECK (kind IN ('username', 'email')),
    -- One name, one user, within a tenant. Enforced here so that two
    -- concurrent registrations of the same address cannot both succeed.
    CONSTRAINT user_identifier_value_unique UNIQUE (tenant_id, kind, value_normalized)
);

SELECT platform.enable_tenant_rls('identity.user_identifier');

CREATE INDEX user_identifier_user_idx ON identity.user_identifier (tenant_id, user_id);

-- At most one primary identifier of each kind per user.
CREATE UNIQUE INDEX user_identifier_one_primary_idx
    ON identity.user_identifier (tenant_id, user_id, kind)
    WHERE is_primary;
