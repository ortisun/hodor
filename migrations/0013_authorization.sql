-- The authorization context: which user holds which role.
-- See docs/architecture/contexts/authorization.md.

CREATE SCHEMA "authorization";
GRANT USAGE ON SCHEMA "authorization" TO hodor_app, hodor_platform;

-- `user_id` refers to a user of the identity context but is deliberately
-- not a foreign key: contexts do not reference each other's tables.
CREATE TABLE "authorization".role_assignment (
    tenant_id   uuid        NOT NULL,
    user_id     uuid        NOT NULL,
    role        text        NOT NULL,
    assigned_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, user_id, role),
    -- The roles are fixed in this version.
    CONSTRAINT role_assignment_role_known
        CHECK (role IN ('tenant_administrator', 'tenant_auditor'))
);

SELECT platform.enable_tenant_rls('"authorization".role_assignment');
