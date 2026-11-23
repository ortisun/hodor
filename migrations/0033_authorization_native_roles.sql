-- Native role-based access control: the permissions and roles a tenant
-- defines for its resource servers, who holds them, and the tenant's role
-- revision. The assignments of the built-in roles of Hodor's
-- administration move into the same table.
-- See docs/architecture/contexts/authorization.md, "Native role-based
-- access control".

-- Namespaces are resource servers' audiences, compared byte for byte, and
-- never `hodor:admin` in the tables a tenant writes to.

CREATE TABLE "authorization".permission (
    tenant_id   uuid        NOT NULL,
    namespace   text        COLLATE "C" NOT NULL,
    name        text        COLLATE "C" NOT NULL,
    description text        NOT NULL,
    created_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, namespace, name),
    CONSTRAINT permission_not_administration CHECK (namespace <> 'hodor:admin'),
    CONSTRAINT permission_namespace_shape CHECK (
        char_length(namespace) <= 255
        AND (namespace LIKE 'https://_%' OR namespace LIKE 'urn:_%')),
    CONSTRAINT permission_name_shape
        CHECK (name ~ '^[a-z][a-z0-9._-]{0,63}:[a-z][a-z0-9._-]{0,63}$'),
    CONSTRAINT permission_description_length CHECK (char_length(description) <= 500)
);

SELECT platform.enable_tenant_rls('"authorization".permission');

CREATE TABLE "authorization".role (
    tenant_id   uuid        NOT NULL,
    namespace   text        COLLATE "C" NOT NULL,
    name        text        COLLATE "C" NOT NULL,
    description text        NOT NULL,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, namespace, name),
    CONSTRAINT role_not_administration CHECK (namespace <> 'hodor:admin'),
    CONSTRAINT role_namespace_shape CHECK (
        char_length(namespace) <= 255
        AND (namespace LIKE 'https://_%' OR namespace LIKE 'urn:_%')),
    CONSTRAINT role_name_shape CHECK (name ~ '^[a-z][a-z0-9._-]{0,63}$'),
    CONSTRAINT role_description_length CHECK (char_length(description) <= 500)
);

SELECT platform.enable_tenant_rls('"authorization".role');

-- What a role holds: permissions of its own namespace. A row goes with its
-- role and with its permission.
CREATE TABLE "authorization".role_permission (
    tenant_id  uuid NOT NULL,
    namespace  text COLLATE "C" NOT NULL,
    role       text COLLATE "C" NOT NULL,
    permission text COLLATE "C" NOT NULL,
    PRIMARY KEY (tenant_id, namespace, role, permission),
    FOREIGN KEY (tenant_id, namespace, role)
        REFERENCES "authorization".role (tenant_id, namespace, name) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, namespace, permission)
        REFERENCES "authorization".permission (tenant_id, namespace, name) ON DELETE CASCADE
);

SELECT platform.enable_tenant_rls('"authorization".role_permission');

-- What a role includes. A row goes with the including role; the included
-- role cannot be removed while a row names it. Cycles are refused by the
-- context before a row is written.
CREATE TABLE "authorization".role_inclusion (
    tenant_id          uuid NOT NULL,
    namespace          text COLLATE "C" NOT NULL,
    role               text COLLATE "C" NOT NULL,
    included_namespace text COLLATE "C" NOT NULL,
    included_role      text COLLATE "C" NOT NULL,
    PRIMARY KEY (tenant_id, namespace, role, included_namespace, included_role),
    CONSTRAINT role_inclusion_not_itself
        CHECK (namespace <> included_namespace OR role <> included_role),
    FOREIGN KEY (tenant_id, namespace, role)
        REFERENCES "authorization".role (tenant_id, namespace, name) ON DELETE CASCADE,
    CONSTRAINT role_inclusion_included_exists FOREIGN KEY (tenant_id, included_namespace, included_role)
        REFERENCES "authorization".role (tenant_id, namespace, name)
);

SELECT platform.enable_tenant_rls('"authorization".role_inclusion');

-- Raised in the same transaction as every change of a tenant's
-- permissions, roles and assignments. The native engine compares it with
-- what it keeps.
CREATE TABLE "authorization".role_revision (
    tenant_id uuid   NOT NULL,
    revision  bigint NOT NULL,
    PRIMARY KEY (tenant_id),
    CONSTRAINT role_revision_positive CHECK (revision > 0)
);

SELECT platform.enable_tenant_rls('"authorization".role_revision');

-- The assignments. The rows written before this migration were all of the
-- built-in roles, to users, for the whole tenant, without a start or end;
-- they keep that meaning.
ALTER TABLE "authorization".role_assignment
    DROP CONSTRAINT role_assignment_role_known,
    DROP CONSTRAINT role_assignment_pkey;

ALTER TABLE "authorization".role_assignment RENAME COLUMN user_id TO principal_id;

ALTER TABLE "authorization".role_assignment
    ALTER COLUMN principal_id TYPE text COLLATE "C" USING principal_id::text,
    ALTER COLUMN role TYPE text COLLATE "C",
    ADD COLUMN principal_kind text NOT NULL DEFAULT 'user',
    ADD COLUMN namespace text COLLATE "C" NOT NULL DEFAULT 'hodor:admin',
    ADD COLUMN application text COLLATE "C" NOT NULL DEFAULT '',
    ADD COLUMN valid_from timestamptz,
    ADD COLUMN valid_until timestamptz;

ALTER TABLE "authorization".role_assignment
    ALTER COLUMN principal_kind DROP DEFAULT,
    ALTER COLUMN namespace DROP DEFAULT,
    ALTER COLUMN application DROP DEFAULT,
    -- The namespace of a role the tenant defined; nothing for a built-in
    -- role, which is not in `authorization.role`.
    ADD COLUMN role_namespace text COLLATE "C"
        GENERATED ALWAYS AS (NULLIF(namespace, 'hodor:admin')) STORED,
    ADD PRIMARY KEY (tenant_id, principal_kind, principal_id, namespace, role, application),
    ADD CONSTRAINT role_assignment_principal_kind CHECK (principal_kind IN ('user', 'client')),
    ADD CONSTRAINT role_assignment_principal_shape
        CHECK (char_length(principal_id) BETWEEN 1 AND 255),
    ADD CONSTRAINT role_assignment_application_shape CHECK (char_length(application) <= 255),
    ADD CONSTRAINT role_assignment_validity
        CHECK (valid_from IS NULL OR valid_until IS NULL OR valid_until > valid_from),
    ADD CONSTRAINT role_assignment_namespace_shape CHECK (
        namespace = 'hodor:admin'
        OR (char_length(namespace) <= 255
            AND (namespace LIKE 'https://_%' OR namespace LIKE 'urn:_%'))),
    -- The built-in roles: only these two, only to users, for the whole
    -- tenant, without a start or an end.
    ADD CONSTRAINT role_assignment_built_in CHECK (
        namespace <> 'hodor:admin'
        OR (role IN ('tenant_administrator', 'tenant_auditor')
            AND principal_kind = 'user'
            AND application = ''
            AND valid_from IS NULL
            AND valid_until IS NULL)),
    ADD CONSTRAINT role_assignment_role_exists FOREIGN KEY (tenant_id, role_namespace, role)
        REFERENCES "authorization".role (tenant_id, namespace, name) ON DELETE CASCADE;
