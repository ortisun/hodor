-- Roles given to groups, and assignments scoped to an organization.
-- See docs/architecture/contexts/authorization.md, "Assignments".

ALTER TABLE "authorization".role_assignment
    DROP CONSTRAINT role_assignment_pkey,
    DROP CONSTRAINT role_assignment_principal_kind,
    ADD COLUMN organization text COLLATE "C" NOT NULL DEFAULT '';

ALTER TABLE "authorization".role_assignment
    ALTER COLUMN organization DROP DEFAULT,
    ADD PRIMARY KEY (
        tenant_id, principal_kind, principal_id, namespace, role, application, organization),
    ADD CONSTRAINT role_assignment_principal_kind
        CHECK (principal_kind IN ('user', 'client', 'group')),
    ADD CONSTRAINT role_assignment_organization_shape CHECK (char_length(organization) <= 255),
    -- An application or an organization, never both.
    ADD CONSTRAINT role_assignment_one_scope CHECK (application = '' OR organization = ''),
    -- Hodor's own roles stay given to users, for the whole tenant.
    ADD CONSTRAINT role_assignment_built_in_tenant_wide
        CHECK (namespace <> 'hodor:admin' OR organization = '');
