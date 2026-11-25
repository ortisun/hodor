-- Per-resource access control lists: entries that let one principal do
-- what one permission says to one resource of a resource server.
-- See docs/architecture/contexts/authorization.md, "Access control lists",
-- and docs/decisions/0035-access-control-lists.md.

CREATE TABLE "authorization".access_entry (
    tenant_id      uuid        NOT NULL,
    id             uuid        NOT NULL,
    namespace      text        COLLATE "C" NOT NULL,
    permission     text        COLLATE "C" NOT NULL,
    -- The first half of the permission, kept for the index below.
    resource_kind  text        COLLATE "C"
        GENERATED ALWAYS AS (split_part(permission, ':', 1)) STORED,
    resource_id    text        COLLATE "C" NOT NULL,
    principal_kind text        NOT NULL,
    -- A user, a client or a group of another context: deliberately not a
    -- reference, as for role assignments.
    principal_id   text        COLLATE "C" NOT NULL,
    granted_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT access_entry_once UNIQUE (
        tenant_id, namespace, permission, resource_id, principal_kind, principal_id),
    -- An entry names a permission its resource server declares, and goes
    -- with it.
    CONSTRAINT access_entry_permission_declared FOREIGN KEY (tenant_id, namespace, permission)
        REFERENCES "authorization".permission (tenant_id, namespace, name) ON DELETE CASCADE,
    CONSTRAINT access_entry_not_administration CHECK (namespace <> 'hodor:admin'),
    CONSTRAINT access_entry_resource_shape CHECK (char_length(resource_id) BETWEEN 1 AND 255),
    CONSTRAINT access_entry_principal_kind
        CHECK (principal_kind IN ('user', 'client', 'group')),
    CONSTRAINT access_entry_principal_shape CHECK (char_length(principal_id) BETWEEN 1 AND 255)
);

SELECT platform.enable_tenant_rls('"authorization".access_entry');

-- A decision reads the entries of one resource for some principals; a
-- listing reads those of a resource, or of a kind of resource.
CREATE INDEX access_entry_resource_idx ON "authorization".access_entry (
    tenant_id, namespace, resource_kind, resource_id, principal_kind, principal_id);

-- The entries of one principal.
CREATE INDEX access_entry_principal_idx ON "authorization".access_entry (
    tenant_id, principal_kind, principal_id);
