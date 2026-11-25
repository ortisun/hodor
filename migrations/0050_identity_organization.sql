-- Organizations, their units and their members.
-- See docs/architecture/contexts/identity.md, "Organizations".

CREATE TABLE identity.organization (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL,
    name            text        NOT NULL,
    name_normalized text        NOT NULL,
    description     text,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    version         integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT organization_name_unique UNIQUE (tenant_id, name_normalized),
    CONSTRAINT organization_name_length CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT organization_name_normalized CHECK (name_normalized = lower(name)),
    CONSTRAINT organization_description_length CHECK (char_length(description) <= 500)
);

SELECT platform.enable_tenant_rls('identity.organization');

CREATE TABLE identity.organization_unit (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL,
    organization_id uuid        NOT NULL,
    parent_id       uuid,
    name            text        NOT NULL,
    name_normalized text        NOT NULL,
    kind            text        NOT NULL,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    -- What a parent and the units of a membership refer to: a unit of the
    -- same organization.
    CONSTRAINT organization_unit_of_organization UNIQUE (tenant_id, organization_id, id),
    CONSTRAINT organization_unit_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES identity.organization (tenant_id, id) ON DELETE CASCADE,
    -- Checked at the end of the statement, so that deleting an
    -- organization takes its whole tree, while a unit with units below
    -- cannot be deleted on its own.
    CONSTRAINT organization_unit_parent_fk
        FOREIGN KEY (tenant_id, organization_id, parent_id)
        REFERENCES identity.organization_unit (tenant_id, organization_id, id),
    CONSTRAINT organization_unit_name_unique
        UNIQUE NULLS NOT DISTINCT (tenant_id, organization_id, parent_id, name_normalized),
    CONSTRAINT organization_unit_name_length CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT organization_unit_name_normalized CHECK (name_normalized = lower(name)),
    CONSTRAINT organization_unit_kind_known CHECK (kind IN ('unit', 'department')),
    CONSTRAINT organization_unit_not_its_own_parent CHECK (parent_id IS DISTINCT FROM id)
);

SELECT platform.enable_tenant_rls('identity.organization_unit');

CREATE TABLE identity.organization_member (
    tenant_id       uuid        NOT NULL,
    organization_id uuid        NOT NULL,
    user_id         uuid        NOT NULL,
    added_at        timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, organization_id, user_id),
    CONSTRAINT organization_member_organization_fk
        FOREIGN KEY (tenant_id, organization_id)
        REFERENCES identity.organization (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT organization_member_user_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES identity."user" (tenant_id, id) ON DELETE CASCADE
);

SELECT platform.enable_tenant_rls('identity.organization_member');
CREATE INDEX organization_member_user_idx ON identity.organization_member (tenant_id, user_id);

CREATE TABLE identity.organization_member_unit (
    tenant_id       uuid NOT NULL,
    organization_id uuid NOT NULL,
    user_id         uuid NOT NULL,
    unit_id         uuid NOT NULL,
    PRIMARY KEY (tenant_id, organization_id, user_id, unit_id),
    CONSTRAINT organization_member_unit_member_fk
        FOREIGN KEY (tenant_id, organization_id, user_id)
        REFERENCES identity.organization_member (tenant_id, organization_id, user_id)
        ON DELETE CASCADE,
    -- The unit is of the membership's organization.
    CONSTRAINT organization_member_unit_unit_fk
        FOREIGN KEY (tenant_id, organization_id, unit_id)
        REFERENCES identity.organization_unit (tenant_id, organization_id, id) ON DELETE CASCADE
);

SELECT platform.enable_tenant_rls('identity.organization_member_unit');
CREATE INDEX organization_member_unit_unit_idx
    ON identity.organization_member_unit (tenant_id, organization_id, unit_id);
