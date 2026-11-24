-- The provisioning context: what SCIM carries of users and groups that the
-- identity context has no place for.
-- See docs/architecture/contexts/provisioning.md, "Storage".
--
-- Rows are keyed by the identity context's user or group, with the tenant
-- first, as plain identifiers: a context never refers to another's tables
-- with a foreign key.

CREATE SCHEMA provisioning;
GRANT USAGE ON SCHEMA provisioning TO hodor_app, hodor_platform;

CREATE TABLE provisioning.user_attribute (
    tenant_id       uuid        NOT NULL,
    user_id         uuid        NOT NULL,
    external_id     text,
    name_formatted  text,
    given_name      text,
    family_name     text,
    employee_number text,
    cost_center     text,
    organization    text,
    division        text,
    department      text,
    manager_id      text,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT user_attribute_text_length CHECK (
        char_length(external_id) BETWEEN 1 AND 256
        AND char_length(name_formatted) BETWEEN 1 AND 256
        AND char_length(given_name) BETWEEN 1 AND 256
        AND char_length(family_name) BETWEEN 1 AND 256
        AND char_length(employee_number) BETWEEN 1 AND 256
        AND char_length(cost_center) BETWEEN 1 AND 256
        AND char_length(organization) BETWEEN 1 AND 256
        AND char_length(division) BETWEEN 1 AND 256
        AND char_length(department) BETWEEN 1 AND 256
        AND char_length(manager_id) BETWEEN 1 AND 256
    )
);

SELECT platform.enable_tenant_rls('provisioning.user_attribute');
-- Filters on externalId, which SCIM clients send to find a person again.
CREATE INDEX user_attribute_external_id_idx ON provisioning.user_attribute (tenant_id, external_id)
    WHERE external_id IS NOT NULL;

CREATE TABLE provisioning.group_attribute (
    tenant_id   uuid        NOT NULL,
    group_id    uuid        NOT NULL,
    external_id text,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, group_id),
    CONSTRAINT group_attribute_text_length CHECK (char_length(external_id) BETWEEN 1 AND 256)
);

SELECT platform.enable_tenant_rls('provisioning.group_attribute');
CREATE INDEX group_attribute_external_id_idx ON provisioning.group_attribute (tenant_id, external_id)
    WHERE external_id IS NOT NULL;
