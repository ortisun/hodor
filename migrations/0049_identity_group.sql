-- Groups of users, and groups inside groups.
-- See docs/architecture/contexts/identity.md, "Groups".

CREATE TABLE identity."group" (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL,
    name            text        NOT NULL,
    name_normalized text        NOT NULL,
    description     text,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    version         integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT group_name_unique UNIQUE (tenant_id, name_normalized),
    CONSTRAINT group_name_length CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT group_name_normalized CHECK (name_normalized = lower(name)),
    CONSTRAINT group_description_length CHECK (char_length(description) <= 500)
);

SELECT platform.enable_tenant_rls('identity."group"');

CREATE TABLE identity.group_member (
    tenant_id       uuid        NOT NULL,
    group_id        uuid        NOT NULL,
    user_id         uuid,
    member_group_id uuid,
    -- The member, whichever kind it is: a user and a group never share an
    -- identifier, so a member is in a group once.
    member_id       uuid        GENERATED ALWAYS AS (COALESCE(user_id, member_group_id)) STORED,
    added_at        timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, group_id, member_id),
    CONSTRAINT group_member_group_fk
        FOREIGN KEY (tenant_id, group_id)
        REFERENCES identity."group" (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT group_member_user_fk
        FOREIGN KEY (tenant_id, user_id)
        REFERENCES identity."user" (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT group_member_member_group_fk
        FOREIGN KEY (tenant_id, member_group_id)
        REFERENCES identity."group" (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT group_member_one_kind CHECK ((user_id IS NULL) <> (member_group_id IS NULL)),
    CONSTRAINT group_member_not_itself CHECK (member_group_id IS DISTINCT FROM group_id)
);

SELECT platform.enable_tenant_rls('identity.group_member');
-- The groups a user is in, and the groups a group is in.
CREATE INDEX group_member_user_idx ON identity.group_member (tenant_id, user_id)
    WHERE user_id IS NOT NULL;
CREATE INDEX group_member_member_group_idx ON identity.group_member (tenant_id, member_group_id)
    WHERE member_group_id IS NOT NULL;
