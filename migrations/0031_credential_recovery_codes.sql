-- The credential context: recovery codes, used once each in place of a
-- second factor the person lost.
-- See docs/architecture/contexts/credential.md, "Recovery codes".

CREATE TABLE credential.recovery_code_set (
    tenant_id  uuid        NOT NULL,
    id         uuid        NOT NULL,
    -- A user of the identity context; deliberately not a foreign key.
    user_id    uuid        NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    -- At most one set per user: of two sets stored at the same moment,
    -- the second is refused.
    CONSTRAINT recovery_code_set_one_per_user UNIQUE (tenant_id, user_id)
);

CREATE TABLE credential.recovery_code (
    tenant_id uuid        NOT NULL,
    id        uuid        NOT NULL,
    set_id    uuid        NOT NULL,
    -- The SHA-256 of the code. The code itself is stored nowhere.
    code_hash bytea       NOT NULL,
    used_at   timestamptz,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, set_id)
        REFERENCES credential.recovery_code_set (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT recovery_code_hash_length CHECK (octet_length(code_hash) = 32),
    CONSTRAINT recovery_code_unique_in_set UNIQUE (tenant_id, set_id, code_hash)
);

SELECT platform.enable_tenant_rls('credential.recovery_code_set');
SELECT platform.enable_tenant_rls('credential.recovery_code');
