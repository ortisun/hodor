-- The policy lifecycle: a tenant's policy versions, which version each
-- bundle revision was built from, and simulations. See
-- docs/architecture/contexts/authorization.md, "The policy lifecycle".

-- A version never changes but for its state and the report of its last
-- check. Its files are text: Rego modules and data documents in canonical
-- form, as JSON `[{"path": …, "contents": …}]`.
CREATE TABLE "authorization".policy_version (
    tenant_id  uuid        NOT NULL,
    number     bigint      NOT NULL,
    written_by text        NOT NULL,
    files      jsonb       NOT NULL,
    digest     bytea       NOT NULL,
    state      text        NOT NULL,
    report     jsonb,
    drafted_at timestamptz NOT NULL,
    changed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, number),
    CONSTRAINT policy_version_number_positive CHECK (number >= 1),
    CONSTRAINT policy_version_written_by CHECK (written_by IN ('operator', 'tenant')),
    CONSTRAINT policy_version_state CHECK (
        state IN ('draft', 'validating', 'validated', 'testing', 'tested', 'rejected')),
    CONSTRAINT policy_version_digest_length CHECK (octet_length(digest) = 32),
    CONSTRAINT policy_version_files_shape CHECK (jsonb_typeof(files) = 'array'),
    -- 8 mebibytes of files, written as JSON text; a little more for escapes.
    CONSTRAINT policy_version_files_size CHECK (pg_column_size(files) <= 33554432),
    CONSTRAINT policy_version_changed_after CHECK (changed_at >= drafted_at)
);

SELECT platform.enable_tenant_rls('"authorization".policy_version');
-- A version is never removed.
REVOKE DELETE ON "authorization".policy_version FROM hodor_app;

-- The worker looks for versions waiting, across tenants.
CREATE INDEX policy_version_waiting
    ON "authorization".policy_version (changed_at)
    WHERE state IN ('validating', 'testing');

-- Which version each revision was built from. Append only, like the
-- bundles themselves.
CREATE TABLE "authorization".policy_publication (
    tenant_id uuid   NOT NULL,
    revision  bigint NOT NULL,
    version   bigint NOT NULL,
    PRIMARY KEY (tenant_id, revision),
    FOREIGN KEY (tenant_id, revision)
        REFERENCES "authorization".policy_bundle (tenant_id, revision),
    FOREIGN KEY (tenant_id, version)
        REFERENCES "authorization".policy_version (tenant_id, number)
);

SELECT platform.enable_tenant_rls('"authorization".policy_publication');
REVOKE UPDATE, DELETE ON "authorization".policy_publication FROM hodor_app;

-- A simulation keeps its inputs only while it waits: they are erased when
-- it is done, and only the results, by position, are kept.
CREATE TABLE "authorization".policy_simulation (
    tenant_id     uuid        NOT NULL,
    id            uuid        NOT NULL,
    version       bigint      NOT NULL,
    namespace     text        NOT NULL,
    inputs        jsonb,
    compared_with bigint,
    results       jsonb,
    report        jsonb,
    state         text        NOT NULL,
    asked_at      timestamptz NOT NULL,
    done_at       timestamptz,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, version)
        REFERENCES "authorization".policy_version (tenant_id, number),
    CONSTRAINT policy_simulation_state CHECK (state IN ('waiting', 'done', 'failed')),
    CONSTRAINT policy_simulation_namespace_length CHECK (char_length(namespace) BETWEEN 1 AND 255),
    -- Waiting, it has its inputs; done or failed, it has none and an end.
    CONSTRAINT policy_simulation_inputs_while_waiting CHECK (
        (state = 'waiting' AND inputs IS NOT NULL AND done_at IS NULL)
        OR (state <> 'waiting' AND inputs IS NULL AND done_at IS NOT NULL)),
    CONSTRAINT policy_simulation_inputs_size CHECK (pg_column_size(inputs) <= 4194304)
);

SELECT platform.enable_tenant_rls('"authorization".policy_simulation');

CREATE INDEX policy_simulation_waiting
    ON "authorization".policy_simulation (asked_at)
    WHERE state = 'waiting';
