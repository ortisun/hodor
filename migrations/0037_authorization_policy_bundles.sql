-- Bundles for Open Policy Agent: the registered instances, the signed
-- bundles they pull, the status they report and the decisions they
-- upload. See docs/architecture/contexts/authorization.md, "Bundles".

-- The instances belong to the installation, not to a tenant: a shared
-- instance serves several tenants, and a credential is checked before any
-- tenant is known. The second platform table after the tenant directory;
-- it holds no secret, only the SHA-256 of each credential.
CREATE TABLE platform.policy_agent_instance (
    id                uuid        PRIMARY KEY,
    name              text        COLLATE "C" NOT NULL UNIQUE,
    tenant_id         uuid,
    credential_digest bytea       NOT NULL UNIQUE,
    registered_at     timestamptz NOT NULL,
    disabled_at       timestamptz,
    CONSTRAINT policy_agent_instance_name_shape CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    CONSTRAINT policy_agent_instance_digest_length CHECK (octet_length(credential_digest) = 32),
    CONSTRAINT policy_agent_instance_disabled_after
        CHECK (disabled_at IS NULL OR disabled_at >= registered_at)
);

-- Registered and disabled from the command line, which connects as the
-- application role; never deleted.
GRANT SELECT, INSERT, UPDATE ON platform.policy_agent_instance TO hodor_app, hodor_platform;

-- A tenant's bundles. Append only: a published revision is never changed
-- or removed, and a rollback is a new revision.
CREATE TABLE "authorization".policy_bundle (
    tenant_id    uuid        NOT NULL,
    revision     bigint      NOT NULL,
    written_by   text        NOT NULL,
    archive      bytea       NOT NULL,
    digest       bytea       NOT NULL,
    published_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, revision),
    CONSTRAINT policy_bundle_revision_positive CHECK (revision >= 1),
    CONSTRAINT policy_bundle_written_by CHECK (written_by IN ('operator', 'tenant')),
    CONSTRAINT policy_bundle_digest_length CHECK (octet_length(digest) = 32),
    -- 8 mebibytes of files compress to less; a little more for headers.
    CONSTRAINT policy_bundle_archive_size CHECK (octet_length(archive) BETWEEN 1 AND 16777216)
);

SELECT platform.enable_tenant_rls('"authorization".policy_bundle');
REVOKE UPDATE, DELETE ON "authorization".policy_bundle FROM hodor_app;

-- The last status each instance reported for the tenant's bundle.
CREATE TABLE "authorization".policy_agent_status (
    tenant_id       uuid        NOT NULL,
    instance_id     uuid        NOT NULL,
    active_revision text,
    last_activation timestamptz,
    last_error      text,
    reported_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, instance_id),
    CONSTRAINT policy_agent_status_revision_length CHECK (char_length(active_revision) <= 255),
    CONSTRAINT policy_agent_status_error_length CHECK (char_length(last_error) <= 1020)
);

SELECT platform.enable_tenant_rls('"authorization".policy_agent_status');

-- The decisions instances uploaded, reduced to what is safe to keep: no
-- input and no result beyond whether it allowed. Retention and masking
-- come with the record of decisions (Issue-76).
CREATE TABLE "authorization".policy_agent_decision (
    tenant_id   uuid        NOT NULL,
    instance_id uuid        NOT NULL,
    decision_id text        NOT NULL,
    path        text        NOT NULL,
    revision    text,
    allowed     boolean,
    decided_at  timestamptz,
    received_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, instance_id, decision_id),
    CONSTRAINT policy_agent_decision_identifier_length
        CHECK (char_length(decision_id) BETWEEN 1 AND 255),
    CONSTRAINT policy_agent_decision_path_length CHECK (char_length(path) <= 1024),
    CONSTRAINT policy_agent_decision_revision_length CHECK (char_length(revision) <= 255)
);

SELECT platform.enable_tenant_rls('"authorization".policy_agent_decision');

CREATE INDEX policy_agent_decision_received
    ON "authorization".policy_agent_decision (tenant_id, received_at DESC);
