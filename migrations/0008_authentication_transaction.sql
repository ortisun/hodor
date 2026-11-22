-- The authentication context: sign-ins in progress.
-- See docs/architecture/contexts/authentication.md.

CREATE TABLE authentication.transaction (
    tenant_id          uuid        NOT NULL,
    id                 uuid        NOT NULL,
    flow_name          text        NOT NULL,
    flow_version       integer     NOT NULL,
    current_step       integer     NOT NULL,
    identified         boolean     NOT NULL,
    -- A user of the identity context; deliberately not a foreign key.
    candidate_user_id  uuid,
    identifier_key     bytea,
    satisfied_methods  text[]      NOT NULL,
    rejections         integer     NOT NULL,
    status             text        NOT NULL,
    started_at         timestamptz NOT NULL,
    expires_at         timestamptz NOT NULL,
    client_address     text,
    client_description text,
    version            integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT transaction_status_known CHECK (
        status IN ('in_progress', 'completed', 'failed', 'cancelled')
    ),
    CONSTRAINT transaction_identifier_key_is_sha256 CHECK (
        identifier_key IS NULL OR octet_length(identifier_key) = 32
    )
);

SELECT platform.enable_tenant_rls('authentication.transaction');
