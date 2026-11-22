-- The audit context: one record per event, chained per tenant.
-- See docs/architecture/contexts/audit.md.

CREATE SCHEMA audit;
GRANT USAGE ON SCHEMA audit TO hodor_app, hodor_platform;

CREATE TABLE audit.record (
    tenant_id      uuid        NOT NULL,
    -- The record's position in its tenant's chain: 1, 2, 3, with no gaps.
    sequence       bigint      NOT NULL,
    event_id       uuid        NOT NULL,
    action         text        NOT NULL,
    occurred_at    timestamptz NOT NULL,
    recorded_at    timestamptz NOT NULL,
    actor          jsonb       NOT NULL,
    correlation_id uuid        NOT NULL,
    details        jsonb       NOT NULL,
    previous_hash  bytea       NOT NULL,
    hash           bytea       NOT NULL,
    PRIMARY KEY (tenant_id, sequence),
    -- An event is recorded once.
    CONSTRAINT record_event_once UNIQUE (tenant_id, event_id),
    CONSTRAINT record_sequence_positive CHECK (sequence >= 1),
    CONSTRAINT record_hashes_are_sha256
        CHECK (octet_length(previous_hash) = 32 AND octet_length(hash) = 32)
);

SELECT platform.enable_tenant_rls('audit.record');

-- Append-only, three times over. First: the application's roles may only
-- insert and read.
REVOKE UPDATE, DELETE ON audit.record FROM hodor_app, hodor_platform;

-- Second: a trigger refuses every change, whoever asks, so that a mistake
-- in a migration or by an operator fails loudly. Removing a tenant's
-- records for good is done by the owner with this trigger disabled for
-- that one operation.
CREATE FUNCTION audit.refuse_change() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit records cannot be changed or removed'
        USING ERRCODE = 'restrict_violation';
END
$$;

CREATE TRIGGER record_is_append_only
    BEFORE UPDATE OR DELETE ON audit.record
    FOR EACH ROW EXECUTE FUNCTION audit.refuse_change();

CREATE TRIGGER record_is_never_emptied
    BEFORE TRUNCATE ON audit.record
    FOR EACH STATEMENT EXECUTE FUNCTION audit.refuse_change();

-- Third: the chain itself, which shows what the first two did not prevent.

-- The end of each tenant's chain. Locked while a record is appended, so
-- that appends for one tenant take turns.
CREATE TABLE audit.chain_head (
    tenant_id uuid   NOT NULL PRIMARY KEY,
    sequence  bigint NOT NULL,
    hash      bytea  NOT NULL,
    CONSTRAINT chain_head_sequence_not_negative CHECK (sequence >= 0),
    CONSTRAINT chain_head_hash_is_sha256 CHECK (octet_length(hash) = 32)
);

SELECT platform.enable_tenant_rls('audit.chain_head');
