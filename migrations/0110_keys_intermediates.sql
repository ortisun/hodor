-- The keys context: the intermediates a tenant's certificate authority
-- signs for its meshes, and their withdrawal.
-- See docs/architecture/contexts/keys.md, "Signing intermediates" and
-- "Storage", and Decision 0071.

CREATE TABLE keys.intermediate (
    tenant_id            uuid        NOT NULL,
    id                   uuid        NOT NULL,
    -- Not a foreign key: removing the authority keeps its intermediates,
    -- so that a withdrawn key stays refused.
    authority_id         uuid        NOT NULL,
    serial_number        text        NOT NULL,
    subject              text        NOT NULL,
    uris                 text[]      NOT NULL DEFAULT '{}',
    dns_names            text[]      NOT NULL DEFAULT '{}',
    permitted_dns_names  text[]      NOT NULL,
    excluded_dns_names   text[]      NOT NULL DEFAULT '{}',
    certificate          bytea       NOT NULL,
    certificate_sha256   text        NOT NULL,
    public_key_sha256    text        NOT NULL,
    request_sha256       text        NOT NULL,
    not_before           timestamptz NOT NULL,
    not_after            timestamptz NOT NULL,
    signed_at            timestamptz NOT NULL,
    state                text        NOT NULL,
    withdrawn_at         timestamptz,
    withdrawal_reason    text,
    version              integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT intermediate_serial_number_unique UNIQUE (tenant_id, serial_number),
    CONSTRAINT intermediate_serial_number_shape CHECK (serial_number ~ '^[0-9a-f]{1,64}$'),
    CONSTRAINT intermediate_subject_length CHECK (char_length(subject) BETWEEN 1 AND 1000),
    CONSTRAINT intermediate_name_count
        CHECK (cardinality(uris) + cardinality(dns_names) <= 20),
    CONSTRAINT intermediate_permitted_count
        CHECK (cardinality(permitted_dns_names) BETWEEN 1 AND 20),
    CONSTRAINT intermediate_excluded_count CHECK (cardinality(excluded_dns_names) <= 20),
    CONSTRAINT intermediate_hashes_shape CHECK (
        certificate_sha256 ~ '^[0-9a-f]{64}$'
        AND public_key_sha256 ~ '^[0-9a-f]{64}$'
        AND request_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT intermediate_validity CHECK (not_after > not_before),
    CONSTRAINT intermediate_state_known CHECK (state IN ('active', 'withdrawn')),
    CONSTRAINT intermediate_withdrawn_exactly CHECK (
        (state = 'withdrawn') = (withdrawn_at IS NOT NULL)
        AND (withdrawn_at IS NULL) = (withdrawal_reason IS NULL)),
    CONSTRAINT intermediate_reason_length
        CHECK (withdrawal_reason IS NULL OR char_length(withdrawal_reason) BETWEEN 1 AND 200)
);

SELECT platform.enable_tenant_rls('keys.intermediate');

-- The withdrawn keys and the intermediates of a key.
CREATE INDEX intermediate_public_key ON keys.intermediate (tenant_id, public_key_sha256);
-- The list of an authority's intermediates, newest first.
CREATE INDEX intermediate_of_authority ON keys.intermediate (tenant_id, authority_id, id);

-- An intermediate is withdrawn, never removed.
REVOKE DELETE ON keys.intermediate FROM hodor_app;
