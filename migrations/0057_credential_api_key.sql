-- The API keys of service accounts and agents: what they present, as it
-- is, to the administration interface and the Authorization API. Only the
-- SHA-256 of a key is kept, never the key.
-- See docs/architecture/contexts/credential.md, "API keys".

CREATE TABLE credential.api_key (
    tenant_id         uuid        NOT NULL,
    id                uuid        NOT NULL,
    -- A user of the identity context; deliberately not a foreign key.
    holder_id         uuid        NOT NULL,
    key_hash          bytea       NOT NULL,
    -- The last four characters of the key, to tell keys apart.
    hint              text        NOT NULL,
    name              text        NOT NULL,
    scopes            text[]      NOT NULL,
    -- An application of the OAuth context; deliberately not a foreign key.
    application_id    uuid,
    created_at        timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    last_used_at      timestamptz,
    revoked_at        timestamptz,
    revocation_reason text,
    -- The key that replaced it, once rotated. Not a reference, so that the
    -- cleanup job can remove either first.
    replaced_by       uuid,
    PRIMARY KEY (tenant_id, id),
    -- A key is looked up by tenant and hash together, so a key presented
    -- to another tenant finds nothing.
    CONSTRAINT api_key_hash_unique UNIQUE (tenant_id, key_hash),
    CONSTRAINT api_key_hash_is_sha256 CHECK (octet_length(key_hash) = 32),
    CONSTRAINT api_key_hint_shape CHECK (hint ~ '^[0-9a-f]{4}$'),
    CONSTRAINT api_key_name_length CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT api_key_scopes_bounded CHECK (cardinality(scopes) BETWEEN 1 AND 50),
    -- There is no key that does not expire.
    CONSTRAINT api_key_expires CHECK (expires_at > created_at),
    CONSTRAINT api_key_revocation_complete CHECK (
        (revoked_at IS NULL) = (revocation_reason IS NULL))
);

SELECT platform.enable_tenant_rls('credential.api_key');

CREATE INDEX api_key_holder_idx ON credential.api_key (tenant_id, holder_id);
-- The cleanup job finds the keys that ended.
CREATE INDEX api_key_ended_idx ON credential.api_key (expires_at);
