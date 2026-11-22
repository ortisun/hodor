-- The federation context: the identity providers a tenant trusts, and
-- whose external identity is whose.
-- See docs/architecture/contexts/federation.md.

CREATE SCHEMA federation;
GRANT USAGE ON SCHEMA federation TO hodor_app, hodor_platform;

CREATE TABLE federation.identity_provider (
    tenant_id     uuid        NOT NULL,
    id            uuid        NOT NULL,
    -- The provider's name in addresses. It never changes.
    alias         text        NOT NULL,
    kind          text        NOT NULL,
    display_name  text        NOT NULL,
    issuer        text        NOT NULL,
    client_id     text        NOT NULL,
    -- The client secret, sealed. See docs/security/secrets-at-rest.md.
    client_secret bytea       NOT NULL,
    scopes        text[]      NOT NULL,
    creates_users boolean     NOT NULL,
    status        text        NOT NULL,
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL,
    version       integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT identity_provider_alias_unique UNIQUE (tenant_id, alias),
    CONSTRAINT identity_provider_alias_shape
        CHECK (alias ~ '^[a-z0-9][a-z0-9-]{1,31}$'),
    CONSTRAINT identity_provider_kind_known CHECK (kind IN ('openid_connect')),
    CONSTRAINT identity_provider_status_known CHECK (status IN ('enabled', 'disabled')),
    CONSTRAINT identity_provider_issuer_is_https CHECK (issuer LIKE 'https://%'),
    -- A sealed secret is never empty, even when the secret is.
    CONSTRAINT identity_provider_secret_is_sealed CHECK (octet_length(client_secret) > 0)
);

SELECT platform.enable_tenant_rls('federation.identity_provider');

CREATE TABLE federation.external_identity (
    tenant_id    uuid        NOT NULL,
    provider_id  uuid        NOT NULL,
    -- The provider's own identifier for the person. Compared exactly.
    subject      text        NOT NULL COLLATE "C",
    -- A user of the identity context; deliberately not a foreign key:
    -- contexts do not reference each other's tables.
    user_id      uuid        NOT NULL,
    linked_at    timestamptz NOT NULL,
    last_used_at timestamptz NOT NULL,
    -- An external identity belongs to at most one user.
    PRIMARY KEY (tenant_id, provider_id, subject),
    -- A link names a provider of the same tenant.
    CONSTRAINT external_identity_provider_fk
        FOREIGN KEY (tenant_id, provider_id)
        REFERENCES federation.identity_provider (tenant_id, id),
    CONSTRAINT external_identity_subject_length
        CHECK (char_length(subject) BETWEEN 1 AND 255)
);

SELECT platform.enable_tenant_rls('federation.external_identity');

CREATE INDEX external_identity_user_idx ON federation.external_identity (tenant_id, user_id);
