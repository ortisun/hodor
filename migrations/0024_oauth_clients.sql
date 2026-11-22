-- The OAuth context, its first part: applications, their clients with
-- secrets and keys, and resource servers.
-- See docs/architecture/contexts/oauth.md, "Storage".

CREATE SCHEMA oauth;
GRANT USAGE ON SCHEMA oauth TO hodor_app, hodor_platform;

CREATE TABLE oauth.application (
    tenant_id   uuid        NOT NULL,
    id          uuid        NOT NULL,
    name        text        NOT NULL,
    first_party boolean     NOT NULL,
    status      text        NOT NULL,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    version     integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT application_name_length CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT application_status_known CHECK (status IN ('enabled', 'disabled'))
);

SELECT platform.enable_tenant_rls('oauth.application');

CREATE TABLE oauth.client (
    tenant_id             uuid        NOT NULL,
    id                    uuid        NOT NULL,
    application_id        uuid        NOT NULL,
    name                  text        NOT NULL,
    client_type           text        NOT NULL,
    authentication_method text        NOT NULL,
    grant_types           text[]      NOT NULL,
    -- Compared byte for byte with what an authorization request names.
    redirect_uris         text[]      COLLATE "C" NOT NULL,
    allowed_scopes        text[]      NOT NULL,
    require_pkce          boolean     NOT NULL,
    access_token_seconds  integer     NOT NULL,
    id_token_seconds      integer     NOT NULL,
    refresh_token_seconds integer     NOT NULL,
    refresh_idle_seconds  integer     NOT NULL,
    status                text        NOT NULL,
    created_at            timestamptz NOT NULL,
    updated_at            timestamptz NOT NULL,
    version               integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    -- A client belongs to an application of its own tenant.
    CONSTRAINT client_application_fk
        FOREIGN KEY (tenant_id, application_id)
        REFERENCES oauth.application (tenant_id, id),
    CONSTRAINT client_name_length CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT client_type_known CHECK (client_type IN ('confidential', 'public')),
    CONSTRAINT client_method_known CHECK (authentication_method IN
        ('client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none')),
    -- A public client proves nothing and always uses PKCE; a confidential
    -- one always proves who it is.
    CONSTRAINT client_public_has_no_method CHECK (
        (client_type = 'public') = (authentication_method = 'none')),
    CONSTRAINT client_public_uses_pkce CHECK (client_type = 'confidential' OR require_pkce),
    CONSTRAINT client_has_a_grant CHECK (cardinality(grant_types) > 0),
    CONSTRAINT client_status_known CHECK (status IN ('enabled', 'disabled'))
);

SELECT platform.enable_tenant_rls('oauth.client');

CREATE INDEX client_application_idx ON oauth.client (tenant_id, application_id);

CREATE TABLE oauth.client_secret (
    tenant_id   uuid        NOT NULL,
    client_id   uuid        NOT NULL,
    id          uuid        NOT NULL,
    -- SHA-256 of the secret. The secret itself is stored nowhere.
    secret_hash bytea       NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, client_id, id),
    CONSTRAINT client_secret_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth.client (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT client_secret_hash_unique UNIQUE (tenant_id, secret_hash),
    CONSTRAINT client_secret_hash_is_sha256 CHECK (octet_length(secret_hash) = 32),
    -- There is no secret that does not expire.
    CONSTRAINT client_secret_expires CHECK (expires_at > created_at)
);

SELECT platform.enable_tenant_rls('oauth.client_secret');

CREATE TABLE oauth.client_key (
    tenant_id uuid        NOT NULL,
    client_id uuid        NOT NULL,
    key_id    text        COLLATE "C" NOT NULL,
    -- The public key as a JSON Web Key. Never a private one.
    jwk       jsonb       NOT NULL,
    -- The order the keys were added in.
    position  integer     NOT NULL,
    added_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, client_id, key_id),
    CONSTRAINT client_key_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth.client (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT client_key_id_length CHECK (char_length(key_id) BETWEEN 1 AND 128),
    CONSTRAINT client_key_is_public CHECK (
        NOT (jwk ?| ARRAY['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']))
);

SELECT platform.enable_tenant_rls('oauth.client_key');

CREATE TABLE oauth.resource_server (
    tenant_id      uuid        NOT NULL,
    id             uuid        NOT NULL,
    application_id uuid        NOT NULL,
    -- The audience of its tokens. Never changes; compared byte for byte.
    audience       text        COLLATE "C" NOT NULL,
    name           text        NOT NULL,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    version        integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT resource_server_application_fk
        FOREIGN KEY (tenant_id, application_id)
        REFERENCES oauth.application (tenant_id, id),
    CONSTRAINT resource_server_audience_unique UNIQUE (tenant_id, audience),
    CONSTRAINT resource_server_application_unique UNIQUE (tenant_id, application_id),
    CONSTRAINT resource_server_audience_shape CHECK (
        char_length(audience) <= 255
        AND (audience LIKE 'https://%' OR audience LIKE 'urn:%')),
    CONSTRAINT resource_server_name_length CHECK (char_length(name) BETWEEN 1 AND 100)
);

SELECT platform.enable_tenant_rls('oauth.resource_server');

CREATE TABLE oauth.resource_server_scope (
    tenant_id          uuid    NOT NULL,
    resource_server_id uuid    NOT NULL,
    name               text    COLLATE "C" NOT NULL,
    description        text    NOT NULL,
    -- The order the scopes were given in.
    position           integer NOT NULL,
    PRIMARY KEY (tenant_id, resource_server_id, name),
    CONSTRAINT resource_server_scope_server_fk
        FOREIGN KEY (tenant_id, resource_server_id)
        REFERENCES oauth.resource_server (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT resource_server_scope_name_length CHECK (char_length(name) BETWEEN 1 AND 128),
    CONSTRAINT resource_server_scope_description_length CHECK (char_length(description) <= 200)
);

SELECT platform.enable_tenant_rls('oauth.resource_server_scope');
