-- Client registration: whether clients may register themselves in a
-- tenant, the application they belong to, the ways a registration is
-- allowed and the policy that bounds it; and the initial access tokens an
-- administrator hands out. Only the SHA-256 of a token is kept, never the
-- token. See docs/architecture/contexts/oauth.md, "Client registration",
-- and Decision 0075.

CREATE TABLE oauth.client_registration (
    tenant_id      uuid        NOT NULL,
    enabled        boolean     NOT NULL,
    application_id uuid,
    ways           text[]      NOT NULL,
    max_clients    integer     NOT NULL,
    -- The limits as the administration interface writes them; `hosts` is
    -- null for any host.
    policy         jsonb       NOT NULL,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    version        integer     NOT NULL DEFAULT 0,
    -- One row per tenant that set its settings; none reads as off.
    PRIMARY KEY (tenant_id),
    -- Only an application of the tenant itself can be named.
    CONSTRAINT client_registration_application_fk
        FOREIGN KEY (tenant_id, application_id)
        REFERENCES oauth.application (tenant_id, id),
    CONSTRAINT client_registration_ways_known CHECK (
        cardinality(ways) <= 3
        AND ways <@ ARRAY['initial_access_token', 'software_statement', 'open']::text[]),
    CONSTRAINT client_registration_on_needs_application_and_way CHECK (
        NOT enabled OR (application_id IS NOT NULL AND cardinality(ways) >= 1)),
    CONSTRAINT client_registration_max_clients_bounded CHECK (max_clients BETWEEN 1 AND 1000),
    CONSTRAINT client_registration_policy_object CHECK (jsonb_typeof(policy) = 'object')
);

SELECT platform.enable_tenant_rls('oauth.client_registration');

CREATE TABLE oauth.initial_access_token (
    tenant_id         uuid        NOT NULL,
    id                uuid        NOT NULL,
    token_hash        bytea       NOT NULL,
    -- The last four characters of the token, to tell tokens apart.
    hint              text        NOT NULL,
    name              text        NOT NULL,
    max_registrations integer     NOT NULL,
    registrations     integer     NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    last_used_at      timestamptz,
    revoked_at        timestamptz,
    PRIMARY KEY (tenant_id, id),
    -- A token is looked up by tenant and hash together, so a token
    -- presented to another tenant finds nothing.
    CONSTRAINT initial_access_token_hash_unique UNIQUE (tenant_id, token_hash),
    CONSTRAINT initial_access_token_hash_is_sha256 CHECK (octet_length(token_hash) = 32),
    CONSTRAINT initial_access_token_hint_shape CHECK (hint ~ '^[0-9a-f]{4}$'),
    CONSTRAINT initial_access_token_name_length CHECK (char_length(name) BETWEEN 1 AND 100),
    CONSTRAINT initial_access_token_registrations_bounded CHECK (
        max_registrations BETWEEN 1 AND 1000
        AND registrations BETWEEN 0 AND max_registrations),
    -- There is no token that does not expire.
    CONSTRAINT initial_access_token_lifetime_bounded CHECK (
        expires_at - created_at BETWEEN interval '1 hour' AND interval '90 days')
);

SELECT platform.enable_tenant_rls('oauth.initial_access_token');

-- The list of a tenant's tokens, newest first.
CREATE INDEX initial_access_token_created_idx
    ON oauth.initial_access_token (tenant_id, created_at DESC);
