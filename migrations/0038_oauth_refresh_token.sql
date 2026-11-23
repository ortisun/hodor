-- Refresh tokens: each family, and every token it has had, by its hash.
-- See docs/architecture/contexts/oauth.md, "Refresh tokens".

CREATE TABLE oauth.refresh_token_family (
    tenant_id         uuid        NOT NULL,
    id                uuid        NOT NULL,
    grant_id          uuid        NOT NULL,
    client_id         uuid        NOT NULL,
    user_id           uuid        NOT NULL,
    session_id        uuid        NOT NULL,
    scopes            text[]      NOT NULL,
    audiences         text[]      COLLATE "C" NOT NULL,
    offline           boolean     NOT NULL,
    signed_in_at      timestamptz NOT NULL,
    methods           text[]      NOT NULL,
    -- The secret each next token is derived with, sealed by the tenant's
    -- secret box for `oauth.refresh_token_family_secret`.
    sealed_secret     bytea       NOT NULL,
    generation        integer     NOT NULL,
    -- SHA-256 of the newest token. No token is stored.
    current_hash      bytea       NOT NULL,
    moved_at          timestamptz,
    -- What the refresh that last moved the family asked for.
    moved_scopes      text[]      NOT NULL DEFAULT '{}',
    moved_resource    text        COLLATE "C",
    status            text        NOT NULL,
    created_at        timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    idle_seconds      integer     NOT NULL,
    last_used_at      timestamptz NOT NULL,
    revoked_at        timestamptz,
    revocation_reason text,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT refresh_token_family_grant_fk
        FOREIGN KEY (tenant_id, grant_id)
        REFERENCES oauth.authorization_grant (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT refresh_token_family_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth.client (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT refresh_token_family_hash_is_sha256 CHECK (octet_length(current_hash) = 32),
    CONSTRAINT refresh_token_family_generation_positive CHECK (generation >= 1),
    -- A family that has moved says when; one that has not, never.
    CONSTRAINT refresh_token_family_moved_known CHECK ((generation > 1) = (moved_at IS NOT NULL)),
    CONSTRAINT refresh_token_family_status_known CHECK (status IN ('active', 'revoked')),
    CONSTRAINT refresh_token_family_revocation_complete CHECK (
        (status = 'revoked') = (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)),
    -- The bounds of the token policy: 1 hour to 365 days, and an idle time
    -- of at least an hour and at most the lifetime.
    CONSTRAINT refresh_token_family_lifetime_bounded CHECK (
        expires_at > created_at AND expires_at <= created_at + interval '365 days'),
    CONSTRAINT refresh_token_family_idle_bounded CHECK (
        idle_seconds >= 3600 AND idle_seconds <= 365 * 86400)
);

SELECT platform.enable_tenant_rls('oauth.refresh_token_family');
CREATE INDEX refresh_token_family_grant_idx ON oauth.refresh_token_family (tenant_id, grant_id);

CREATE TABLE oauth.refresh_token (
    tenant_id  uuid        NOT NULL,
    -- SHA-256 of a token of the family. The token itself is stored nowhere.
    token_hash bytea       NOT NULL,
    family_id  uuid        NOT NULL,
    generation integer     NOT NULL,
    issued_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, token_hash),
    CONSTRAINT refresh_token_family_fk
        FOREIGN KEY (tenant_id, family_id)
        REFERENCES oauth.refresh_token_family (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT refresh_token_hash_is_sha256 CHECK (octet_length(token_hash) = 32),
    CONSTRAINT refresh_token_generation_positive CHECK (generation >= 1),
    -- A family has one token per generation.
    CONSTRAINT refresh_token_generation_unique UNIQUE (tenant_id, family_id, generation)
);

SELECT platform.enable_tenant_rls('oauth.refresh_token');
