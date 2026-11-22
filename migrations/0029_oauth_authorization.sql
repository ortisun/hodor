-- The authorization endpoint: requests waiting for their person to sign
-- in, grants, and authorization codes.
-- See docs/architecture/contexts/oauth.md, "Authorization endpoint".

CREATE TABLE oauth.authorization_request (
    tenant_id   uuid        NOT NULL,
    id          uuid        NOT NULL,
    -- SHA-256 of the secret the browser holds. The secret is stored nowhere.
    secret_hash bytea       NOT NULL,
    client_id   uuid        NOT NULL,
    -- The checked request, as the OAuth context wrote it.
    request     jsonb       NOT NULL,
    received_at timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT authorization_request_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth.client (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT authorization_request_secret_is_sha256 CHECK (octet_length(secret_hash) = 32),
    CONSTRAINT authorization_request_expires CHECK (expires_at > received_at)
);

SELECT platform.enable_tenant_rls('oauth.authorization_request');

CREATE TABLE oauth.authorization_grant (
    tenant_id         uuid        NOT NULL,
    id                uuid        NOT NULL,
    client_id         uuid        NOT NULL,
    user_id           uuid        NOT NULL,
    session_id        uuid        NOT NULL,
    scopes            text[]      NOT NULL,
    audiences         text[]      COLLATE "C" NOT NULL,
    status            text        NOT NULL,
    created_at        timestamptz NOT NULL,
    revoked_at        timestamptz,
    revocation_reason text,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT authorization_grant_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth.client (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT authorization_grant_status_known CHECK (status IN ('active', 'revoked')),
    -- A revoked grant says when and why; an active one says neither.
    CONSTRAINT authorization_grant_revocation_complete CHECK (
        (status = 'revoked') = (revoked_at IS NOT NULL AND revocation_reason IS NOT NULL))
);

SELECT platform.enable_tenant_rls('oauth.authorization_grant');

CREATE INDEX authorization_grant_client_idx ON oauth.authorization_grant (tenant_id, client_id);

CREATE TABLE oauth.authorization_code (
    tenant_id      uuid        NOT NULL,
    -- SHA-256 of the code. The code itself is stored nowhere.
    code_hash      bytea       NOT NULL,
    grant_id       uuid        NOT NULL,
    client_id      uuid        NOT NULL,
    -- Compared byte for byte with what the token request names.
    redirect_uri   text        COLLATE "C" NOT NULL,
    scopes         text[]      NOT NULL,
    audiences      text[]      COLLATE "C" NOT NULL,
    code_challenge text,
    nonce          text,
    session_id     uuid        NOT NULL,
    user_id        uuid        NOT NULL,
    signed_in_at   timestamptz NOT NULL,
    methods        text[]      NOT NULL,
    issued_at      timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    redeemed_at    timestamptz,
    PRIMARY KEY (tenant_id, code_hash),
    CONSTRAINT authorization_code_grant_fk
        FOREIGN KEY (tenant_id, grant_id)
        REFERENCES oauth.authorization_grant (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT authorization_code_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth.client (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT authorization_code_hash_is_sha256 CHECK (octet_length(code_hash) = 32),
    -- A code lives a minute at most.
    CONSTRAINT authorization_code_short_lived CHECK (
        expires_at > issued_at AND expires_at <= issued_at + interval '60 seconds'),
    -- An S256 challenge is the base64url of a SHA-256 digest.
    CONSTRAINT authorization_code_challenge_shape CHECK (
        code_challenge IS NULL OR code_challenge ~ '^[A-Za-z0-9_-]{43}$')
);

SELECT platform.enable_tenant_rls('oauth.authorization_code');

CREATE INDEX authorization_code_grant_idx ON oauth.authorization_code (tenant_id, grant_id);
