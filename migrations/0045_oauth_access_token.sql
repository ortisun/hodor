-- The register of access tokens: a record of every access token issued,
-- by its `jti`, so that revocation and introspection can tell whether it
-- is still in force. The token itself is stored nowhere.
-- See docs/architecture/contexts/oauth.md, "The register of access tokens".

CREATE TABLE oauth.access_token (
    tenant_id         uuid        NOT NULL,
    -- The `jti` of the token, compared byte for byte.
    token_id          text        COLLATE "C" NOT NULL,
    client_id         uuid        NOT NULL,
    -- The grant it was issued under; none for client credentials.
    grant_id          uuid,
    -- The refresh token family it came from; none for a code or client
    -- credentials.
    family_id         uuid,
    expires_at        timestamptz NOT NULL,
    revoked_at        timestamptz,
    revocation_reason text,
    PRIMARY KEY (tenant_id, token_id),
    CONSTRAINT access_token_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth.client (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT access_token_grant_fk
        FOREIGN KEY (tenant_id, grant_id)
        REFERENCES oauth.authorization_grant (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT access_token_family_fk
        FOREIGN KEY (tenant_id, family_id)
        REFERENCES oauth.refresh_token_family (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT access_token_id_shape CHECK (char_length(token_id) BETWEEN 1 AND 255),
    -- A token from a family was issued under the family's grant.
    CONSTRAINT access_token_family_has_grant CHECK (family_id IS NULL OR grant_id IS NOT NULL),
    CONSTRAINT access_token_revocation_complete CHECK (
        (revoked_at IS NULL) = (revocation_reason IS NULL))
);

SELECT platform.enable_tenant_rls('oauth.access_token');
CREATE INDEX access_token_expiry_idx ON oauth.access_token (expires_at);
