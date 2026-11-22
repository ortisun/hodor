-- The token endpoint: the assertions clients proved who they are with, so
-- that each is used once.
-- See docs/architecture/contexts/oauth.md, "Checking a client assertion".

CREATE TABLE oauth.client_assertion (
    tenant_id  uuid        NOT NULL,
    client_id  uuid        NOT NULL,
    -- The `jti` of the assertion, compared byte for byte.
    jti        text        COLLATE "C" NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, client_id, jti),
    CONSTRAINT client_assertion_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth.client (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT client_assertion_jti_shape CHECK (char_length(jti) BETWEEN 1 AND 255)
);

SELECT platform.enable_tenant_rls('oauth.client_assertion');
