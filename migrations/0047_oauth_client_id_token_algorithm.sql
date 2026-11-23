-- How a client's ID tokens are signed, its `id_token_signed_response_alg`
-- of OpenID Connect Registration: ES256, Hodor's own default, or RS256,
-- which OpenID Connect requires every OpenID Provider to offer.
-- See docs/architecture/contexts/oauth.md, "The ID token".

ALTER TABLE oauth.client
    ADD COLUMN id_token_algorithm text NOT NULL DEFAULT 'ES256'
        CONSTRAINT client_id_token_algorithm_known CHECK (id_token_algorithm IN ('ES256', 'RS256'));
