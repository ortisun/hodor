-- How a client's ID tokens and UserInfo answers are signed: its
-- `id_token_signed_response_alg`, now ES256, RS256, PS256 or EdDSA, and its
-- `userinfo_signed_response_alg`, one of the same four, or null, as for
-- every client made before it, for UserInfo answered in JSON.
-- See docs/architecture/contexts/oauth.md, "The ID token" and "Signed
-- UserInfo answers".

ALTER TABLE oauth.client DROP CONSTRAINT client_id_token_algorithm_known;
ALTER TABLE oauth.client ADD CONSTRAINT client_id_token_algorithm_known
    CHECK (id_token_algorithm IN ('ES256', 'RS256', 'PS256', 'EdDSA'));

ALTER TABLE oauth.client
    ADD COLUMN userinfo_signed_response_alg text
        CONSTRAINT client_userinfo_signed_response_alg_known
            CHECK (userinfo_signed_response_alg IN ('ES256', 'RS256', 'PS256', 'EdDSA'));
