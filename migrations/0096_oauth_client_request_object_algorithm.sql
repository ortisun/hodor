-- How a client signs its request objects, its `request_object_signing_alg`
-- of OpenID Connect Registration: ES256, RS256 or PS256, which accepts only
-- objects signed with it; none, which accepts only unsigned objects; or
-- null, as for every client made before it, which accepts any of the three.
-- See docs/architecture/contexts/oauth.md, "Request objects".

ALTER TABLE oauth.client
    ADD COLUMN request_object_signing_alg text
        CONSTRAINT client_request_object_signing_alg_known
            CHECK (request_object_signing_alg IN ('ES256', 'RS256', 'PS256', 'none'));
