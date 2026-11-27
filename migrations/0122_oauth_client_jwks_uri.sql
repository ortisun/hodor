-- Issue-136: a client's keys at its address. A client using
-- `private_key_jwt` may name the address where it publishes its keys
-- itself, its `jwks_uri`, in place of keys kept in `oauth.client_key`.
-- What the address answers is never stored: each server keeps it in memory
-- for an hour at most (Decision 0079).
-- See docs/architecture/contexts/oauth.md, "Keys at the client's address".

ALTER TABLE oauth.client
    -- Compared byte for byte; checked for a public address when it is set,
    -- and again by the guarded client at every fetch.
    ADD COLUMN jwks_uri text COLLATE "C";

ALTER TABLE oauth.client
    ADD CONSTRAINT client_jwks_uri_form CHECK (
        char_length(jwks_uri) BETWEEN 1 AND 2000
        AND (jwks_uri LIKE 'https://%' OR jwks_uri LIKE 'http://%')),
    -- Only a client that proves who it is with its own keys has them at
    -- an address.
    ADD CONSTRAINT client_jwks_uri_needs_private_key_jwt CHECK (
        jwks_uri IS NULL OR authentication_method = 'private_key_jwt');
