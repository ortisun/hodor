-- Issue-134: managing a registration. A client's login initiation address,
-- which a registration names and the account page links to; and the
-- SHA-256 of a registered client's registration access token, replaced at
-- every change of its registration. Removing a registration deletes the
-- client's row, and every table that references it goes with it by the
-- `ON DELETE CASCADE` of its reference.
-- See docs/architecture/contexts/oauth.md, "Managing a registration", and
-- Decision 0084.

ALTER TABLE oauth.client
    -- Kept exactly as given; the person's browser follows it, Hodor never
    -- calls it.
    ADD COLUMN initiate_login_uri text COLLATE "C",
    -- Never the token: only its hash.
    ADD COLUMN registration_token_hash bytea;

ALTER TABLE oauth.client
    ADD CONSTRAINT client_initiate_login_uri_https CHECK (
        initiate_login_uri IS NULL
        OR (initiate_login_uri LIKE 'https://%' AND char_length(initiate_login_uri) <= 2000)),
    -- Only a registered client manages its registration.
    ADD CONSTRAINT client_registration_token_shape CHECK (
        registration_token_hash IS NULL
        OR (registered AND octet_length(registration_token_hash) = 32));
