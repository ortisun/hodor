-- Issue-60: where logout initiated by the relying party may send a person
-- back to. Specified in docs/architecture/contexts/oauth.md, "Logout
-- initiated by the relying party".

ALTER TABLE oauth.client
    -- Compared byte for byte with what a logout request names.
    ADD COLUMN post_logout_redirect_uris text[] COLLATE "C" NOT NULL DEFAULT '{}';

ALTER TABLE oauth.client
    -- Only a client that signs people in with a code gets ID tokens, and
    -- with them a reason to send people back after signing out.
    ADD CONSTRAINT client_post_logout_needs_code CHECK (
        cardinality(post_logout_redirect_uris) = 0
        OR 'authorization_code' = ANY (grant_types)),
    ADD CONSTRAINT client_post_logout_at_most_ten CHECK (
        cardinality(post_logout_redirect_uris) <= 10);
