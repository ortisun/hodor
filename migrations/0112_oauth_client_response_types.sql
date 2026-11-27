-- Issue-127: the response types a client registers, what the authorization
-- endpoint may answer it with. Only a client of the authorization code has
-- them; every such client made before they existed answers `code` alone.
-- See docs/architecture/contexts/oauth.md, "Response types of a client",
-- and docs/decisions/0072-the-state-hash-and-the-response-types-of-a-client.md.

ALTER TABLE oauth.client
    ADD COLUMN response_types text[] NOT NULL DEFAULT '{}';

-- Row-level security is forced on the table, so it is lifted for the
-- backfill alone, in this transaction, and forced again.
ALTER TABLE oauth.client NO FORCE ROW LEVEL SECURITY;

UPDATE oauth.client
SET response_types = '{code}'
WHERE 'authorization_code' = ANY (grant_types);

ALTER TABLE oauth.client FORCE ROW LEVEL SECURITY;

ALTER TABLE oauth.client
    ADD CONSTRAINT client_response_types_known CHECK (
        response_types <@ ARRAY['code', 'id_token', 'code id_token', 'none']::text[]),
    -- At least one with the grant that lets a client send people to the
    -- authorization endpoint, and none without it.
    ADD CONSTRAINT client_response_types_need_code CHECK (
        (cardinality(response_types) > 0) = ('authorization_code' = ANY (grant_types)));
