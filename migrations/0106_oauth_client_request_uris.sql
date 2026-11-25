-- Issue-122: the addresses where a client keeps request objects Hodor may
-- fetch, its `request_uris` of OpenID Connect Registration. A request's
-- `request_uri` is fetched only when it starts with one of them.
-- See docs/architecture/contexts/oauth.md, "Request object addresses".

ALTER TABLE oauth.client
    -- Compared byte for byte with the start of what a request names.
    ADD COLUMN request_uris text[] COLLATE "C" NOT NULL DEFAULT '{}';

ALTER TABLE oauth.client
    -- Only a client that sends authorization requests sends them by
    -- reference.
    ADD CONSTRAINT client_request_uris_need_code CHECK (
        cardinality(request_uris) = 0
        OR 'authorization_code' = ANY (grant_types)),
    ADD CONSTRAINT client_request_uris_at_most_ten CHECK (
        cardinality(request_uris) <= 10);
