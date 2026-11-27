-- Issue-139: front-channel logout. The address the signed-out page loads in
-- a frame to tell a client that a session it signed a person in with ended
-- in the person's browser, and the frames kept for one sign-out, found by
-- the SHA-256 of the handle the browser holds. The handle itself is never
-- stored. See docs/architecture/contexts/oauth.md, "Front-channel logout",
-- and Decision 0081.

ALTER TABLE oauth.client
    -- Compared byte for byte. That it shares the scheme, host and port of
    -- one of the client's redirect addresses is checked by the domain, as
    -- the rules of redirect addresses are.
    ADD COLUMN frontchannel_logout_uri text COLLATE "C",
    ADD COLUMN frontchannel_logout_session_required boolean NOT NULL DEFAULT false;

ALTER TABLE oauth.client
    ADD CONSTRAINT client_frontchannel_logout_uri_form CHECK (
        char_length(frontchannel_logout_uri) BETWEEN 1 AND 2000
        AND (frontchannel_logout_uri LIKE 'https://%' OR frontchannel_logout_uri LIKE 'http://%')),
    -- Only a client that signs people in with a code has sessions to be
    -- told about.
    ADD CONSTRAINT client_frontchannel_logout_needs_code CHECK (
        frontchannel_logout_uri IS NULL OR 'authorization_code' = ANY (grant_types)),
    ADD CONSTRAINT client_frontchannel_logout_session_needs_uri CHECK (
        NOT frontchannel_logout_session_required OR frontchannel_logout_uri IS NOT NULL);

-- `session_id` names a row of the session context; it is not a reference,
-- since contexts do not reference each other's tables.
CREATE TABLE oauth.frontchannel_logout (
    tenant_id   uuid        NOT NULL,
    id          uuid        NOT NULL,
    handle_hash bytea       NOT NULL,
    session_id  uuid        NOT NULL,
    frames      text[]      NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    -- A handle is looked up by tenant and hash together, so a handle
    -- presented to another tenant finds nothing.
    CONSTRAINT frontchannel_logout_handle_unique UNIQUE (tenant_id, handle_hash),
    CONSTRAINT frontchannel_logout_handle_is_sha256 CHECK (octet_length(handle_hash) = 32),
    CONSTRAINT frontchannel_logout_has_frames CHECK (cardinality(frames) >= 1),
    CONSTRAINT frontchannel_logout_lives_two_minutes CHECK (
        expires_at = created_at + interval '120 seconds')
);

SELECT platform.enable_tenant_rls('oauth.frontchannel_logout');

-- The cleanup of expired frames.
CREATE INDEX frontchannel_logout_expires_idx
    ON oauth.frontchannel_logout (expires_at);
