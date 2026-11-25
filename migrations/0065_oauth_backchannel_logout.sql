-- Issue-100: back-channel logout. Where a client is sent a logout token
-- when a session it signed a person in with ends, and the deliveries that
-- carry one token to one client for one session.
-- See docs/architecture/contexts/oauth.md, "Back-channel logout".

ALTER TABLE oauth.client
    -- Compared byte for byte; checked for a public address when it is set,
    -- and again by the guarded client at every attempt.
    ADD COLUMN backchannel_logout_uri text COLLATE "C",
    ADD COLUMN backchannel_logout_session_required boolean NOT NULL DEFAULT false;

ALTER TABLE oauth.client
    ADD CONSTRAINT client_backchannel_logout_uri_form CHECK (
        char_length(backchannel_logout_uri) BETWEEN 1 AND 2000
        AND (backchannel_logout_uri LIKE 'https://%' OR backchannel_logout_uri LIKE 'http://%')),
    -- Only a client that signs people in with a code has sessions to be
    -- told about.
    ADD CONSTRAINT client_backchannel_logout_needs_code CHECK (
        backchannel_logout_uri IS NULL OR 'authorization_code' = ANY (grant_types)),
    ADD CONSTRAINT client_backchannel_logout_session_needs_uri CHECK (
        NOT backchannel_logout_session_required OR backchannel_logout_uri IS NOT NULL);

-- The clients of a session: the grants made in it.
CREATE INDEX authorization_grant_session_idx
    ON oauth.authorization_grant (tenant_id, session_id);

-- `session_id` and `user_id` name rows of the session and identity
-- contexts; they are not references, since contexts do not reference each
-- other's tables.
CREATE TABLE oauth.logout_delivery (
    tenant_id            uuid        NOT NULL,
    id                   uuid        NOT NULL,
    client_id            uuid        NOT NULL,
    session_id           uuid        NOT NULL,
    user_id              uuid        NOT NULL,
    status               text        NOT NULL,
    attempts             integer     NOT NULL,
    next_attempt_at      timestamptz NOT NULL,
    leased_until         timestamptz,
    last_response_status integer,
    last_error           text,
    created_at           timestamptz NOT NULL,
    finished_at          timestamptz,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT logout_delivery_client_fk
        FOREIGN KEY (tenant_id, client_id)
        REFERENCES oauth.client (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT logout_delivery_once_per_client_and_session
        UNIQUE (tenant_id, client_id, session_id),
    CONSTRAINT logout_delivery_status_known CHECK (status IN ('pending', 'delivered', 'set_aside')),
    CONSTRAINT logout_delivery_attempts_not_negative CHECK (attempts >= 0),
    CONSTRAINT logout_delivery_last_error_length CHECK (char_length(last_error) <= 500),
    CONSTRAINT logout_delivery_finished_when_not_pending
        CHECK ((status = 'pending') = (finished_at IS NULL)),
    CONSTRAINT logout_delivery_leased_only_while_pending
        CHECK (status = 'pending' OR leased_until IS NULL)
);

SELECT platform.enable_tenant_rls('oauth.logout_delivery');

-- The worker's search for deliveries that are due, across tenants.
CREATE INDEX logout_delivery_due_idx
    ON oauth.logout_delivery (next_attempt_at)
    WHERE status = 'pending';
-- The deliveries a client has in flight.
CREATE INDEX logout_delivery_leased_idx
    ON oauth.logout_delivery (tenant_id, client_id, leased_until)
    WHERE status = 'pending' AND leased_until IS NOT NULL;
-- The cleanup of finished deliveries.
CREATE INDEX logout_delivery_finished_idx
    ON oauth.logout_delivery (finished_at)
    WHERE status <> 'pending';
