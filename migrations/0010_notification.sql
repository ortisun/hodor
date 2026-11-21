-- The notification context: messages waiting to be delivered, and the
-- record of the ones that were.
-- See docs/architecture/contexts/notification.md.

CREATE SCHEMA notification;
GRANT USAGE ON SCHEMA notification TO hodor_app, hodor_platform;

-- `variables` holds what will be sent, including any link, and is emptied
-- the moment the message stops being pending.
CREATE TABLE notification.message (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL,
    recipient       text        NOT NULL,
    template        text        NOT NULL,
    locale          text        NOT NULL,
    variables       jsonb       NOT NULL,
    status          text        NOT NULL,
    attempts        integer     NOT NULL,
    next_attempt_at timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    last_error      text,
    created_at      timestamptz NOT NULL,
    sent_at         timestamptz,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT message_status_known
        CHECK (status IN ('pending', 'sent', 'failed', 'expired')),
    CONSTRAINT message_attempts_not_negative CHECK (attempts >= 0),
    CONSTRAINT message_contents_only_while_pending
        CHECK (status = 'pending' OR variables = '{}'::jsonb),
    CONSTRAINT message_sent_has_a_moment
        CHECK ((status = 'sent') = (sent_at IS NOT NULL))
);

SELECT platform.enable_tenant_rls('notification.message');

-- The worker's search for messages that are due, across tenants.
CREATE INDEX message_due_idx
    ON notification.message (next_attempt_at, created_at)
    WHERE status = 'pending';
