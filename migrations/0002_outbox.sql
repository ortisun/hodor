-- Transactional outbox. Events are inserted in the same transaction as the
-- state change that produced them and delivered to handlers by the worker.
-- See docs/adr/0003-context-communication.md.

CREATE TABLE platform.outbox (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL,
    event_type      text        NOT NULL,
    payload         jsonb       NOT NULL,
    occurred_at     timestamptz NOT NULL,
    actor           jsonb       NOT NULL,
    correlation_id  uuid        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    dispatched_at   timestamptz,
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error      text,
    PRIMARY KEY (tenant_id, id)
);

SELECT platform.enable_tenant_rls('platform.outbox');

-- The dispatcher's scan for pending events.
CREATE INDEX outbox_pending_idx
    ON platform.outbox (next_attempt_at, created_at)
    WHERE dispatched_at IS NULL;
