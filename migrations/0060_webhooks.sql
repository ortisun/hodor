-- The webhooks context: endpoints of a tenant, the event types each
-- receives, the sealed secrets deliveries are signed with, and the
-- deliveries themselves.
-- See docs/architecture/contexts/webhooks.md, "Storage".

CREATE SCHEMA webhooks;
GRANT USAGE ON SCHEMA webhooks TO hodor_app, hodor_platform;

CREATE TABLE webhooks.endpoint (
    tenant_id   uuid        NOT NULL,
    id          uuid        NOT NULL,
    url         text        NOT NULL,
    description text,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    version     integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT endpoint_url_length CHECK (char_length(url) BETWEEN 1 AND 1000),
    CONSTRAINT endpoint_url_scheme CHECK (url LIKE 'https://%' OR url LIKE 'http://%'),
    CONSTRAINT endpoint_description_length CHECK (char_length(description) <= 200)
);

SELECT platform.enable_tenant_rls('webhooks.endpoint');

CREATE TABLE webhooks.subscription (
    tenant_id   uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    event_type  text NOT NULL,
    PRIMARY KEY (tenant_id, endpoint_id, event_type),
    CONSTRAINT subscription_endpoint_fk
        FOREIGN KEY (tenant_id, endpoint_id)
        REFERENCES webhooks.endpoint (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT subscription_event_type_length CHECK (char_length(event_type) BETWEEN 1 AND 100)
);

SELECT platform.enable_tenant_rls('webhooks.subscription');
-- The fan-out: the endpoints of a tenant subscribed to a type.
CREATE INDEX subscription_event_type_idx ON webhooks.subscription (tenant_id, event_type);

-- `sealed_secret` is sealed with the secret box for the purpose
-- `webhooks.signing_secret`; `expires_at` is NULL for the current secret.
CREATE TABLE webhooks.signing_secret (
    tenant_id     uuid        NOT NULL,
    id            uuid        NOT NULL,
    endpoint_id   uuid        NOT NULL,
    sealed_secret bytea       NOT NULL,
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT signing_secret_endpoint_fk
        FOREIGN KEY (tenant_id, endpoint_id)
        REFERENCES webhooks.endpoint (tenant_id, id) ON DELETE CASCADE
);

SELECT platform.enable_tenant_rls('webhooks.signing_secret');
CREATE INDEX signing_secret_endpoint_idx ON webhooks.signing_secret (tenant_id, endpoint_id);

CREATE TABLE webhooks.delivery (
    tenant_id            uuid        NOT NULL,
    id                   uuid        NOT NULL,
    endpoint_id          uuid        NOT NULL,
    event_id             uuid        NOT NULL,
    event_type           text        NOT NULL,
    payload              text        NOT NULL,
    status               text        NOT NULL,
    attempts             integer     NOT NULL,
    next_attempt_at      timestamptz NOT NULL,
    leased_until         timestamptz,
    last_response_status integer,
    last_error           text,
    created_at           timestamptz NOT NULL,
    finished_at          timestamptz,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT delivery_endpoint_fk
        FOREIGN KEY (tenant_id, endpoint_id)
        REFERENCES webhooks.endpoint (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT delivery_once_per_endpoint_and_event UNIQUE (tenant_id, endpoint_id, event_id),
    CONSTRAINT delivery_status_known CHECK (status IN ('pending', 'delivered', 'set_aside')),
    CONSTRAINT delivery_payload_size CHECK (octet_length(payload) <= 65536),
    CONSTRAINT delivery_attempts_not_negative CHECK (attempts >= 0),
    CONSTRAINT delivery_last_error_length CHECK (char_length(last_error) <= 500),
    CONSTRAINT delivery_finished_when_not_pending
        CHECK ((status = 'pending') = (finished_at IS NULL)),
    CONSTRAINT delivery_leased_only_while_pending
        CHECK (status = 'pending' OR leased_until IS NULL)
);

SELECT platform.enable_tenant_rls('webhooks.delivery');

-- The worker's search for deliveries that are due, across tenants.
CREATE INDEX delivery_due_idx
    ON webhooks.delivery (next_attempt_at)
    WHERE status = 'pending';
-- The deliveries an endpoint has in flight.
CREATE INDEX delivery_leased_idx
    ON webhooks.delivery (tenant_id, endpoint_id, leased_until)
    WHERE status = 'pending' AND leased_until IS NOT NULL;
-- Listing a tenant's deliveries, newest first, by endpoint.
CREATE INDEX delivery_endpoint_idx ON webhooks.delivery (tenant_id, endpoint_id, id);
-- The cleanup of finished deliveries.
CREATE INDEX delivery_finished_idx
    ON webhooks.delivery (finished_at)
    WHERE status <> 'pending';
