-- When each subscription of a webhook endpoint began, so that an event
-- dispatched after an endpoint was registered or given a type, but that
-- happened before, is not delivered to it. Subscriptions that exist already
-- count from now: what was dispatched before this migration is unchanged.
ALTER TABLE webhooks.subscription
    ADD COLUMN since timestamptz NOT NULL DEFAULT now();
ALTER TABLE webhooks.subscription
    ALTER COLUMN since DROP DEFAULT;
