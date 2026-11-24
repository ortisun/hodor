# hodor-webhooks application

## Overview

The ports and the use cases of the webhooks context, over the domain
module. Every port method that touches a tenant's data takes a
`UnitOfWork` bound to that tenant; `DueDeliveries` is the one port that is
not.

## Interface

- `ports.rs`: `EndpointStore` (`insert`, `get`, `lock`, `list`, `count`,
  `update`, `remove`, `subscribed_to`, `add_secret`, `secrets`,
  `end_secret`, `remove_ended_secrets`), `DeliveryStore` (`insert`, `get`,
  `take`, `lock`, `leased`, `update`, `list`) with `DeliveryQuery`,
  `DueDeliveries` (`due(now, limit)`), `HmacSha256` (`mac(key, message)`).
- `service.rs`: `WebhookService::new(units_of_work, endpoints, deliveries,
  secrets, destinations, random, clock)` with `register`, `get`, `list`,
  `replace_subscriptions`, `rotate_secret`, `remove`, `deliveries`,
  `redeliver`, `event_types`.
- `fan_out.rs`: `WebhookFanOut`, an `EventHandler` named `webhooks` that
  handles the types of the catalog.
- `delivery.rs`: `WebhookSender::new(SenderPorts, DeliverySettings)` with
  `lease_due(limit)` and `send(lease)`; `DeliverySettings` (retry policy,
  time limit, in flight per endpoint, `LEASE_MARGIN` of 60 seconds).

## Invariants

- `register` checks the address syntax, then `DestinationCheck`, before
  anything is stored; `http.url_invalid`, `http.destination_forbidden` and
  `http.unreachable` become `webhooks.endpoint_address_invalid`,
  `webhooks.endpoint_address_forbidden` and
  `webhooks.endpoint_address_unresolvable`. `count` is taken under a lock
  per tenant before the twentieth endpoint is passed.
- `rotate_secret` locks the endpoint, gives the replaced secret the overlap
  and ends any older one at once (`domain::secret::rotation`).
- `WebhookFanOut::handle` refuses an event whose tenant is not the unit of
  work's (`webhooks.tenant_mismatch`) and makes at most one delivery per
  endpoint and event.
- `WebhookSender::lease_due` locks the endpoint, then takes the delivery
  skipping one another worker holds, counts the endpoint's leases and
  commits before anything is sent; `send` records only if the delivery is
  still as leased (`Delivery::is_as_leased`), otherwise it answers
  `Skipped`. A secret that does not open fails the attempt.

## Side Effects

- Records `webhooks.endpoint_registered`, `webhooks.subscriptions_changed`,
  `webhooks.secret_rotated`, `webhooks.endpoint_removed`,
  `webhooks.redelivery_requested` and `webhooks.delivery_set_aside`.
- Sends `POST` requests with `webhook-id`, `webhook-timestamp` and
  `webhook-signature` through `HttpClient`, each with the time limit of an
  attempt.

## Verification

- Run: `cargo test -p hodor-webhooks --test service`
