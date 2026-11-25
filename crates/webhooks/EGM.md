# hodor-webhooks

## Overview

The `hodor-webhooks` crate (`Cargo.toml` description: "The webhooks
context: endpoints of a tenant subscribed to its events, signed deliveries
made from the outbox and sent by the worker."). A base context: it depends
on `hodor-kernel` alone (`tests/architecture/src/lib.rs`, `RULES`).
Administrators manage endpoints through `WebhookService`; the outbox
dispatcher hands events to `WebhookFanOut`, which makes deliveries; the
worker sends them through `WebhookSender`. The specification is
`docs/architecture/contexts/webhooks.md`; Decision 0032 says why it is a
context of its own.

## Subdirectories & Boundaries

- src: [./src/EGM.md](./src/EGM.md) - the `api` facade, the `testing`
  module, and the `application` and `domain` modules.

## Interface

- Ports implemented elsewhere: `EndpointStore` by `PgEndpointStore`,
  `DeliveryStore` by `PgDeliveryStore` and `DueDeliveries` by
  `PgDueDeliveries`, all in `crates/adapters-postgres/src/webhooks.rs`;
  `HmacSha256` by `AwsLcHmacSha256` in `crates/adapters-crypto/src/hmac.rs`.
  The kernel ports `DestinationCheck` and `HttpClient` are implemented by
  `GuardedHttpClient` (`crates/adapters-http`), and `SecretBox` by
  `TenantSecretBox` (`crates/keys`).
- Dependencies: `hodor-kernel`, `async-trait`, `base64`, `serde`,
  `serde_json`, `time`.
- Feature `testing`: enables the public `testing` module and
  `hodor-kernel/testing`.
- Dev dependencies: `hodor-kernel` with `testing`, the crate itself with
  `testing`, `tokio`.

## Invariants

- Only event types of `CATALOG` (`src/domain/catalog.rs`) are published;
  the context's own events are not in it.
- A tenant has at most `MAX_ENDPOINTS` (20) endpoints; at most two secrets
  sign for an endpoint; a delivery body is at most `MAX_PAYLOAD_BYTES`
  (65536 bytes).
- No transaction is open while an endpoint answers: `WebhookSender` leases
  in one unit of work and records in another (see
  [application](./src/application/EGM.md)).

## Side Effects

- Through the ports: stores endpoints, subscriptions, sealed secrets and
  deliveries; seals and opens secrets; resolves addresses; sends HTTP
  requests. Records the `webhooks.*` events through
  `UnitOfWork::record_event`.

## Verification

- Run: `cargo test -p hodor-webhooks`
