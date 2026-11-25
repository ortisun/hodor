# hodor-webhooks source

## Overview

`lib.rs` keeps `application` and `domain` private and exposes the public
surface through `pub mod api`, and the test support through `pub mod
testing` (`#[cfg(any(test, feature = "testing"))]`).

## Subdirectories & Boundaries

- application: [./application/EGM.md](./application/EGM.md) - the ports,
  the administrators' use cases, the outbox handler and the sender.
- domain: [./domain/EGM.md](./domain/EGM.md) - the catalog, endpoints,
  secrets, deliveries, events and the signature.

## Interface

- `api` re-exports:
  - Use cases: `WebhookService`, `RegisterEndpoint`, `EndpointDetails`,
    `SecretInForce`; `WebhookFanOut`; `WebhookSender`, `SenderPorts`,
    `DeliverySettings`, `Lease`, `AttemptOutcome`.
  - Ports: `EndpointStore`, `DeliveryStore`, `DeliveryQuery`,
    `DueDeliveries`, `HmacSha256`.
  - Domain: `CATALOG`, `EventType`, `is_published`; `Endpoint`,
    `EndpointId`, `EndpointSnapshot`, `event_types`, `MAX_ENDPOINTS`,
    `MAX_URL_LENGTH`, `MAX_DESCRIPTION_LENGTH`; `Delivery`, `DeliveryId`,
    `DeliverySnapshot`, `DeliveryStatus`, `RetryPolicy`,
    `MAX_PAYLOAD_BYTES`, `MAX_ERROR_LENGTH`; `SigningSecret`,
    `SigningSecretId`, `SIGNING_SECRET_PURPOSE`, `SECRET_BYTES`,
    `SECRET_PREFIX`, `DEFAULT_OVERLAP_HOURS`, `MAX_OVERLAP_HOURS`;
    `WebhookEvent`; `envelope`, `signed_content`, `signature_header`.
- `testing` (`testing.rs`):
  - `InMemoryWebhooks`: implements `EndpointStore`, `DeliveryStore` and
    `DueDeliveries` over one shared map; `deliveries_of(TenantId)` and
    `secrets_of(TenantId)`.
  - `FakeHmac` (not a MAC), `FakeDestinations` (a `DestinationCheck`
    without a resolver: `localhost`, `internal.example` and private literal
    addresses refused, `nowhere.example` unresolvable), and
    `RecordingEndpoints` with `Answer` (an `HttpClient` that keeps requests
    and answers each address as told, `204` by default).
  - `Ports<'a> { units_of_work, endpoints, deliveries, due }` and
    `run_contract(ports)`: the rules every store passes, tenant isolation
    among them; `endpoint(url)` and `secret(endpoint, created, bytes)` build
    valid values.

## Verification

- Run: `cargo test -p hodor-webhooks`
