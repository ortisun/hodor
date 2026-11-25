# hodor-webhooks domain

## Overview

Pure rules of the webhooks context: which event types are published, what
an endpoint, a secret and a delivery are, and what is sent and signed. No
input or output.

## Interface

- `catalog.rs`: `CATALOG` (43 event types), `is_published`, `EventType`.
- `endpoint.rs`: `EndpointId`, `Endpoint` (`register`, `replace_subscriptions`,
  `is_subscribed_to`), `EndpointSnapshot`, `event_types`, `MAX_ENDPOINTS`
  (20), `MAX_URL_LENGTH` (1000), `MAX_DESCRIPTION_LENGTH` (200).
- `secret.rs`: `SigningSecretId`, `SigningSecret` (`is_in_force`),
  `SIGNING_SECRET_PURPOSE` (`webhooks.signing_secret`), `SECRET_BYTES` (32),
  `SECRET_PREFIX` (`whsec_`), `DEFAULT_OVERLAP_HOURS` (24),
  `MAX_OVERLAP_HOURS` (168); crate-private `written`, `overlap`, `rotation`.
- `delivery.rs`: `DeliveryId`, `DeliveryStatus` (`pending`, `delivered`,
  `set_aside`), `RetryPolicy` (`DEFAULT`: 8 attempts from 30 seconds,
  `LONGEST_WAIT` one hour, `wait_after`), `Delivery` (`make`, `is_due`,
  `is_leased`, `lease`, `is_as_leased`, `record_success`,
  `record_failure`, `redeliver`), `MAX_PAYLOAD_BYTES` (65536),
  `MAX_ERROR_LENGTH` (500).
- `event.rs`: `WebhookEvent` and its six `webhooks.*` types.
- `signature.rs`: `envelope` (the body of version 1), `signed_content`
  (`id.timestamp.body`), `signature_header` (`v1,` and Base64, separated by
  spaces).

## Invariants

- An address is `http://` or `https://` with a host, printable, without a
  name and password or a fragment; whether it may be called is the
  destination check's to say.
- Waits double from the first, at most an hour; the attempt numbered
  `max_attempts` sets a delivery aside.
- A body larger than `MAX_PAYLOAD_BYTES` is set aside at once, emptied, and
  cannot be delivered again.
- Events carry identifiers and event types, never an address or a secret.

## Verification

- Run: `cargo test -p hodor-webhooks --lib`
