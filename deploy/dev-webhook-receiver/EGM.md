# dev-webhook-receiver

## Overview

A development receiver of webhooks in one file, `receiver.mjs`, using only Node.js and its standard library (`node:http`). The header comment says it is "NOT FOR ANYTHING REAL". It answers every `POST` with `204` and keeps what it got, so that the development stack and the demonstrations of Milestones 8 and 9 ([demo](../demo/EGM.md)) have an endpoint Hodor can deliver webhooks and logout tokens to. It checks nothing: the demonstrations check the signatures themselves. In the stack it is the `webhook-receiver` service of [docker](../docker/EGM.md), reached by Hodor as `webhook-receiver:9600` and from this machine as `localhost:9600`.

## Interface

Configuration, read from the environment at start:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `9600` | listening port |

Routes:

| Route | Behavior |
| --- | --- |
| `GET /health` | `200 ok`, used by the compose health check |
| `GET /received` | `{ "items": [ … ] }`, oldest first, each `{ path, headers, body, received_at }`; `headers` holds `content-type`, `webhook-id`, `webhook-timestamp` and `webhook-signature`, `null` when absent; `body` is the text as sent. `?path=` keeps those sent to one path, `?webhook-id=` those of one event |
| `POST` on any path | keeps the request and answers `204` |
| anything else | `404` |

## Invariants

- Only the last 500 requests are kept, in memory: a restart forgets them all.
- A body over 128 kibibytes is refused with `413` and not kept; Hodor sends at most 64 kibibytes.
- Every JSON answer carries `cache-control: no-store`.
