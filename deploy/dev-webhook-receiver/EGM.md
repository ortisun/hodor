# dev-webhook-receiver

## Overview

A development receiver of webhooks in one file, `receiver.mjs`, using only Node.js and its standard library (`node:http`). The header comment says it is "NOT FOR ANYTHING REAL". It answers every `POST` with `204` and keeps what it got, so that the development stack and the demonstrations of Milestones 8 and 9 ([demo](../demo/EGM.md)) have an endpoint Hodor can deliver webhooks and logout tokens to. It also answers what a `PUT` gave it to every `GET` of that path, so that the demonstration of Milestone 13 has an address of an application's own where Hodor fetches request objects. It checks nothing: the demonstrations check the signatures themselves. In the stack it is the `webhook-receiver` service of [docker](../docker/EGM.md), reached by Hodor as `webhook-receiver:9600` and from this machine as `localhost:9600`.

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
| `GET /fetched` | `{ "items": [ … ] }`, oldest first, each `{ path, accept, fetched_at }`: the `GET`s answered with what a `PUT` gave. `?path=` keeps those of one path |
| `POST` on any path | keeps the request and answers `204` |
| `PUT` on any path | keeps the body as the answer to every later `GET` of that path, and answers `204` |
| `GET` of a path a `PUT` gave | the body, as `application/oauth-authz-req+jwt` with `cache-control: no-store`, and the `GET` is kept for `/fetched` |
| anything else | `404` |

## Invariants

- Only the last 500 requests, the last 500 paths a `PUT` gave and the last 500 of their `GET`s are kept, in memory: a restart forgets them all.
- A body over 128 kibibytes is refused with `413` and not kept; Hodor sends at most 64 kibibytes.
- Every JSON answer carries `cache-control: no-store`.
