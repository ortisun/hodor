# The notification context

The `notification` context sends messages to people: today, email. Other contexts say what to tell whom; this context turns that into a message in the person's language and gets it delivered.

It decides nothing about why a message is sent. The authentication context decides that a person must verify an email address; this context sends the message that lets them.

This page specifies the part built in Milestone 1: email with built-in templates. Text messages to phones, templates a tenant can change, and messages in HTML are added by later phases.

## How a message gets sent

A message is not sent by the code that asks for it. It is put in a queue, and a worker delivers it.

```mermaid
sequenceDiagram
    participant Context as A context, for example authentication
    participant Queue as The message queue
    participant Worker as hodor-worker
    participant Mail as The mail server

    Context->>Queue: enqueue, in the same transaction as its own change
    Note over Context,Queue: Either the change and the message both exist, or neither does
    Worker->>Queue: take the next pending message
    Worker->>Worker: render the template in the recipient's language
    Worker->>Mail: send
    alt accepted
        Worker->>Queue: mark sent, erase the message's contents
    else refused or unreachable
        Worker->>Queue: record the failure, try again later
    end
```

Why a queue:

- **A change and its message stand or fall together.** A person who registers either has an account and a verification message on its way, or has neither. There is never an account whose message was lost because the mail server was down at that moment.
- **A slow or broken mail server does not slow or break the request** that caused the message.
- **Delivery is retried** without the person having to ask again.

## What a message is

| Field | Meaning |
|---|---|
| Identifier | A `MessageId` |
| Recipient | The email address to send to |
| Template | Which message this is; see [templates](#templates) |
| Locale | The language to write it in |
| Variables | The values the template needs, such as a link |
| Status | `pending`, `sent`, `failed` or `expired` |
| Attempts | How many times delivery was tried |
| Next attempt | When to try again |
| Expires at | After this moment the message is no longer worth sending |

```mermaid
stateDiagram-v2
    [*] --> Pending: enqueued
    Pending --> Sent: the mail server accepted it
    Pending --> Pending: delivery failed, will retry
    Pending --> Failed: delivery failed too many times
    Pending --> Expired: not delivered before it expired
    Sent --> [*]
    Failed --> [*]
    Expired --> [*]
```

Rules:

- A message is delivered inside one transaction of its tenant, which holds the message locked while the mail server is spoken to. The mail adapter gives up after 30 seconds, so the lock is never held for long.
- Delivery is tried up to 8 times. After a failure the next try waits twice as long as the one before, starting at 30 seconds, up to 30 minutes.
- A message that can never be delivered fails at once, without being tried again: one that cannot be written because a variable is missing, or one whose recipient the mail adapter cannot address.
- A refusal by the mail server is always tried again, even when the server calls it permanent. A server that refuses everything because it is set up wrongly says the same thing as one that refuses a single recipient, and losing every message during such a mistake is worse than trying a hopeless one a few more times.
- A message that expires before it is delivered is dropped. A link that no longer works is worse than no message.
- "Sent" means the mail server accepted the message. Whether it reaches an inbox is beyond what Hodor can know.
- A message may, rarely, be sent twice: if the worker stops after the mail server accepted it and before that was recorded. Messages are written so that receiving one twice is harmless.

### What is kept, and for how long

A message waiting to be sent contains what will be sent, including any link in it. A verification or recovery link is as good as the token inside it, so a waiting message is sensitive.

- The variables are erased the moment the message is sent, fails for good or expires. What remains is the record that a message of a given kind was sent to a recipient.
- A message never outlives the link it carries: it expires when the link does.
- Until then the variables are in the database as they will be sent. This is the one place where something equivalent to a token is stored in a readable form, for at most the life of the link. The alternative, sending within the request and losing the message when the mail server is down, was judged worse.

Events about messages carry the message's identifier, its template and its status. They never carry the recipient or the variables.

## Templates

A template is a subject and a body, in plain text, with named placeholders. Templates are built into Hodor in this version, in English and in Brazilian Portuguese.

| Template | Sent when | Variables |
|---|---|---|
| `email_verification` | A person must prove control of an email address | `link`, `tenant_name`, `expires_in` |
| `already_registered` | Someone tried to register with an address that already has an account | `tenant_name` |
| `password_recovery` | A person asked to choose a new password | `link`, `tenant_name`, `expires_in` |
| `password_changed` | A password was changed | `tenant_name` |

Rules:

- **Language.** The message is written in the requested locale if there is a template for it; otherwise in the same language without the region, so `pt-PT` falls back to `pt-BR`'s language; otherwise in English.
- **Every placeholder must be given.** A message with a missing variable is not sent; it fails at once, since trying again would not help.
- **Plain text only.** No HTML, no images, no tracking of any kind.
- **Values are inserted as they are.** In plain text there is nothing to escape, but a value that contains a line break is refused, so that a variable can never add lines of its own to a message.
- **No secrets in subjects.** Subjects are shown in notifications and lists.

## Operations

| Use case | What it does |
|---|---|
| Enqueue | Puts a message in the queue, inside the caller's unit of work. Checks that the template's variables are all given |
| Deliver pending | Takes a batch of pending messages, across tenants, and tries to deliver each |

### Events

| Event type | When |
|---|---|
| `notification.message_sent` | The mail server accepted a message |
| `notification.message_failed` | A message failed for good or expired |

### Ports

| Port | Purpose |
|---|---|
| `MessageQueue` | Store a message of a tenant; take one for delivery so that no other worker takes it; store what delivery did to it |
| `PendingMessages` | Find the messages that are due, across tenants. The one port of this context that is not bound to a tenant; only the worker is given it |
| `EmailSender` | Hand a rendered message to a mail server. An error of the kind "invalid" means the message can never be sent; any other error means: try again |

`EmailSender` is implemented by the `adapters-smtp` crate. Any number of workers can deliver at once: a message being delivered is locked, and other workers skip it.

## Storage

### `notification.message`

| Column | Type | Notes |
|---|---|---|
| `tenant_id`, `id` | `uuid` | Primary key |
| `recipient` | `text` | |
| `template` | `text` | |
| `locale` | `text` | |
| `variables` | `jsonb` | Emptied once the message is no longer pending |
| `status` | `text` | `pending`, `sent`, `failed`, `expired` |
| `attempts` | `integer` | |
| `next_attempt_at` | `timestamptz` | |
| `expires_at` | `timestamptz` | |
| `last_error` | `text` | What the mail server said, for operators |
| `created_at`, `sent_at` | `timestamptz` | |

A tenant table under row-level security. The worker finds pending messages with its cross-tenant connection and delivers each one inside its tenant, exactly as it does for outbox events.

## Configuration

| Setting | Meaning |
|---|---|
| `HODOR_SMTP_URL` | Where to send mail, for example `smtps://user:password@mail.example.com:465`. Without it the worker delivers nothing and messages wait |
| `HODOR_MAIL_FROM` | The address messages are sent from, for example `Hodor <no-reply@example.com>` |

One sender address serves the whole installation in this version. Both settings belong to `hodor-worker`; see [local setup](../../development/local-setup.md#hodor-worker) for every setting of the worker.

The development stack includes a mail server that accepts every message and delivers none, so that what Hodor sends can be read without sending anything to anyone.

## Not built yet

| Item | Planned in |
|---|---|
| Templates a tenant can change, and a sender address per tenant | Phase 4 |
| Messages in HTML | Phase 4 |
| Text messages to phones | Phase 4 |
| Noticing that an address bounces | Not scheduled |
| Removing old message records | Later in Phase 1 |
