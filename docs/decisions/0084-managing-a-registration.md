# Decision 0084: A registration is managed at its own address with a token Hodor keeps only as a hash, replaced at every change, and removing it deletes the client

Status: Accepted

## Context

[Decision 0049](0049-dynamic-client-registration.md) says that a registration gives back a registration access token and `registration_client_uri`, `{issuer}/oauth2/register/{client_id}`, and that the token "is shown once, kept as a hash, and replaced at every change", reading, changing and removing that registration only. [Decision 0080](0080-the-registration-endpoint.md) built the registration endpoint without either, and left `initiate_login_uri` ignored. [Issue-134](../product/epics.md#milestone-15-clients-that-register-themselves) builds the rest: reading, changing and removing a registration as [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592) writes it, and `initiate_login_uri`, the address where a client starts a sign-in that someone else asked for, which OpenID Connect Core calls third-party initiated login and the account page uses.

Six questions were open. RFC 7592 wants the current token in every answer, the answer to a read included, and Hodor keeps only its hash: what does a read answer? What does a change replace, and what does it keep? Two changes sent at once with one token: which wins, and what is the other told? What does removing a client remove, when nothing in Hodor removes a client today? Where does the account page send a person, with what? And the suite's 3rd Party-Init plan, the acceptance of the issue, registers a client of `client_secret_basic` with keys, which the registration endpoint refuses today, since only a client of `private_key_jwt` has keys.

## Decision

### One token per registration, kept as a hash, that never expires

A registration access token is `hodor_rat_` followed by 64 lowercase hexadecimal characters, 32 random bytes from the operating system, as every secret Hodor makes is. Only its SHA-256 is kept, on the client. It is given in the answer of the registration, and a new one in the answer of every change; the old one is refused from the moment the change is stored. It has no expiry: RFC 7592 says it should not expire while the client is registered, since a client whose token expired could never manage its registration again.

A read answers the token it was sent, which is the current one, since it was just compared with the hash: RFC 7592 asks for the current token in the answer, and Hodor cannot give back what it does not keep. A read replaces nothing. A change always replaces the token, even when it changes nothing else, so that a client knows the token it changed with is spent. A client has no secret Hodor could give back either: a read and a change answer without `client_secret`, unless the change made one.

### The address answers the token, and nothing else

`{issuer}/oauth2/register/{client_id}` takes `GET`, `PUT` and `DELETE`, with the token in `Authorization: Bearer`. Every way a token can fail is answered alike, `401` with `invalid_token`: a client the tenant does not have, a client of another tenant, a client an administrator made, a client registered before this decision, which has no token, an old token, another client's token, a value without the shape of a token. The hash is compared in constant time. While registration is off in the tenant, the address answers `404`, as the registration endpoint does; turning registration on again makes each token work again. A client's status does not matter: a client an administrator disabled may still read and remove its registration, and change it, which does not enable it.

### A change is a registration again, of the same client

The body of a `PUT` is read by the rules of a registration, member by member, a member left out taking the default of its specification, as RFC 7592 says that a member left out is removed. It must name the client's own `client_id`; a `client_secret`, if sent, must be a secret of the client that works; the members only an answer carries, `registration_access_token`, `registration_client_uri`, `client_id_issued_at` and `client_secret_expires_at`, are ignored. Then the client's settings are checked by the rules of every client, as an administrator's change is, its keys replaced by those sent, each checked as an administrator adds one, then the tenant's policy, the hosts of the redirect addresses first. The type never changes: a confidential client cannot become public, nor the reverse.

The addresses Hodor will call are checked as an administrator's change checks them, only when they are new or changed, and only once the token is known good. A client that moves to a method that takes a secret and holds none that works is given a new one, in the answer once, as at its registration; a client that moves away from one loses its secrets, as any client does.

The bounds of registration count registrations, not changes: a change takes no place in the application and none in the count of an address.

### Two changes at once: the first stored wins, and the other's token is old

The change is stored in one unit of work that locks the client's row, then compares the token again, then stores the client with its new token. A second change sent with the same token waits for the lock, finds the token replaced, and is refused with `invalid_token`, as any old token is: one change wins, and the client that sent the other learns that its token is spent, which is what happened. A change of the client by an administrator between the check of the token and the storing is refused with `409`, and the client sends its change again.

### Removing a registration deletes the client

A `DELETE` deletes the client's row, and with it, by the database's cascades, every row that names it: its secrets and keys, its authorization requests, grants and codes, the identifiers of its client assertions, its refresh token families, the records of its access tokens, the consents given to it and their history, its claim mappers and its logout deliveries. Its `client_id`, secret and token stop working at once, as RFC 7592 asks. An access token already issued is no longer in force, as a token without a record is, for introspection, UserInfo and every resource server that asks; one that checks tokens by itself accepts it until it expires, the window [Decision 0004](0004-token-formats.md) accepts. The answer is `204`. The removal is an event of the audit log, which keeps the client's identifier after the client is gone.

Removing is the client's alone: an administrator still disables a client, and removes none.

### The login initiation address sends the person to the client with the issuer, and nothing else

`initiate_login_uri` is kept, as every other address a registration names: one HTTPS address with a host, at most 2000 characters, without a name and password or a fragment, within the policy's hosts. Anything else is refused with `invalid_client_metadata`, as OpenID Connect Registration asks. Hodor never calls it.

The account page lists the applications the person agreed to. Beside a client that has a login initiation address, it shows a link that starts a sign-in there: the address with `iss`, the tenant's issuer, added to its query, as OpenID Connect Core, section 4, writes it. The link carries no `login_hint`, so the client learns nothing of the person before the person signs in, and no `target_link_uri`. It is opened in a new tab without a referrer, as the consent page's links are. Only a client the person agreed to is listed, so the page sends no one to a client they never let in.

### Keys of a client that does not sign with them are ignored

A registration that names `jwks` with a method other than `private_key_jwt` has its keys ignored, and left out of the answer, where it was refused until now. Hodor reads a client's keys for one thing, to check what the client signs: its client assertions, and its request objects, which only a client with keys can sign. A client of a secret method that sends keys relies on nothing Hodor would do with them, and a signed request object of it is refused when it comes, as today. The suite registers every client with keys, whatever its method, so that the Dynamic and 3rd Party-Init plans register nothing otherwise. `jwks_uri` with such a method is still refused: it is an address Hodor would call.

## Consequences

- A registered client reads, changes and removes itself, and the 3rd Party-Init plan can run: its registration is answered with the token and the address, its read gives back `initiate_login_uri`, and its removal at the end of each test is answered `204`.
- A client keeps one token for its life unless it changes, and a stolen token works until the next change of the client or until it is removed. A tenant that suspects a token disables the client, which stops its tokens at every endpoint but this one, or asks its developer to change it.
- A registration made before this decision has no token, and cannot be managed; its administrator manages it as any client.
- Removing deletes the rows of twelve tables that name the client, in one statement. Nothing else in Hodor deletes a client, and an administrator's way to stop one stays disabling.
- The account page links to addresses that clients chose, within the policy's hosts, and only for clients the person agreed to.
- The `jwks` of a client of a secret method is not kept, and the client learns it from the answer, as for every member Hodor ignores.

## Alternatives considered

- **Replacing the token at every read too.** RFC 7592 allows it, and Hodor would never need to give back a token it was sent. Set aside: a client that reads its registration and loses the answer, by a timeout or a crash, can never manage it again, and a read becomes a write.
- **Keeping the token encrypted, to answer it at a read.** What a read of RFC 7592 could answer without the token being sent. Set aside: the token is sent with every read anyway, and a token Hodor could decrypt is one a stolen database could give away.
- **Optimistic locking alone for two changes at once**, refusing the second with `409`. Set aside: the second token is old by then, and telling the client so is what lets it understand that its token is spent, rather than retrying a change with it.
- **Disabling the client on removal**, keeping its row. Nothing would be deleted, and an administrator would still see it. Set aside: RFC 7592 says the client identifier is invalidated, Decision 0080 lets a removed client leave the count of its address, and a disabled client still holds a place in its application and its consents and grants.
- **Building the link with `login_hint`**, the person's email address. The client could fill its sign-in form. Set aside: it gives a client the person's address before the person signs in to it, and the client gets it from the ID token a moment later if the person allows.
- **Keeping the keys of any client**, to check request objects of a client of a secret method. Set aside for now: it changes what an administrator's client may hold, and a client of the Dynamic plan that signs request objects is Issue-137's to settle.
