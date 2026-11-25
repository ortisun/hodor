# Decision 0033: API keys are credentials of workloads, recognized by their prefix

Status: Accepted

## Context

[Issue-94](../product/epics.md#slice-y--workloads-and-agents-epic-22) asks for API keys: an identifiable prefix, kept as hashes, with scopes, an expiry, rotation with an overlap, revocation and the time of last use, accepted by the Authorization API and the administration interface. A key found in a public repository must be recognized by its prefix.

[Decision 0031](0031-workloads-are-users.md) made service accounts and agents users of the identity context, which never sign in and prove who they are through a client of the client credentials grant. A client gets an access token that lives minutes; a key is presented as it is, on every request, for months. Three questions had to be answered: who holds a key, what a key may do, and how it is told from every other secret Hodor makes.

## Decision

- **A key is a credential of the credential context, held by a service account or an agent.** The context keeps the key's SHA-256 and never the key, as for client secrets and the tokens of the administration interface. A person holds no key: a person signs in, with every factor the tenant asks for, and a key would be a way around them that lives for months. The administration interface manages a workload's keys under the workload.
- **A key is `hodor_ak_` followed by 64 lowercase hexadecimal characters**, 32 random bytes. The prefix names Hodor and, in its two letters, the kind of secret, as `hodor_cs_` does for a client secret and `hodor_at_` for a token of the administration interface. A secret scanner recognizes all three with one pattern each, and a person who finds one knows what it is and whom to tell.
- **What a key may do is its scopes, and no more than its holder may do.**
  - A scope is a permission of the administration interface, such as `users:read`, or a scope of the Authorization API, such as `authz:evaluate`. Nothing else is accepted when the key is made.
  - At the administration interface a request needs the permission among the key's scopes **and** in the roles its holder holds, so that a key never widens what its holder may do and whoever makes a key never gives more than the holder has.
  - At the Authorization API a key names the application whose resource server it asks about, as a client's application does for a token.
- **A key is refused, in one way whatever the reason, when it is malformed, unknown in the tenant, revoked, expired, or held by a workload that may not act.** Disabling a workload stops its keys at once without revoking them, since a key is meant to live long; deleting it revokes them.
- **Rotation makes a new key and shortens the old one**, which keeps working for an overlap of 0 to 30 days, so that whoever uses it can change over without stopping. The old key names the new one, and only the newest of a line can be rotated again.
- **The time of last use is kept to the minute**: a key used more than once a minute is written once, so that a busy key does not write on every request.

## Consequences

- A tenant can let a program read its users, or ask the Authorization API, with one header and no token endpoint.
- A workload needs a built-in role of the administration interface for its keys to do anything there. The operator gives one with `hodor-cli admin grant`, as the first administrator is made: the administration interface still gives no built-in role.
- A key presented to the Authorization API is checked with one more read of the identity context and one of the OAuth context than a token is, through the composition root.
- Secret scanning services can be given the three patterns, `hodor_ak_[0-9a-f]{64}`, `hodor_cs_[0-9a-f]{64}` and `hodor_at_[0-9a-f]{64}`, without a call to Hodor.

## Alternatives considered

- **Keys held by people.** Common in other products. Set aside because a key does not prove a second factor, and Hodor has OAuth and sessions for people.
- **A key as a client secret, exchanged at the token endpoint.** A client already does that. Set aside because the issue asks for a key that the Authorization API and the administration interface take directly.
- **A checksum in the key, as some providers add, so that a scanner can tell a real key from a random string offline.** Set aside for now: the prefix and the length already make a false match unlikely, and the checksum can be added later as a new kind of key without breaking the old ones.
- **Scopes alone, without the holder's roles.** Set aside because an administrator who may manage workloads could then make a key worth more than their own permissions.
