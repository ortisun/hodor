# Decision 0036: A code or a link by email is an alternative of the flow, kept apart from the sign-in that asked for it, and counted as the first factor

Status: Accepted (made for Issue-101; the project owner asked for one-time passwords and links by email, not for these choices)

## Context

[Milestone 9](../product/epics.md#milestone-9-what-020-left-out) asks that a person sign in with a code or a link sent by email: authenticators of the flow, the code and the link kept as hashes, good for one use and expiring, tied to the browser that asked, counted with the lockout. A code or a link must be accepted once even when presented many times at once; a link opened in another browser must not sign that browser in; asking must not tell whether an address belongs to someone.

Five questions had to be answered before the code:

1. Where a code or a link fits in a flow, whose steps run one after the other and whose alternatives are taken at the very start.
2. Where the code and the link are kept, and how one is used once.
3. How a link is tied to the browser that asked for it, when the person opens it from a mail program.
4. What a code or a link proves: which kind of factor, and so which assurance a sign-in reaches with it.
5. How a tenant turns them on.

What already existed shaped the answers. The flow has alternatives: an authenticator that, at the start of a sign-in, both says who the person is and proves it, after which the steps that are not required still apply ([the authentication context](../architecture/contexts/authentication.md#alternatives)). Some steps need a challenge, asked for before the step is submitted. A sign-in in progress is a transaction bound to its browser by a secret of 256 bits held in a cookie, of which the server keeps the SHA-256. Registration and password recovery already send links by email, kept as hashes and used once, and already answer asking in the same way whoever the address belongs to.

## Decision

- **Two alternatives of the flow, `email_code` and `email_link`.** Each establishes who is signing in and proves it in one step, as a passkey and an identity provider do, so each is taken only at the very start of a sign-in, never in a step-up. A person who typed an identifier goes on with the password.
- **Asking is a challenge that carries values.** Asking for a challenge already exists for the steps that need one; it now carries named values, which only the authenticator reads, and the email alternatives read the address from them. The engine's rule stays: a challenge is asked for only for the current step or for an alternative while no step has been satisfied. A challenge no longer has to be kept in the transaction: the email alternatives keep nothing there.
- **A code or a link is kept in a table of its own, one row per sign-in**, `authentication.email_sign_in`, keyed by the tenant and the transaction. It holds the SHA-256 of the code or of the link's token, the method, a digest of the address asked about, the person it signs in, and when it expires and was used. Asking again replaces the row, so only the newest is good. A row is kept for every asking, also when the address belongs to nobody, with nobody as its person: what follows asking, and how attempts are counted, is then the same whoever the address belongs to.
- **Used once by one conditional update.** Using a code or a link marks the row used if, and only if, it is unused, unexpired, belongs to someone and its hash matches. Of many requests at once one gets past it. A request that finds the right code just used by another is answered as a concurrent change of the sign-in, and stores nothing, so that it cannot overwrite the sign-in the winner is completing.
- **Tied to the browser by the transaction.** A code or a link is good only within the sign-in that asked for it, which is continued only with the secret its browser holds. The link's page, opened from the mail program, presents the token with the sign-in cookie of the browser it is opened in: the browser that asked finishes its own sign-in, and any other browser has no sign-in, or another one, and gets nothing.
- **Counted with the lockout, as the password is.** Each code or link presented is admitted before it is looked at, against a digest of the address asked about made as the identifier step makes it, and against the address of the request, with the tenant's lockout rules. A lockout reached with codes therefore stops passwords for that identifier, and the other way round. Asking is limited too, in counts of its own, like asking for a recovery link.
- **A code or a link counts as the first factor, of the kind a password is.** The person proved they can read the mailbox, and the mailbox's owner signed in to it; Hodor counts this as it counts an identity provider, which signed the person in in a way Hodor did not see. A second factor after it makes the sign-in multi-factor, so a tenant that requires a second factor still lets in a person who signs in by email and has one. Neither resists phishing.
- **Off by default, turned on per tenant**, the code and the link each on its own, in the tenant's authentication policy: from the command-line tool and from the administration interface.
- **A code is six digits**, chosen uniformly; **a link carries 32 random bytes** in the fragment of its address, like the links of recovery. Both live ten minutes, and never longer than the sign-in that asked.

## Consequences

- A copy of the database yields nothing usable: a six-digit code is easy to recover from its hash, but it is good only with the browser's secret, of which only a hash of 256 bits of randomness is stored, and only for ten minutes. The message waiting in the queue holds the code or the link readable, as it does for recovery, until it is sent or expires with it.
- Asking answers `accepted` in every case and does the same writes, a row and the counts, whoever the address belongs to; only the message differs, and it goes to the mailbox. The time taken differs by one insert in the same transaction.
- A link opened on another device, a phone for example, signs nobody in. That is the price of tying it to the browser: someone who asks for a link with another person's address can never be signed in by that person opening it. The page says to open the link in the browser where it was asked for.
- A person who mistypes a code can type it again: rejections count with the lockout and towards the five a sign-in tolerates, but do not spend the code. A challenge kept in the transaction is spent by any answer, which would make one typo mean another message.
- Two writes happen when a code is accepted: the row is used up, then the transaction advances. A wrong code stored at that same moment by another request of the same browser makes the second write fail, and the code is spent with nobody signed in; the person asks again.
- The `amr` of a token names `otp` for a code, a one-time password of RFC 8176, and nothing for a link, for which RFC 8176 has no name. Both count as something known towards `mfa`, as the authentication context's table counts them.
- Removing expired rows is a new kind of the worker's cleanup, `email_sign_ins`.

## Alternatives considered

- **The code as a challenge kept in the transaction.** No table, and single use from the transaction's version. Set aside: any rejected answer spends a challenge, the transaction has nowhere to keep whom the code signs in nor the digest attempts are counted by, and a link needs a lookup the transaction cannot give.
- **The code or the link as a substitute for the password step.** The person would type the identifier first, as today, and choose "email me a code" instead of the password. Set aside: a substitute never replaces the first factor, and the identifier step answers the same for everyone, so a substitute there would have to be offered to nobody's identifiers as well; an alternative already holds every rule this needs.
- **A link that signs in the browser that asked, wherever it is opened**, with the first tab waiting for the second. Works across devices. Set aside: whoever asks for a link with someone else's address would be signed in as soon as the owner opens it, which is the attack the issue names; making it safe needs the person to confirm, on the device that opened the link, a code shown by the browser that asked, a larger piece of work.
- **The mailbox as something the person has.** Closer to what a mailbox is. Set aside: a code by email followed by the code of an authenticator application would be two things held, one factor, and every person signing in by email under a tenant that requires a second factor would be refused at the end. An identity provider is counted as something known for the same reason.
- **One message with both a code and a link.** One authenticator. Set aside: the code and the link have different pages, a tenant may want one and not the other, and the method a token records would not say which was used.
- **Eight digits.** Fewer guesses succeed. Set aside for now: guesses are bounded by the lockout of the address asked about, five in fifteen minutes by default with lockouts that double, and by the five rejections a sign-in tolerates; six digits are what people expect to type from a message.
