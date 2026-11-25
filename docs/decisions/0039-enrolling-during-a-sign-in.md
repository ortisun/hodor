# Decision 0039: A second factor is enrolled during a sign-in at the last step of the flow, only by a person the policy holds back, and counts as that sign-in's second factor

Status: Accepted (made for Issue-103; the project owner asked that a person who has no second factor set one up while signing in, not for these choices)

## Context

[Milestone 9](../product/epics.md#milestone-9-what-020-left-out) asks that, under a tenant that requires a second factor, a person who has none set up an authenticator application, a security key or a passkey after the first factor, get recovery codes, and complete the sign-in at multi-factor assurance. Under the policy, a person without a factor must complete a sign-in only by enrolling one; enrolling must be offered only after the first factor was proved; and abandoning the enrollment must not complete the sign-in.

Until now such a person could not sign in at all: the sign-in failed at completion, because its methods did not reach multi-factor, and an operator had to enroll an authenticator application for them with the command-line tool.

Five questions had to be answered before the code:

1. Where enrolling fits in a sign-in, whose steps run one after the other through one engine ([Decision 0013](0013-auth-flow-as-data.md)).
2. When it is offered, and to whom.
3. How what was begun in one sign-in is kept from being finished in another.
4. What an enrollment proves, and so which methods and which assurance the sign-in records.
5. How the recovery codes made with the first factor reach the person, once.

What already existed shaped the answers. The flow has steps that are not required, performed when a condition holds and the step's authenticator says the person has the means for it, which come after every required step ([the authentication context](../architecture/contexts/authentication.md#steps-and-authenticators)). A step may need a challenge, asked for before the step is submitted, with named values only its authenticator reads. A person's own pages already enroll an authenticator application, register a security key or a passkey, and make recovery codes with the first factor, through `FactorService`, which asks the credential context to do each thing. An enrollment of an application waits ten minutes for a code to confirm it, one per person; a registration of a key waits five minutes and is used up by the first answer.

## Decision

- **Enrolling is a step of the flow, `enrollment`, the last one**, after the security key and the authenticator application, conditional on the assurance the sign-in must reach not being reached yet. Its authenticator says the person has the means for it only when the sign-in is not a step-up, a factor was proved in this sign-in, the person has no second factor at all, neither an authenticator application in use nor a security key or a passkey, and the installation offers something to enroll. So, under the policy, a person with a second factor is asked for it and the step is passed over once they give it; a person without one reaches it after the first factor; with the policy off, after a passkey, and in a step-up, it is passed over.
- **Two requests, through what the engine already has.** Beginning is asking for the step's challenge, with the kind the person chose among `authenticator_application`, `security_key` and `passkey`: the authenticator begins it through the same use cases of `FactorService` as the security page, and answers with the secret and its `otpauth://` address, or the options for the browser. Finishing is submitting the step, with the code the application shows or what the authenticator answered. A person declines nothing: there is no way past the step but finishing it.
- **The sign-in keeps what it began.** The transaction holds the kind and the identifier of the enrollment it began, in two new columns, in place of an earlier one. A rejection keeps it, so a mistyped code can be typed again; satisfying the step empties it. Finishing finishes only that enrollment: the credential context confirms an authenticator application only when the enrollment waiting is the one named, and a key's registration is finished by the identifier the transaction holds, never one the browser gives. What was begun in another sign-in, on the security page or in another tenant cannot be finished here.
- **Checked again when beginning and when finishing.** A person who has a second factor by then, put in use by another sign-in or by an operator, is refused, `authentication.enrollment_not_needed`, and nothing is begun or put in use: they start again and are asked for it.
- **The recovery codes come with the factor**, as on the security page: made when the factor is put in use and the person has no unused code, and returned once, in the answer that satisfies the step, which is the one that completes the sign-in.
- **What it proves: the second factor of this sign-in, of the kind something the person has, never resisting phishing.** The method recorded is `enrollment`, whatever was enrolled; a password and an enrollment reach multi-factor and satisfy the policy. It does not resist phishing even when a key was registered: the key was bound by whoever held the first factor, and a registration checks no signature.
- **Not counted with the lockout.** A code typed to confirm an application is computed from a secret this very browser was just given; guessing it gains nothing. The five rejections a sign-in tolerates bound it.
- **The event `authentication.second_factor_enrolled`** records the person and the kind, besides the credential context's own events.

## Consequences

- **Whoever holds a person's first factor, and nothing else, can bind a second factor of their own and sign in, if they do so before the person.** That is trust on first use, and the price of letting a person who never enrolled sign in under the policy. What the policy still gains: every later sign-in of the person asks for the factor, and the audit log records the enrollment. A tenant that cannot accept this has its people enroll before turning the policy on, from their security page or by an operator.
- A person whose administrator removed their last factor sets up a new one at their next sign-in, with no operator.
- The `amr` of a token says `mfa` and the first factor's own value. It names nothing for the enrollment, for which RFC 8176 has no name; the `acr` is the tenant's multi-factor level.
- A page reloaded after beginning cannot show the secret again: it begins again, which replaces the enrollment.
- An abandoned enrollment completes nothing. The sign-in waits at the step until it expires or is ended; the enrollment of an application waits ten minutes, is never used to sign in, and is replaced by the next one; a registration of a key waits five minutes and is removed by the cleanup.
- Two sign-ins of one person that finish an enrollment at the same moment are not serialized: both factors may be put in use, as two removals at once may both go through. It gives the person a factor more; it takes none away.
- An application that asks a step-up for multi-factor of a person who has no factor is still told the assurance cannot be reached: enrolling needs a first factor proved in the same sign-in, and a step-up carries one proved earlier.

## Alternatives considered

- **Asking the person to use the new factor once more before the sign-in completes**, a fresh code of the application or a signature of the new key. Set aside: whoever enrolled the factor holds it, so it proves nothing more about who is signing in, and a fresh code means waiting up to thirty seconds for the next one.
- **Recording the enrolled factor's own method, `totp` or `webauthn`.** The `amr` would name `otp` or `pop`. Set aside: `webauthn` would make the sign-in phishing-resistant, which it is not, and neither the session nor the audit log would tell an enrollment from a use.
- **Completing the sign-in at single factor with a session good only for enrolling**, and sending the person to the security page. Set aside: it needs a new kind of limited session, which every route would have to check, and the issue asks that the sign-in complete at multi-factor.
- **An interface of its own, outside the flow.** Set aside: every sign-in runs through the one engine, and a procedure beside it would repeat the rules of binding, expiry and completion.
- **The begun enrollment kept as the transaction's challenge.** No new column. Set aside: any answer spends a challenge, so a mistyped code would mean a new secret and scanning again.
- **Offering enrollment in a step-up too.** Set aside: a browser left signed in would let anyone bind a factor of their own, which [proving oneself again](../architecture/contexts/authentication.md#proving-oneself-again) exists to prevent.
