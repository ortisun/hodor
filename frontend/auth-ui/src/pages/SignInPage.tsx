import { Heading } from "@astryxdesign/core/Heading";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useCallback, useEffect, useRef, useState } from "react";
import type { NoticeName, PageName } from "../address";
import type { Client, Enrollment, EnrollmentKind, Failure, OfferedProvider, SignInAnswer } from "../client";
import { describe, type Messages } from "../messages";
import { Field, PasswordField } from "../parts/Field";
import { Form } from "../parts/Form";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { QrCode } from "../parts/QrCode";
import { Action, Submit } from "../parts/Submit";
import { PageLink, Ways, Words } from "../parts/Words";
import { askAuthenticator, askToCreate, conditionalMediationAvailable, webAuthnAvailable } from "../webauthn";
import { asFailure, grouped, type PageProps } from "./shared";

type View =
  | { kind: "loading" }
  /** The sign-in waits for a step. `shown` counts answers, so that each one gets a fresh form. */
  | { kind: "step"; step: string; rejected: boolean; attemptsLeft: number | null; shown: number }
  | { kind: "ended" }
  /** Nothing could be shown at all. */
  | { kind: "stopped"; failure: Failure };

/** The codes that mean "this sign-in is gone": the page starts another. */
const GONE = ["authentication.transaction_not_found", "authentication.transaction_not_active"];
/** The codes that mean "the page and the server disagree about where the sign-in stands": the page asks again. */
const OUT_OF_STEP = [
  "authentication.unexpected_step",
  "authentication.transaction_modified_concurrently",
  "request.csrf_token_invalid",
];

/**
 * Sends an identifier, and sends it once more if the sign-in was changed by
 * another request at the same moment. That request is the page's own: while
 * the identifier step is shown, it asks for the passkey challenge, which
 * changes the sign-in. The first identifier was not taken, and sending an
 * identifier counts no attempt, so sending it again is safe.
 */
async function sendIdentifier(client: Client, identifier: string): Promise<SignInAnswer> {
  try {
    return await client.submitIdentifier(identifier);
  } catch (thrown) {
    if (asFailure(thrown).code === "authentication.transaction_modified_concurrently") {
      return client.submitIdentifier(identifier);
    }
    throw thrown;
  }
}

type Found =
  | { kind: "signed-in" }
  | { kind: "answer"; answer: SignInAnswer }
  | { kind: "stopped"; failure: Failure };

/**
 * Finds out where things stand: somebody is signed in, a sign-in is in
 * progress, or one is started. With `afresh`, starts one without asking.
 * With `signInAgain`, an application asked for a new sign-in: whoever is
 * signed in already does not count.
 */
async function findOut(client: Client, afresh: boolean, signInAgain: boolean): Promise<Found> {
  try {
    if (!afresh && !signInAgain && (await client.session()) !== null) {
      return { kind: "signed-in" };
    }
    let current: SignInAnswer | null = null;
    if (!afresh) {
      try {
        current = await client.currentSignIn();
      } catch (thrown) {
        if (!GONE.includes(asFailure(thrown).code ?? "")) {
          throw thrown;
        }
      }
    }
    return { kind: "answer", answer: current ?? (await client.startSignIn()) };
  } catch (thrown) {
    return { kind: "stopped", failure: asFailure(thrown) };
  }
}

/** What the page before had to say, and whether it is good news. */
function noticeText(notice: NoticeName | null, text: Messages): { kind: "success" | "danger"; said: string } | null {
  switch (notice) {
    case "registered":
      return { kind: "success", said: text.noticeRegistered };
    case "password-changed":
      return { kind: "success", said: text.noticePasswordChanged };
    case "signed-out":
      return { kind: "success", said: text.noticeSignedOut };
    case "provider-refused":
      return { kind: "danger", said: text.noticeProviderRefused };
    case "provider-cancelled":
      return { kind: "danger", said: text.noticeProviderCancelled };
    default:
      return null;
  }
}

interface SignInPageProps extends PageProps {
  notice: NoticeName | null;
  /** An application's request, or a change of factors, waits for this sign-in: sign in even when signed in. */
  signInAgain?: boolean;
  /** The identifier an application suggested: the field starts with it. */
  loginHint?: string | null;
  /** Where a completed sign-in goes when the answer names nowhere else. */
  afterSignIn?: PageName;
}

/** The steps a recovery code can stand in for. */
const SECOND_FACTORS = ["webauthn", "totp"];
/** The step at which a person whose organization requires a second factor, and who has none, sets one up. */
const ENROLLMENT = "enrollment";
/** The steps this page knows how to show. */
const KNOWN_STEPS = ["identifier", "password", "totp", "webauthn", ENROLLMENT];
/** The person has a second factor by now: the sign-in starts again, to ask for it. */
const ENROLLMENT_NOT_NEEDED = "authentication.enrollment_not_needed";

/** A code or a link the person asked for by email, in place of the identifier and the password. */
interface ByEmail {
  method: "code" | "link";
  /** The address it was asked for, as typed. */
  address: string;
}

/**
 * Signing in. The page shows the form for the step the server names and
 * sends back what was typed; it decides nothing.
 */
export function SignInPage({
  tenant,
  client,
  text,
  go,
  leave,
  path,
  notice,
  signInAgain = false,
  loginHint = null,
  afterSignIn = "account",
}: SignInPageProps) {
  const [view, setView] = useState<View>({ kind: "loading" });
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [expired, setExpired] = useState(false);
  const [identifier, setIdentifier] = useState(loginHint ?? "");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  /** Whether the person chose to give a recovery code where the code of their application is asked. */
  const [recovering, setRecovering] = useState(false);
  /** How many times the person switched between the two; the field shown after a switch takes the focus. */
  const [switches, setSwitches] = useState(0);
  const codeField = useRef<HTMLInputElement | null>(null);
  useEffect(() => {
    if (switches === 0) {
      return undefined;
    }
    // After the press that switched has been handled whole: the button keeps the focus otherwise.
    const timer = setTimeout(() => codeField.current?.focus(), 0);
    return () => clearTimeout(timer);
  }, [switches]);
  const switchTo = (recovery: boolean) => {
    setCode("");
    setRecovering(recovery);
    setSwitches((count) => count + 1);
  };
  const [providers, setProviders] = useState<OfferedProvider[]>([]);
  /** The directory the person chose to sign in through, if any. */
  const [directory, setDirectory] = useState<OfferedProvider | null>(null);
  /** The security key gave no answer the last time it was asked. */
  const [noAnswer, setNoAnswer] = useState(false);
  /** The passkey gave no answer the last time the person asked for it. */
  const [passkeyNoAnswer, setPasskeyNoAnswer] = useState(false);
  /** The conditional request that offers passkeys in the identifier field, while it waits. */
  const offering = useRef<AbortController | null>(null);
  /** The ways to sign in by email the tenant offers. */
  const [byEmailOffered, setByEmailOffered] = useState<{ code: boolean; link: boolean }>({
    code: false,
    link: false,
  });
  /** What the person asked for by email, while the sign-in waits for its first step. */
  const [byEmail, setByEmail] = useState<ByEmail | null>(null);
  /** The person asked for a code or a link without typing an address. */
  const [needAddress, setNeedAddress] = useState(false);
  /** What can be set up at the enrollment step, once the server said. */
  const [kinds, setKinds] = useState<EnrollmentKind[] | null>(null);
  /** The authenticator application being set up at the enrollment step: its secret, shown once. */
  const [settingUp, setSettingUp] = useState<Enrollment | null>(null);
  const [keyName, setKeyName] = useState("");
  /** The key did not answer the last time it was asked to register. */
  const [keyNoAnswer, setKeyNoAnswer] = useState(false);
  /** Recovery codes made with a factor just set up, to keep before the page goes on, and the answer to go on with. */
  const [keeping, setKeeping] = useState<{ codes: string[]; then: SignInAnswer } | null>(null);

  const show = useCallback(
    (answer: SignInAnswer) => {
      if (answer.recoveryCodes !== undefined) {
        // Shown once: the person keeps them before the page goes on.
        const { recoveryCodes, ...then } = answer;
        setKeeping({ codes: recoveryCodes, then });
        return;
      }
      if (answer.status === "completed") {
        if (answer.continueTo === undefined) {
          go(afterSignIn);
        } else {
          leave(answer.continueTo);
        }
        return;
      }
      if (answer.status === "failed") {
        setView({ kind: "ended" });
        return;
      }
      setView((before) => {
        // A choice made for one step does not carry over to the next.
        if (before.kind !== "step" || before.step !== (answer.step ?? "")) {
          setRecovering(false);
          setSettingUp(null);
          setKeyNoAnswer(false);
        }
        return {
          kind: "step",
          step: answer.step ?? "",
          rejected: answer.status === "rejected",
          attemptsLeft: answer.attemptsLeft,
          shown: before.kind === "step" ? before.shown + 1 : 0,
        };
      });
    },
    [go, leave, afterSignIn],
  );

  const apply = useCallback(
    (found: Found) => {
      if (found.kind === "signed-in") {
        go(afterSignIn);
      } else if (found.kind === "stopped") {
        setView({ kind: "stopped", failure: found.failure });
      } else {
        show(found.answer);
      }
    },
    [go, show, afterSignIn],
  );

  useEffect(() => {
    let current = true;
    // A tenant that offers none, or a list that cannot be had, shows none.
    client.alternatives().then(
      (offered) => {
        if (current) {
          setByEmailOffered({ code: offered.includes("email_code"), link: offered.includes("email_link") });
        }
      },
      () => undefined,
    );
    client.providers().then(
      (offered) => {
        if (current) {
          setProviders(offered);
        }
      },
      () => undefined,
    );
    void findOut(client, false, signInAgain).then((found) => {
      if (current) {
        apply(found);
      }
    });
    return () => {
      current = false;
    };
  }, [client, apply, signInAgain]);

  const open = async (afresh: boolean) => {
    if (afresh) {
      // A new sign-in never asked for anything.
      setByEmail(null);
    }
    apply(await findOut(client, afresh, signInAgain));
  };

  async function send(request: () => Promise<SignInAnswer>) {
    if (busy) {
      return;
    }
    setBusy(true);
    setFailure(null);
    setExpired(false);
    try {
      const answer = await request();
      setPassword("");
      setCode("");
      show(answer);
    } catch (thrown) {
      const failed = asFailure(thrown);
      const code = failed.code ?? "";
      if (GONE.includes(code)) {
        setPassword("");
        setCode("");
        setExpired(true);
        await open(true);
      } else if (OUT_OF_STEP.includes(code)) {
        setPassword("");
        setCode("");
        await open(false);
      } else if (code === ENROLLMENT_NOT_NEEDED) {
        setCode("");
        await open(true);
        setFailure(failed);
      } else {
        setFailure(failed);
      }
    } finally {
      setBusy(false);
    }
  }

  /** Begins setting up an authenticator application: its QR code and its key are shown once. */
  async function beginApplication() {
    await send(async () => {
      setSettingUp(await client.beginApplicationEnrollment());
      return { status: "pending", step: ENROLLMENT, attemptsLeft: null };
    });
  }

  /**
   * Adds a security key or a passkey: begins its registration, then asks
   * the authenticator. When it makes nothing, nothing is sent and the
   * person tries again, which begins anew.
   */
  async function addKey(passkey: boolean) {
    setKeyNoAnswer(false);
    await send(async () => {
      const registration = await askToCreate(await client.beginKeyEnrollment(passkey));
      if (registration === null) {
        setKeyNoAnswer(true);
        return { status: "pending", step: ENROLLMENT, attemptsLeft: null };
      }
      const name = keyName.trim() === "" ? (passkey ? text.defaultPasskeyName : text.defaultKeyName) : keyName;
      return client.finishKeyEnrollment(registration, name);
    });
  }

  async function startAgain() {
    if (busy) {
      return;
    }
    setBusy(true);
    setFailure(null);
    setExpired(false);
    setPassword("");
    setCode("");
    setRecovering(false);
    setByEmail(null);
    setNeedAddress(false);
    try {
      await client.abandonSignIn();
      await open(true);
    } catch (thrown) {
      // Nothing can be shown but the reason, and the way to try once more.
      setView({ kind: "stopped", failure: asFailure(thrown) });
    } finally {
      setBusy(false);
    }
  }

  async function leaveFor(provider: OfferedProvider) {
    if (busy) {
      return;
    }
    // Nobody leaves for a directory: its form is shown here.
    if (provider.isDirectory) {
      setFailure(null);
      setPassword("");
      setCode("");
      setDirectory(provider);
      return;
    }
    setBusy(true);
    setFailure(null);
    setExpired(false);
    try {
      leave(await client.chooseProvider(provider.alias));
    } catch (thrown) {
      const failed = asFailure(thrown);
      if (GONE.includes(failed.code ?? "")) {
        setExpired(true);
        await open(true);
      } else {
        setFailure(failed);
      }
    } finally {
      setBusy(false);
    }
  }

  /**
   * Asks for the challenge, then the authenticator. When the authenticator
   * gives no answer, nothing is submitted: the person tries again.
   */
  async function askSecurityKey() {
    setNoAnswer(false);
    await send(async () => {
      const answer = await askAuthenticator(await client.webAuthnOptions());
      if (answer === null) {
        setNoAnswer(true);
        return { status: "pending", step: "webauthn", attemptsLeft: null };
      }
      return client.submitWebAuthn(answer);
    });
  }

  /** Stops offering passkeys in the identifier field. */
  function stopOffering() {
    offering.current?.abort();
    offering.current = null;
  }

  /**
   * Signs in with a passkey: asks for the challenge, then the authenticator.
   * When it gives no answer, nothing is submitted and the identifier is
   * still asked for.
   */
  async function askPasskey() {
    stopOffering();
    setPasskeyNoAnswer(false);
    await send(async () => {
      const answer = await askAuthenticator(await client.passkeyOptions());
      if (answer === null) {
        setPasskeyNoAnswer(true);
        return { status: "pending", step: "identifier", attemptsLeft: null };
      }
      return client.submitPasskey(answer);
    });
  }

  /**
   * Asks for a code or a link to be sent to the address typed. The answer
   * is the same whoever the address belongs to. Sent once more when the
   * sign-in was changed at the same moment by the page's own request for
   * the passkey challenge, which is stopped first.
   */
  async function askByEmail(method: "code" | "link") {
    const address = identifier.trim();
    if (address === "") {
      setNeedAddress(true);
      return;
    }
    if (busy) {
      return;
    }
    stopOffering();
    setNeedAddress(false);
    setBusy(true);
    setFailure(null);
    setExpired(false);
    try {
      try {
        await client.askByEmail(method, address, text.locale);
      } catch (thrown) {
        if (asFailure(thrown).code !== "authentication.transaction_modified_concurrently") {
          throw thrown;
        }
        await client.askByEmail(method, address, text.locale);
      }
      setCode("");
      setByEmail({ method, address });
      // The rejection of an earlier code is not about this one.
      setView((before) => (before.kind === "step" ? { ...before, rejected: false, shown: before.shown + 1 } : before));
    } catch (thrown) {
      const failed = asFailure(thrown);
      const code = failed.code ?? "";
      if (GONE.includes(code)) {
        setExpired(true);
        await open(true);
      } else if (OUT_OF_STEP.includes(code)) {
        await open(false);
      } else {
        setFailure(failed);
      }
    } finally {
      setBusy(false);
    }
  }

  const enrolling = view.kind === "step" && view.step === ENROLLMENT;
  // What can be set up is read when the step is shown.
  useEffect(() => {
    if (!enrolling) {
      return undefined;
    }
    let current = true;
    client.enrollmentKinds().then(
      (listed) => {
        if (current) {
          setKinds(listed);
        }
      },
      () => {
        if (current) {
          setKinds([]);
        }
      },
    );
    return () => {
      current = false;
    };
  }, [enrolling, client]);

  const waitsByEmail = view.kind === "step" && view.step === "identifier" && byEmail !== null;
  const asksIdentifier =
    view.kind === "step" && view.step === "identifier" && directory === null && byEmail === null;
  const shownAt = view.kind === "step" ? view.shown : -1;

  // Where the browser can, the passkeys it holds are offered in the
  // identifier field. The request is abandoned when the step is left.
  useEffect(() => {
    if (!asksIdentifier) {
      return undefined;
    }
    const controller = new AbortController();
    offering.current = controller;
    void (async () => {
      if (!(await conditionalMediationAvailable()) || controller.signal.aborted) {
        return;
      }
      try {
        const options = await client.passkeyOptions();
        if (controller.signal.aborted) {
          return;
        }
        const answer = await askAuthenticator(options, navigator.credentials, {
          mediation: "conditional",
          signal: controller.signal,
        });
        if (answer !== null && !controller.signal.aborted) {
          offering.current = null;
          await send(() => client.submitPasskey(answer));
        }
      } catch {
        // Offering passkeys is a convenience: the identifier is still asked for.
      }
    })();
    return () => controller.abort();
    // `send` is the same procedure on every render; the request starts once per step shown.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [asksIdentifier, shownAt, client]);

  function submit(event: FormEvent, request: () => Promise<SignInAnswer>) {
    event.preventDefault();
    void send(request);
  }

  const told = noticeText(notice, text);

  if (keeping !== null) {
    return (
      <Frame tenant={tenant} title={text.signInTitle} text={text}>
        <VStack gap={4}>
          <Heading level={2}>{text.codesTitle}</Heading>
          <Words>{text.codesLead}</Words>
          <ul className="auth-codes" aria-label={text.codesTitle}>
            {keeping.codes.map((one) => (
              <li key={one}>
                <Text className="auth-code">{one}</Text>
              </li>
            ))}
          </ul>
          <Action
            variant="primary"
            label={text.codesKept}
            onClick={() => {
              const then = keeping.then;
              setKeeping(null);
              show(then);
            }}
          />
        </VStack>
      </Frame>
    );
  }

  const offersApplication = kinds?.includes("authenticator_application") === true;
  const offersKeys =
    webAuthnAvailable() && (kinds?.includes("security_key") === true || kinds?.includes("passkey") === true);

  return (
    <Frame tenant={tenant} title={text.signInTitle} text={text}>
      {told !== null && view.kind !== "stopped" ? <Notice kind={told.kind}>{told.said}</Notice> : null}
      {expired ? <Notice kind="info">{text.signInExpired}</Notice> : null}
      {failure !== null ? <Notice kind="danger">{describe(failure, text)}</Notice> : null}

      {view.kind === "loading" ? (
        <Words quiet announced>
          {text.loading}
        </Words>
      ) : null}

      {view.kind === "stopped" ? (
        <>
          <Notice kind="danger">{describe(view.failure, text)}</Notice>
          <Action label={text.startAgain} onClick={() => void startAgain()} />
        </>
      ) : null}

      {view.kind === "ended" ? (
        <>
          <Notice kind="danger">{text.signInEnded}</Notice>
          <Action variant="primary" label={text.startAgain} onClick={() => void startAgain()} />
        </>
      ) : null}

      {view.kind === "step" && view.rejected ? (
        <Notice kind="danger">
          {view.attemptsLeft !== null ? `${text.rejected} ${text.attemptsLeft(view.attemptsLeft)}` : text.rejected}
        </Notice>
      ) : null}

      {view.kind === "step" && view.step === "identifier" && directory !== null ? (
        <Form
          key={`directory-${view.shown}`}
          onSubmit={(event) =>
            submit(event, () => client.signInWithDirectory(directory.alias, identifier, password))
          }
        >
          <Field
            label={text.directoryIdentifierLabel(directory.displayName)}
            name="identifier"
            autoComplete="username"
            verbatim
            autoFocus
            value={identifier}
            onChange={setIdentifier}
          />
          <PasswordField
            text={text}
            label={text.passwordLabel}
            name="password"
            autoComplete="current-password"
            value={password}
            onChange={setPassword}
          />
          <Submit label={text.signIn} busy={busy} text={text} />
          <Action
            variant="ghost"
            label={text.otherWays}
            onClick={() => {
              setDirectory(null);
              setFailure(null);
              setPassword("");
              setCode("");
            }}
          />
        </Form>
      ) : null}

      {view.kind === "step" && waitsByEmail && byEmail.method === "code" ? (
        <Form key={`email-code-${view.shown}`} onSubmit={(event) => submit(event, () => client.submitEmailCode(code))}>
          <Notice kind="info">{text.emailCodeSent(byEmail.address)}</Notice>
          <Field
            label={text.emailCodeLabel}
            hint={text.emailCodeHint}
            name="email-code"
            autoComplete="one-time-code"
            inputMode="numeric"
            autoFocus
            verbatim
            value={code}
            onChange={setCode}
          />
          <Submit label={text.signIn} busy={busy} text={text} />
          <Action variant="ghost" label={text.sendAnotherCode} busy={busy} onClick={() => void askByEmail("code")} />
          <Action variant="ghost" label={text.useAnotherIdentifier} onClick={() => void startAgain()} />
        </Form>
      ) : null}

      {view.kind === "step" && waitsByEmail && byEmail.method === "link" ? (
        <>
          <Notice kind="info">{text.emailLinkSent(byEmail.address)}</Notice>
          <Ways>
            <li>
              <Action variant="ghost" label={text.sendAnotherLink} busy={busy} onClick={() => void askByEmail("link")} />
            </li>
            <li>
              <Action variant="ghost" label={text.useAnotherIdentifier} onClick={() => void startAgain()} />
            </li>
          </Ways>
        </>
      ) : null}

      {view.kind === "step" && view.step === "identifier" && directory === null && byEmail === null ? (
        <Form
          key={view.shown}
          onSubmit={(event) => {
            stopOffering();
            submit(event, () => sendIdentifier(client, identifier));
          }}
        >
          {passkeyNoAnswer ? <Notice kind="danger">{text.passkeyNoAnswer}</Notice> : null}
          <Field
            label={text.identifierLabel}
            name="identifier"
            autoComplete="username webauthn"
            verbatim
            autoFocus
            value={identifier}
            onChange={setIdentifier}
          />
          {needAddress ? <Notice kind="danger">{text.typeAddressFirst}</Notice> : null}
          <Submit label={text.continue} busy={busy} text={text} />
          {webAuthnAvailable() ? (
            <Action label={text.signInWithPasskey} busy={busy} onClick={() => void askPasskey()} />
          ) : null}
          {byEmailOffered.code ? (
            <Action label={text.emailMeACode} busy={busy} onClick={() => void askByEmail("code")} />
          ) : null}
          {byEmailOffered.link ? (
            <Action label={text.emailMeALink} busy={busy} onClick={() => void askByEmail("link")} />
          ) : null}
        </Form>
      ) : null}

      {view.kind === "step" &&
      view.step === "identifier" &&
      directory === null &&
      byEmail === null &&
      providers.length > 0 ? (
        <>
          <p className="auth-divider">{text.or}</p>
          <Ways>
            {providers.map((provider) => (
              <li key={provider.alias}>
                <Action
                  label={text.continueWith(provider.displayName)}
                  busy={busy}
                  onClick={() => void leaveFor(provider)}
                />
              </li>
            ))}
          </Ways>
        </>
      ) : null}

      {view.kind === "step" && view.step === "password" ? (
        <Form
          key={view.shown}
          onSubmit={(event) => submit(event, () => client.submitPassword(password))}
        >
          {identifier !== "" ? (
            <>
              <Words quiet>{text.signingInAs(identifier)}</Words>
              {/* Not shown and not reachable: it tells a password manager whose password this is. */}
              <input
                className="auth-hidden"
                type="text"
                name="identifier"
                autoComplete="username"
                value={identifier}
                readOnly
                tabIndex={-1}
                aria-hidden="true"
              />
            </>
          ) : null}
          <PasswordField
            text={text}
            label={text.passwordLabel}
            name="password"
            autoComplete="current-password"
            autoFocus
            value={password}
            onChange={setPassword}
          />
          <Submit label={text.signIn} busy={busy} text={text} />
          <Action variant="ghost" label={text.useAnotherIdentifier} onClick={() => void startAgain()} />
        </Form>
      ) : null}

      {view.kind === "step" && SECOND_FACTORS.includes(view.step) && recovering ? (
        <Form key={view.shown} onSubmit={(event) => submit(event, () => client.submitRecoveryCode(code))}>
          {identifier !== "" ? <Words quiet>{text.signingInAs(identifier)}</Words> : null}
          <Field
            label={text.recoveryCodeLabel}
            hint={text.recoveryCodeHint}
            name="recovery-code"
            autoComplete="off"
            autoFocus
            verbatim
            inputRef={codeField}
            value={code}
            onChange={setCode}
          />
          <Submit label={text.signIn} busy={busy} text={text} />
          <Action
            variant="ghost"
            label={view.step === "webauthn" ? text.useSecurityKeyInstead : text.useAuthenticatorApplication}
            onClick={() => switchTo(false)}
          />
          <Action variant="ghost" label={text.useAnotherIdentifier} onClick={() => void startAgain()} />
        </Form>
      ) : null}

      {view.kind === "step" && view.step === "totp" && !recovering ? (
        <Form key={view.shown} onSubmit={(event) => submit(event, () => client.submitTotp(code))}>
          {identifier !== "" ? <Words quiet>{text.signingInAs(identifier)}</Words> : null}
          <Field
            label={text.totpLabel}
            hint={text.totpHint}
            name="code"
            autoComplete="one-time-code"
            inputMode="numeric"
            autoFocus
            verbatim
            inputRef={codeField}
            value={code}
            onChange={setCode}
          />
          <Submit label={text.signIn} busy={busy} text={text} />
          <Action
            variant="ghost"
            label={text.useRecoveryCode}
            onClick={() => switchTo(true)}
          />
          <Action variant="ghost" label={text.useAnotherIdentifier} onClick={() => void startAgain()} />
        </Form>
      ) : null}

      {view.kind === "step" && view.step === "webauthn" && !recovering ? (
        <Form
          key={view.shown}
          onSubmit={(event) => {
            event.preventDefault();
            void askSecurityKey();
          }}
        >
          {noAnswer ? <Notice kind="danger">{text.securityKeyNoAnswer}</Notice> : null}
          {webAuthnAvailable() ? (
            <>
              <Words>{text.securityKeyLead}</Words>
              <Submit label={text.useSecurityKey} busy={busy} text={text} />
            </>
          ) : (
            <Notice kind="danger">{text.securityKeyUnavailable}</Notice>
          )}
          <Action variant="ghost" label={text.useRecoveryCode} onClick={() => switchTo(true)} />
          <Action variant="ghost" label={text.startAgain} onClick={() => void startAgain()} />
        </Form>
      ) : null}

      {enrolling && settingUp !== null ? (
        <Form
          key={`enrollment-${view.shown}`}
          onSubmit={(event) => submit(event, () => client.finishApplicationEnrollment(code.replace(/\s/g, "")))}
        >
          <Words>{text.setUpLead}</Words>
          <QrCode value={settingUp.uri} label={text.qrLabel} />
          <VStack gap={1}>
            <Text as="p" type="supporting" color="secondary">
              {text.secretLabel}
            </Text>
            <Text as="p" className="auth-code">
              {grouped(settingUp.secret)}
            </Text>
          </VStack>
          <Field
            label={text.totpLabel}
            hint={text.totpHint}
            name="code"
            autoComplete="one-time-code"
            inputMode="numeric"
            autoFocus
            verbatim
            value={code}
            onChange={setCode}
          />
          <Submit label={text.confirmAndSignIn} busy={busy} text={text} />
          <Action
            variant="ghost"
            label={text.chooseAnotherWay}
            onClick={() => {
              setCode("");
              setSettingUp(null);
            }}
          />
        </Form>
      ) : null}

      {enrolling && settingUp === null ? (
        <VStack gap={4}>
          <Words>{text.enrollLead}</Words>
          {kinds === null ? (
            <Words quiet announced>
              {text.loading}
            </Words>
          ) : null}
          {offersApplication ? (
            <Action
              variant="primary"
              label={text.setUpApplication}
              busy={busy}
              onClick={() => void beginApplication()}
            />
          ) : null}
          {offersKeys ? (
            <VStack gap={2}>
              <Words>{text.enrollKeysLead}</Words>
              {keyNoAnswer ? <Notice kind="danger">{text.keyNoAnswer}</Notice> : null}
              <Field
                label={text.keyNameLabel}
                hint={text.keyNameHint}
                name="key-name"
                autoComplete="off"
                value={keyName}
                onChange={setKeyName}
              />
              {kinds?.includes("security_key") === true ? (
                <Action label={text.addSecurityKey} busy={busy} onClick={() => void addKey(false)} />
              ) : null}
              {kinds?.includes("passkey") === true ? (
                <Action label={text.addPasskey} busy={busy} onClick={() => void addKey(true)} />
              ) : null}
            </VStack>
          ) : null}
          {kinds !== null && !offersApplication && !offersKeys ? (
            <Notice kind="danger">{text.nothingToSetUp}</Notice>
          ) : null}
          <Action variant="ghost" label={text.useAnotherIdentifier} onClick={() => void startAgain()} />
        </VStack>
      ) : null}

      {view.kind === "step" && !KNOWN_STEPS.includes(view.step) ? (
        <>
          <Notice kind="danger">{text.unknownStep}</Notice>
          <Action label={text.startAgain} onClick={() => void startAgain()} />
        </>
      ) : null}

      <Ways>
        <li>
          <PageLink href={path("recover")}>{text.forgotPassword}</PageLink>
        </li>
        <li>
          {text.noAccountYet} <PageLink href={path("register")}>{text.register}</PageLink>
        </li>
      </Ways>
    </Frame>
  );
}
