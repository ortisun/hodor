import { type FormEvent, useCallback, useEffect, useState } from "react";
import type { NoticeName } from "../address";
import type { Client, Failure, OfferedProvider, SignInAnswer } from "../client";
import { describe, type Messages } from "../messages";
import { Field, PasswordField } from "../parts/Field";
import { Form } from "../parts/Form";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { Action, Submit } from "../parts/Submit";
import { PageLink, Ways, Words } from "../parts/Words";
import { askAuthenticator, webAuthnAvailable } from "../webauthn";
import { asFailure, type PageProps } from "./shared";

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
  /** An application's request waits for this sign-in: sign in even when signed in. */
  signInAgain?: boolean;
}

/**
 * Signing in. The page shows the form for the step the server names and
 * sends back what was typed; it decides nothing.
 */
export function SignInPage({ tenant, client, text, go, leave, path, notice, signInAgain = false }: SignInPageProps) {
  const [view, setView] = useState<View>({ kind: "loading" });
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [expired, setExpired] = useState(false);
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [providers, setProviders] = useState<OfferedProvider[]>([]);
  /** The directory the person chose to sign in through, if any. */
  const [directory, setDirectory] = useState<OfferedProvider | null>(null);
  /** The security key gave no answer the last time it was asked. */
  const [noAnswer, setNoAnswer] = useState(false);

  const show = useCallback(
    (answer: SignInAnswer) => {
      if (answer.status === "completed") {
        if (answer.continueTo === undefined) {
          go("account");
        } else {
          leave(answer.continueTo);
        }
        return;
      }
      if (answer.status === "failed") {
        setView({ kind: "ended" });
        return;
      }
      setView((before) => ({
        kind: "step",
        step: answer.step ?? "",
        rejected: answer.status === "rejected",
        attemptsLeft: answer.attemptsLeft,
        shown: before.kind === "step" ? before.shown + 1 : 0,
      }));
    },
    [go, leave],
  );

  const apply = useCallback(
    (found: Found) => {
      if (found.kind === "signed-in") {
        go("account");
      } else if (found.kind === "stopped") {
        setView({ kind: "stopped", failure: found.failure });
      } else {
        show(found.answer);
      }
    },
    [go, show],
  );

  useEffect(() => {
    let current = true;
    // A tenant that offers none, or a list that cannot be had, shows none.
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

  const open = async (afresh: boolean) => apply(await findOut(client, afresh, signInAgain));

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
      } else {
        setFailure(failed);
      }
    } finally {
      setBusy(false);
    }
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

  function submit(event: FormEvent, request: () => Promise<SignInAnswer>) {
    event.preventDefault();
    void send(request);
  }

  const told = noticeText(notice, text);

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

      {view.kind === "step" && view.step === "identifier" && directory === null ? (
        <Form
          key={view.shown}
          onSubmit={(event) => submit(event, () => client.submitIdentifier(identifier))}
        >
          <Field
            label={text.identifierLabel}
            name="identifier"
            autoComplete="username"
            verbatim
            autoFocus
            value={identifier}
            onChange={setIdentifier}
          />
          <Submit label={text.continue} busy={busy} text={text} />
        </Form>
      ) : null}

      {view.kind === "step" && view.step === "identifier" && directory === null && providers.length > 0 ? (
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

      {view.kind === "step" && view.step === "totp" ? (
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
            value={code}
            onChange={setCode}
          />
          <Submit label={text.signIn} busy={busy} text={text} />
          <Action variant="ghost" label={text.useAnotherIdentifier} onClick={() => void startAgain()} />
        </Form>
      ) : null}

      {view.kind === "step" && view.step === "webauthn" ? (
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
          <Action variant="ghost" label={text.startAgain} onClick={() => void startAgain()} />
        </Form>
      ) : null}

      {view.kind === "step" && !["identifier", "password", "totp", "webauthn"].includes(view.step) ? (
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
