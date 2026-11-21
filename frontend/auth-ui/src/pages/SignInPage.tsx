import { type FormEvent, useCallback, useEffect, useState } from "react";
import type { NoticeName } from "../address";
import type { Client, Failure, SignInAnswer } from "../client";
import { describe, type Messages } from "../messages";
import { Field, PasswordField } from "../parts/Field";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { Submit } from "../parts/Submit";
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
 */
async function findOut(client: Client, afresh: boolean): Promise<Found> {
  try {
    if (!afresh && (await client.session()) !== null) {
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

function noticeText(notice: NoticeName | null, text: Messages): string | null {
  switch (notice) {
    case "registered":
      return text.noticeRegistered;
    case "password-changed":
      return text.noticePasswordChanged;
    case "signed-out":
      return text.noticeSignedOut;
    default:
      return null;
  }
}

interface SignInPageProps extends PageProps {
  notice: NoticeName | null;
}

/**
 * Signing in. The page shows the form for the step the server names and
 * sends back what was typed; it decides nothing.
 */
export function SignInPage({ tenant, client, text, go, path, notice }: SignInPageProps) {
  const [view, setView] = useState<View>({ kind: "loading" });
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [expired, setExpired] = useState(false);
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");

  const show = useCallback(
    (answer: SignInAnswer) => {
      if (answer.status === "completed") {
        go("account");
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
    [go],
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
    void findOut(client, false).then((found) => {
      if (current) {
        apply(found);
      }
    });
    return () => {
      current = false;
    };
  }, [client, apply]);

  const open = async (afresh: boolean) => apply(await findOut(client, afresh));

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
      show(answer);
    } catch (thrown) {
      const failed = asFailure(thrown);
      const code = failed.code ?? "";
      if (GONE.includes(code)) {
        setPassword("");
        setExpired(true);
        await open(true);
      } else if (OUT_OF_STEP.includes(code)) {
        setPassword("");
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

  function submit(event: FormEvent, request: () => Promise<SignInAnswer>) {
    event.preventDefault();
    void send(request);
  }

  const told = noticeText(notice, text);

  return (
    <Frame tenant={tenant} title={text.signInTitle} text={text}>
      {told !== null && view.kind !== "stopped" ? <Notice kind="success">{told}</Notice> : null}
      {expired ? <Notice kind="info">{text.signInExpired}</Notice> : null}
      {failure !== null ? <Notice kind="danger">{describe(failure, text)}</Notice> : null}

      {view.kind === "loading" ? (
        <p className="auth-text muted" role="status">
          {text.loading}
        </p>
      ) : null}

      {view.kind === "stopped" ? (
        <>
          <Notice kind="danger">{describe(view.failure, text)}</Notice>
          <button type="button" className="button auth-wide" onClick={() => void startAgain()}>
            {text.startAgain}
          </button>
        </>
      ) : null}

      {view.kind === "ended" ? (
        <>
          <Notice kind="danger">{text.signInEnded}</Notice>
          <button type="button" className="button button--primary auth-wide" onClick={() => void startAgain()}>
            {text.startAgain}
          </button>
        </>
      ) : null}

      {view.kind === "step" && view.rejected ? (
        <Notice kind="danger">
          {text.rejected}
          {view.attemptsLeft !== null ? ` ${text.attemptsLeft(view.attemptsLeft)}` : ""}
        </Notice>
      ) : null}

      {view.kind === "step" && view.step === "identifier" ? (
        <form
          key={view.shown}
          className="auth-form"
          method="post"
          noValidate
          onSubmit={(event) => submit(event, () => client.submitIdentifier(identifier))}
        >
          <Field
            label={text.identifierLabel}
            name="identifier"
            type="text"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            autoFocus
            required
            value={identifier}
            onChange={(event) => setIdentifier(event.target.value)}
          />
          <Submit label={text.continue} busy={busy} text={text} />
        </form>
      ) : null}

      {view.kind === "step" && view.step === "password" ? (
        <form
          key={view.shown}
          className="auth-form"
          method="post"
          noValidate
          onSubmit={(event) => submit(event, () => client.submitPassword(password))}
        >
          {identifier !== "" ? (
            <>
              <p className="auth-text muted">{text.signingInAs(identifier)}</p>
              {/* Not shown and not reachable: it tells a password manager whose password this is. */}
              <input
                className="visually-hidden"
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
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
          <Submit label={text.signIn} busy={busy} text={text} />
          <button type="button" className="button button--ghost auth-wide" onClick={() => void startAgain()}>
            {text.useAnotherIdentifier}
          </button>
        </form>
      ) : null}

      {view.kind === "step" && view.step !== "identifier" && view.step !== "password" ? (
        <>
          <Notice kind="danger">{text.unknownStep}</Notice>
          <button type="button" className="button auth-wide" onClick={() => void startAgain()}>
            {text.startAgain}
          </button>
        </>
      ) : null}

      <ul className="auth-links">
        <li>
          <a href={path("recover")}>{text.forgotPassword}</a>
        </li>
        <li>
          {text.noAccountYet} <a href={path("register")}>{text.register}</a>
        </li>
      </ul>
    </Frame>
  );
}
