import { type FormEvent, useCallback, useEffect, useState } from "react";
import type { NoticeName } from "../address";
import type { Client, Failure, SignInAnswer } from "../client";
import { describe, type Messages } from "../messages";
import { Field, PasswordField } from "../parts/Field";
import { Form } from "../parts/Form";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { Action, Submit } from "../parts/Submit";
import { PageLink, Ways, Words } from "../parts/Words";
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

      {view.kind === "step" && view.step === "identifier" ? (
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

      {view.kind === "step" && view.step !== "identifier" && view.step !== "password" ? (
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
