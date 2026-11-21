import { type FormEvent, useState } from "react";
import type { Failure } from "../client";
import { describe } from "../messages";
import { Field } from "../parts/Field";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { Submit } from "../parts/Submit";
import { asFailure, type PageProps } from "./shared";

interface AskPageProps extends PageProps {
  /** What the link in the message will be for. */
  purpose: "registration" | "recovery";
}

/**
 * Asking for a link by email, to register or to recover a password. The
 * answer shown is the same whatever the address.
 */
export function AskPage({ tenant, client, text, path, purpose }: AskPageProps) {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [sentTo, setSentTo] = useState<string | null>(null);

  async function ask() {
    const address = email.trim();
    if (busy || address === "") {
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      if (purpose === "registration") {
        await client.askToRegister(address, text.locale);
      } else {
        await client.askToRecover(address, text.locale);
      }
      setSentTo(address);
    } catch (thrown) {
      setFailure(asFailure(thrown));
    } finally {
      setBusy(false);
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    void ask();
  }

  if (sentTo !== null) {
    return (
      <Frame tenant={tenant} title={text.checkMailboxTitle} text={text}>
        <p className="auth-text">{text.checkMailbox(sentTo)}</p>
        <p className="auth-text muted">{text.checkMailboxHint}</p>
        <button type="button" className="button auth-wide" onClick={() => setSentTo(null)}>
          {text.askAgain}
        </button>
        <ul className="auth-links">
          <li>
            <a href={path("sign-in")}>{text.backToSignIn}</a>
          </li>
        </ul>
      </Frame>
    );
  }

  const registering = purpose === "registration";
  return (
    <Frame tenant={tenant} title={registering ? text.registerTitle : text.recoverTitle} text={text}>
      <p className="auth-text">{registering ? text.registerLead : text.recoverLead}</p>
      {failure !== null ? <Notice kind="danger">{describe(failure, text)}</Notice> : null}
      <form className="auth-form" method="post" noValidate onSubmit={submit}>
        <Field
          label={text.emailLabel}
          name="email"
          type="email"
          autoComplete="email"
          autoCapitalize="none"
          spellCheck={false}
          autoFocus
          required
          value={email}
          onChange={(event) => setEmail(event.target.value)}
        />
        <Submit label={text.sendLink} busy={busy} text={text} />
      </form>
      <ul className="auth-links">
        <li>
          {registering ? `${text.alreadyRegistered} ` : null}
          <a href={path("sign-in")}>{registering ? text.signIn : text.backToSignIn}</a>
        </li>
      </ul>
    </Frame>
  );
}
