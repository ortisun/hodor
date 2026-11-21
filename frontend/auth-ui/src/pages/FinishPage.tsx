import { type FormEvent, useState } from "react";
import type { Failure } from "../client";
import { describe, fieldProblem, type FieldProblem } from "../messages";
import { Field, PasswordField } from "../parts/Field";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { Submit } from "../parts/Submit";
import { asFailure, type PageProps } from "./shared";

interface FinishPageProps extends PageProps {
  /** What the link was for. */
  purpose: "registration" | "recovery";
  /** The token of the link; `null` when the address carries none. */
  token: string | null;
}

/**
 * Where the link in a message leads: the person chooses a password, and
 * the registration or the recovery is finished with the link's token.
 */
export function FinishPage({ tenant, client, text, go, path, purpose, token }: FinishPageProps) {
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [problem, setProblem] = useState<FieldProblem | null>(null);
  const [linkGood, setLinkGood] = useState(token !== null);

  const registering = purpose === "registration";

  async function finish(linkToken: string) {
    if (busy) {
      return;
    }
    setBusy(true);
    setFailure(null);
    setProblem(null);
    try {
      if (registering) {
        await client.completeRegistration(linkToken, password, displayName);
      } else {
        await client.resetPassword(linkToken, password);
      }
      go("sign-in", registering ? "registered" : "password-changed");
    } catch (thrown) {
      const failed = asFailure(thrown);
      const about = fieldProblem(failed, text);
      if (failed.code === "authentication.verification_token_invalid") {
        setLinkGood(false);
      } else if (about !== null) {
        setProblem(about);
      } else {
        setFailure(failed);
      }
    } finally {
      setBusy(false);
    }
  }

  if (token === null || !linkGood) {
    return (
      <Frame tenant={tenant} title={text.linkInvalidTitle} text={text}>
        <Notice kind="danger">{text.linkInvalid}</Notice>
        <ul className="auth-links">
          <li>
            <a href={path(registering ? "register" : "recover")}>
              {registering ? text.askForNewRegistrationLink : text.askForNewRecoveryLink}
            </a>
          </li>
          <li>
            <a href={path("sign-in")}>{text.backToSignIn}</a>
          </li>
        </ul>
      </Frame>
    );
  }

  function submit(event: FormEvent, linkToken: string) {
    event.preventDefault();
    void finish(linkToken);
  }

  return (
    <Frame
      tenant={tenant}
      title={registering ? text.completeRegistrationTitle : text.resetPasswordTitle}
      text={text}
    >
      {failure !== null ? <Notice kind="danger">{describe(failure, text)}</Notice> : null}
      <form className="auth-form" method="post" noValidate onSubmit={(event) => submit(event, token)}>
        {registering ? (
          <Field
            label={`${text.displayNameLabel} (${text.optional})`}
            name="name"
            type="text"
            autoComplete="name"
            value={displayName}
            error={problem?.field === "displayName" ? problem.message : null}
            onChange={(event) => setDisplayName(event.target.value)}
          />
        ) : null}
        <PasswordField
          text={text}
          label={text.newPasswordLabel}
          hint={text.newPasswordHint}
          name="new-password"
          autoComplete="new-password"
          autoFocus={!registering}
          required
          value={password}
          error={problem?.field === "password" ? problem.message : null}
          onChange={(event) => setPassword(event.target.value)}
        />
        <Submit label={registering ? text.createAccount : text.changePassword} busy={busy} text={text} />
      </form>
    </Frame>
  );
}
