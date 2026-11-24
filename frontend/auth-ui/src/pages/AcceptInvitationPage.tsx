import { type FormEvent, useEffect, useState } from "react";
import type { Failure, InvitationDescription } from "../client";
import { describe, fieldProblem, type FieldProblem } from "../messages";
import { Field, PasswordField } from "../parts/Field";
import { Form } from "../parts/Form";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { Submit } from "../parts/Submit";
import { PageLink, Ways, Words } from "../parts/Words";
import { asFailure, type PageProps } from "./shared";

interface AcceptInvitationPageProps extends PageProps {
  /** The token of the link; `null` when the address carries none. */
  token: string | null;
}

type View =
  | { kind: "loading" }
  | { kind: "invalid" }
  | { kind: "new"; invitation: InvitationDescription }
  | { kind: "join"; invitation: InvitationDescription }
  | { kind: "sign-in"; invitation: InvitationDescription }
  | { kind: "someone-else"; invitation: InvitationDescription }
  | { kind: "stopped"; failure: Failure };

/**
 * Where the link of an invitation leads. The page asks what the invitation
 * is for, then lets the person create an account and join, join as the
 * account they are signed in with, or sign in first.
 */
export function AcceptInvitationPage({ tenant, client, text, go, path, token }: AcceptInvitationPageProps) {
  const [view, setView] = useState<View>({ kind: token === null ? "invalid" : "loading" });
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [problem, setProblem] = useState<FieldProblem | null>(null);

  useEffect(() => {
    if (token === null) {
      return;
    }
    let current = true;
    void (async () => {
      try {
        const invitation = await client.describeInvitation(token);
        if (!invitation.hasAccount) {
          if (current) setView({ kind: "new", invitation });
          return;
        }
        // Asking who is signed in also gives the session's CSRF token.
        const session = await client.session();
        if (current) setView({ kind: session === null ? "sign-in" : "join", invitation });
      } catch (thrown) {
        const failed = asFailure(thrown);
        if (current) {
          setView(failed.code === "identity.invitation_invalid" ? { kind: "invalid" } : { kind: "stopped", failure: failed });
        }
      }
    })();
    return () => {
      current = false;
    };
  }, [client, token]);

  async function accept(linkToken: string, invitation: InvitationDescription, withPassword: boolean) {
    if (busy) {
      return;
    }
    setBusy(true);
    setFailure(null);
    setProblem(null);
    try {
      if (withPassword) {
        await client.acceptInvitation(linkToken, password, displayName);
        go("sign-in", "registered");
      } else {
        await client.acceptInvitation(linkToken);
        go("account");
      }
    } catch (thrown) {
      const failed = asFailure(thrown);
      const about = fieldProblem(failed, text);
      if (failed.code === "identity.invitation_invalid") {
        setView({ kind: "invalid" });
      } else if (failed.code === "authentication.invitation_for_someone_else") {
        setView({ kind: "someone-else", invitation });
      } else if (failed.code === "authentication.invitation_needs_sign_in") {
        setView({ kind: "sign-in", invitation });
      } else if (about !== null) {
        setProblem(about);
      } else {
        setFailure(failed);
      }
    } finally {
      setBusy(false);
    }
  }

  function submit(event: FormEvent, linkToken: string, invitation: InvitationDescription, withPassword: boolean) {
    event.preventDefault();
    void accept(linkToken, invitation, withPassword);
  }

  if (view.kind === "loading") {
    return (
      <Frame tenant={tenant} title={text.loading} text={text}>
        <Words>{text.loading}</Words>
      </Frame>
    );
  }
  if (view.kind === "invalid" || token === null) {
    return (
      <Frame tenant={tenant} title={text.linkInvalidTitle} text={text}>
        <Notice kind="danger">{text.linkInvalid}</Notice>
        <Ways>
          <li>
            <PageLink href={path("sign-in")}>{text.backToSignIn}</PageLink>
          </li>
        </Ways>
      </Frame>
    );
  }
  if (view.kind === "stopped") {
    return (
      <Frame tenant={tenant} title={text.linkInvalidTitle} text={text}>
        <Notice kind="danger">{describe(view.failure, text)}</Notice>
      </Frame>
    );
  }

  const { invitation } = view;
  const title = text.acceptInvitationTitle(invitation.organizationName);
  return (
    <Frame tenant={tenant} title={title} text={text}>
      <Words>{text.invitationFor(invitation.email)}</Words>
      {failure !== null ? <Notice kind="danger">{describe(failure, text)}</Notice> : null}
      {view.kind === "new" ? (
        <Form onSubmit={(event) => submit(event, token, invitation, true)}>
          <Words>{text.invitationNewAccount}</Words>
          <Field
            label={`${text.displayNameLabel} (${text.optional})`}
            name="name"
            autoComplete="name"
            value={displayName}
            error={problem?.field === "displayName" ? problem.message : null}
            onChange={setDisplayName}
          />
          <PasswordField
            text={text}
            label={text.newPasswordLabel}
            hint={text.newPasswordHint}
            name="new-password"
            autoComplete="new-password"
            value={password}
            error={problem?.field === "password" ? problem.message : null}
            onChange={setPassword}
          />
          <Submit label={text.createAccountAndJoin} busy={busy} text={text} />
        </Form>
      ) : null}
      {view.kind === "join" ? (
        <Form onSubmit={(event) => submit(event, token, invitation, false)}>
          <Submit label={text.join} busy={busy} text={text} />
        </Form>
      ) : null}
      {view.kind === "sign-in" ? (
        <>
          <Notice kind="info">{text.invitationSignIn(invitation.email)}</Notice>
          <Ways>
            <li>
              <PageLink href={path("sign-in")}>{text.signIn}</PageLink>
            </li>
          </Ways>
        </>
      ) : null}
      {view.kind === "someone-else" ? (
        <>
          <Notice kind="danger">{text.invitationOtherAccount(invitation.email)}</Notice>
          <Ways>
            <li>
              <PageLink href={path("sign-out")}>{text.signOut}</PageLink>
            </li>
          </Ways>
        </>
      ) : null}
    </Frame>
  );
}
