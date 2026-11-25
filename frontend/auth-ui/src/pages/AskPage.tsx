import { type FormEvent, useState } from "react";
import type { Failure } from "../client";
import { describe } from "../messages";
import { Field } from "../parts/Field";
import { Form } from "../parts/Form";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { Action, Submit } from "../parts/Submit";
import { PageLink, Ways, Words } from "../parts/Words";
import { asFailure, type PageProps } from "./shared";

interface AskPageProps extends PageProps {
  /** What the link in the message will be for. */
  purpose: "registration" | "recovery";
  /**
   * An application sent the person here to register, with `prompt=create`:
   * once they sign in, its request goes on.
   */
  forApplication?: boolean;
}

/**
 * Asking for a link by email, to register or to recover a password. The
 * answer shown is the same whatever the address.
 */
export function AskPage({ tenant, client, text, path, purpose, forApplication = false }: AskPageProps) {
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

  const registering = purpose === "registration";
  const forAnApplication = registering && forApplication;
  // A person who signs in from here signs in for the application, even
  // when someone is signed in already.
  const signIn = forAnApplication ? `${path("sign-in")}?continue=authorization` : path("sign-in");

  if (sentTo !== null) {
    return (
      <Frame tenant={tenant} title={text.checkMailboxTitle} text={text}>
        <Words>{text.checkMailbox(sentTo)}</Words>
        <Words quiet>{text.checkMailboxHint}</Words>
        <Action label={text.askAgain} onClick={() => setSentTo(null)} />
        <Ways>
          <li>
            <PageLink href={signIn}>{text.backToSignIn}</PageLink>
          </li>
        </Ways>
      </Frame>
    );
  }

  return (
    <Frame tenant={tenant} title={registering ? text.registerTitle : text.recoverTitle} text={text}>
      <Words>{registering ? text.registerLead : text.recoverLead}</Words>
      {forAnApplication ? <Words quiet>{text.registerForApplication}</Words> : null}
      {failure !== null ? <Notice kind="danger">{describe(failure, text)}</Notice> : null}
      <Form onSubmit={submit}>
        <Field
          label={text.emailLabel}
          name="email"
          type="email"
          autoComplete="email"
          verbatim
          autoFocus
          value={email}
          onChange={setEmail}
        />
        <Submit label={text.sendLink} busy={busy} text={text} />
      </Form>
      <Ways>
        <li>
          {registering ? `${text.alreadyRegistered} ` : null}
          <PageLink href={signIn}>{registering ? text.signIn : text.backToSignIn}</PageLink>
        </li>
      </Ways>
    </Frame>
  );
}
