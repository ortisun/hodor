import { useEffect, useState } from "react";
import type { Failure } from "../client";
import { describe } from "../messages";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { Action } from "../parts/Submit";
import { Words } from "../parts/Words";
import { asFailure, type PageProps } from "./shared";

/**
 * Where an application's request to sign out asks the person first. Where
 * the application wants the person back stays with the server, which
 * sends the browser there from the finish address.
 */
export function SignOutPage({ tenant, client, text, go, leave }: PageProps) {
  const finish = `/t/${tenant}/oauth2/logout/finish`;
  const [signedIn, setSignedIn] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);

  useEffect(() => {
    let current = true;
    client.session().then(
      (found) => {
        if (!current) {
          return;
        }
        if (found === null) {
          // Nobody to sign out: the request finishes at once.
          leave(finish);
        } else {
          setSignedIn(true);
        }
      },
      (thrown: unknown) => {
        if (current) {
          setFailure(asFailure(thrown));
        }
      },
    );
    return () => {
      current = false;
    };
  }, [client, leave, finish]);

  async function signOut() {
    if (busy) {
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      await client.signOut();
      leave(finish);
    } catch (thrown) {
      const failed = asFailure(thrown);
      if (failed.status === 401) {
        // The session ended in the meantime: the person is signed out already.
        leave(finish);
      } else {
        setFailure(failed);
        setBusy(false);
      }
    }
  }

  return (
    <Frame tenant={tenant} title={signedIn ? text.signOutTitle : text.loading} text={text}>
      {failure !== null ? <Notice kind="danger">{describe(failure, text)}</Notice> : null}
      {signedIn ? (
        <>
          <Words>{text.signOutQuestion(tenant)}</Words>
          <Action
            label={busy ? text.working : text.signOut}
            variant="primary"
            busy={busy}
            onClick={() => void signOut()}
          />
          <Action label={text.staySignedIn} onClick={() => go("account")} />
        </>
      ) : null}
    </Frame>
  );
}
