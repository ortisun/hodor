import { useEffect, useState } from "react";
import type { Failure, Session } from "../client";
import { describe } from "../messages";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { asFailure, type PageProps } from "./shared";

/** Where a signed-in person lands: who they are to the server, and the way out. */
export function AccountPage({ tenant, client, text, go }: PageProps) {
  const [session, setSession] = useState<Session | null>(null);
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
          go("sign-in");
        } else {
          setSession(found);
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
  }, [client, go]);

  async function signOut() {
    if (busy) {
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      await client.signOut();
      go("sign-in", "signed-out");
    } catch (thrown) {
      const failed = asFailure(thrown);
      if (failed.status === 401) {
        // The session ended in the meantime: the person is signed out already.
        go("sign-in", "signed-out");
      } else {
        setFailure(failed);
      }
    } finally {
      setBusy(false);
    }
  }

  const since =
    session === null
      ? null
      : new Intl.DateTimeFormat(text.locale, { dateStyle: "long", timeStyle: "short" }).format(
          new Date(session.signedInAt),
        );

  return (
    <Frame tenant={tenant} title={session === null ? text.loading : text.accountTitle} text={text}>
      {failure !== null ? <Notice kind="danger">{describe(failure, text)}</Notice> : null}
      {since !== null ? (
        <>
          <p className="auth-text">{text.signedInSince(since)}</p>
          <button type="button" className="button auth-wide" aria-disabled={busy} onClick={() => void signOut()}>
            {busy ? text.working : text.signOut}
          </button>
        </>
      ) : null}
    </Frame>
  );
}
