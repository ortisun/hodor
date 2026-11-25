import { VStack } from "@astryxdesign/core/VStack";
import { useEffect, useState } from "react";
import type { Failure, GivenConsent, Session } from "../client";
import { describe } from "../messages";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { Action } from "../parts/Submit";
import { PageLink, Ways, Words } from "../parts/Words";
import type { Messages } from "../messages";
import { asFailure, type PageProps } from "./shared";

/** Where a signed-in person lands: who they are to the server, their second factors, and the way out. */
export function AccountPage({ tenant, client, text, go, path }: PageProps) {
  const [session, setSession] = useState<Session | null>(null);
  const [consents, setConsents] = useState<GivenConsent[]>([]);
  const [withdrawn, setWithdrawn] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);

  useEffect(() => {
    let current = true;
    const load = async (): Promise<[Session, GivenConsent[]] | null> => {
      const found = await client.session();
      return found === null ? null : [found, await client.consents()];
    };
    load().then(
      (found) => {
        if (!current) {
          return;
        }
        if (found === null) {
          go("sign-in");
        } else {
          setSession(found[0]);
          setConsents(found[1]);
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

  async function withdraw(consent: GivenConsent) {
    if (busy) {
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      await client.withdrawConsent(consent.clientId);
      setConsents((listed) => listed.filter((other) => other.clientId !== consent.clientId));
      setWithdrawn(consent.application);
    } catch (thrown) {
      setFailure(asFailure(thrown));
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
          <Words>{text.signedInSince(since)}</Words>
          <Consents
            consents={consents}
            withdrawn={withdrawn}
            busy={busy}
            text={text}
            withdraw={(consent) => void withdraw(consent)}
          />
          <Ways>
            <li>
              <PageLink href={path("profile")}>{text.profileLink}</PageLink>
            </li>
            <li>
              <PageLink href={path("security")}>{text.securityLink}</PageLink>
            </li>
          </Ways>
          <Action label={busy ? text.working : text.signOut} busy={busy} onClick={() => void signOut()} />
        </>
      ) : null}
    </Frame>
  );
}

interface ConsentsProps {
  consents: GivenConsent[];
  /** The application the person just withdrew, to say so. */
  withdrawn: string | null;
  busy: boolean;
  text: Messages;
  withdraw: (consent: GivenConsent) => void;
}

/** The applications the person let into their account, each with a way to withdraw it. */
function Consents({ consents, withdrawn, busy, text, withdraw }: ConsentsProps) {
  const until = (moment: string) =>
    new Intl.DateTimeFormat(text.locale, { dateStyle: "long" }).format(new Date(moment));
  return (
    <VStack as="section" gap={3} aria-label={text.givenConsentsTitle}>
      <Words>{text.givenConsentsTitle}</Words>
      {withdrawn !== null ? <Notice kind="success">{text.consentWithdrawn(withdrawn)}</Notice> : null}
      {consents.length === 0 ? (
        <Words quiet>{text.givenConsentsNone}</Words>
      ) : (
        <ul className="auth-consent-scopes">
          {consents.map((consent) => (
            <li key={consent.clientId}>
              <VStack gap={2}>
                <Words>{text.givenConsent(consent.application, until(consent.expiresAt))}</Words>
                <Action
                  label={text.withdrawConsent(consent.application)}
                  variant="ghost"
                  busy={busy}
                  onClick={() => withdraw(consent)}
                />
              </VStack>
            </li>
          ))}
        </ul>
      )}
    </VStack>
  );
}
