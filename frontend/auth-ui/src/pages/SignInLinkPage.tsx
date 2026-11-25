import { useEffect, useState } from "react";
import type { Failure } from "../client";
import { describe } from "../messages";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { PageLink, Ways, Words } from "../parts/Words";
import { asFailure, type PageProps } from "./shared";

interface SignInLinkPageProps extends PageProps {
  /** The token of the link, from after `#`; `null` when the address has none. */
  token: string | null;
}

type View =
  | { kind: "working" }
  /** This browser has no sign-in: the link was asked for in another one. */
  | { kind: "elsewhere" }
  /** The token was rejected, or the sign-in moved on. */
  | { kind: "refused" }
  | { kind: "stopped"; failure: Failure };

/**
 * Where the link of a message to sign in opens. The page presents the
 * token within the sign-in of this browser, which is the one that asked
 * for it or none: a link opened anywhere else signs nobody in. It decides
 * nothing.
 */
export function SignInLinkPage({ tenant, client, text, go, leave, path, token }: SignInLinkPageProps) {
  const [view, setView] = useState<View>({ kind: "working" });

  useEffect(() => {
    let current = true;
    const finish = async (): Promise<() => void> => {
      if (token === null) {
        return () => setView({ kind: "refused" });
      }
      // Asking where the sign-in stands is what gives this page the token
      // its request needs; with no sign-in here, nothing is sent.
      if ((await client.currentSignIn()) === null) {
        return () => setView({ kind: "elsewhere" });
      }
      const result = await client.submitEmailLink(token);
      if (result.status === "completed") {
        const next = result.continueTo;
        return next === undefined ? () => go("account") : () => leave(next);
      }
      // Accepted, and a second factor is asked for next: its page asks.
      if (result.status === "pending") {
        return () => go("sign-in");
      }
      return () => setView({ kind: "refused" });
    };
    finish().then(
      (next) => {
        if (current) {
          next();
        }
      },
      (thrown: unknown) => {
        if (!current) {
          return;
        }
        const failed = asFailure(thrown);
        // The sign-in ended or moved on meanwhile, or the link was used
        // at the same moment: the link does not work here, said in one way.
        if (failed.status === 404 || failed.status === 409 || failed.status === 422) {
          setView({ kind: "refused" });
        } else {
          setView({ kind: "stopped", failure: failed });
        }
      },
    );
    return () => {
      current = false;
    };
  }, [client, go, leave, token]);

  return (
    <Frame tenant={tenant} title={text.signInLinkTitle} text={text}>
      {view.kind === "working" ? (
        <Words quiet announced>
          {text.loading}
        </Words>
      ) : null}
      {view.kind === "elsewhere" ? <Notice kind="info">{text.signInLinkElsewhere}</Notice> : null}
      {view.kind === "refused" ? <Notice kind="danger">{text.signInLinkRefused}</Notice> : null}
      {view.kind === "stopped" ? <Notice kind="danger">{describe(view.failure, text)}</Notice> : null}
      {view.kind !== "working" ? (
        <Ways>
          <li>
            <PageLink href={path("sign-in")}>{text.goToSignIn}</PageLink>
          </li>
        </Ways>
      ) : null}
    </Frame>
  );
}
