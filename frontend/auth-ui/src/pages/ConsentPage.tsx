import { VStack } from "@astryxdesign/core/VStack";
import { useEffect, useState } from "react";
import type { AskedScope, ConsentQuestion, Failure } from "../client";
import type { Messages } from "../messages";
import { describe } from "../messages";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { Action } from "../parts/Submit";
import { PageLink, Ways, Words } from "../parts/Words";
import { asFailure, type PageProps } from "./shared";

/** What a scope lets the application do, in the person's language. */
function wordsFor(scope: AskedScope, text: Messages): string {
  if (scope.kind === "resource") {
    return text.consentScopeOfResource(scope.description, scope.resourceServer);
  }
  switch (scope.scope) {
    case "openid":
      return text.consentScopeOpenid;
    case "profile":
      return text.consentScopeProfile;
    case "email":
      return text.consentScopeEmail;
    case "address":
      return text.consentScopeAddress;
    case "phone":
      return text.consentScopePhone;
    default:
      return scope.scope;
  }
}

type View =
  | { kind: "loading" }
  | { kind: "nothing" }
  | { kind: "asking"; question: ConsentQuestion };

/**
 * Where a person is asked whether an application may have the access it
 * asks for. The application's request waits in the browser; the answer
 * sends the browser back to the authorization endpoint.
 */
export function ConsentPage({ tenant, client, text, go, leave, path }: PageProps) {
  const [view, setView] = useState<View>({ kind: "loading" });
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);

  useEffect(() => {
    let current = true;
    const load = async (): Promise<View | "signed-out"> => {
      if ((await client.session()) === null) {
        return "signed-out";
      }
      const question = await client.consentQuestion();
      return question === null ? { kind: "nothing" } : { kind: "asking", question };
    };
    load().then(
      (loaded) => {
        if (!current) {
          return;
        }
        if (loaded === "signed-out") {
          go("sign-in");
        } else {
          setView(loaded);
        }
      },
      (thrown: unknown) => {
        if (current) {
          setFailure(asFailure(thrown));
          setView({ kind: "nothing" });
        }
      },
    );
    return () => {
      current = false;
    };
  }, [client, go]);

  async function answer(decision: "allow" | "deny") {
    if (busy) {
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      leave(await client.answerConsent(decision));
    } catch (thrown) {
      const failed = asFailure(thrown);
      if (failed.status === 404) {
        // Answered already, or gone: there is nothing left to answer.
        setView({ kind: "nothing" });
      } else {
        setFailure(failed);
      }
      setBusy(false);
    }
  }

  const notice = failure === null ? null : <Notice kind="danger">{describe(failure, text)}</Notice>;

  if (view.kind === "loading") {
    return (
      <Frame tenant={tenant} title={text.loading} text={text}>
        {notice}
      </Frame>
    );
  }
  if (view.kind === "nothing") {
    return (
      <Frame tenant={tenant} title={text.consentNothingTitle} text={text}>
        {notice}
        <Words>{text.consentNothing}</Words>
        <Ways>
          <li>
            <PageLink href={path("account")}>{text.goToAccount}</PageLink>
          </li>
        </Ways>
      </Frame>
    );
  }

  const { question } = view;
  return (
    <Frame tenant={tenant} title={text.consentTitle(question.application)} text={text}>
      {notice}
      <Words>{text.consentLead}</Words>
      <ul className="auth-consent-scopes">
        {question.scopes.map((scope) => (
          <li key={scope.scope}>{wordsFor(scope, text)}</li>
        ))}
        {question.offlineAccess ? <li>{text.consentOffline}</li> : null}
      </ul>
      <VStack gap={3}>
        <Action
          label={busy ? text.working : text.consentAllow}
          variant="primary"
          busy={busy}
          onClick={() => void answer("allow")}
        />
        <Action label={text.consentDeny} onClick={() => void answer("deny")} />
      </VStack>
    </Frame>
  );
}
