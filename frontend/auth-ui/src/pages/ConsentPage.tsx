import { Link } from "@astryxdesign/core/Link";
import { VStack } from "@astryxdesign/core/VStack";
import { useEffect, useState } from "react";
import type { AskedScope, ConsentQuestion, Failure, SelfDescription } from "../client";
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
    case "groups":
      return text.consentScopeGroups;
    default:
      return scope.scope;
  }
}

/**
 * What an application that registered itself says of itself: its logo,
 * a sentence that nobody checked it, and its links. The logo is loaded and
 * the links followed without a referrer; each link opens in a new tab.
 */
function SelfDescribed({ described, text }: { described: SelfDescription; text: Messages }) {
  const links = [
    { href: described.clientUri, label: text.consentHomePage },
    { href: described.policyUri, label: text.consentPrivacyPolicy },
    { href: described.tosUri, label: text.consentTerms },
  ].filter((link): link is { href: string; label: string } => link.href !== null);
  return (
    <>
      {described.logoUri === null ? null : (
        <img
          className="auth-consent-logo"
          src={described.logoUri}
          alt=""
          referrerPolicy="no-referrer"
          width={64}
          height={64}
        />
      )}
      <Words quiet>{text.consentSelfNamed}</Words>
      {links.length === 0 ? null : (
        <Ways>
          {links.map((link) => (
            <li key={link.href}>
              <Link href={link.href} hasUnderline isExternalLink newTabLabel={text.opensInNewTab}>
                {link.label}
              </Link>
            </li>
          ))}
        </Ways>
      )}
    </>
  );
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
      {question.registered === null ? null : <SelfDescribed described={question.registered} text={text} />}
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
