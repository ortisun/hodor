import { useEffect, useState } from "react";
import type { ProviderAnswer } from "../address";
import type { Failure } from "../client";
import { describe } from "../messages";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { asFailure, type PageProps } from "./shared";

interface ComingBackPageProps extends PageProps {
  /** The alias of the provider that sent the person back. */
  provider: string;
  /** What the provider put in the address. */
  answer: ProviderAnswer;
}

/**
 * Where an identity provider sends a person back to. The page presents
 * what arrived in its address to the server, from Hodor's own origin, and
 * goes on to wherever the answer leads. It decides nothing.
 */
export function ComingBackPage({ tenant, client, text, go, path, provider, answer }: ComingBackPageProps) {
  const [failure, setFailure] = useState<Failure | null>(null);
  const { code, state, error } = answer;

  useEffect(() => {
    let current = true;
    const finish = async () => {
      // The provider sent no code: the person cancelled there, or it refused.
      if (error !== null || code === null || state === null) {
        return () => go("sign-in", "provider-cancelled");
      }
      // Asking where the sign-in stands is what gives this page the
      // token its request needs.
      if ((await client.currentSignIn()) === null) {
        return () => go("sign-in", "provider-refused");
      }
      const result = await client.finishWithProvider(provider, code, state);
      return result.status === "completed"
        ? () => go("account")
        : () => go("sign-in", "provider-refused");
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
        // The sign-in ended or moved on meanwhile: back to its page,
        // which finds out where things stand.
        if (failed.status === 404 || failed.status === 409 || failed.status === 422) {
          go("sign-in", "provider-refused");
        } else {
          setFailure(failed);
        }
      },
    );
    return () => {
      current = false;
    };
  }, [client, go, provider, code, state, error]);

  return (
    <Frame tenant={tenant} title={text.comingBackTitle} text={text}>
      {failure === null ? (
        <p className="auth-text muted" role="status">
          {text.loading}
        </p>
      ) : (
        <>
          <Notice kind="danger">{describe(failure, text)}</Notice>
          <ul className="auth-links">
            <li>
              <a href={path("sign-in")}>{text.backToSignIn}</a>
            </li>
          </ul>
        </>
      )}
    </Frame>
  );
}
