import { useEffect, useState } from "react";
import type { ProviderAnswer } from "../address";
import type { Failure } from "../client";
import { describe } from "../messages";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { PageLink, Ways, Words } from "../parts/Words";
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
export function ComingBackPage({ tenant, client, text, go, leave, path, provider, answer }: ComingBackPageProps) {
  const [failure, setFailure] = useState<Failure | null>(null);
  const { code, state, error, binding, receipt } = answer;

  useEffect(() => {
    let current = true;
    const finish = async () => {
      let proof: { code: string } | { receipt: string };
      if (binding === "saml") {
        // Hodor kept a SAML response and sent this browser here with a
        // receipt for it. Without one, there is nothing it could use.
        if (state === null || receipt === null) {
          return () => go("sign-in", "provider-refused");
        }
        proof = { receipt };
      } else {
        // The provider sent no code: the person cancelled there, or it refused.
        if (error !== null || code === null || state === null) {
          return () => go("sign-in", "provider-cancelled");
        }
        proof = { code };
      }
      // Asking where the sign-in stands is what gives this page the
      // token its request needs.
      if ((await client.currentSignIn()) === null) {
        return () => go("sign-in", "provider-refused");
      }
      const result = await client.finishWithProvider(provider, state, proof);
      if (result.status !== "completed") {
        return () => go("sign-in", "provider-refused");
      }
      const next = result.continueTo;
      return next === undefined ? () => go("account") : () => leave(next);
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
  }, [client, go, leave, provider, code, state, error, binding, receipt]);

  return (
    <Frame tenant={tenant} title={text.comingBackTitle} text={text}>
      {failure === null ? (
        <Words quiet announced>
          {text.loading}
        </Words>
      ) : (
        <>
          <Notice kind="danger">{describe(failure, text)}</Notice>
          <Ways>
            <li>
              <PageLink href={path("sign-in")}>{text.backToSignIn}</PageLink>
            </li>
          </Ways>
        </>
      )}
    </Frame>
  );
}
