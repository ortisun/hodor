import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useEffect, useState } from "react";
import { type Enrollment, type Factors, Failure, type Key } from "../client";
import { describe } from "../messages";
import { Field } from "../parts/Field";
import { Form } from "../parts/Form";
import { Frame } from "../parts/Frame";
import { Notice } from "../parts/Notice";
import { QrCode } from "../parts/QrCode";
import { Action, Submit } from "../parts/Submit";
import { PageLink, Ways, Words } from "../parts/Words";
import { askToCreate, webAuthnAvailable } from "../webauthn";
import { asFailure, type PageProps } from "./shared";

interface SecurityPageProps extends PageProps {
  /** Sends the person to sign in again and come back here. */
  reauthenticate: () => void;
}

/** What the page shows besides the overview. */
type View =
  | { kind: "overview" }
  | { kind: "setting-up"; enrollment: Enrollment }
  | { kind: "codes"; codes: string[] }
  | { kind: "removing"; what: "application" | Key }
  | { kind: "generating" }
  | { kind: "renaming"; key: Key };

/** The key of an authenticator application in groups of four, as people type it. */
function grouped(secret: string): string {
  return secret.replace(/(.{4})/g, "$1 ").trim();
}

/** Whether changes are allowed now, by the time the server gave. */
function recent(factors: Factors): boolean {
  return factors.recentSignInUntil !== null && Date.parse(factors.recentSignInUntil) > Date.now();
}

/**
 * The person's second factors: their authenticator application, security
 * keys and passkeys, and recovery codes. The server decides every rule; a
 * change it refuses for want of a recent sign-in sends the person to sign
 * in again.
 */
export function SecurityPage({ tenant, client, text, go, path, reauthenticate }: SecurityPageProps) {
  const [factors, setFactors] = useState<Factors | null>(null);
  const [view, setView] = useState<View>({ kind: "overview" });
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [done, setDone] = useState(false);
  const [code, setCode] = useState("");
  const [keyName, setKeyName] = useState("");
  const [newName, setNewName] = useState("");

  useEffect(() => {
    let current = true;
    // The session hands the client its CSRF token.
    client
      .session()
      .then(async (found) => {
        if (found === null) {
          go("sign-in");
          return;
        }
        const read = await client.factors();
        if (current) {
          setFactors(read);
        }
      })
      .catch((thrown: unknown) => {
        if (current) {
          setFailure(asFailure(thrown));
        }
      });
    return () => {
      current = false;
    };
  }, [client, go]);

  /** Runs a change; whatever it answers, the factors are read again. */
  async function change(action: () => Promise<View | null>) {
    if (busy) {
      return;
    }
    setBusy(true);
    setFailure(null);
    setDone(false);
    try {
      const next = await action();
      if (next !== null) {
        setView(next);
        setDone(next.kind === "overview");
      }
      setFactors(await client.factors());
    } catch (thrown) {
      const failed = asFailure(thrown);
      // A refused removal shows the factors again with the reason; a code
      // or a name that was refused keeps its form, to be corrected.
      setView((before) => (before.kind === "removing" || before.kind === "generating" ? { kind: "overview" } : before));
      if (failed.code === "authentication.recent_sign_in_required") {
        setView({ kind: "overview" });
        setFactors(await client.factors().catch(() => factors));
      }
      setFailure(failed);
    } finally {
      setBusy(false);
    }
  }

  const shownCodes = (codes: string[] | null): View => (codes === null ? { kind: "overview" } : { kind: "codes", codes });

  function confirmApplication(event: FormEvent) {
    event.preventDefault();
    void change(async () => {
      const codes = await client.confirmAuthenticatorApplication(code.replace(/\s/g, ""));
      setCode("");
      return shownCodes(codes);
    });
  }

  function addKey(passkey: boolean) {
    void change(async () => {
      const begun = await client.beginKey(passkey);
      const registration = await askToCreate(begun.publicKey);
      if (registration === null) {
        setFailure(new Failure("credential.webauthn_registration_refused", 422));
        return null;
      }
      const name = keyName.trim() === "" ? (passkey ? text.defaultPasskeyName : text.defaultKeyName) : keyName;
      const codes = await client.finishKey(begun.registrationId, registration, name);
      setKeyName("");
      return shownCodes(codes);
    });
  }

  function rename(event: FormEvent, key: Key) {
    event.preventDefault();
    void change(async () => {
      await client.renameKey(key.id, newName);
      return { kind: "overview" };
    });
  }

  const title =
    view.kind === "codes" ? text.codesTitle : view.kind === "setting-up" ? text.setUpApplication : text.securityTitle;

  if (factors === null) {
    return (
      <Frame tenant={tenant} title={failure === null ? text.loading : text.securityTitle} text={text}>
        {failure !== null ? <Notice kind="danger">{describe(failure, text)}</Notice> : null}
      </Frame>
    );
  }

  const allowed = recent(factors);
  const lastFactor =
    (factors.authenticatorApplication?.inUse === true ? 1 : 0) + factors.keys.length === 1;

  return (
    <Frame tenant={tenant} title={title} text={text}>
      {failure !== null ? <Notice kind="danger">{describe(failure, text)}</Notice> : null}
      {done && failure === null ? <Notice kind="success">{text.changed}</Notice> : null}

      {view.kind === "codes" ? (
        <VStack gap={4}>
          <Words>{text.codesLead}</Words>
          <ul className="auth-codes" aria-label={text.codesTitle}>
            {view.codes.map((one) => (
              <li key={one}>
                <Text className="auth-code">{one}</Text>
              </li>
            ))}
          </ul>
          <Action
            variant="primary"
            label={text.codesKept}
            onClick={() => {
              setView({ kind: "overview" });
              setDone(true);
            }}
          />
        </VStack>
      ) : null}

      {view.kind === "setting-up" ? (
        <Form onSubmit={confirmApplication}>
          <Words>{text.setUpLead}</Words>
          <QrCode value={view.enrollment.uri} label={text.qrLabel} />
          <VStack gap={1}>
            <Text as="p" type="supporting" color="secondary">
              {text.secretLabel}
            </Text>
            <Text as="p" className="auth-code">
              {grouped(view.enrollment.secret)}
            </Text>
          </VStack>
          <Field
            label={text.totpLabel}
            hint={text.totpHint}
            name="code"
            autoComplete="one-time-code"
            inputMode="numeric"
            value={code}
            onChange={setCode}
          />
          <Submit label={text.confirmApplication} busy={busy} text={text} />
          <Action
            variant="ghost"
            label={text.cancel}
            onClick={() => {
              setCode("");
              setView({ kind: "overview" });
            }}
          />
        </Form>
      ) : null}

      {view.kind === "removing" || view.kind === "generating" ? (
        <VStack gap={4}>
          <Heading level={2}>
            {view.kind === "generating"
              ? text.generateCodes
              : text.removeTitle(view.what === "application" ? text.theApplication : view.what.name)}
          </Heading>
          <Words>{view.kind === "generating" ? text.generateCodesLead : text.removeLead}</Words>
          {view.kind === "removing" && lastFactor ? <Words>{text.removeLastLead}</Words> : null}
          <HStack gap={2} wrap="wrap">
            <Action label={text.keepIt} variant="primary" onClick={() => setView({ kind: "overview" })} />
            <Action
              label={view.kind === "generating" ? text.generateCodes : text.removeKey(view.what === "application" ? text.theApplication : view.what.name)}
              busy={busy}
              onClick={() =>
                void change(async () => {
                  if (view.kind === "generating") {
                    return shownCodes(await client.generateRecoveryCodes());
                  }
                  if (view.what === "application") {
                    await client.removeAuthenticatorApplication();
                  } else {
                    await client.removeKey(view.what.id);
                  }
                  return { kind: "overview" };
                })
              }
            />
          </HStack>
        </VStack>
      ) : null}

      {view.kind === "overview" || view.kind === "renaming" ? (
        <VStack gap={5}>
          {!allowed ? (
            <VStack gap={3}>
              <Notice kind="info">{text.signInAgainLead}</Notice>
              <Action variant="primary" label={text.signInAgain} onClick={reauthenticate} />
            </VStack>
          ) : null}

          {factors.authenticatorApplication !== null ? (
            <VStack as="section" gap={3}>
              <Heading level={2}>{text.applicationHeading}</Heading>
              <Words>{factors.authenticatorApplication.inUse ? text.applicationInUse : text.applicationNotInUse}</Words>
              {allowed ? (
                <VStack gap={2}>
                  <Action
                    label={factors.authenticatorApplication.inUse ? text.replaceApplication : text.setUpApplication}
                    busy={busy}
                    onClick={() =>
                      void change(async () => ({
                        kind: "setting-up",
                        enrollment: await client.beginAuthenticatorApplication(),
                      }))
                    }
                  />
                  {factors.authenticatorApplication.inUse ? (
                    <Action
                      variant="ghost"
                      label={text.removeApplication}
                      onClick={() => setView({ kind: "removing", what: "application" })}
                    />
                  ) : null}
                </VStack>
              ) : null}
            </VStack>
          ) : null}

          <VStack as="section" gap={3}>
            <Heading level={2}>{text.keysHeading}</Heading>
            {factors.keys.length === 0 ? <Words>{text.noKeys}</Words> : null}
            {factors.keys.length > 0 ? (
              <VStack as="ul" gap={3} className="auth-keys">
                {factors.keys.map((key) => (
                  <li key={key.id}>
                    <VStack gap={1}>
                      <Text as="p" weight="semibold">
                        {key.name}
                      </Text>
                      <Text as="p" type="supporting" color="secondary">
                        {key.passkey ? text.keyKindPasskey : text.keyKindSecurityKey}.{" "}
                        {text.keyAdded(when(key.createdAt, text.locale))}{" "}
                        {key.lastUsedAt === null ? text.keyNeverUsed : text.keyLastUsed(when(key.lastUsedAt, text.locale))}
                      </Text>
                      {view.kind === "renaming" && view.key.id === key.id ? (
                        <Form onSubmit={(event) => rename(event, key)}>
                          <Field
                            label={text.keyNameLabel}
                            name="name"
                            autoComplete="off"
                            autoFocus
                            value={newName}
                            onChange={setNewName}
                          />
                          <Submit label={text.save} busy={busy} text={text} />
                          <Action variant="ghost" label={text.cancel} onClick={() => setView({ kind: "overview" })} />
                        </Form>
                      ) : allowed ? (
                        <HStack gap={2} wrap="wrap">
                          <Action
                            variant="ghost"
                            label={text.renameKey(key.name)}
                            onClick={() => {
                              setNewName(key.name);
                              setView({ kind: "renaming", key });
                            }}
                          />
                          <Action
                            variant="ghost"
                            label={text.removeKey(key.name)}
                            onClick={() => setView({ kind: "removing", what: key })}
                          />
                        </HStack>
                      ) : null}
                    </VStack>
                  </li>
                ))}
              </VStack>
            ) : null}
            {allowed && webAuthnAvailable() ? (
              <VStack gap={2}>
                <Field
                  label={text.keyNameLabel}
                  hint={text.keyNameHint}
                  name="key-name"
                  autoComplete="off"
                  value={keyName}
                  onChange={setKeyName}
                />
                <Action label={text.addSecurityKey} busy={busy} onClick={() => addKey(false)} />
                <Action label={text.addPasskey} busy={busy} onClick={() => addKey(true)} />
              </VStack>
            ) : null}
            {allowed && !webAuthnAvailable() ? <Words quiet>{text.securityKeyUnavailable}</Words> : null}
          </VStack>

          <VStack as="section" gap={3}>
            <Heading level={2}>{text.recoveryHeading}</Heading>
            <Words>
              {factors.recoveryCodesRemaining > 0
                ? text.recoveryRemaining(factors.recoveryCodesRemaining)
                : text.recoveryNone}
            </Words>
            {allowed && (factors.authenticatorApplication?.inUse === true || factors.keys.length > 0) ? (
              <Action label={text.generateCodes} onClick={() => setView({ kind: "generating" })} />
            ) : null}
          </VStack>

          <Ways>
            <li>
              <PageLink href={path("account")}>{text.backToAccount}</PageLink>
            </li>
          </Ways>
        </VStack>
      ) : null}
    </Frame>
  );
}

function when(moment: string, locale: string): string {
  return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(new Date(moment));
}
