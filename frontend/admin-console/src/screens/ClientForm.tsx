import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { CheckboxList, CheckboxListItem } from "@astryxdesign/core/CheckboxList";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { Text } from "@astryxdesign/core/Text";
import { TextArea } from "@astryxdesign/core/TextArea";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useState } from "react";
import type { ApplicationClient, ClientSettings, Failure } from "../client";
import { describe, named, type Messages } from "../messages";
import { Ladder } from "../parts/Confirm";
import { asFailure } from "../parts/Loaded";
import { scopesOf } from "./ProviderForm";

const GRANTS = ["authorization_code", "refresh_token", "client_credentials"] as const;
const CONFIDENTIAL_METHODS = ["client_secret_basic", "client_secret_post", "private_key_jwt"] as const;

/** Redirect addresses as typed: one per line, kept exactly as written otherwise. */
export function linesOf(typed: string): string[] {
  return typed
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

interface Props {
  /** The client being changed; `null` to create one. */
  current: ApplicationClient | null;
  /** Creates or changes; a failure it throws is shown and the form stays open. */
  submit: (type: string, settings: ClientSettings) => Promise<void>;
  onClose: () => void;
  text: Messages;
}

/**
 * The form of a client. The server checks every rule of a client; the
 * form keeps to what can be chosen, so that a public client is never
 * offered a secret.
 */
export function ClientForm({ current, submit, onClose, text }: Props) {
  const [type, setType] = useState(current?.type ?? "confidential");
  const [name, setName] = useState(current?.name ?? "");
  const [method, setMethod] = useState(current?.authenticationMethod ?? "client_secret_basic");
  const [grants, setGrants] = useState<string[]>(current?.grantTypes ?? ["authorization_code"]);
  const [redirects, setRedirects] = useState((current?.redirectUris ?? []).join("\n"));
  const [afterLogout, setAfterLogout] = useState((current?.postLogoutRedirectUris ?? []).join("\n"));
  const [scopes, setScopes] = useState((current?.allowedScopes ?? ["openid"]).join(" "));
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const isPublic = type === "public";
  const filled = name.trim() !== "" && grants.length > 0;

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || !filled) {
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      await submit(type, {
        name,
        authenticationMethod: isPublic ? "none" : method,
        // Kept in the order the server documents them.
        grantTypes: GRANTS.filter((grant) => grants.includes(grant)),
        redirectUris: linesOf(redirects),
        postLogoutRedirectUris: linesOf(afterLogout),
        allowedScopes: scopesOf(scopes),
      });
    } catch (thrown) {
      setFailure(asFailure(thrown));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={640} purpose="form">
      <DialogHeader
        title={current === null ? text.addClient : text.changeSettingsTitle(current.name)}
        subtitle={<Ladder action={current === null ? "addClient" : "changeClient"} text={text} />}
      />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {failure !== null ? <Banner status="error" title={describe(failure, text)} role="alert" /> : null}
          <TextInput
            label={text.clientNameLabel}
            value={name}
            onChange={setName}
            autoComplete="off"
            hasAutoFocus
            width="100%"
          />
          <VStack gap={1}>
            <Text>{text.clientTypeLabel}</Text>
            {current === null ? (
              <SegmentedControl label={text.clientTypeLabel} value={type} onChange={setType}>
                <SegmentedControlItem value="confidential" label={named(text.clientTypes, "confidential")} />
                <SegmentedControlItem value="public" label={named(text.clientTypes, "public")} />
              </SegmentedControl>
            ) : (
              <Text>{named(text.clientTypes, type)}</Text>
            )}
            <Text type="supporting" color="secondary">
              {current === null ? named(text.clientTypeHints, type) : text.clientTypeFixed}
            </Text>
          </VStack>
          {isPublic ? null : (
            <VStack gap={1}>
              <Text>{text.methodLabel}</Text>
              <SegmentedControl label={text.methodLabel} value={method} onChange={setMethod}>
                {CONFIDENTIAL_METHODS.map((value) => (
                  <SegmentedControlItem key={value} value={value} label={named(text.methods, value)} />
                ))}
              </SegmentedControl>
            </VStack>
          )}
          <CheckboxList label={text.grantsLabel} value={grants} onChange={setGrants}>
            {GRANTS.filter((grant) => !(isPublic && grant === "client_credentials")).map((grant) => (
              <CheckboxListItem key={grant} value={grant} label={named(text.grants, grant)} />
            ))}
          </CheckboxList>
          <TextArea
            label={text.redirectUrisLabel}
            description={text.redirectUrisHint}
            value={redirects}
            onChange={setRedirects}
            rows={3}
            width="100%"
          />
          <TextArea
            label={text.postLogoutRedirectUrisLabel}
            description={text.postLogoutRedirectUrisHint}
            value={afterLogout}
            onChange={setAfterLogout}
            rows={2}
            width="100%"
          />
          <TextInput
            label={text.allowedScopesLabel}
            description={text.allowedScopesHint}
            value={scopes}
            onChange={setScopes}
            autoComplete="off"
            autoCapitalize="none"
            hasSpellCheck={false}
            width="100%"
          />
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button
              type="submit"
              variant="primary"
              label={current === null ? text.addClient : text.saveClient}
              isDisabled={!filled}
              isLoading={busy}
            />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
