import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { Switch } from "@astryxdesign/core/Switch";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useState } from "react";
import type { Failure, NewProvider, Provider, ProviderChange } from "../client";
import { describe, type Messages } from "../messages";
import { Ladder } from "../parts/Confirm";
import { asFailure } from "../parts/Loaded";

/** The scopes as typed: words separated by spaces. */
export function scopesOf(typed: string): string[] {
  return typed.split(/\s+/).filter((scope) => scope !== "");
}

const DEFAULT_SCOPES = "openid email profile";

type Props =
  | {
      /** Adds a provider: the alias and the client secret are asked for, once. */
      adding: true;
      submit: (added: NewProvider) => Promise<Provider>;
      onDone: (provider: Provider) => void;
      onClose: () => void;
      text: Messages;
    }
  | {
      /** Changes a provider: only what was changed is sent. */
      adding: false;
      current: Provider;
      submit: (change: ProviderChange) => Promise<Provider>;
      onDone: (provider: Provider) => void;
      onClose: () => void;
      text: Messages;
    };

/**
 * The form of an identity provider. Before its button it says who will
 * be able to sign in, which is the consequence that puts both actions on
 * level 1 of the ladder.
 */
export function ProviderForm(props: Props) {
  const { text, onClose, onDone } = props;
  const current = props.adding ? null : props.current;
  const [alias, setAlias] = useState("");
  const [name, setName] = useState(current?.displayName ?? "");
  const [issuer, setIssuer] = useState(current?.issuer ?? "");
  const [clientId, setClientId] = useState(current?.clientId ?? "");
  const [secret, setSecret] = useState("");
  const [scopes, setScopes] = useState(current?.scopes.join(" ") ?? DEFAULT_SCOPES);
  const [createsUsers, setCreatesUsers] = useState(current?.createsUsers ?? true);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);

  const change: ProviderChange = {};
  if (current !== null) {
    if (name.trim() !== current.displayName) change.displayName = name;
    if (issuer.trim() !== current.issuer) change.issuer = issuer;
    if (clientId.trim() !== current.clientId) change.clientId = clientId;
    if (scopesOf(scopes).join(" ") !== current.scopes.join(" ")) change.scopes = scopesOf(scopes);
    if (createsUsers !== current.createsUsers) change.createsUsers = createsUsers;
  }
  const changed = Object.keys(change).length > 0;
  const filled = props.adding
    ? [alias, name, issuer, clientId, secret].every((value) => value.trim() !== "")
    : changed;

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || !filled) {
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      const done = props.adding
        ? await props.submit({ alias, displayName: name, issuer, clientId, clientSecret: secret, scopes: scopesOf(scopes), createsUsers })
        : await props.submit(change);
      // The secret is not kept a moment longer than needed.
      setSecret("");
      onDone(done);
    } catch (thrown) {
      setFailure(asFailure(thrown));
      setBusy(false);
    }
  }

  const shownName = name.trim() === "" ? (current?.displayName ?? alias.trim()) : name.trim();
  const action = props.adding ? "addProvider" : "changeProvider";

  return (
    <Dialog isOpen onOpenChange={onClose} width={560} purpose="form">
      <DialogHeader
        title={props.adding ? text.addProvider : text.changeSettingsTitle(current?.displayName ?? "")}
        subtitle={<Ladder action={action} text={text} />}
      />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {failure !== null ? <Banner status="error" title={describe(failure, text)} role="alert" /> : null}
          {props.adding ? (
            <TextInput
              label={text.aliasLabel}
              description={text.aliasHint}
              value={alias}
              onChange={setAlias}
              autoComplete="off"
              autoCapitalize="none"
              hasSpellCheck={false}
              hasAutoFocus
              width="100%"
            />
          ) : null}
          <TextInput
            label={text.providerNameLabel}
            value={name}
            onChange={setName}
            autoComplete="off"
            hasAutoFocus={!props.adding}
            width="100%"
          />
          <TextInput
            label={text.issuerLabel}
            description={text.issuerHint}
            type="url"
            value={issuer}
            onChange={setIssuer}
            autoComplete="off"
            autoCapitalize="none"
            hasSpellCheck={false}
            width="100%"
          />
          <TextInput
            label={text.clientIdLabel}
            description={text.clientIdHint}
            value={clientId}
            onChange={setClientId}
            autoComplete="off"
            autoCapitalize="none"
            hasSpellCheck={false}
            width="100%"
          />
          {props.adding ? (
            <TextInput
              label={text.clientSecretLabel}
              description={text.clientSecretHint}
              type="password"
              value={secret}
              onChange={setSecret}
              autoComplete="off"
              hasSpellCheck={false}
              width="100%"
            />
          ) : null}
          <TextInput
            label={text.scopesLabel}
            description={text.scopesHint}
            value={scopes}
            onChange={setScopes}
            autoComplete="off"
            autoCapitalize="none"
            hasSpellCheck={false}
            width="100%"
          />
          <Switch label={text.createsUsersLabel} value={createsUsers} onChange={setCreatesUsers} />
          {shownName !== "" ? (
            <Text color="secondary">
              {createsUsers ? text.createsUsersOn(shownName) : text.createsUsersOff(shownName)}
            </Text>
          ) : null}
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button
              type="submit"
              variant="primary"
              label={props.adding ? text.addProvider : text.saveSettings}
              isDisabled={!filled}
              isLoading={busy}
            />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
