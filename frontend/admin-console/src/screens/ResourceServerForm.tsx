import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { TextArea } from "@astryxdesign/core/TextArea";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useState } from "react";
import type { Failure, ResourceServer, Scope } from "../client";
import { describe, type Messages } from "../messages";
import { Ladder } from "../parts/Confirm";
import { asFailure } from "../parts/Loaded";

/** Scopes as typed: one per line, the name, a space, then what it allows. */
export function definedScopesOf(typed: string): Scope[] {
  return typed
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "")
    .map((line) => {
      const space = line.search(/\s/);
      return space === -1
        ? { name: line, description: "" }
        : { name: line.slice(0, space), description: line.slice(space).trim() };
    });
}

/** Scopes written as the form takes them. */
export function writtenScopes(scopes: Scope[]): string {
  return scopes.map((scope) => (scope.description === "" ? scope.name : `${scope.name} ${scope.description}`)).join("\n");
}

interface Props {
  /** The resource server being changed; `null` to register one. */
  current: ResourceServer | null;
  /** Registers one with an audience, or changes the current one. */
  submit: (audience: string, name: string, scopes: Scope[]) => Promise<ResourceServer>;
  onDone: (server: ResourceServer) => void;
  onClose: () => void;
  text: Messages;
}

/** The form of an application's resource server. Its audience is given once and never changed. */
export function ResourceServerForm({ current, submit, onDone, onClose, text }: Props) {
  const [audience, setAudience] = useState(current?.audience ?? "");
  const [name, setName] = useState(current?.name ?? "");
  const [scopes, setScopes] = useState(current === null ? "" : writtenScopes(current.scopes));
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const filled = audience.trim() !== "" && name.trim() !== "";

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || !filled) {
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      onDone(await submit(audience, name, definedScopesOf(scopes)));
    } catch (thrown) {
      setFailure(asFailure(thrown));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={600} purpose="form">
      <DialogHeader
        title={current === null ? text.addResourceServer : text.changeResourceServer}
        subtitle={<Ladder action="changeResourceServer" text={text} />}
      />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {failure !== null ? <Banner status="error" title={describe(failure, text)} role="alert" /> : null}
          <TextInput
            label={text.audienceLabel}
            description={text.audienceHint}
            value={audience}
            onChange={setAudience}
            isDisabled={current !== null}
            autoComplete="off"
            autoCapitalize="none"
            hasSpellCheck={false}
            hasAutoFocus={current === null}
            width="100%"
          />
          <TextInput
            label={text.resourceServerNameLabel}
            value={name}
            onChange={setName}
            autoComplete="off"
            width="100%"
          />
          <TextArea
            label={text.definedScopesLabel}
            description={text.definedScopesHint}
            value={scopes}
            onChange={setScopes}
            rows={5}
            width="100%"
          />
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button
              type="submit"
              variant="primary"
              label={current === null ? text.addResourceServer : text.saveSettings}
              isDisabled={!filled}
              isLoading={busy}
            />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
