import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { Text } from "@astryxdesign/core/Text";
import { TextArea } from "@astryxdesign/core/TextArea";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useState } from "react";
import { isIdentifier } from "../address";
import type { Workload, WorkloadKind, WorkloadSettings } from "../client";
import { describe, type Messages } from "../messages";
import { Ladder } from "../parts/Confirm";
import { asFailure } from "../parts/Loaded";

/** The lines of a field, each trimmed, the empty ones left out. */
export function linesOf(typed: string): string[] {
  return typed
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

interface Props {
  kind: WorkloadKind;
  /** The workload being changed; `null` to create one. */
  current: Workload | null;
  submit: (settings: WorkloadSettings) => Promise<Workload>;
  onDone: (saved: Workload) => void;
  onClose: () => void;
  text: Messages;
}

/**
 * The form of a service account or an agent: its name and its owners, by
 * their user identifiers, one a line. Creating is level 0; changing says,
 * before its button, that its clients, keys and roles stay as they are.
 */
export function WorkloadForm({ kind, current, submit, onDone, onClose, text }: Props) {
  const [name, setName] = useState(current?.name ?? "");
  const [owners, setOwners] = useState(current?.owners.join("\n") ?? "");
  const [busy, setBusy] = useState(false);
  // What went wrong, in words: said before asking the server when an owner is not an identifier.
  const [message, setMessage] = useState<string | null>(null);
  const listed = linesOf(owners).map((owner) => owner.toLowerCase());
  const filled = name.trim() !== "" && listed.length > 0;
  const action = current === null ? "createWorkload" : "changeWorkload";
  const title =
    current === null ? ofKind(kind, text.createWorkloadTitle) : text.changeWorkloadTitle(current.name);

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || !filled) {
      return;
    }
    if (!listed.every(isIdentifier)) {
      setMessage(text.ownersNotIdentifiers);
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      onDone(await submit({ name, owners: listed }));
    } catch (thrown) {
      setMessage(describe(asFailure(thrown), text));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={560} purpose="form">
      <DialogHeader title={title} subtitle={<Ladder action={action} text={text} />} />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {message !== null ? <Banner status="error" title={message} role="alert" /> : null}
          <TextInput
            label={text.nameLabel}
            value={name}
            onChange={setName}
            autoComplete="off"
            hasAutoFocus
            width="100%"
          />
          <TextArea
            label={text.ownersLabel}
            description={text.ownersHint}
            value={owners}
            onChange={setOwners}
            rows={3}
            width="100%"
          />
          {current !== null ? <Text color="secondary">{text.workloadKept(current.name)}</Text> : null}
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button
              type="submit"
              variant="primary"
              label={current === null ? ofKind(kind, text.createWorkload) : text.saveWorkload}
              isDisabled={!filled}
              isLoading={busy}
            />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}

/** The copy of one kind of workload, from a pair of both. */
export function ofKind<T>(kind: WorkloadKind, pair: { service_account: T; agent: T }): T {
  return pair[kind];
}
