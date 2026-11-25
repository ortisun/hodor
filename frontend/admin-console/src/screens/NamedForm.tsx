import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { Text } from "@astryxdesign/core/Text";
import { TextArea } from "@astryxdesign/core/TextArea";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useState } from "react";
import type { ActionName } from "../actions";
import type { Failure, Named, NamedSettings } from "../client";
import { describe, type Messages } from "../messages";
import { Ladder } from "../parts/Confirm";
import { asFailure } from "../parts/Loaded";

interface Props {
  /** The group or organization being changed; `null` to create one. */
  current: Named | null;
  /** The action as the catalog names it, which decides the level shown. */
  action: ActionName;
  title: string;
  /** The button that sends the form. */
  confirmLabel: string;
  submit: (settings: NamedSettings) => Promise<Named>;
  onDone: (saved: Named) => void;
  onClose: () => void;
  text: Messages;
}

/**
 * The form of a group or an organization: a name and an optional
 * description. Creating is level 0; changing says, before its button,
 * that whatever was given stays given.
 */
export function NamedForm({ current, action, title, confirmLabel, submit, onDone, onClose, text }: Props) {
  const [name, setName] = useState(current?.name ?? "");
  const [description, setDescription] = useState(current?.description ?? "");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const changed =
    current === null || name.trim() !== current.name || description.trim() !== (current.description ?? "");
  const filled = name.trim() !== "" && changed;
  const aboutName = failure?.code?.endsWith("_name_taken") === true || failure?.code?.endsWith("_name_invalid") === true;

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || !filled) {
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      onDone(await submit({ name, description }));
    } catch (thrown) {
      setFailure(asFailure(thrown));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={560} purpose="form">
      <DialogHeader title={title} subtitle={<Ladder action={action} text={text} />} />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {failure !== null && !aboutName ? (
            <Banner status="error" title={describe(failure, text)} role="alert" />
          ) : null}
          <TextInput
            label={text.nameLabel}
            value={name}
            onChange={setName}
            autoComplete="off"
            hasAutoFocus
            status={failure !== null && aboutName ? { type: "error", message: describe(failure, text) } : undefined}
            statusVariant="detached"
            width="100%"
          />
          <TextArea
            label={`${text.descriptionLabel} (${text.optional})`}
            value={description}
            onChange={setDescription}
            rows={3}
            width="100%"
          />
          {current !== null ? <Text color="secondary">{text.identifierKept(current.name)}</Text> : null}
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button type="submit" variant="primary" label={confirmLabel} isDisabled={!filled} isLoading={busy} />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
