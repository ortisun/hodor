import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { Switch } from "@astryxdesign/core/Switch";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useState } from "react";
import type { Application, ApplicationSettings, Failure } from "../client";
import { describe, type Messages } from "../messages";
import { Ladder } from "../parts/Confirm";
import { asFailure } from "../parts/Loaded";

interface Props {
  /** The application being changed; `null` to register one. */
  current: Application | null;
  submit: (settings: ApplicationSettings) => Promise<Application>;
  onDone: (application: Application) => void;
  onClose: () => void;
  text: Messages;
}

/**
 * The form of an application. Before its button it says whether people
 * will be asked for consent, the consequence that puts it on level 1.
 */
export function ApplicationForm({ current, submit, onDone, onClose, text }: Props) {
  const [name, setName] = useState(current?.name ?? "");
  const [firstParty, setFirstParty] = useState(current?.firstParty ?? true);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const changed = current === null || name.trim() !== current.name || firstParty !== current.firstParty;
  const filled = name.trim() !== "" && changed;
  const shown = name.trim() === "" ? (current?.name ?? "") : name.trim();

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || !filled) {
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      onDone(await submit({ name, firstParty }));
    } catch (thrown) {
      setFailure(asFailure(thrown));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={560} purpose="form">
      <DialogHeader
        title={current === null ? text.addApplication : text.changeSettingsTitle(current.name)}
        subtitle={<Ladder action={current === null ? "addApplication" : "changeApplication"} text={text} />}
      />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {failure !== null ? <Banner status="error" title={describe(failure, text)} role="alert" /> : null}
          <TextInput
            label={text.applicationNameLabel}
            value={name}
            onChange={setName}
            autoComplete="off"
            hasAutoFocus
            width="100%"
          />
          <Switch label={text.firstPartyLabel} value={firstParty} onChange={setFirstParty} />
          {shown !== "" ? (
            <Text color="secondary">{firstParty ? text.consentSkipped(shown) : text.consentAsked(shown)}</Text>
          ) : null}
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button
              type="submit"
              variant="primary"
              label={current === null ? text.addApplication : text.saveApplication}
              isDisabled={!filled}
              isLoading={busy}
            />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
