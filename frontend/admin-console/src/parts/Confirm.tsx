import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, type ReactNode, useState } from "react";
import { ACTIONS, type ActionName } from "../actions";
import { Failure } from "../client";
import { describe, type Messages } from "../messages";

/** The level of an action, as steps and words. */
export function Ladder({ action, text }: { action: ActionName; text: Messages }) {
  const { level } = ACTIONS[action];
  return (
    <span className="console-ladder">
      <span className="console-ladder__steps" aria-hidden="true">
        {[1, 2, 3, 4].map((step) => (
          <span
            key={step}
            className={step <= level ? "console-ladder__step console-ladder__step--on" : "console-ladder__step"}
          />
        ))}
      </span>
      {text.level(level)} · {text.levelFriction[level] ?? ""}
    </span>
  );
}

/** One line of what an action will do: what, and how much. */
export function Consequence({ what, value }: { what: string; value: ReactNode }) {
  return (
    <li className="console-fact">
      <span>{what}</span>
      <strong>{value}</strong>
    </li>
  );
}

interface ConfirmProps {
  /** The action, as the catalog names it: its level decides the confirmation. */
  action: ActionName;
  title: string;
  /** The button that acts, a verb that names the result. */
  confirmLabel: string;
  /** At level 2 and above: the name the person types to confirm. */
  typed?: string;
  /** Whether what else the dialog asks for has been given. */
  ready?: boolean;
  /** Does it. A failure it throws is shown in the dialog, which stays open. */
  onConfirm: () => Promise<void>;
  onClose: () => void;
  text: Messages;
  children: ReactNode;
}

/**
 * The confirmation of an action that changes something, as its level on
 * the dangerous action ladder asks (docs/design/design-system.md,
 * section 6.2). The button that acts is never first, never focused when
 * the dialog opens, and Enter does not press it.
 */
export function Confirm({
  action,
  title,
  confirmLabel,
  typed,
  ready = true,
  onConfirm,
  onClose,
  text,
  children,
}: ConfirmProps) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const mustType = ACTIONS[action].level >= 2 && typed !== undefined;
  const allowed = ready && (!mustType || name.trim() === typed);

  async function confirm() {
    if (busy || !allowed) {
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      await onConfirm();
    } catch (thrown) {
      setFailure(thrown instanceof Failure ? thrown : new Failure(null, 500));
      setBusy(false);
    }
  }

  function swallow(event: FormEvent) {
    // Enter in a field of a confirmation does nothing: the action is taken with its button.
    event.preventDefault();
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={520} purpose="form">
      <DialogHeader title={title} subtitle={<Ladder action={action} text={text} />} />
      <form noValidate onSubmit={swallow}>
        <VStack gap={4} padding={4}>
          {failure !== null ? <Banner status="error" title={describe(failure, text)} role="alert" /> : null}
          {children}
          {mustType ? (
            <TextInput
              label={text.typeToConfirm(typed)}
              value={name}
              onChange={setName}
              autoComplete="off"
              autoCapitalize="none"
              hasSpellCheck={false}
              width="100%"
            />
          ) : null}
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button
              variant="destructive"
              label={confirmLabel}
              isDisabled={!allowed}
              isLoading={busy}
              onClick={() => void confirm()}
            />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
