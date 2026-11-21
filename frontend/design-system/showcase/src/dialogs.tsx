// The confirmations of the dangerous action ladder, the step-up prompt and
// the secret shown once (docs/design/design-system.md, sections 6.2 and 6.4).

import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { CheckboxInput } from "@astryxdesign/core/CheckboxInput";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { Icon } from "@astryxdesign/core/Icon";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { useClipboard } from "@astryxdesign/core/hooks";
import { Fingerprint } from "lucide-react";
import { type ReactNode, useState } from "react";
import { Fact, Facts, HoldButton, Ladder } from "./parts";

export type DialogName = "rotate" | "revoke" | "secret" | "publish";

interface ConfirmationProps {
  /** Closes the dialog; with words, the action was done and they say what happened. */
  onDone: (said?: string) => void;
}

interface FrameProps extends ConfirmationProps {
  title: string;
  subtitle: ReactNode;
  /** A dialog that must be answered cannot be dismissed with Escape or a click outside. */
  required?: boolean;
  footer: ReactNode;
  children: ReactNode;
}

function Frame({ title, subtitle, required = false, footer, onDone, children }: FrameProps) {
  return (
    <Dialog isOpen onOpenChange={() => onDone()} width={520} purpose={required ? "required" : "form"}>
      <DialogHeader title={title} subtitle={subtitle} />
      <VStack gap={4} padding={4}>
        {children}
        <HStack gap={2} justify="end">
          {footer}
        </HStack>
      </VStack>
    </Dialog>
  );
}

/** A field that must hold the name of what is about to be changed. */
function TypeToConfirm({ name, value, onChange, hint }: { name: string; value: string; onChange: (value: string) => void; hint?: string }) {
  return (
    <TextInput
      label={`Type ${name} to confirm`}
      description={hint}
      value={value}
      onChange={onChange}
      autoComplete="off"
      hasSpellCheck={false}
      hasAutoFocus
      width="100%"
    />
  );
}

/** Level 3: the name is typed, then a recent authentication is asked for. */
function RotateKey({ onDone }: ConfirmationProps) {
  const [typed, setTyped] = useState("");
  const [step, setStep] = useState<"confirm" | "step-up">("confirm");

  if (step === "step-up") {
    return (
      <Frame
        title="Confirm it is you"
        subtitle="Rotating a signing key needs an authentication from the last 5 minutes."
        onDone={onDone}
        footer={
          <>
            <Button label="Cancel" onClick={() => onDone()} />
            <Button
              variant="primary"
              label="Simulate passkey"
              onClick={() => onDone("Signing key rotated. New key 0193c4a9…e2b0 is active.")}
            />
          </>
        }
      >
        <VStack gap={2} hAlign="center" paddingBlock={4}>
          <Icon icon={Fingerprint} size="lg" color="accent" />
          <Text>
            Use your passkey for <strong>rafaela.lima</strong>
          </Text>
          <Text type="supporting" color="secondary">
            Waiting for your device…
          </Text>
        </VStack>
      </Frame>
    );
  }

  return (
    <Frame
      title="Rotate signing key set tenant-signing"
      subtitle={<Ladder level={3}>Level 3 · recent authentication required</Ladder>}
      onDone={onDone}
      footer={
        <>
          <Button label="Cancel" onClick={() => onDone()} />
          <Button
            variant="destructive"
            label="Rotate key"
            isDisabled={typed.trim() !== "tenant-signing"}
            onClick={() => setStep("step-up")}
          />
        </>
      }
    >
      <Facts>
        <Fact what="New key becomes active for signing" value="Immediately" />
        <Fact what="Current key stays in the JWKS for verification" value="7 days" />
        <Fact what="Applications that cache the JWKS longer than that" value="0" />
      </Facts>
      <TypeToConfirm
        name="tenant-signing"
        value={typed}
        onChange={setTyped}
        hint="You will be asked to confirm with your passkey."
      />
    </Frame>
  );
}

/** Level 2, with the hold-to-confirm button of the most destructive actions. */
function RevokeSessions({ onDone }: ConfirmationProps) {
  const [typed, setTyped] = useState("");
  return (
    <Frame
      title="Revoke all sessions of ana.mendes"
      subtitle={<Ladder level={2}>Level 2 · type to confirm</Ladder>}
      onDone={onDone}
      footer={
        <>
          <Button label="Cancel" onClick={() => onDone()} />
          <HoldButton
            label="Hold to revoke sessions"
            isDisabled={typed.trim() !== "ana.mendes"}
            onConfirm={() => onDone("Revoked 3 sessions and 11 refresh tokens of ana.mendes.")}
          />
        </>
      }
    >
      <Facts>
        <Fact what="Single sign-on sessions ended" value="3" />
        <Fact what="Application sessions ended" value="7" />
        <Fact what="Refresh tokens revoked" value="11" />
      </Facts>
      <Text color="secondary">
        She must sign in again on every device. Access tokens already issued stay valid until they expire, at most
        5 minutes.
      </Text>
      <TypeToConfirm name="ana.mendes" value={typed} onChange={setTyped} />
    </Frame>
  );
}

const SECRET = "hds_live_K9vT2mXq7RbW4nLp8sYc3HdF6jZa1Ue5";

/** A secret is shown once, and the panel closes only after the person says it is stored. */
function NewSecret({ onDone }: ConfirmationProps) {
  const [stored, setStored] = useState(false);
  const { copy, isCopied } = useClipboard();
  return (
    <Frame
      title="New client secret for reporting-batch"
      subtitle="This is the only time the secret is shown. Hodor stores only a hash of it."
      required
      onDone={onDone}
      footer={
        <Button
          variant="primary"
          label="Close"
          isDisabled={!stored}
          onClick={() => onDone("Secret created. Last characters a1Ue5.")}
        />
      }
    >
      <div className="hodor-secret">
        <span>{SECRET}</span>
        <Button size="sm" label={isCopied ? "Copied" : "Copy"} onClick={() => void copy(SECRET)} />
      </div>
      <HStack justify="between">
        <Text type="supporting" color="secondary">
          Expires 2027-11-20
        </Text>
        <Text type="supporting" color="secondary">
          Previous secret valid until 2026-11-29
        </Text>
      </HStack>
      <CheckboxInput label="I have stored this secret in a secrets manager" value={stored} onChange={setStored} />
    </Frame>
  );
}

function PublishPolicy({ onDone }: ConfirmationProps) {
  return (
    <Frame
      title="Publish orders-access version 14 to production"
      subtitle={<Ladder level={3}>Level 3 · recent authentication required</Ladder>}
      onDone={onDone}
      footer={
        <>
          <Button label="Cancel" onClick={() => onDone()} />
          <Button
            variant="primary"
            label="Publish after step-up"
            onClick={() => onDone("Version 14 published. Recorded as audit record 0193c4b2…91d7.")}
          />
        </>
      }
    >
      <Facts>
        <Fact what="Subjects whose decision changes" value="412" />
        <Fact what="Rollback to version 13" value="One action" />
      </Facts>
      <Banner status="warning" title="Validation warning" description="412 subjects lose orders:refund." />
    </Frame>
  );
}

export function Confirmation({ name, onDone }: ConfirmationProps & { name: DialogName }) {
  switch (name) {
    case "rotate":
      return <RotateKey onDone={onDone} />;
    case "revoke":
      return <RevokeSessions onDone={onDone} />;
    case "secret":
      return <NewSecret onDone={onDone} />;
    case "publish":
      return <PublishPolicy onDone={onDone} />;
  }
}
