import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { useClipboard } from "@astryxdesign/core/hooks";
import type { Messages } from "../messages";

interface ShownOnceProps {
  /** The secret, as the answer that made it gave it. */
  secret: string;
  /** Closes the dialog; whoever shows it forgets the secret then. */
  onClose: () => void;
  text: Messages;
}

/**
 * A client's new secret, in the one place the console ever shows it:
 * the dialog that follows the answer that made it. The server keeps only
 * its hash, so once this closes nobody can see it again.
 */
export function ShownOnce({ secret, onClose, text }: ShownOnceProps) {
  const { copy, isCopied } = useClipboard();
  return (
    <Dialog isOpen onOpenChange={onClose} width={560} purpose="form">
      <DialogHeader title={text.shownOnceTitle} />
      <VStack gap={4} padding={4}>
        <Banner status="warning" title={text.shownOnceLead} />
        <VStack gap={1}>
          <Text type="supporting" color="secondary">
            {text.secretLabel}
          </Text>
          <span className="console-mono console-wrap" data-testid="shown-once">
            {secret}
          </span>
        </VStack>
        <HStack gap={2} justify="end">
          <Button label={isCopied ? text.secretCopied : text.copySecret} onClick={() => void copy(secret)} />
          <Button variant="primary" label={text.secretKept} onClick={onClose} />
        </HStack>
      </VStack>
    </Dialog>
  );
}
