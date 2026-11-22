import { Icon } from "@astryxdesign/core/Icon";
import { IconButton } from "@astryxdesign/core/IconButton";
import { useClipboard } from "@astryxdesign/core/hooks";
import { Check, Copy } from "lucide-react";
import type { Messages } from "../messages";

/** An identifier with the part that differs between two of them kept: the start and the end. */
export function shortened(value: string): string {
  return value.length <= 14 ? value : `${value.slice(0, 8)}…${value.slice(-4)}`;
}

interface IdentifierProps {
  value: string;
  /** Shown whole where there is room for it, such as on the page of the object it names. */
  whole?: boolean;
  text: Messages;
}

/**
 * An identifier: in the mono family, shortened in the middle, with the
 * whole value one click away (docs/design/design-system.md, section 6.5).
 */
export function Identifier({ value, whole = false, text }: IdentifierProps) {
  const { copy, isCopied } = useClipboard();
  return (
    <span className="console-identifier" title={value}>
      <span>{whole ? value : shortened(value)}</span>
      <IconButton
        variant="ghost"
        size="sm"
        label={isCopied ? text.copied : text.copyIdentifier}
        icon={<Icon icon={isCopied ? Check : Copy} />}
        onClick={() => void copy(value)}
      />
    </span>
  );
}
