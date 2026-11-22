import { Button } from "@astryxdesign/core/Button";
import type { Messages } from "../messages";

interface SubmitProps {
  label: string;
  busy: boolean;
  text: Messages;
}

/**
 * The button that sends a form. While the request is on its way it stays
 * where it is and keeps focus, and says that work is going on.
 */
export function Submit({ label, busy, text }: SubmitProps) {
  return (
    <Button
      type="submit"
      variant="primary"
      size="lg"
      width="100%"
      label={busy ? text.working : label}
      isLoading={busy}
    />
  );
}

interface ActionProps {
  label: string;
  /** How much the action stands out. A page has one primary action at most. */
  variant?: "primary" | "secondary" | "ghost";
  busy?: boolean;
  onClick: () => void;
}

/** A button that does something other than sending the form. */
export function Action({ label, variant = "secondary", busy = false, onClick }: ActionProps) {
  return <Button variant={variant} size="lg" width="100%" label={label} isLoading={busy} onClick={onClick} />;
}
