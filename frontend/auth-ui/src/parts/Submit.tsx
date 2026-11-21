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
    <button type="submit" className="button button--primary auth-wide" aria-disabled={busy}>
      {busy ? text.working : label}
    </button>
  );
}
