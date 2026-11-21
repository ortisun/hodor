import type { ReactNode } from "react";

interface NoticeProps {
  kind: "danger" | "success" | "info";
  children: ReactNode;
}

/** A message about the whole form. A failure is announced at once. */
export function Notice({ kind, children }: NoticeProps) {
  const variant = kind === "info" ? "alert" : `alert alert--${kind}`;
  return (
    <div className={variant} role={kind === "danger" ? "alert" : "status"}>
      <p>{children}</p>
    </div>
  );
}
