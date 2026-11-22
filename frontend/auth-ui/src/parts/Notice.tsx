import { Banner } from "@astryxdesign/core/Banner";

interface NoticeProps {
  kind: "danger" | "success" | "info";
  children: string;
}

const status = { danger: "error", success: "success", info: "info" } as const;

/** A message about the whole form. A failure is announced at once. */
export function Notice({ kind, children }: NoticeProps) {
  return <Banner status={status[kind]} title={children} role={kind === "danger" ? "alert" : "status"} />;
}
