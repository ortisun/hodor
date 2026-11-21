// Where a page is: which tenant, which page. The tenant comes from the
// address and from nothing else, as on the server.

export const PAGES = [
  "sign-in",
  "register",
  "complete-registration",
  "recover",
  "reset-password",
  "account",
] as const;

export type PageName = (typeof PAGES)[number];

/** Something to tell the person on the page they are sent to. */
export const NOTICES = ["registered", "password-changed", "signed-out"] as const;

export type NoticeName = (typeof NOTICES)[number];

export interface Place {
  tenant: string;
  /** `null` when the address is under `/account` but names no page. */
  page: PageName | null;
}

const PATH = /^\/t\/([a-z0-9][a-z0-9-]{1,62})\/account(?:\/([a-z-]+))?\/?$/;

/** Reads the tenant and the page from a path such as `/t/acme/account/sign-in`. */
export function placeOf(pathname: string): Place | null {
  const match = PATH.exec(pathname);
  if (!match) {
    return null;
  }
  const [, tenant, name] = match;
  if (tenant === undefined) {
    return null;
  }
  if (name === undefined) {
    return { tenant, page: "account" };
  }
  const page = PAGES.find((known) => known === name && known !== "account");
  return { tenant, page: page ?? null };
}

/** The path of a page of a tenant. */
export function pathOf(tenant: string, page: PageName, notice?: NoticeName): string {
  const path = page === "account" ? `/t/${tenant}/account` : `/t/${tenant}/account/${page}`;
  return notice ? `${path}?notice=${notice}` : path;
}

/** The notice named in a query string, if it is one the pages know. */
export function noticeOf(search: string): NoticeName | null {
  const named = new URLSearchParams(search).get("notice");
  return NOTICES.find((known) => known === named) ?? null;
}

/**
 * The token of a link from a message. It comes after `#`, which a browser
 * never sends to a server.
 */
export function tokenOf(hash: string): string | null {
  const token = new URLSearchParams(hash.replace(/^#/, "")).get("token");
  return token && /^[0-9a-f]{16,128}$/.test(token) ? token : null;
}
