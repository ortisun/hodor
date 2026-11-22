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
export const NOTICES = [
  "registered",
  "password-changed",
  "signed-out",
  "provider-refused",
  "provider-cancelled",
] as const;

export type NoticeName = (typeof NOTICES)[number];

export interface Place {
  tenant: string;
  /** `null` when the address is under `/account` but names no page. */
  page: PageName | "provider-callback" | null;
  /** The alias of the identity provider, on the page it sends people back to. */
  provider?: string;
}

const CALLBACK = /^\/t\/([a-z0-9][a-z0-9-]{1,62})\/account\/providers\/([a-z0-9][a-z0-9-]{1,31})\/callback\/?$/;

const PATH = /^\/t\/([a-z0-9][a-z0-9-]{1,62})\/account(?:\/([a-z-]+))?\/?$/;

/** Reads the tenant and the page from a path such as `/t/acme/account/sign-in`. */
export function placeOf(pathname: string): Place | null {
  const back = CALLBACK.exec(pathname);
  if (back?.[1] !== undefined && back[2] !== undefined) {
    return { tenant: back[1], page: "provider-callback", provider: back[2] };
  }
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

/** What an identity provider put in the address when it sent the person back. */
export interface ProviderAnswer {
  code: string | null;
  state: string | null;
  /** The provider's own word for why it sent no code, such as `access_denied`. */
  error: string | null;
  /**
   * `saml` when a SAML identity provider's response was posted to Hodor,
   * which sent the browser here with the state and a receipt instead of a
   * code.
   */
  binding: "saml" | null;
  /** What Hodor gave the browser that carried a SAML response. */
  receipt: string | null;
}

export function providerAnswerOf(search: string): ProviderAnswer {
  const query = new URLSearchParams(search);
  return {
    code: query.get("code"),
    state: query.get("state"),
    error: query.get("error"),
    binding: query.get("binding") === "saml" ? "saml" : null,
    receipt: query.get("receipt"),
  };
}
