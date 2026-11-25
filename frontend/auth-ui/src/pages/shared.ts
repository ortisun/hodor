import type { NoticeName, PageName } from "../address";
import { type Client, Failure } from "../client";
import type { Messages } from "../messages";

/** What every page is given. */
export interface PageProps {
  tenant: string;
  client: Client;
  text: Messages;
  /** Sends the person to another page of the tenant. */
  go: (page: PageName, notice?: NoticeName) => void;
  /** Sends the browser to another site: an identity provider. */
  leave: (url: string) => void;
  /** The path of another page of the tenant, for links. */
  path: (page: PageName) => string;
}

/** The key of an authenticator application in groups of four, as people type it. */
export function grouped(secret: string): string {
  return secret.replace(/(.{4})/g, "$1 ").trim();
}

/** Anything thrown that is not a failure of a request is shown as "something went wrong". */
export function asFailure(thrown: unknown): Failure {
  return thrown instanceof Failure ? thrown : new Failure(null, 500);
}
