// Where the console is, read from the address. The tenant is part of
// every address of the console: a tab never changes tenant on its own.
// See docs/architecture/admin-console.md.

export type Screen =
  | { name: "home" }
  | { name: "users" }
  | { name: "user"; id: string }
  | { name: "audit" }
  | { name: "providers" }
  | { name: "provider"; id: string }
  | { name: "applications" }
  | { name: "application"; id: string }
  | { name: "client"; id: string }
  | { name: "authorization" };

export interface Place {
  tenant: string;
  /** `null` when the address is under the console and names no screen it has. */
  screen: Screen | null;
}

const TENANT = /^[a-z0-9][a-z0-9-]*$/;
const IDENTIFIER = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Whether a text has the shape of an identifier, such as a user's. */
export function isIdentifier(text: string): boolean {
  return IDENTIFIER.test(text);
}

/** The tenant and the screen an address names; `null` when it is not the console's. */
export function placeOf(pathname: string): Place | null {
  const parts = pathname.split("/").filter((part) => part !== "");
  const [t, tenant, console, ...rest] = parts;
  if (t !== "t" || tenant === undefined || !TENANT.test(tenant) || console !== "console") {
    return null;
  }
  return { tenant, screen: screenOf(rest) };
}

function screenOf(rest: string[]): Screen | null {
  const [first, second, ...more] = rest;
  if (first === undefined) {
    return { name: "home" };
  }
  if (first === "users" && second === undefined) {
    return { name: "users" };
  }
  if (first === "users" && second !== undefined && more.length === 0 && isIdentifier(second)) {
    return { name: "user", id: second.toLowerCase() };
  }
  if (first === "audit" && second === undefined) {
    return { name: "audit" };
  }
  if (first === "identity-providers" && second === undefined) {
    return { name: "providers" };
  }
  if (first === "identity-providers" && second !== undefined && more.length === 0 && isIdentifier(second)) {
    return { name: "provider", id: second.toLowerCase() };
  }
  if (first === "applications" && second === undefined) {
    return { name: "applications" };
  }
  if (first === "applications" && second !== undefined && more.length === 0 && isIdentifier(second)) {
    return { name: "application", id: second.toLowerCase() };
  }
  if (first === "authorization" && second === undefined) {
    return { name: "authorization" };
  }
  if (first === "clients" && second !== undefined && more.length === 0 && isIdentifier(second)) {
    return { name: "client", id: second.toLowerCase() };
  }
  return null;
}

/** The address of a screen of a tenant's console. */
export function pathOf(tenant: string, screen: Screen): string {
  const base = `/t/${tenant}/console`;
  switch (screen.name) {
    case "home":
      return base;
    case "users":
      return `${base}/users`;
    case "user":
      return `${base}/users/${screen.id}`;
    case "audit":
      return `${base}/audit`;
    case "providers":
      return `${base}/identity-providers`;
    case "provider":
      return `${base}/identity-providers/${screen.id}`;
    case "applications":
      return `${base}/applications`;
    case "application":
      return `${base}/applications/${screen.id}`;
    case "client":
      return `${base}/clients/${screen.id}`;
    case "authorization":
      return `${base}/authorization`;
  }
}

/** Where a person signs in, and where they land when they have no access here. */
export function signInPath(tenant: string): string {
  return `/t/${tenant}/account/sign-in`;
}

export function accountPath(tenant: string): string {
  return `/t/${tenant}/account`;
}
