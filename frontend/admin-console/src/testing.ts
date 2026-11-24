// What the unit tests share: a server that answers from a script, and
// the things it answers with.

import { Client } from "./client";

export interface Sent {
  method: string;
  /** The path under the tenant, such as `/console/api/users?limit=50`. */
  path: string;
  body: unknown;
  csrfToken: string | null;
}

type Answer = Response | (() => Response);

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/** A problem document, as the server writes them. */
export function problem(status: number, code: string): Response {
  return json(status, { type: `urn:hodor:error:${code}`, status, code, detail: "from the server", request_id: "request-1" });
}

export function empty(status: number): Response {
  return new Response(null, { status });
}

/**
 * A client of the tenant `acme` whose requests are answered from `script`:
 * for each `METHOD path`, the answers to give, in order. A request with no
 * answer left fails the test.
 */
export function scripted(script: Record<string, Answer[]>) {
  const sent: Sent[] = [];
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input.toString();
    const method = init?.method ?? "GET";
    const path = url.replace("/t/acme", "");
    sent.push({
      method,
      path,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : null,
      csrfToken: new Headers(init?.headers).get("X-CSRF-Token"),
    });
    const answer = script[`${method} ${path}`]?.shift();
    if (answer === undefined) {
      throw new Error(`unexpected request: ${method} ${path}`);
    }
    return typeof answer === "function" ? answer() : answer;
  };
  return { client: new Client("acme", fetch), sent };
}

export const ANA = "0193f1c2-0000-7000-8000-000000000001";
export const BIA = "0193f1c2-0000-7000-8000-000000000002";

/** A user, as the console interface writes one. */
export function userBody(id: string, email: string, more: Record<string, unknown> = {}) {
  return {
    id,
    kind: "human",
    status: "active",
    status_reason: null,
    display_name: null,
    locale: null,
    identifiers: [{ id: `${id.slice(0, -1)}f`, kind: "email", value: email, verified: true, primary: true }],
    created_at: "2026-11-20T14:03:11Z",
    updated_at: "2026-11-20T14:03:11Z",
    ...more,
  };
}

const EVERYTHING = [
  "users:read",
  "users:write",
  "sessions:read",
  "sessions:revoke",
  "audit:read",
  "identity-providers:read",
  "identity-providers:write",
  "applications:read",
  "applications:write",
];

export const GOOGLE = "0193f1c2-0000-7000-8000-00000000000a";

/** An identity provider, as the console interface writes one. */
export function providerBody(more: Record<string, unknown> = {}) {
  return {
    id: GOOGLE,
    alias: "google",
    kind: "openid_connect",
    display_name: "Google",
    issuer: "https://accounts.google.com",
    client_id: "1234.apps.googleusercontent.com",
    scopes: ["openid", "email", "profile"],
    creates_users: true,
    trusts_email: false,
    status: "enabled",
    callback_address: "https://auth.example/t/acme/account/providers/google/callback",
    directory: null,
    created_at: "2026-11-21T14:03:11Z",
    updated_at: "2026-11-21T14:03:11Z",
    ...more,
  };
}

/** The answer of `/me` for Ana, an administrator unless told otherwise. */
export function meBody(permissions: string[] = EVERYTHING, roles: string[] = ["tenant_administrator"]) {
  return {
    user: userBody(ANA, "ana@example.com"),
    roles,
    permissions,
    signed_in_at: "2026-11-21T14:03:11Z",
    console_until: "2026-11-22T02:03:11Z",
    csrf_token: "token-of-the-session",
  };
}

export const BILLING = "0193f1c2-0000-7000-8000-0000000000b1";
export const WEB = "0193f1c2-0000-7000-8000-0000000000c1";

/** An application, as the console interface writes one. */
export function applicationBody(more: Record<string, unknown> = {}) {
  return {
    id: BILLING,
    name: "Billing",
    first_party: true,
    status: "enabled",
    created_at: "2026-11-22T14:03:11Z",
    updated_at: "2026-11-22T14:03:11Z",
    ...more,
  };
}

/** A confidential client of Billing, as the console interface writes one. */
export function clientBody(more: Record<string, unknown> = {}) {
  return {
    id: WEB,
    application_id: BILLING,
    name: "Billing web site",
    type: "confidential",
    authentication_method: "client_secret_basic",
    grant_types: ["authorization_code"],
    redirect_uris: ["https://billing.example.com/callback"],
    post_logout_redirect_uris: [],
    allowed_scopes: ["openid"],
    require_pkce: true,
    token_policy: {
      access_token_seconds: 300,
      id_token_seconds: 300,
      refresh_token_seconds: 2592000,
      refresh_idle_seconds: 604800,
    },
    secrets: [
      { id: "0193f1c2-0000-7000-8000-0000000000d1", created_at: "2026-11-22T14:03:11Z", expires_at: "2027-11-22T14:03:11Z" },
    ],
    keys: [],
    status: "enabled",
    created_at: "2026-11-22T14:03:11Z",
    updated_at: "2026-11-22T14:03:11Z",
    ...more,
  };
}

export const FINANCE = "0193f2a0-0000-7000-8000-0000000000e1";
export const PAYABLES = "0193f2a0-0000-7000-8000-0000000000e2";
export const ACME = "0193f2b0-0000-7000-8000-0000000000f1";
export const ENGINEERING = "0193f2b1-0000-7000-8000-0000000000f2";
export const PLATFORM = "0193f2b1-0000-7000-8000-0000000000f3";
export const SALES = "0193f2b1-0000-7000-8000-0000000000f4";

/** A group, or an organization, as the console interface writes one. */
export function namedBody(id: string, name: string, more: Record<string, unknown> = {}) {
  return { id, name, created_at: "2026-11-23T14:03:11Z", updated_at: "2026-11-23T14:03:11Z", ...more };
}

/** A unit of an organization, as the console interface writes one. */
export function unitBody(id: string, name: string, parentId: string | null, kind = "unit") {
  return {
    id,
    parent_id: parentId,
    name,
    kind,
    created_at: "2026-11-23T14:03:11Z",
    updated_at: "2026-11-23T14:03:11Z",
  };
}

/** What an administrator of groups and organizations holds, besides reading users. */
export const MEMBERSHIPS = ["users:read", "groups:read", "groups:write", "organizations:read", "organizations:write"];
