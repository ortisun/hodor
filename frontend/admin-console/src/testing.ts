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

export const EXPORT = "0193f2c0-0000-7000-8000-000000000011";
export const ASSISTANT = "0193f2c0-0000-7000-8000-000000000012";
export const REPORTS_KEY = "0193f2d0-0000-7000-8000-000000000021";
export const ROTATED_KEY = "0193f2d0-0000-7000-8000-000000000022";
export const HOOK = "0193f2c4-0000-7000-8000-000000000031";
export const SET_ASIDE = "0193f2d0-0000-7000-8000-000000000041";
export const EVENT = "0193f2cf-0000-7000-8000-000000000051";

/** A service account or an agent, as the console interface writes one: owned by Ana unless told otherwise. */
export function workloadBody(id: string, name: string, more: Record<string, unknown> = {}) {
  return {
    id,
    kind: "service_account",
    name,
    status: "active",
    owners: [ANA],
    created_at: "2026-11-24T14:03:11Z",
    updated_at: "2026-11-24T14:03:11Z",
    ...more,
  };
}

/** An API key, as the console interface writes one: never the key. */
export function apiKeyBody(id: string, name: string, more: Record<string, unknown> = {}) {
  return {
    id,
    name,
    hint: "…7c1e",
    scopes: ["users:read"],
    application_id: null,
    status: "active",
    created_at: "2026-11-24T14:03:11Z",
    expires_at: "2027-02-22T14:03:11Z",
    last_used_at: null,
    revoked_at: null,
    replaced_by: null,
    ...more,
  };
}

/** A webhook endpoint, as the console interface writes one: never a secret. */
export function endpointBody(more: Record<string, unknown> = {}) {
  return {
    id: HOOK,
    url: "https://hooks.example.com/hodor",
    description: "Our directory",
    event_types: ["session.started"],
    secrets: [{ created_at: "2026-11-24T14:03:11Z", expires_at: null }],
    created_at: "2026-11-24T14:03:11Z",
    updated_at: "2026-11-24T14:03:11Z",
    ...more,
  };
}

/** A delivery set aside after its last attempt, as the console interface writes one: never its body. */
export function deliveryBody(more: Record<string, unknown> = {}) {
  return {
    id: SET_ASIDE,
    endpoint_id: HOOK,
    event_id: EVENT,
    event_type: "session.started",
    status: "set_aside",
    attempts: 8,
    next_attempt_at: null,
    last_response_status: 503,
    last_error: "the endpoint answered 503",
    created_at: "2026-11-24T14:03:11Z",
    finished_at: "2026-11-24T16:03:11Z",
    ...more,
  };
}

/** What an administrator of workloads holds, besides reading users. */
export const WORKLOADS = ["users:read", "workloads:read", "workloads:write"];

/** What an administrator of webhooks holds. */
export const WEBHOOKS = ["webhooks:read", "webhooks:write"];

export const PROD = "0193f3a0-0000-7000-8000-000000000061";
export const CLUSTER = "0193f3a0-0000-7000-8000-000000000062";
export const STAGING = "0193f3a0-0000-7000-8000-000000000063";

/** A bundle of one authority for X509-SVIDs and one key for JWT-SVIDs, as the server keeps it. */
export function bundleBody(more: Record<string, unknown> = {}) {
  return {
    spiffe_sequence: 12,
    spiffe_refresh_hint: 300,
    keys: [
      { use: "x509-svid", kty: "EC", crv: "P-256", x: "x-of-the-authority", y: "y-of-the-authority", x5c: ["MIIB"] },
      { use: "jwt-svid", kty: "EC", crv: "P-256", kid: "jwt-1", x: "x-of-the-key", y: "y-of-the-key" },
    ],
    ...more,
  };
}

/** A trust domain fetched from its bundle endpoint, as the console interface writes one. */
export function trustDomainBody(more: Record<string, unknown> = {}) {
  return {
    id: PROD,
    name: "prod.example.com",
    source: "bundle_endpoint",
    bundle_endpoint_url: "https://spire.example.com/bundle",
    bundle: bundleBody(),
    bundle_changed_at: "2026-11-25T14:03:11Z",
    refresh: {
      fetched_at: "2026-11-25T15:03:11Z",
      next_at: "2026-11-25T15:08:11Z",
      failing_since: null,
      last_error: null,
    },
    created_at: "2026-11-25T14:03:11Z",
    updated_at: "2026-11-25T14:03:11Z",
    ...more,
  };
}

/** A trust domain the mesh checks, with no bundle, as the console interface writes one. */
export function meshTrustDomainBody(more: Record<string, unknown> = {}) {
  return {
    id: CLUSTER,
    name: "cluster.local",
    source: "mesh",
    created_at: "2026-11-25T14:03:11Z",
    updated_at: "2026-11-25T14:03:11Z",
    ...more,
  };
}

/** What an administrator of trust domains holds. */
export const KEYS = ["keys:read", "keys:write"];
