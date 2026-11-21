// The client for the console interface. It is the only place that knows
// paths, headers and the shape of answers; the screens see values.
// See docs/api/console-interface.md.

/** Why a request did not do what was asked. */
export class Failure {
  constructor(
    /** The `code` of the problem document; `null` when there was none. */
    readonly code: string | null,
    /** The HTTP status; `0` when the server could not be reached. */
    readonly status: number,
    /** The identifier to quote when reporting the problem. */
    readonly requestId: string | null = null,
  ) {}

  /** The session is gone, or too old for the console: the person signs in again. */
  get signedOut(): boolean {
    return this.status === 401;
  }
}

export type Permission =
  | "users:read"
  | "users:write"
  | "sessions:read"
  | "sessions:revoke"
  | "audit:read"
  | "identity-providers:read"
  | "identity-providers:write";

export interface Identifier {
  id: string;
  kind: string;
  value: string;
  verified: boolean;
  primary: boolean;
}

export interface User {
  id: string;
  kind: string;
  status: string;
  statusReason: string | null;
  displayName: string | null;
  locale: string | null;
  identifiers: Identifier[];
  createdAt: string;
  updatedAt: string;
}

/** Who is using the console, and what they may do. */
export interface Me {
  user: User;
  roles: string[];
  permissions: string[];
  signedInAt: string;
  /** When the console stops answering for this sign-in. */
  consoleUntil: string;
}

export interface Session {
  sessionId: string;
  startedAt: string;
  lastActivityAt: string;
  expiresAt: string;
  address: string | null;
  description: string | null;
}

export interface AuditRecord {
  sequence: number;
  action: string;
  occurredAt: string;
  recordedAt: string;
  actor: { kind: string; id: string | null };
  correlationId: string;
  details: Record<string, unknown>;
  previousHash: string;
  hash: string;
}

/** An identity provider. Its client secret is never part of it: the server never gives it back. */
export interface Provider {
  id: string;
  alias: string;
  kind: string;
  displayName: string;
  issuer: string;
  clientId: string;
  scopes: string[];
  createsUsers: boolean;
  status: string;
  /** The address to register at the provider, where it sends people back to. */
  callbackAddress: string;
  createdAt: string;
  updatedAt: string;
}

/** What an administrator gives to add a provider. */
export interface NewProvider {
  alias: string;
  displayName: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  scopes: string[];
  createsUsers: boolean;
}

/** What an administrator may change of a provider; what is left out stays as it is. */
export interface ProviderChange {
  displayName?: string;
  issuer?: string;
  clientId?: string;
  scopes?: string[];
  createsUsers?: boolean;
}

export interface Page<T> {
  items: T[];
  /** What to ask for next; `null` on the last page. */
  nextCursor: string | null;
}

type Fetch = typeof globalThis.fetch;
type Fields = Record<string, unknown>;

function text(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function fields(value: unknown): Fields {
  return typeof value === "object" && value !== null ? (value as Fields) : {};
}

function list(value: unknown): Fields[] {
  return Array.isArray(value) ? value.map(fields) : [];
}

/** A text the answer must have; an answer without it is not one this client understands. */
function required(value: unknown): string {
  const found = text(value);
  if (found === null) {
    throw new Failure(null, 502);
  }
  return found;
}

function user(body: Fields): User {
  return {
    id: required(body["id"]),
    kind: required(body["kind"]),
    status: required(body["status"]),
    statusReason: text(body["status_reason"]),
    displayName: text(body["display_name"]),
    locale: text(body["locale"]),
    identifiers: list(body["identifiers"]).map((identifier) => ({
      id: required(identifier["id"]),
      kind: required(identifier["kind"]),
      value: required(identifier["value"]),
      verified: identifier["verified"] === true,
      primary: identifier["primary"] === true,
    })),
    createdAt: required(body["created_at"]),
    updatedAt: required(body["updated_at"]),
  };
}

function session(body: Fields): Session {
  return {
    sessionId: required(body["session_id"]),
    startedAt: required(body["started_at"]),
    lastActivityAt: required(body["last_activity_at"]),
    expiresAt: required(body["expires_at"]),
    address: text(body["address"]),
    description: text(body["description"]),
  };
}

function auditRecord(body: Fields): AuditRecord {
  const actor = fields(body["actor"]);
  const sequence = body["sequence"];
  if (typeof sequence !== "number") {
    throw new Failure(null, 502);
  }
  return {
    sequence,
    action: required(body["action"]),
    occurredAt: required(body["occurred_at"]),
    recordedAt: required(body["recorded_at"]),
    actor: { kind: text(actor["kind"]) ?? "unknown", id: text(actor["id"]) },
    correlationId: required(body["correlation_id"]),
    details: fields(body["details"]),
    previousHash: required(body["previous_hash"]),
    hash: required(body["hash"]),
  };
}

function provider(body: Fields): Provider {
  return {
    id: required(body["id"]),
    alias: required(body["alias"]),
    kind: required(body["kind"]),
    displayName: required(body["display_name"]),
    issuer: required(body["issuer"]),
    clientId: required(body["client_id"]),
    scopes: strings(body["scopes"]),
    createsUsers: body["creates_users"] === true,
    status: required(body["status"]),
    callbackAddress: required(body["callback_address"]),
    createdAt: required(body["created_at"]),
    updatedAt: required(body["updated_at"]),
  };
}

function page<T>(body: Fields, item: (fields: Fields) => T): Page<T> {
  return { items: list(body["items"]).map(item), nextCursor: text(body["next_cursor"]) };
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export class Client {
  /** The token to send back with requests that change something; `/me` gives it. */
  #csrfToken: string | null = null;
  readonly #tenant: string;
  readonly #fetch: Fetch;

  constructor(tenant: string, fetch: Fetch = (...input) => globalThis.fetch(...input)) {
    this.#tenant = tenant;
    this.#fetch = fetch;
  }

  async #send(method: string, path: string, body?: unknown, base = "console/api"): Promise<Fields> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (this.#csrfToken !== null && method !== "GET") {
      headers["X-CSRF-Token"] = this.#csrfToken;
    }
    let response: Response;
    try {
      response = await this.#fetch(`/t/${this.#tenant}/${base}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
      });
    } catch {
      throw new Failure(null, 0);
    }
    let parsed: unknown = null;
    try {
      parsed = await response.json();
    } catch {
      // No body, or not JSON: handled below by the status alone.
    }
    const answer = fields(parsed);
    if (!response.ok) {
      throw new Failure(
        text(answer["code"]),
        response.status,
        text(answer["request_id"]) ?? response.headers.get("X-Request-Id"),
      );
    }
    return answer;
  }

  /** Who is using the console; `null` when nobody is signed in, or the sign-in is too old. */
  async me(): Promise<Me | null> {
    let body: Fields;
    try {
      body = await this.#send("GET", "/me");
    } catch (failure) {
      if (failure instanceof Failure && failure.signedOut) {
        return null;
      }
      throw failure;
    }
    this.#csrfToken = required(body["csrf_token"]);
    return {
      user: user(fields(body["user"])),
      roles: strings(body["roles"]),
      permissions: strings(body["permissions"]),
      signedInAt: required(body["signed_in_at"]),
      consoleUntil: required(body["console_until"]),
    };
  }

  /** Signs out of this browser: the session ends, for the console and for the account pages. */
  async signOut(): Promise<void> {
    await this.#send("DELETE", "/session", undefined, "interaction");
    this.#csrfToken = null;
  }

  async listUsers(cursor: string | null = null): Promise<Page<User>> {
    return page(await this.#send("GET", `/users${query(cursor)}`), user);
  }

  async getUser(id: string): Promise<User> {
    return user(await this.#send("GET", `/users/${encodeURIComponent(id)}`));
  }

  async createUser(email: string, displayName: string): Promise<User> {
    const name = displayName.trim();
    return user(
      await this.#send("POST", "/users", { email: email.trim(), ...(name === "" ? {} : { display_name: name }) }),
    );
  }

  async suspendUser(id: string, reason: string): Promise<User> {
    return user(await this.#send("POST", `/users/${encodeURIComponent(id)}:suspend`, { reason: reason.trim() }));
  }

  async listSessions(userId: string): Promise<Session[]> {
    const body = await this.#send("GET", `/users/${encodeURIComponent(userId)}/sessions`);
    return list(body["items"]).map(session);
  }

  async endSession(sessionId: string): Promise<void> {
    await this.#send("DELETE", `/sessions/${encodeURIComponent(sessionId)}`);
  }

  async listProviders(): Promise<Provider[]> {
    return list((await this.#send("GET", "/identity-providers"))["items"]).map(provider);
  }

  async getProvider(id: string): Promise<Provider> {
    return provider(await this.#send("GET", `/identity-providers/${encodeURIComponent(id)}`));
  }

  async addProvider(added: NewProvider): Promise<Provider> {
    return provider(
      await this.#send("POST", "/identity-providers", {
        alias: added.alias.trim(),
        display_name: added.displayName.trim(),
        issuer: added.issuer.trim(),
        client_id: added.clientId.trim(),
        client_secret: added.clientSecret,
        scopes: added.scopes,
        creates_users: added.createsUsers,
      }),
    );
  }

  async changeProvider(id: string, change: ProviderChange): Promise<Provider> {
    const body: Fields = {};
    if (change.displayName !== undefined) body["display_name"] = change.displayName.trim();
    if (change.issuer !== undefined) body["issuer"] = change.issuer.trim();
    if (change.clientId !== undefined) body["client_id"] = change.clientId.trim();
    if (change.scopes !== undefined) body["scopes"] = change.scopes;
    if (change.createsUsers !== undefined) body["creates_users"] = change.createsUsers;
    return provider(await this.#send("PATCH", `/identity-providers/${encodeURIComponent(id)}`, body));
  }

  /** Sends a new client secret, once. The page keeps no copy of it. */
  async replaceClientSecret(id: string, clientSecret: string): Promise<void> {
    await this.#send("PUT", `/identity-providers/${encodeURIComponent(id)}/client-secret`, {
      client_secret: clientSecret,
    });
  }

  async disableProvider(id: string): Promise<Provider> {
    return provider(await this.#send("POST", `/identity-providers/${encodeURIComponent(id)}:disable`));
  }

  async enableProvider(id: string): Promise<Provider> {
    return provider(await this.#send("POST", `/identity-providers/${encodeURIComponent(id)}:enable`));
  }

  async listAuditRecords(cursor: string | null = null): Promise<Page<AuditRecord>> {
    return page(await this.#send("GET", `/audit-records${query(cursor)}`), auditRecord);
  }
}

const PAGE_SIZE = 50;

function query(cursor: string | null): string {
  return `?limit=${PAGE_SIZE}${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`;
}
