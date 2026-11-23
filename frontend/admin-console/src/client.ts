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
  | "identity-providers:write"
  | "keys:read"
  | "keys:write"
  | "applications:read"
  | "applications:write"
  | "credentials:read"
  | "credentials:write";

/** A security key or a passkey of a person. Nothing of its key is ever here. */
export interface PersonKey {
  id: string;
  name: string;
  passkey: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

/** A person's second factors, as an administrator sees them. */
export interface PersonFactors {
  /** `null` when the installation offers no authenticator application. */
  authenticatorApplication: { inUse: boolean } | null;
  keys: PersonKey[];
  recoveryCodesRemaining: number;
  secondFactorRequired: boolean;
}

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
  /** Whether the provider vouches for the addresses it gives. */
  trustsEmail: boolean;
  status: string;
  /** The address to register at the provider, where it sends people back to; `null` for a directory. */
  callbackAddress: string | null;
  /** Where a directory searches; `null` for every other kind. */
  directory: { base: string; filter: string } | null;
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

/** An application registered in the tenant. */
export interface Application {
  id: string;
  name: string;
  /** A first-party application is not asked for consent. */
  firstParty: boolean;
  status: string;
  createdAt: string;
  updatedAt: string;
}

/** What an administrator gives to register or change an application. */
export interface ApplicationSettings {
  name: string;
  firstParty: boolean;
}

/** How long a client's tokens live, in seconds. */
export interface TokenPolicy {
  accessTokenSeconds: number;
  idTokenSeconds: number;
  refreshTokenSeconds: number;
  refreshIdleSeconds: number;
}

/**
 * A client of an application: what talks to Hodor's endpoints. Its
 * secrets are named by identifier and expiry; the server never gives a
 * secret back after the answer that made it.
 */
export interface ApplicationClient {
  /** The `client_id`. Not a secret. */
  id: string;
  applicationId: string;
  name: string;
  type: string;
  authenticationMethod: string;
  grantTypes: string[];
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  allowedScopes: string[];
  requirePkce: boolean;
  tokenPolicy: TokenPolicy;
  secrets: { id: string; createdAt: string; expiresAt: string }[];
  keys: { kid: string; jwk: Record<string, unknown>; addedAt: string }[];
  status: string;
  createdAt: string;
  updatedAt: string;
}

/** What an administrator decides about a client. */
export interface ClientSettings {
  name: string;
  authenticationMethod: string;
  grantTypes: string[];
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  allowedScopes: string[];
}

/** A new client, with its first secret when it has one: shown once. */
export interface CreatedClient {
  client: ApplicationClient;
  secret: string | null;
}

/** A new secret of a client: shown once. */
export interface NewSecret {
  id: string;
  secret: string;
  expiresAt: string;
}

export interface Scope {
  name: string;
  description: string;
}

/** The interface that accepts an application's access tokens. */
export interface ResourceServer {
  id: string;
  applicationId: string;
  /** The audience of its tokens. It never changes. */
  audience: string;
  name: string;
  scopes: Scope[];
  createdAt: string;
  updatedAt: string;
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

function personFactors(body: Fields): PersonFactors {
  const application = body["authenticator_application"];
  const remaining = fields(body["recovery_codes"])["remaining"];
  return {
    authenticatorApplication:
      typeof application === "object" && application !== null
        ? { inUse: fields(application)["in_use"] === true }
        : null,
    keys: list(body["keys"]).map((key) => ({
      id: required(key["id"]),
      name: required(key["name"]),
      passkey: key["passkey"] === true,
      createdAt: required(key["created_at"]),
      lastUsedAt: text(key["last_used_at"]),
    })),
    recoveryCodesRemaining: typeof remaining === "number" ? remaining : 0,
    secondFactorRequired: body["second_factor_required"] === true,
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

function directoryOf(value: unknown): { base: string; filter: string } | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const found = fields(value);
  return { base: required(found["base"]), filter: required(found["filter"]) };
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
    trustsEmail: body["trusts_email"] === true,
    status: required(body["status"]),
    callbackAddress: text(body["callback_address"]),
    directory: directoryOf(body["directory"]),
    createdAt: required(body["created_at"]),
    updatedAt: required(body["updated_at"]),
  };
}

function application(body: Fields): Application {
  return {
    id: required(body["id"]),
    name: required(body["name"]),
    firstParty: body["first_party"] === true,
    status: required(body["status"]),
    createdAt: required(body["created_at"]),
    updatedAt: required(body["updated_at"]),
  };
}

function seconds(value: unknown): number {
  return typeof value === "number" ? value : 0;
}

function applicationClient(body: Fields): ApplicationClient {
  const policy = fields(body["token_policy"]);
  return {
    id: required(body["id"]),
    applicationId: required(body["application_id"]),
    name: required(body["name"]),
    type: required(body["type"]),
    authenticationMethod: required(body["authentication_method"]),
    grantTypes: strings(body["grant_types"]),
    redirectUris: strings(body["redirect_uris"]),
    postLogoutRedirectUris: strings(body["post_logout_redirect_uris"]),
    allowedScopes: strings(body["allowed_scopes"]),
    requirePkce: body["require_pkce"] === true,
    tokenPolicy: {
      accessTokenSeconds: seconds(policy["access_token_seconds"]),
      idTokenSeconds: seconds(policy["id_token_seconds"]),
      refreshTokenSeconds: seconds(policy["refresh_token_seconds"]),
      refreshIdleSeconds: seconds(policy["refresh_idle_seconds"]),
    },
    secrets: list(body["secrets"]).map((secret) => ({
      id: required(secret["id"]),
      createdAt: required(secret["created_at"]),
      expiresAt: required(secret["expires_at"]),
    })),
    keys: list(body["keys"]).map((key) => ({
      kid: required(key["kid"]),
      jwk: fields(key["jwk"]),
      addedAt: required(key["added_at"]),
    })),
    status: required(body["status"]),
    createdAt: required(body["created_at"]),
    updatedAt: required(body["updated_at"]),
  };
}

function resourceServer(body: Fields): ResourceServer {
  return {
    id: required(body["id"]),
    applicationId: required(body["application_id"]),
    audience: required(body["audience"]),
    name: required(body["name"]),
    scopes: list(body["scopes"]).map((scope) => ({
      name: required(scope["name"]),
      description: text(scope["description"]) ?? "",
    })),
    createdAt: required(body["created_at"]),
    updatedAt: required(body["updated_at"]),
  };
}

function clientBody(settings: ClientSettings): Fields {
  return {
    name: settings.name.trim(),
    authentication_method: settings.authenticationMethod,
    grant_types: settings.grantTypes,
    redirect_uris: settings.redirectUris,
    post_logout_redirect_uris: settings.postLogoutRedirectUris,
    allowed_scopes: settings.allowedScopes,
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

  async listFactors(userId: string): Promise<PersonFactors> {
    return personFactors(await this.#send("GET", `/users/${encodeURIComponent(userId)}/factors`));
  }

  async removeAuthenticatorApplication(userId: string): Promise<void> {
    await this.#send("DELETE", `/users/${encodeURIComponent(userId)}/factors/authenticator-application`);
  }

  async removePersonKey(userId: string, keyId: string): Promise<void> {
    await this.#send(
      "DELETE",
      `/users/${encodeURIComponent(userId)}/factors/keys/${encodeURIComponent(keyId)}`,
    );
  }

  async removeRecoveryCodes(userId: string): Promise<void> {
    await this.#send("DELETE", `/users/${encodeURIComponent(userId)}/factors/recovery-codes`);
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

  async listApplications(): Promise<Application[]> {
    return list((await this.#send("GET", "/applications"))["items"]).map(application);
  }

  async getApplication(id: string): Promise<Application> {
    return application(await this.#send("GET", `/applications/${encodeURIComponent(id)}`));
  }

  async addApplication(settings: ApplicationSettings): Promise<Application> {
    return application(
      await this.#send("POST", "/applications", { name: settings.name.trim(), first_party: settings.firstParty }),
    );
  }

  async changeApplication(id: string, settings: ApplicationSettings): Promise<Application> {
    return application(
      await this.#send("PATCH", `/applications/${encodeURIComponent(id)}`, {
        name: settings.name.trim(),
        first_party: settings.firstParty,
      }),
    );
  }

  async disableApplication(id: string): Promise<Application> {
    return application(await this.#send("POST", `/applications/${encodeURIComponent(id)}:disable`));
  }

  async enableApplication(id: string): Promise<Application> {
    return application(await this.#send("POST", `/applications/${encodeURIComponent(id)}:enable`));
  }

  async listClients(applicationId: string): Promise<ApplicationClient[]> {
    const body = await this.#send("GET", `/applications/${encodeURIComponent(applicationId)}/clients`);
    return list(body["items"]).map(applicationClient);
  }

  /** Creates a client. Its first secret, when it has one, is in this answer only. */
  async addClient(applicationId: string, type: string, settings: ClientSettings): Promise<CreatedClient> {
    const body = await this.#send("POST", `/applications/${encodeURIComponent(applicationId)}/clients`, {
      ...clientBody(settings),
      type,
    });
    return { client: applicationClient(body), secret: text(body["client_secret"]) };
  }

  async getClient(id: string): Promise<ApplicationClient> {
    return applicationClient(await this.#send("GET", `/clients/${encodeURIComponent(id)}`));
  }

  async changeClient(id: string, settings: ClientSettings): Promise<ApplicationClient> {
    return applicationClient(await this.#send("PATCH", `/clients/${encodeURIComponent(id)}`, clientBody(settings)));
  }

  async disableClient(id: string): Promise<ApplicationClient> {
    return applicationClient(await this.#send("POST", `/clients/${encodeURIComponent(id)}:disable`));
  }

  async enableClient(id: string): Promise<ApplicationClient> {
    return applicationClient(await this.#send("POST", `/clients/${encodeURIComponent(id)}:enable`));
  }

  /** Gives a client a new secret, in this answer only. */
  async rotateSecret(id: string): Promise<NewSecret> {
    const body = await this.#send("POST", `/clients/${encodeURIComponent(id)}/secrets`, {});
    return { id: required(body["id"]), secret: required(body["client_secret"]), expiresAt: required(body["expires_at"]) };
  }

  async revokeSecret(id: string, secretId: string): Promise<void> {
    await this.#send("DELETE", `/clients/${encodeURIComponent(id)}/secrets/${encodeURIComponent(secretId)}`);
  }

  /** Adds a public key, given as the JSON Web Key it is. */
  async addKey(id: string, jwk: unknown): Promise<ApplicationClient> {
    return applicationClient(await this.#send("POST", `/clients/${encodeURIComponent(id)}/keys`, { jwk }));
  }

  async removeKey(id: string, kid: string): Promise<void> {
    await this.#send("DELETE", `/clients/${encodeURIComponent(id)}/keys/${encodeURIComponent(kid)}`);
  }

  async listResourceServers(): Promise<ResourceServer[]> {
    return list((await this.#send("GET", "/resource-servers"))["items"]).map(resourceServer);
  }

  async addResourceServer(applicationId: string, audience: string, name: string, scopes: Scope[]): Promise<ResourceServer> {
    return resourceServer(
      await this.#send("POST", "/resource-servers", {
        application_id: applicationId,
        audience: audience.trim(),
        name: name.trim(),
        scopes,
      }),
    );
  }

  async changeResourceServer(id: string, name: string, scopes: Scope[]): Promise<ResourceServer> {
    return resourceServer(
      await this.#send("PATCH", `/resource-servers/${encodeURIComponent(id)}`, { name: name.trim(), scopes }),
    );
  }

  async listAuditRecords(cursor: string | null = null): Promise<Page<AuditRecord>> {
    return page(await this.#send("GET", `/audit-records${query(cursor)}`), auditRecord);
  }
}

const PAGE_SIZE = 50;

function query(cursor: string | null): string {
  return `?limit=${PAGE_SIZE}${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`;
}
