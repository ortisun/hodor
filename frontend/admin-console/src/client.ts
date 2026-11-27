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
  | "credentials:write"
  | "decisions:read"
  | "decision-log:write"
  | "roles:read"
  | "roles:write"
  | "bindings:read"
  | "bindings:write"
  | "policies:read"
  | "policies:write"
  | "groups:read"
  | "groups:write"
  | "organizations:read"
  | "organizations:write"
  | "workloads:read"
  | "workloads:write"
  | "webhooks:read"
  | "webhooks:write";

/** A permission a role holds, with its condition when it has one. */
export interface HeldPermission {
  name: string;
  condition: string | null;
}

/** A role a tenant defined for one resource server. */
export interface RoleDefinition {
  namespace: string;
  name: string;
  description: string;
  permissions: HeldPermission[];
  includes: { namespace: string; name: string }[];
}

/** A role given to a user or a client. */
export interface RoleAssignment {
  principal: { kind: "user" | "client"; id: string };
  role: { namespace: string; name: string };
  applicationId: string | null;
  validUntil: string | null;
}

/** Which engine answers for a resource server. */
export interface Binding {
  namespace: string;
  engine: string;
  timeLimitMilliseconds: number;
  sensitive: boolean;
  failOpenActions: string[];
}

/** What is published for Open Policy Agent, and what each instance runs. */
export interface PolicyStatus {
  latest: { revision: number; version: number | null; publishedAt: string } | null;
  instances: { instance: string; activeRevision: string | null; current: boolean; error: string | null }[];
  pendingActivation: boolean;
}

/** One recorded decision, as the list shows it. */
export interface DecisionRecord {
  id: string;
  namespace: string;
  subject: string;
  action: string;
  effect: "allow" | "deny" | "indeterminate";
  reason: string;
  engine: string | null;
  decidedAt: string;
}

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
  /**
   * The person's standard claims that have a value, in the order of
   * `CLAIMS`: `given_name` and the others, and the parts of the address as
   * `address.locality` and so on. None for a workload.
   */
  claims: [string, string][];
  /** Whether someone vouched for the telephone number. */
  phoneNumberVerified: boolean;
  createdAt: string;
  updatedAt: string;
}

/** The standard claims of a person, in the order the console shows them. */
export const CLAIMS = [
  "given_name",
  "middle_name",
  "family_name",
  "nickname",
  "gender",
  "birthdate",
  "zoneinfo",
  "profile",
  "picture",
  "website",
  "phone_number",
  "address.formatted",
  "address.street_address",
  "address.locality",
  "address.region",
  "address.postal_code",
  "address.country",
] as const;

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
  /** The address the signed-out page loads in a frame to tell it; `null` for none. */
  frontchannelLogoutUri: string | null;
  /** Whether it needs `iss` and `sid` in the address of its frame. */
  frontchannelLogoutSessionRequired: boolean;
  allowedScopes: string[];
  requirePkce: boolean;
  tokenPolicy: TokenPolicy;
  secrets: { id: string; createdAt: string; expiresAt: string }[];
  keys: { kid: string; jwk: Record<string, unknown>; addedAt: string }[];
  /** The service account or agent the client acts as; `null` for none. */
  principal: string | null;
  /** The SPIFFE identifier it is bound to, for a method that takes one; `null` otherwise. */
  spiffeId: string | null;
  /** The Linkerd identity it is bound to, for a method that takes one; `null` otherwise. */
  linkerdIdentity: string | null;
  /** Whether its access tokens are bound to the certificate the proxy forwards. */
  certificateBoundAccessTokens: boolean;
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
  /** The front-channel logout address; `null` for none, which removes one a client had. */
  frontchannelLogoutUri: string | null;
  frontchannelLogoutSessionRequired: boolean;
  allowedScopes: string[];
  /**
   * The service account a client of a workload's identity acts as; `null`
   * to send none, which leaves a changed client's principal as it is.
   */
  principal: string | null;
  /** The SPIFFE identifier to bind it to; `null` to send none. */
  spiffeId: string | null;
  /** The Linkerd identity to bind it to; `null` to send none. */
  linkerdIdentity: string | null;
  certificateBoundAccessTokens: boolean;
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

/** A group of users, or an organization: both have a name and an optional description. */
export interface Named {
  id: string;
  name: string;
  description: string | null;
  createdAt: string;
  updatedAt: string;
}

export type Group = Named;
export type Organization = Named;

/** What an administrator gives to create or change a group or an organization. */
export interface NamedSettings {
  name: string;
  /** Empty for none. */
  description: string;
}

/** A direct member of a group: a user, or another group. */
export interface GroupMember {
  kind: "user" | "group";
  id: string;
}

/** A group a user is in, and whether they are in it directly rather than only through another group. */
export interface GroupOfUser {
  id: string;
  direct: boolean;
}

export type UnitKind = "unit" | "department";

/** A part of an organization. */
export interface Unit {
  id: string;
  /** The unit it is part of; `null` at the top of the organization. */
  parentId: string | null;
  name: string;
  kind: UnitKind;
  createdAt: string;
  updatedAt: string;
}

/** What an administrator decides about a unit: all three replace what it had. */
export interface UnitSettings {
  parentId: string | null;
  name: string;
  kind: UnitKind;
}

/** A user's membership of an organization, with the units they are in. */
export interface OrganizationMember {
  userId: string;
  unitIds: string[];
  addedAt: string;
}

/** An organization a user is a member of, with the units they are in. */
export interface OrganizationOfUser {
  organizationId: string;
  unitIds: string[];
  addedAt: string;
}

/**
 * A pending invitation to an organization. Its link and its secret are
 * never here: the server sends the link in the message only.
 */
export interface Invitation {
  id: string;
  email: string;
  unitIds: string[];
  createdAt: string;
  expiresAt: string;
}

/** The two kinds of workload, each under a path of its own. */
export type WorkloadKind = "service_account" | "agent";

/** A service account or an agent: a principal of the tenant that is not a person. */
export interface Workload {
  id: string;
  kind: WorkloadKind;
  name: string;
  status: string;
  /** The user identifiers of the people responsible for it, in the order they became owners. */
  owners: string[];
  createdAt: string;
  updatedAt: string;
}

/** What an administrator gives to create a workload, or to rename it and replace its owners. */
export interface WorkloadSettings {
  name: string;
  owners: string[];
}

/** An API key of a workload. The key itself is never here: only its last four characters. */
export interface ApiKey {
  id: string;
  name: string;
  hint: string;
  scopes: string[];
  applicationId: string | null;
  status: string;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  replacedBy: string | null;
}

/** What an administrator gives to make an API key. */
export interface ApiKeySettings {
  name: string;
  scopes: string[];
  /** Needed with a scope of the Authorization API; `null` otherwise. */
  applicationId: string | null;
  lifetimeDays: number;
}

/** A new API key, and the key itself: shown once. */
export interface MadeApiKey {
  key: ApiKey;
  secret: string;
}

/** Where the bundle of a trust domain comes from. */
export type TrustDomainSource = "uploaded" | "bundle_endpoint" | "mesh";

/** The bundle a trust domain trusts now, summarized: its authorities are counted, never shown. */
export interface TrustBundleSummary {
  sequence: number | null;
  /** In seconds; `null` when the bundle gives none. */
  refreshHint: number | null;
  x509Authorities: number;
  jwtAuthorities: number;
}

/** How a fetched bundle is kept current: for a bundle endpoint only. */
export interface BundleRefresh {
  /** The last fetch that read; `null` before any. */
  fetchedAt: string | null;
  nextAt: string;
  /** While fetching fails: since when, and the code of the last reason. */
  failingSince: string | null;
  lastError: string | null;
}

/** A SPIFFE trust domain the tenant trusts. */
export interface TrustDomain {
  id: string;
  name: string;
  source: TrustDomainSource;
  /** For `bundle_endpoint` only. */
  bundleEndpointUrl: string | null;
  /** The bundle in force; `null` for `mesh`. */
  bundle: TrustBundleSummary | null;
  bundleChangedAt: string | null;
  /** For `bundle_endpoint` only. */
  refresh: BundleRefresh | null;
  createdAt: string;
  updatedAt: string;
}

/** Where a trust domain's bundle comes from, with what that source needs. */
export type TrustDomainSettings =
  | { source: "uploaded"; bundle: unknown }
  | { source: "bundle_endpoint"; bundleEndpointUrl: string }
  | { source: "mesh" };

/** A webhook endpoint, with when its secrets in force started and stop. Never a secret. */
export interface WebhookEndpoint {
  id: string;
  url: string;
  description: string | null;
  eventTypes: string[];
  /** Newest first; `expiresAt` is `null` for the current secret. */
  secrets: { createdAt: string; expiresAt: string | null }[];
  createdAt: string;
  updatedAt: string;
}

/** What an administrator gives to register an endpoint. */
export interface EndpointSettings {
  url: string;
  /** Empty for none. */
  description: string;
  eventTypes: string[];
}

/** An endpoint with its new secret: shown once. */
export interface SignedEndpoint {
  endpoint: WebhookEndpoint;
  secret: string;
}

export type DeliveryStatus = "pending" | "delivered" | "set_aside";

/** One event on its way to one endpoint, without the body it carries. */
export interface WebhookDelivery {
  id: string;
  endpointId: string;
  eventId: string;
  eventType: string;
  status: DeliveryStatus;
  attempts: number;
  nextAttemptAt: string | null;
  lastResponseStatus: number | null;
  lastError: string | null;
  createdAt: string;
  finishedAt: string | null;
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
    ...claimsOf(body["claims"]),
    createdAt: required(body["created_at"]),
    updatedAt: required(body["updated_at"]),
  };
}

function claimsOf(value: unknown): Pick<User, "claims" | "phoneNumberVerified"> {
  const given = typeof value === "object" && value !== null ? (value as Fields) : {};
  const address = typeof given["address"] === "object" && given["address"] !== null ? (given["address"] as Fields) : {};
  const claims: [string, string][] = [];
  for (const name of CLAIMS) {
    const found = text(name.startsWith("address.") ? address[name.slice("address.".length)] : given[name]);
    if (found !== null) {
      claims.push([name, found]);
    }
  }
  return { claims, phoneNumberVerified: given["phone_number_verified"] === true };
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
    frontchannelLogoutUri: text(body["frontchannel_logout_uri"]),
    frontchannelLogoutSessionRequired: body["frontchannel_logout_session_required"] === true,
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
    principal: text(body["principal"]),
    spiffeId: text(body["spiffe_id"]),
    linkerdIdentity: text(body["linkerd_identity"]),
    certificateBoundAccessTokens: body["tls_client_certificate_bound_access_tokens"] === true,
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

function named(body: Fields): Named {
  return {
    id: required(body["id"]),
    name: required(body["name"]),
    description: text(body["description"]),
    createdAt: required(body["created_at"]),
    updatedAt: required(body["updated_at"]),
  };
}

function namedBody(settings: NamedSettings): Fields {
  const description = settings.description.trim();
  // A missing description removes it.
  return { name: settings.name.trim(), ...(description === "" ? {} : { description }) };
}

function groupMember(body: Fields): GroupMember {
  return { kind: body["kind"] === "group" ? "group" : "user", id: required(body["id"]) };
}

function unit(body: Fields): Unit {
  return {
    id: required(body["id"]),
    parentId: text(body["parent_id"]),
    name: required(body["name"]),
    kind: body["kind"] === "department" ? "department" : "unit",
    createdAt: required(body["created_at"]),
    updatedAt: required(body["updated_at"]),
  };
}

function unitBody(settings: UnitSettings): Fields {
  return { parent_id: settings.parentId, name: settings.name.trim(), kind: settings.kind };
}

function organizationMember(body: Fields): OrganizationMember {
  return {
    userId: required(body["user_id"]),
    unitIds: strings(body["unit_ids"]),
    addedAt: required(body["added_at"]),
  };
}

function invitation(body: Fields): Invitation {
  return {
    id: required(body["id"]),
    email: required(body["email"]),
    unitIds: strings(body["unit_ids"]),
    createdAt: required(body["created_at"]),
    expiresAt: required(body["expires_at"]),
  };
}

function clientBody(settings: ClientSettings): Fields {
  return {
    name: settings.name.trim(),
    authentication_method: settings.authenticationMethod,
    grant_types: settings.grantTypes,
    redirect_uris: settings.redirectUris,
    post_logout_redirect_uris: settings.postLogoutRedirectUris,
    frontchannel_logout_uri: settings.frontchannelLogoutUri === null ? null : settings.frontchannelLogoutUri.trim(),
    frontchannel_logout_session_required:
      settings.frontchannelLogoutUri !== null && settings.frontchannelLogoutSessionRequired,
    allowed_scopes: settings.allowedScopes,
    ...(settings.principal === null ? {} : { principal: settings.principal.trim() }),
    ...(settings.spiffeId === null ? {} : { spiffe_id: settings.spiffeId.trim() }),
    ...(settings.linkerdIdentity === null ? {} : { linkerd_identity: settings.linkerdIdentity.trim() }),
    tls_client_certificate_bound_access_tokens: settings.certificateBoundAccessTokens,
  };
}

/** The collection a kind of workload is under. */
function collectionOf(kind: WorkloadKind): string {
  return kind === "agent" ? "/agents" : "/service-accounts";
}

function workload(body: Fields): Workload {
  return {
    id: required(body["id"]),
    kind: body["kind"] === "agent" ? "agent" : "service_account",
    name: required(body["name"]),
    status: required(body["status"]),
    owners: strings(body["owners"]),
    createdAt: required(body["created_at"]),
    updatedAt: required(body["updated_at"]),
  };
}

function workloadBody(settings: WorkloadSettings): Fields {
  return { name: settings.name.trim(), owners: settings.owners };
}

function apiKey(body: Fields): ApiKey {
  return {
    id: required(body["id"]),
    name: required(body["name"]),
    hint: required(body["hint"]),
    scopes: strings(body["scopes"]),
    applicationId: text(body["application_id"]),
    status: required(body["status"]),
    createdAt: required(body["created_at"]),
    expiresAt: required(body["expires_at"]),
    lastUsedAt: text(body["last_used_at"]),
    revokedAt: text(body["revoked_at"]),
    replacedBy: text(body["replaced_by"]),
  };
}

function madeApiKey(body: Fields): MadeApiKey {
  return { key: apiKey(body), secret: required(body["api_key"]) };
}

function endpoint(body: Fields): WebhookEndpoint {
  return {
    id: required(body["id"]),
    url: required(body["url"]),
    description: text(body["description"]),
    eventTypes: strings(body["event_types"]),
    secrets: list(body["secrets"]).map((secret) => ({
      createdAt: required(secret["created_at"]),
      expiresAt: text(secret["expires_at"]),
    })),
    createdAt: required(body["created_at"]),
    updatedAt: required(body["updated_at"]),
  };
}

function count(value: unknown): number | null {
  return typeof value === "number" ? value : null;
}

function trustDomainSource(value: unknown): TrustDomainSource {
  return value === "uploaded" || value === "mesh" ? value : "bundle_endpoint";
}

function trustDomain(body: Fields): TrustDomain {
  const bundle = body["bundle"];
  const refresh = body["refresh"];
  const keys = typeof bundle === "object" && bundle !== null ? list(fields(bundle)["keys"]) : [];
  return {
    id: required(body["id"]),
    name: required(body["name"]),
    source: trustDomainSource(body["source"]),
    bundleEndpointUrl: text(body["bundle_endpoint_url"]),
    bundle:
      typeof bundle === "object" && bundle !== null
        ? {
            sequence: count(fields(bundle)["spiffe_sequence"]),
            refreshHint: count(fields(bundle)["spiffe_refresh_hint"]),
            x509Authorities: keys.filter((key) => key["use"] === "x509-svid").length,
            jwtAuthorities: keys.filter((key) => key["use"] === "jwt-svid").length,
          }
        : null,
    bundleChangedAt: text(body["bundle_changed_at"]),
    refresh:
      typeof refresh === "object" && refresh !== null
        ? {
            fetchedAt: text(fields(refresh)["fetched_at"]),
            nextAt: required(fields(refresh)["next_at"]),
            failingSince: text(fields(refresh)["failing_since"]),
            lastError: text(fields(refresh)["last_error"]),
          }
        : null,
    createdAt: required(body["created_at"]),
    updatedAt: required(body["updated_at"]),
  };
}

function trustDomainBody(settings: TrustDomainSettings): Fields {
  switch (settings.source) {
    case "uploaded":
      return { source: "uploaded", bundle: settings.bundle };
    case "bundle_endpoint":
      return { source: "bundle_endpoint", bundle_endpoint_url: settings.bundleEndpointUrl.trim() };
    case "mesh":
      return { source: "mesh" };
  }
}

function signedEndpoint(body: Fields): SignedEndpoint {
  return { endpoint: endpoint(fields(body["endpoint"])), secret: required(body["secret"]) };
}

function deliveryStatus(value: unknown): DeliveryStatus {
  return value === "delivered" || value === "set_aside" ? value : "pending";
}

function delivery(body: Fields): WebhookDelivery {
  return {
    id: required(body["id"]),
    endpointId: required(body["endpoint_id"]),
    eventId: required(body["event_id"]),
    eventType: required(body["event_type"]),
    status: deliveryStatus(body["status"]),
    attempts: typeof body["attempts"] === "number" ? body["attempts"] : 0,
    nextAttemptAt: text(body["next_attempt_at"]),
    lastResponseStatus: typeof body["last_response_status"] === "number" ? body["last_response_status"] : null,
    lastError: text(body["last_error"]),
    createdAt: required(body["created_at"]),
    finishedAt: text(body["finished_at"]),
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

  async listRoles(): Promise<RoleDefinition[]> {
    return list((await this.#send("GET", "/roles"))["items"]).map((role) => ({
      namespace: required(role["namespace"]),
      name: required(role["name"]),
      description: text(role["description"]) ?? "",
      permissions: list(role["permissions"]).map((held) => ({
        name: required(held["name"]),
        condition: text(held["condition"]),
      })),
      includes: list(role["includes"]).map((included) => ({
        namespace: required(included["namespace"]),
        name: required(included["name"]),
      })),
    }));
  }

  /** Defines a role, or replaces it whole; the server checks its conditions. */
  async defineRole(resourceServerId: string, role: RoleDefinition): Promise<void> {
    await this.#send(
      "PUT",
      `/resource-servers/${encodeURIComponent(resourceServerId)}/roles/${encodeURIComponent(role.name)}`,
      {
        description: role.description,
        permissions: role.permissions.map((held) =>
          held.condition === null ? { name: held.name } : { name: held.name, condition: held.condition },
        ),
        includes: role.includes,
      },
    );
  }

  async listAssignments(kind: "user" | "client", id: string): Promise<RoleAssignment[]> {
    const owner = kind === "user" ? "users" : "clients";
    return list((await this.#send("GET", `/${owner}/${encodeURIComponent(id)}/role-assignments`))["items"]).map(
      (held) => {
        const principal = fields(held["principal"]);
        const role = fields(held["role"]);
        return {
          principal: { kind: principal["kind"] === "client" ? "client" : "user", id: required(principal["id"]) },
          role: { namespace: required(role["namespace"]), name: required(role["name"]) },
          applicationId: text(held["application_id"]),
          validUntil: text(held["valid_until"]),
        };
      },
    );
  }

  async revokeAssignment(assignment: RoleAssignment): Promise<void> {
    await this.#send("POST", "/role-assignments:revoke", {
      principal: assignment.principal,
      role: assignment.role,
      ...(assignment.applicationId === null ? {} : { application_id: assignment.applicationId }),
    });
  }

  async unbind(resourceServerId: string): Promise<void> {
    await this.#send("DELETE", `/resource-servers/${encodeURIComponent(resourceServerId)}/binding`);
  }

  async listBindings(): Promise<Binding[]> {
    return list((await this.#send("GET", "/bindings"))["items"]).map((binding) => ({
      namespace: required(binding["namespace"]),
      engine: required(binding["engine"]),
      timeLimitMilliseconds: typeof binding["time_limit_milliseconds"] === "number" ? binding["time_limit_milliseconds"] : 0,
      sensitive: binding["sensitive"] === true,
      failOpenActions: Array.isArray(binding["fail_open_actions"])
        ? binding["fail_open_actions"].filter((action): action is string => typeof action === "string")
        : [],
    }));
  }

  async policyStatus(): Promise<PolicyStatus> {
    const body = await this.#send("GET", "/policy-status");
    const latest = body["latest"] === undefined ? null : fields(body["latest"]);
    return {
      latest:
        latest === null
          ? null
          : {
              revision: typeof latest["revision"] === "number" ? latest["revision"] : 0,
              version: typeof latest["version"] === "number" ? latest["version"] : null,
              publishedAt: required(latest["published_at"]),
            },
      instances: list(body["instances"]).map((instance) => ({
        instance: required(instance["instance"]),
        activeRevision: text(instance["active_revision"]),
        current: instance["current"] === true,
        error: text(instance["error"]),
      })),
      pendingActivation: body["pending_activation"] === true,
    };
  }

  async listDecisions(effect: string | null): Promise<DecisionRecord[]> {
    const query = effect === null ? "" : `&effect=${encodeURIComponent(effect)}`;
    return list((await this.#send("GET", `/decisions?limit=50${query}`))["items"]).map((record) => {
      const subject = fields(record["subject"]);
      const effectOf = record["effect"];
      return {
        id: required(record["decision_id"]),
        namespace: required(record["namespace"]),
        subject: `${required(subject["kind"])}:${required(subject["id"])}`,
        action: required(record["action"]),
        effect: effectOf === "allow" || effectOf === "indeterminate" ? effectOf : "deny",
        reason: required(record["reason"]),
        engine: text(record["engine"]),
        decidedAt: required(record["decided_at"]),
      };
    });
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

  async listGroups(cursor: string | null = null): Promise<Page<Group>> {
    return page(await this.#send("GET", `/groups${query(cursor)}`), named);
  }

  async getGroup(id: string): Promise<Group> {
    return named(await this.#send("GET", `/groups/${encodeURIComponent(id)}`));
  }

  async createGroup(settings: NamedSettings): Promise<Group> {
    return named(await this.#send("POST", "/groups", namedBody(settings)));
  }

  /** Replaces the name and the description; an empty description removes it. */
  async changeGroup(id: string, settings: NamedSettings): Promise<Group> {
    return named(await this.#send("PATCH", `/groups/${encodeURIComponent(id)}`, namedBody(settings)));
  }

  async deleteGroup(id: string): Promise<void> {
    await this.#send("DELETE", `/groups/${encodeURIComponent(id)}`);
  }

  /** The direct members of a group, users first. */
  async listGroupMembers(id: string, cursor: string | null = null): Promise<Page<GroupMember>> {
    return page(await this.#send("GET", `/groups/${encodeURIComponent(id)}/members${query(cursor)}`), groupMember);
  }

  async addGroupMember(id: string, member: GroupMember): Promise<void> {
    await this.#send("POST", `/groups/${encodeURIComponent(id)}/members`, { kind: member.kind, id: member.id.trim() });
  }

  async removeGroupMember(id: string, member: GroupMember): Promise<void> {
    await this.#send("POST", `/groups/${encodeURIComponent(id)}/members:remove`, { kind: member.kind, id: member.id });
  }

  /** The groups a user is in, directly or through other groups. */
  async groupsOfUser(userId: string): Promise<GroupOfUser[]> {
    return list((await this.#send("GET", `/users/${encodeURIComponent(userId)}/groups`))["items"]).map((found) => ({
      id: required(found["id"]),
      direct: found["direct"] === true,
    }));
  }

  async listOrganizations(cursor: string | null = null): Promise<Page<Organization>> {
    return page(await this.#send("GET", `/organizations${query(cursor)}`), named);
  }

  async getOrganization(id: string): Promise<Organization> {
    return named(await this.#send("GET", `/organizations/${encodeURIComponent(id)}`));
  }

  async createOrganization(settings: NamedSettings): Promise<Organization> {
    return named(await this.#send("POST", "/organizations", namedBody(settings)));
  }

  /** Replaces the name and the description; an empty description removes it. */
  async changeOrganization(id: string, settings: NamedSettings): Promise<Organization> {
    return named(await this.#send("PATCH", `/organizations/${encodeURIComponent(id)}`, namedBody(settings)));
  }

  async deleteOrganization(id: string): Promise<void> {
    await this.#send("DELETE", `/organizations/${encodeURIComponent(id)}`);
  }

  async listUnits(organizationId: string): Promise<Unit[]> {
    return list((await this.#send("GET", `/organizations/${encodeURIComponent(organizationId)}/units`))["items"]).map(
      unit,
    );
  }

  async createUnit(organizationId: string, settings: UnitSettings): Promise<Unit> {
    return unit(
      await this.#send("POST", `/organizations/${encodeURIComponent(organizationId)}/units`, unitBody(settings)),
    );
  }

  /** Renames a unit, changes its kind, or moves it with what is below it. */
  async changeUnit(organizationId: string, unitId: string, settings: UnitSettings): Promise<Unit> {
    return unit(
      await this.#send(
        "PUT",
        `/organizations/${encodeURIComponent(organizationId)}/units/${encodeURIComponent(unitId)}`,
        unitBody(settings),
      ),
    );
  }

  async deleteUnit(organizationId: string, unitId: string): Promise<void> {
    await this.#send(
      "DELETE",
      `/organizations/${encodeURIComponent(organizationId)}/units/${encodeURIComponent(unitId)}`,
    );
  }

  async listOrganizationMembers(organizationId: string, cursor: string | null = null): Promise<Page<OrganizationMember>> {
    return page(
      await this.#send("GET", `/organizations/${encodeURIComponent(organizationId)}/members${query(cursor)}`),
      organizationMember,
    );
  }

  /** Makes a user a member with these units, or replaces the units of a member. */
  async putOrganizationMember(organizationId: string, userId: string, unitIds: string[]): Promise<OrganizationMember> {
    return organizationMember(
      await this.#send(
        "PUT",
        `/organizations/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(userId.trim())}`,
        { unit_ids: unitIds },
      ),
    );
  }

  async removeOrganizationMember(organizationId: string, userId: string): Promise<void> {
    await this.#send(
      "DELETE",
      `/organizations/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(userId)}`,
    );
  }

  async listInvitations(organizationId: string): Promise<Invitation[]> {
    return list(
      (await this.#send("GET", `/organizations/${encodeURIComponent(organizationId)}/invitations`))["items"],
    ).map(invitation);
  }

  /** Sends an invitation. The answer holds nothing: the link is in the message only. */
  async invite(organizationId: string, email: string, unitIds: string[], locale: string): Promise<void> {
    await this.#send("POST", `/organizations/${encodeURIComponent(organizationId)}/invitations`, {
      email: email.trim(),
      unit_ids: unitIds,
      locale,
    });
  }

  async withdrawInvitation(organizationId: string, invitationId: string): Promise<void> {
    await this.#send(
      "DELETE",
      `/organizations/${encodeURIComponent(organizationId)}/invitations/${encodeURIComponent(invitationId)}`,
    );
  }

  /** The organizations a user is a member of, with their units. */
  async organizationsOfUser(userId: string): Promise<OrganizationOfUser[]> {
    return list((await this.#send("GET", `/users/${encodeURIComponent(userId)}/organizations`))["items"]).map(
      (found) => ({
        organizationId: required(found["organization_id"]),
        unitIds: strings(found["unit_ids"]),
        addedAt: required(found["added_at"]),
      }),
    );
  }

  async listWorkloads(kind: WorkloadKind, cursor: string | null = null): Promise<Page<Workload>> {
    return page(await this.#send("GET", `${collectionOf(kind)}${query(cursor)}`), workload);
  }

  async getWorkload(kind: WorkloadKind, id: string): Promise<Workload> {
    return workload(await this.#send("GET", `${collectionOf(kind)}/${encodeURIComponent(id)}`));
  }

  async createWorkload(kind: WorkloadKind, settings: WorkloadSettings): Promise<Workload> {
    return workload(await this.#send("POST", collectionOf(kind), workloadBody(settings)));
  }

  /** Renames it and replaces the whole list of its owners. */
  async changeWorkload(kind: WorkloadKind, id: string, settings: WorkloadSettings): Promise<Workload> {
    return workload(await this.#send("PATCH", `${collectionOf(kind)}/${encodeURIComponent(id)}`, workloadBody(settings)));
  }

  async disableWorkload(kind: WorkloadKind, id: string): Promise<Workload> {
    return workload(await this.#send("POST", `${collectionOf(kind)}/${encodeURIComponent(id)}:disable`));
  }

  async enableWorkload(kind: WorkloadKind, id: string): Promise<Workload> {
    return workload(await this.#send("POST", `${collectionOf(kind)}/${encodeURIComponent(id)}:enable`));
  }

  async deleteWorkload(kind: WorkloadKind, id: string): Promise<void> {
    await this.#send("DELETE", `${collectionOf(kind)}/${encodeURIComponent(id)}`);
  }

  /** A workload's API keys, newest first. */
  async listApiKeys(kind: WorkloadKind, id: string): Promise<ApiKey[]> {
    return list((await this.#send("GET", `${collectionOf(kind)}/${encodeURIComponent(id)}/api-keys`))["items"]).map(
      apiKey,
    );
  }

  async createApiKey(kind: WorkloadKind, id: string, settings: ApiKeySettings): Promise<MadeApiKey> {
    return madeApiKey(
      await this.#send("POST", `${collectionOf(kind)}/${encodeURIComponent(id)}/api-keys`, {
        name: settings.name.trim(),
        scopes: settings.scopes,
        ...(settings.applicationId === null ? {} : { application_id: settings.applicationId }),
        lifetime_days: settings.lifetimeDays,
      }),
    );
  }

  /** Replaces a key with a new one, shown once; the old one keeps working for the server's default overlap. */
  async rotateApiKey(kind: WorkloadKind, id: string, keyId: string): Promise<MadeApiKey> {
    return madeApiKey(
      await this.#send(
        "POST",
        `${collectionOf(kind)}/${encodeURIComponent(id)}/api-keys/${encodeURIComponent(keyId)}:rotate`,
        {},
      ),
    );
  }

  async revokeApiKey(kind: WorkloadKind, id: string, keyId: string): Promise<void> {
    await this.#send("DELETE", `${collectionOf(kind)}/${encodeURIComponent(id)}/api-keys/${encodeURIComponent(keyId)}`);
  }

  /** The event types an endpoint can receive. */
  async listEventTypes(): Promise<string[]> {
    return strings((await this.#send("GET", "/webhook-event-types"))["items"]);
  }

  async listEndpoints(cursor: string | null = null): Promise<Page<WebhookEndpoint>> {
    return page(await this.#send("GET", `/webhook-endpoints${query(cursor)}`), endpoint);
  }

  async getEndpoint(id: string): Promise<WebhookEndpoint> {
    return endpoint(await this.#send("GET", `/webhook-endpoints/${encodeURIComponent(id)}`));
  }

  async registerEndpoint(settings: EndpointSettings): Promise<SignedEndpoint> {
    const description = settings.description.trim();
    return signedEndpoint(
      await this.#send("POST", "/webhook-endpoints", {
        url: settings.url.trim(),
        ...(description === "" ? {} : { description }),
        event_types: settings.eventTypes,
      }),
    );
  }

  async replaceSubscriptions(id: string, eventTypes: string[]): Promise<WebhookEndpoint> {
    return endpoint(
      await this.#send("PUT", `/webhook-endpoints/${encodeURIComponent(id)}/subscriptions`, { event_types: eventTypes }),
    );
  }

  /** A new secret, shown once; the previous one keeps signing for the server's default overlap. */
  async rotateEndpointSecret(id: string): Promise<SignedEndpoint> {
    return signedEndpoint(await this.#send("POST", `/webhook-endpoints/${encodeURIComponent(id)}:rotate-secret`));
  }

  async removeEndpoint(id: string): Promise<void> {
    await this.#send("DELETE", `/webhook-endpoints/${encodeURIComponent(id)}`);
  }

  /** An endpoint's deliveries, newest first, of one status or of all. */
  async listDeliveries(
    endpointId: string,
    status: DeliveryStatus | null,
    cursor: string | null = null,
  ): Promise<Page<WebhookDelivery>> {
    const filter = `&endpoint_id=${encodeURIComponent(endpointId)}${status === null ? "" : `&status=${status}`}`;
    return page(await this.#send("GET", `/webhook-deliveries${query(cursor)}${filter}`), delivery);
  }

  async redeliver(id: string): Promise<WebhookDelivery> {
    return delivery(await this.#send("POST", `/webhook-deliveries/${encodeURIComponent(id)}:redeliver`));
  }

  async listTrustDomains(cursor: string | null = null): Promise<Page<TrustDomain>> {
    return page(await this.#send("GET", `/trust-domains${query(cursor)}`), trustDomain);
  }

  async getTrustDomain(id: string): Promise<TrustDomain> {
    return trustDomain(await this.#send("GET", `/trust-domains/${encodeURIComponent(id)}`));
  }

  /** Adds a trust domain; a bundle endpoint is fetched by the server before anything is kept. */
  async addTrustDomain(name: string, settings: TrustDomainSettings): Promise<TrustDomain> {
    return trustDomain(await this.#send("POST", "/trust-domains", { name: name.trim(), ...trustDomainBody(settings) }));
  }

  /** Replaces its source and bundle; the name never changes, and a refusal leaves it as it was. */
  async replaceTrustDomain(id: string, settings: TrustDomainSettings): Promise<TrustDomain> {
    return trustDomain(await this.#send("PUT", `/trust-domains/${encodeURIComponent(id)}`, trustDomainBody(settings)));
  }

  async removeTrustDomain(id: string): Promise<void> {
    await this.#send("DELETE", `/trust-domains/${encodeURIComponent(id)}`);
  }

  async listAuditRecords(cursor: string | null = null): Promise<Page<AuditRecord>> {
    return page(await this.#send("GET", `/audit-records${query(cursor)}`), auditRecord);
  }
}

const PAGE_SIZE = 50;

function query(cursor: string | null): string {
  return `?limit=${PAGE_SIZE}${cursor === null ? "" : `&cursor=${encodeURIComponent(cursor)}`}`;
}
