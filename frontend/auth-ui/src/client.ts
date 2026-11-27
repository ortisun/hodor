// The client for the interaction interface. It is the only place that
// knows paths, headers and the shape of answers; the pages see values.
// See docs/api/interaction-api.md.

import type { KeyRegistration, WebAuthnAnswer } from "./webauthn";

/** Why a request did not do what was asked. */
export class Failure {
  constructor(
    /** The `code` of the problem document; `null` when there was none. */
    readonly code: string | null,
    /** The HTTP status; `0` when the server could not be reached. */
    readonly status: number,
    /** The identifier to quote when reporting the problem. */
    readonly requestId: string | null = null,
    /** How long to wait before trying again, when the server said. */
    readonly retryAfterSeconds: number | null = null,
    /** The problem's `detail`, in English: what was wrong, never a value the person typed. */
    readonly detail: string | null = null,
  ) {}

  get unreachable(): boolean {
    return this.status === 0;
  }
}

export type SignInStatus = "pending" | "rejected" | "failed" | "completed";

/** Where a sign-in stands. */
export interface SignInAnswer {
  status: SignInStatus;
  /** The step to ask for next, when the sign-in goes on. */
  step: string | null;
  attemptsLeft: number | null;
  /**
   * Where to go once the sign-in completed, when an application's request
   * waits for it: an address of Hodor's own authorization endpoint of this
   * tenant, and nothing else.
   */
  continueTo?: string;
  /**
   * The recovery codes made with a second factor the person just set up
   * during the sign-in, shown once before the page goes on.
   */
  recoveryCodes?: string[];
}

/** What a person may set up at the enrollment step of a sign-in. */
export type EnrollmentKind = "authenticator_application" | "security_key" | "passkey";

const ENROLLMENT_KINDS: readonly EnrollmentKind[] = ["authenticator_application", "security_key", "passkey"];

/** An identity provider as the sign-in page shows it. */
export interface OfferedProvider {
  alias: string;
  displayName: string;
  /** A directory is signed in through here, with a password; any other provider by leaving for it. */
  isDirectory: boolean;
}

/** Who is signed in. */
export interface Session {
  userId: string;
  sessionId: string;
  signedInAt: string;
  expiresAt: string;
}

/** A security key or a passkey of the person. */
export interface Key {
  id: string;
  name: string;
  /** Whether it signs the person in on its own. */
  passkey: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

/** The person's second factors. */
/** What an invitation's link is for, as the server describes it. */
export interface InvitationDescription {
  organizationName: string;
  email: string;
  hasAccount: boolean;
  expiresAt: string;
}

export interface Factors {
  /** `null` when the installation offers no authenticator application. */
  authenticatorApplication: { inUse: boolean } | null;
  keys: Key[];
  recoveryCodesRemaining: number;
  secondFactorRequired: boolean;
  /** Until when changes are allowed without signing in again; `null` when they are not now. */
  recentSignInUntil: string | null;
}

/** An authenticator application being set up: its secret, shown once. */
export interface Enrollment {
  secret: string;
  uri: string;
}

/** A registration of a key that was just asked for. */
export interface BegunKey {
  registrationId: string;
  publicKey: Record<string, unknown>;
}

/** A scope an application asks for, as the consent page shows it. */
export type AskedScope =
  | { kind: "openid"; scope: string }
  | { kind: "resource"; scope: string; description: string; resourceServer: string };

/**
 * What an application that registered itself says of itself. Nobody
 * checked it: the page shows it as the application's own words.
 */
export interface SelfDescription {
  /** Its home page. */
  clientUri: string | null;
  /** An image of its logo. */
  logoUri: string | null;
  /** Its privacy policy. */
  policyUri: string | null;
  /** Its terms of service. */
  tosUri: string | null;
}

/** What an application's request asks the person to agree to. */
export interface ConsentQuestion {
  /** The application's name; for one that registered itself, the name it gave itself. */
  application: string;
  scopes: AskedScope[];
  /** Whether it asks to keep access when the person is not there. */
  offlineAccess: boolean;
  /** For an application that registered itself, what it says of itself. */
  registered: SelfDescription | null;
}

/** An address the server gave, only when it is HTTPS: nothing else is loaded or linked to. */
function httpsAddress(value: unknown): string | null {
  return typeof value === "string" && value.startsWith("https://") ? value : null;
}

/** An application the person agreed to. */
export interface GivenConsent {
  clientId: string;
  application: string;
  scopes: string[];
  givenAt: string;
  expiresAt: string;
}

/**
 * The standard claims a person keeps, by the names the server gives them:
 * `given_name` and the others, and the parts of the address as
 * `address.locality` and so on. Each is text; an empty one is no value.
 */
export const CLAIM_FIELDS = [
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

export type ClaimField = (typeof CLAIM_FIELDS)[number];

/** What the account page shows and changes of the person. */
export interface Profile {
  displayName: string;
  claims: Record<ClaimField, string>;
  /** Whether someone vouched for the telephone number. The person cannot. */
  phoneNumberVerified: boolean;
}

function profileOf(body: Record<string, unknown>): Profile {
  const given =
    typeof body["claims"] === "object" && body["claims"] !== null ? (body["claims"] as Record<string, unknown>) : {};
  const address =
    typeof given["address"] === "object" && given["address"] !== null
      ? (given["address"] as Record<string, unknown>)
      : {};
  const claims = Object.fromEntries(
    CLAIM_FIELDS.map((field) => {
      const value = field.startsWith("address.") ? address[field.slice("address.".length)] : given[field];
      return [field, typeof value === "string" ? value : ""];
    }),
  ) as Record<ClaimField, string>;
  return {
    displayName: text(body["display_name"]) ?? "",
    claims,
    phoneNumberVerified: given["phone_number_verified"] === true,
  };
}

type Fetch = typeof globalThis.fetch;

function keyOf(value: unknown): Key | null {
  const fields = typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
  const id = text(fields["id"]);
  const name = text(fields["name"]);
  const createdAt = text(fields["created_at"]);
  if (id === null || name === null || createdAt === null) {
    return null;
  }
  return { id, name, passkey: fields["passkey"] === true, createdAt, lastUsedAt: text(fields["last_used_at"]) };
}

/** New recovery codes in an answer, if it holds any. */
function codesOf(body: Record<string, unknown>): string[] | null {
  const codes = body["recovery_codes"];
  return Array.isArray(codes) ? codes.filter((code): code is string => typeof code === "string") : null;
}

interface Reply {
  status: number;
  body: Record<string, unknown>;
}

function text(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

const STATUSES: readonly SignInStatus[] = ["pending", "rejected", "failed", "completed"];

export class Client {
  /** The token to send back with requests that change something. */
  #csrfToken: string | null = null;
  readonly #base: string;
  /** The only addresses a completed sign-in may continue to. */
  readonly #continues: string;
  readonly #fetch: Fetch;

  constructor(tenant: string, fetch: Fetch = (...input) => globalThis.fetch(...input)) {
    this.#base = `/t/${tenant}/interaction`;
    this.#continues = `/t/${tenant}/oauth2/`;
    this.#fetch = fetch;
  }

  async #send(method: string, path: string, body?: unknown): Promise<Reply> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (this.#csrfToken !== null && method !== "GET") {
      headers["X-CSRF-Token"] = this.#csrfToken;
    }
    let response: Response;
    try {
      response = await this.#fetch(this.#base + path, {
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
    const fields =
      typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : {};
    if (!response.ok) {
      const seconds = Number(response.headers.get("Retry-After"));
      throw new Failure(
        text(fields["code"]),
        response.status,
        text(fields["request_id"]) ?? response.headers.get("X-Request-Id"),
        Number.isFinite(seconds) && seconds > 0 ? seconds : null,
        text(fields["detail"]),
      );
    }
    const token = text(fields["csrf_token"]);
    if (token !== null) {
      this.#csrfToken = token;
    }
    return { status: response.status, body: fields };
  }

  #signIn(reply: Reply): SignInAnswer {
    const status = STATUSES.find((known) => known === reply.body["status"]);
    if (status === undefined) {
      throw new Failure(null, reply.status);
    }
    if (status === "failed" || status === "completed") {
      this.#csrfToken = null;
    }
    const left = reply.body["attempts_left"];
    const answer: SignInAnswer = {
      status,
      step: text(reply.body["step"]),
      attemptsLeft: typeof left === "number" ? left : null,
    };
    const next = text(reply.body["continue"]);
    if (status === "completed" && next !== null && this.#isOwnAuthorization(next)) {
      answer.continueTo = next;
    }
    const codes = codesOf(reply.body);
    if (codes !== null && codes.length > 0) {
      answer.recoveryCodes = codes;
    }
    return answer;
  }

  /** Whether `path` is an address of this tenant's authorization endpoint, on this origin. */
  #isOwnAuthorization(path: string): boolean {
    return path.startsWith(this.#continues) && /^[A-Za-z0-9/_-]+$/.test(path) && !path.includes("//");
  }

  /** Who is signed in; `null` when nobody is. */
  async session(): Promise<Session | null> {
    let reply: Reply;
    try {
      reply = await this.#send("GET", "/session");
    } catch (failure) {
      if (failure instanceof Failure && failure.status === 401) {
        return null;
      }
      throw failure;
    }
    const userId = text(reply.body["user_id"]);
    const sessionId = text(reply.body["session_id"]);
    const signedInAt = text(reply.body["signed_in_at"]);
    const expiresAt = text(reply.body["expires_at"]);
    if (userId === null || sessionId === null || signedInAt === null || expiresAt === null) {
      throw new Failure(null, reply.status);
    }
    return { userId, sessionId, signedInAt, expiresAt };
  }

  /** Signs out of this browser. Needs `session()` to have answered first. */
  async signOut(): Promise<void> {
    await this.#send("DELETE", "/session");
    this.#csrfToken = null;
  }

  /** Where the sign-in of this browser stands; `null` when there is none. */
  async currentSignIn(): Promise<SignInAnswer | null> {
    try {
      return this.#signIn(await this.#send("GET", "/sign-in"));
    } catch (failure) {
      if (failure instanceof Failure && failure.status === 404) {
        return null;
      }
      throw failure;
    }
  }

  /** The identity providers the tenant offers. */
  async providers(): Promise<OfferedProvider[]> {
    const reply = await this.#send("GET", "/sign-in/providers");
    const listed = reply.body["providers"];
    if (!Array.isArray(listed)) {
      return [];
    }
    return listed.flatMap((entry: unknown) => {
      const fields = typeof entry === "object" && entry !== null ? (entry as Record<string, unknown>) : {};
      const alias = text(fields["alias"]);
      const displayName = text(fields["display_name"]);
      const isDirectory = text(fields["kind"]) === "ldap";
      return alias !== null && displayName !== null ? [{ alias, displayName, isDirectory }] : [];
    });
  }

  /**
   * Chooses a provider for the current sign-in. Answers the address at
   * the provider to send the browser to.
   */
  async chooseProvider(alias: string): Promise<string> {
    const reply = await this.#send("POST", `/sign-in/providers/${encodeURIComponent(alias)}`);
    const redirect = text(reply.body["redirect"]);
    // Only ever an address of the web: never a script or a file.
    if (redirect === null || !/^https?:\/\//.test(redirect)) {
      throw new Failure(null, reply.status);
    }
    return redirect;
  }

  /** Signs in through a directory with what the person typed. */
  async signInWithDirectory(alias: string, identifier: string, password: string): Promise<SignInAnswer> {
    return this.#signIn(
      await this.#send("POST", `/sign-in/providers/${encodeURIComponent(alias)}/password`, { identifier, password }),
    );
  }

  /** Finishes the sign-in with what the provider sent back. */
  /**
   * Finishes with what came back: a code from an OpenID Connect provider,
   * or the receipt Hodor gave the browser that carried a SAML response.
   */
  async finishWithProvider(
    alias: string,
    state: string,
    proof: { code: string } | { receipt: string },
  ): Promise<SignInAnswer> {
    return this.#signIn(
      await this.#send("POST", `/sign-in/providers/${encodeURIComponent(alias)}/callback`, { ...proof, state }),
    );
  }

  async startSignIn(): Promise<SignInAnswer> {
    this.#csrfToken = null;
    return this.#signIn(await this.#send("POST", "/sign-in"));
  }

  async submitIdentifier(identifier: string): Promise<SignInAnswer> {
    return this.#signIn(await this.#send("POST", "/sign-in/steps/identifier", { identifier }));
  }

  async submitPassword(password: string): Promise<SignInAnswer> {
    return this.#signIn(await this.#send("POST", "/sign-in/steps/password", { password }));
  }

  /** Sends a code of the person's authenticator application. */
  async submitTotp(code: string): Promise<SignInAnswer> {
    return this.#signIn(await this.#send("POST", "/sign-in/steps/totp", { code }));
  }

  /** The challenge of the WebAuthn step, in the options the interface gives. */
  async webAuthnOptions(): Promise<Record<string, unknown>> {
    return this.#publicKey("/sign-in/steps/webauthn/options");
  }

  async submitWebAuthn(answer: WebAuthnAnswer): Promise<SignInAnswer> {
    return this.#signIn(await this.#send("POST", "/sign-in/steps/webauthn", answer));
  }

  /** The challenge of signing in with a passkey, while the sign-in waits for the identifier. */
  async passkeyOptions(): Promise<Record<string, unknown>> {
    return this.#publicKey("/sign-in/steps/passkey/options");
  }

  /** Sends what a passkey answered, in place of the identifier and the password. */
  async submitPasskey(answer: WebAuthnAnswer): Promise<SignInAnswer> {
    return this.#signIn(await this.#send("POST", "/sign-in/steps/passkey", answer));
  }

  async #publicKey(path: string): Promise<Record<string, unknown>> {
    const reply = await this.#send("POST", path);
    const options = reply.body["public_key"];
    if (typeof options !== "object" || options === null) {
      throw new Failure(null, reply.status);
    }
    return options as Record<string, unknown>;
  }

  /** The ways to sign in, other than the identifier and the password, that the tenant offers. */
  async alternatives(): Promise<string[]> {
    const reply = await this.#send("GET", "/sign-in/alternatives");
    const listed = reply.body["alternatives"];
    return Array.isArray(listed) ? listed.filter((entry): entry is string => typeof entry === "string") : [];
  }

  /**
   * Asks for a code or a link to be sent to an address, in place of the
   * identifier and the password. The answer is the same whoever the
   * address belongs to.
   */
  async askByEmail(method: "code" | "link", email: string, locale: string): Promise<void> {
    await this.#send("POST", `/sign-in/steps/email_${method}/send`, { email, locale });
  }

  /** Sends the code that came by email. */
  async submitEmailCode(code: string): Promise<SignInAnswer> {
    return this.#signIn(await this.#send("POST", "/sign-in/steps/email_code", { code }));
  }

  /** Sends the token of the link that came by email, within this browser's sign-in. */
  async submitEmailLink(token: string): Promise<SignInAnswer> {
    return this.#signIn(await this.#send("POST", "/sign-in/steps/email_link", { token }));
  }

  /** What can be set up at the enrollment step of a sign-in here, in the order to offer it. */
  async enrollmentKinds(): Promise<EnrollmentKind[]> {
    const reply = await this.#send("GET", "/sign-in/steps/enrollment/kinds");
    const listed = reply.body["kinds"];
    return Array.isArray(listed)
      ? ENROLLMENT_KINDS.filter((kind) => listed.includes(kind))
      : [];
  }

  /** Begins setting up an authenticator application at the enrollment step. The secret is given once. */
  async beginApplicationEnrollment(): Promise<Enrollment> {
    const reply = await this.#send("POST", "/sign-in/steps/enrollment/options", { kind: "authenticator_application" });
    const secret = text(reply.body["secret"]);
    const uri = text(reply.body["uri"]);
    if (secret === null || uri === null) {
      throw new Failure(null, reply.status);
    }
    return { secret, uri };
  }

  /** Begins registering a security key, or a passkey, at the enrollment step: the options for the browser. */
  async beginKeyEnrollment(passkey: boolean): Promise<Record<string, unknown>> {
    const reply = await this.#send("POST", "/sign-in/steps/enrollment/options", {
      kind: passkey ? "passkey" : "security_key",
    });
    const options = reply.body["public_key"];
    if (typeof options !== "object" || options === null) {
      throw new Failure(null, reply.status);
    }
    return options as Record<string, unknown>;
  }

  /** Finishes setting up the application with a code it shows. */
  async finishApplicationEnrollment(code: string): Promise<SignInAnswer> {
    return this.#signIn(await this.#send("POST", "/sign-in/steps/enrollment", { code }));
  }

  /** Finishes registering the key with what the browser answered. */
  async finishKeyEnrollment(registration: KeyRegistration, name: string): Promise<SignInAnswer> {
    const named = name.trim();
    return this.#signIn(
      await this.#send("POST", "/sign-in/steps/enrollment", {
        ...registration,
        ...(named === "" ? {} : { name: named }),
      }),
    );
  }

  /** Sends one of the person's recovery codes, in place of their security key or the code of their application. */
  async submitRecoveryCode(code: string): Promise<SignInAnswer> {
    return this.#signIn(await this.#send("POST", "/sign-in/steps/recovery_code", { code }));
  }

  /** Abandons the sign-in. One that is already gone is not an error. */
  async abandonSignIn(): Promise<void> {
    try {
      await this.#send("DELETE", "/sign-in");
    } catch (failure) {
      if (!(failure instanceof Failure) || failure.unreachable || failure.status >= 500) {
        throw failure;
      }
    } finally {
      this.#csrfToken = null;
    }
  }

  /** What the request waiting in this browser asks for; `null` when none waits for this person. */
  async consentQuestion(): Promise<ConsentQuestion | null> {
    let reply: Reply;
    try {
      reply = await this.#send("GET", "/consent");
    } catch (failure) {
      if (failure instanceof Failure && failure.status === 404) {
        return null;
      }
      throw failure;
    }
    const application = text(reply.body["application"]);
    const listed = reply.body["scopes"];
    if (application === null || !Array.isArray(listed)) {
      throw new Failure(null, reply.status);
    }
    const scopes = listed.flatMap((entry: unknown): AskedScope[] => {
      const fields = typeof entry === "object" && entry !== null ? (entry as Record<string, unknown>) : {};
      const scope = text(fields["scope"]);
      if (scope === null) {
        return [];
      }
      if (fields["kind"] === "openid") {
        return [{ kind: "openid", scope }];
      }
      return [
        {
          kind: "resource",
          scope,
          description: text(fields["description"]) ?? scope,
          resourceServer: text(fields["resource_server"]) ?? "",
        },
      ];
    });
    const registered: SelfDescription | null =
      reply.body["registered"] === true
        ? {
            clientUri: httpsAddress(reply.body["client_uri"]),
            logoUri: httpsAddress(reply.body["logo_uri"]),
            policyUri: httpsAddress(reply.body["policy_uri"]),
            tosUri: httpsAddress(reply.body["tos_uri"]),
          }
        : null;
    return { application, scopes, offlineAccess: reply.body["offline_access"] === true, registered };
  }

  /**
   * Sends the person's answer. Answers where to go: an address of this
   * tenant's authorization endpoint, and nothing else.
   */
  async answerConsent(decision: "allow" | "deny"): Promise<string> {
    const reply = await this.#send("POST", "/consent", { decision });
    const next = text(reply.body["continue"]);
    if (next === null || !this.#isOwnAuthorization(next)) {
      throw new Failure(null, reply.status);
    }
    return next;
  }

  /** The applications the person agreed to. Needs `session()` to have answered first to withdraw one. */
  async consents(): Promise<GivenConsent[]> {
    const reply = await this.#send("GET", "/consents");
    const listed = reply.body["consents"];
    if (!Array.isArray(listed)) {
      return [];
    }
    return listed.flatMap((entry: unknown): GivenConsent[] => {
      const fields = typeof entry === "object" && entry !== null ? (entry as Record<string, unknown>) : {};
      const clientId = text(fields["client_id"]);
      const application = text(fields["application"]);
      const givenAt = text(fields["given_at"]);
      const expiresAt = text(fields["expires_at"]);
      const scopes = Array.isArray(fields["scopes"])
        ? fields["scopes"].filter((scope): scope is string => typeof scope === "string")
        : [];
      return clientId !== null && application !== null && givenAt !== null && expiresAt !== null
        ? [{ clientId, application, scopes, givenAt, expiresAt }]
        : [];
    });
  }

  /** The person's display name and standard claims. */
  async profile(): Promise<Profile> {
    const reply = await this.#send("GET", "/profile");
    return profileOf(reply.body);
  }

  /**
   * Replaces the person's display name and standard claims. A field left
   * empty is removed. Whether the number is verified is the server's to say.
   */
  async saveProfile(displayName: string, claims: Record<ClaimField, string>): Promise<Profile> {
    const body: Record<string, unknown> = {};
    const address: Record<string, string> = {};
    for (const field of CLAIM_FIELDS) {
      const value = claims[field].trim();
      if (value === "") {
        continue;
      }
      if (field.startsWith("address.")) {
        address[field.slice("address.".length)] = value;
      } else {
        body[field] = value;
      }
    }
    if (Object.keys(address).length > 0) {
      body["address"] = address;
    }
    const name = displayName.trim();
    const reply = await this.#send("PUT", "/profile", {
      ...(name === "" ? {} : { display_name: name }),
      claims: body,
    });
    return profileOf(reply.body);
  }

  /** Withdraws the person's agreement to one application. One already withdrawn is not an error. */
  async withdrawConsent(clientId: string): Promise<void> {
    try {
      await this.#send("DELETE", `/consents/${encodeURIComponent(clientId)}`);
    } catch (failure) {
      if (!(failure instanceof Failure) || failure.status !== 404) {
        throw failure;
      }
    }
  }

  async askToRegister(email: string, locale: string): Promise<void> {
    await this.#send("POST", "/registration", { email, locale });
  }

  async completeRegistration(token: string, password: string, displayName: string): Promise<void> {
    const name = displayName.trim();
    await this.#send("POST", "/registration/complete", {
      token,
      password,
      ...(name === "" ? {} : { display_name: name }),
    });
  }

  /** What an invitation's link is for. */
  async describeInvitation(token: string): Promise<InvitationDescription> {
    const reply = await this.#send("POST", "/invitations/describe", { token });
    return {
      organizationName: text(reply.body["organization_name"]) ?? "",
      email: text(reply.body["email"]) ?? "",
      hasAccount: reply.body["has_account"] === true,
      expiresAt: text(reply.body["expires_at"]) ?? "",
    };
  }

  /**
   * Accepts an invitation. With a password, creates the account of an
   * address that has none; without, joins as the signed-in person.
   */
  async acceptInvitation(token: string, password?: string, displayName?: string): Promise<void> {
    const name = displayName?.trim() ?? "";
    await this.#send("POST", "/invitations/accept", {
      token,
      ...(password === undefined ? {} : { password }),
      ...(name === "" ? {} : { display_name: name }),
    });
  }

  async askToRecover(email: string, locale: string): Promise<void> {
    await this.#send("POST", "/recovery", { email, locale });
  }

  async resetPassword(token: string, password: string): Promise<void> {
    await this.#send("POST", "/recovery/complete", { token, password });
  }

  /** The person's second factors. */
  async factors(): Promise<Factors> {
    const reply = await this.#send("GET", "/factors");
    const application = reply.body["authenticator_application"];
    const codes = reply.body["recovery_codes"];
    const remaining =
      typeof codes === "object" && codes !== null ? (codes as Record<string, unknown>)["remaining"] : null;
    const keys = Array.isArray(reply.body["keys"]) ? reply.body["keys"] : [];
    return {
      authenticatorApplication:
        typeof application === "object" && application !== null
          ? { inUse: (application as Record<string, unknown>)["in_use"] === true }
          : null,
      keys: keys.flatMap((key: unknown) => keyOf(key) ?? []),
      recoveryCodesRemaining: typeof remaining === "number" ? remaining : 0,
      secondFactorRequired: reply.body["second_factor_required"] === true,
      recentSignInUntil: text(reply.body["recent_sign_in_until"]),
    };
  }

  /** Begins setting up an authenticator application. The secret is given once. */
  async beginAuthenticatorApplication(): Promise<Enrollment> {
    const reply = await this.#send("POST", "/factors/authenticator-application");
    const secret = text(reply.body["secret"]);
    const uri = text(reply.body["uri"]);
    if (secret === null || uri === null) {
      throw new Failure(null, reply.status);
    }
    return { secret, uri };
  }

  /** Confirms the application with a code it shows. Answers new recovery codes, when it is the first factor. */
  async confirmAuthenticatorApplication(code: string): Promise<string[] | null> {
    const reply = await this.#send("POST", "/factors/authenticator-application/confirmation", { code });
    return codesOf(reply.body);
  }

  async removeAuthenticatorApplication(): Promise<void> {
    await this.#send("DELETE", "/factors/authenticator-application");
  }

  /** Begins registering a security key, or a passkey. */
  async beginKey(passkey: boolean): Promise<BegunKey> {
    const reply = await this.#send("POST", "/webauthn/registrations", { passkey });
    const registrationId = text(reply.body["registration_id"]);
    const publicKey = reply.body["public_key"];
    if (registrationId === null || typeof publicKey !== "object" || publicKey === null) {
      throw new Failure(null, reply.status);
    }
    return { registrationId, publicKey: publicKey as Record<string, unknown> };
  }

  /** Finishes registering it. Answers new recovery codes, when it is the first factor. */
  async finishKey(registrationId: string, registration: KeyRegistration, name: string): Promise<string[] | null> {
    const named = name.trim();
    const reply = await this.#send("POST", `/webauthn/registrations/${encodeURIComponent(registrationId)}`, {
      ...registration,
      ...(named === "" ? {} : { name: named }),
    });
    return codesOf(reply.body);
  }

  async renameKey(id: string, name: string): Promise<Key> {
    const reply = await this.#send("PATCH", `/factors/keys/${encodeURIComponent(id)}`, { name });
    const key = keyOf(reply.body);
    if (key === null) {
      throw new Failure(null, reply.status);
    }
    return key;
  }

  async removeKey(id: string): Promise<void> {
    await this.#send("DELETE", `/factors/keys/${encodeURIComponent(id)}`);
  }

  /** A new set of recovery codes in place of the old one, shown once. */
  async generateRecoveryCodes(): Promise<string[]> {
    const reply = await this.#send("POST", "/factors/recovery-codes");
    const codes = codesOf(reply.body);
    if (codes === null) {
      throw new Failure(null, reply.status);
    }
    return codes;
  }
}
