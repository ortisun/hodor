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
}

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
