// The client for the interaction interface. It is the only place that
// knows paths, headers and the shape of answers; the pages see values.
// See docs/api/interaction-api.md.

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
}

/** Who is signed in. */
export interface Session {
  userId: string;
  sessionId: string;
  signedInAt: string;
  expiresAt: string;
}

type Fetch = typeof globalThis.fetch;

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
  readonly #fetch: Fetch;

  constructor(tenant: string, fetch: Fetch = (...input) => globalThis.fetch(...input)) {
    this.#base = `/t/${tenant}/interaction`;
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
    return {
      status,
      step: text(reply.body["step"]),
      attemptsLeft: typeof left === "number" ? left : null,
    };
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
}
