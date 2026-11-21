// What the unit tests share: a server that answers from a script.

import { Client } from "./client";

export interface Sent {
  method: string;
  path: string;
  body: unknown;
  csrfToken: string | null;
}

type Answer = Response | (() => Response);

/** A JSON answer. */
export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

/** A problem document, as the server writes them. */
export function problem(status: number, code: string, headers: Record<string, string> = {}): Response {
  return json(
    status,
    { type: `urn:hodor:error:${code}`, status, code, detail: "from the server", request_id: "request-1" },
    headers,
  );
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
    const path = url.replace("/t/acme/interaction", "");
    const headers = new Headers(init?.headers);
    sent.push({
      method,
      path,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : null,
      csrfToken: headers.get("X-CSRF-Token"),
    });
    const answer = script[`${method} ${path}`]?.shift();
    if (answer === undefined) {
      throw new Error(`unexpected request: ${method} ${path}`);
    }
    return typeof answer === "function" ? answer() : answer;
  };
  return { client: new Client("acme", fetch), sent };
}
