import { describe, expect, it } from "vitest";
import { Client, Failure } from "./client";
import { empty, json, problem, scripted } from "./testing";

describe("the client for the interaction interface", () => {
  it("sends the token of the last answer back with requests that change something", async () => {
    const { client, sent } = scripted({
      "POST /sign-in": [json(201, { status: "pending", step: "identifier", csrf_token: "first" })],
      "POST /sign-in/steps/identifier": [json(200, { status: "pending", step: "password", csrf_token: "second" })],
      "POST /sign-in/steps/password": [json(200, { status: "completed" })],
    });

    expect(await client.startSignIn()).toEqual({ status: "pending", step: "identifier", attemptsLeft: null });
    await client.submitIdentifier("ana@example.com");
    expect(await client.submitPassword("a password")).toEqual({
      status: "completed",
      step: null,
      attemptsLeft: null,
    });

    expect(sent.map((request) => request.csrfToken)).toEqual([null, "first", "second"]);
    expect(sent[1]?.body).toEqual({ identifier: "ana@example.com" });
    expect(sent[2]?.body).toEqual({ password: "a password" });
  });

  it("reads a rejection as an answer, not as a failure", async () => {
    const { client } = scripted({
      "POST /sign-in/steps/password": [
        json(200, { status: "rejected", step: "password", attempts_left: 3, csrf_token: "t" }),
      ],
    });
    expect(await client.submitPassword("wrong")).toEqual({ status: "rejected", step: "password", attemptsLeft: 3 });
  });

  it("says there is no sign-in when the server knows none", async () => {
    const { client } = scripted({
      "GET /sign-in": [problem(404, "authentication.transaction_not_found")],
    });
    expect(await client.currentSignIn()).toBeNull();
  });

  it("says nobody is signed in on 401", async () => {
    const { client } = scripted({ "GET /session": [problem(401, "session.not_authenticated")] });
    expect(await client.session()).toBeNull();
  });

  it("signs out with the token the session answered with", async () => {
    const { client, sent } = scripted({
      "GET /session": [
        json(200, {
          user_id: "user",
          session_id: "session",
          signed_in_at: "2026-11-20T14:03:11Z",
          expires_at: "2026-11-20T14:33:11Z",
          csrf_token: "of-the-session",
        }),
      ],
      "DELETE /session": [empty(204)],
    });
    expect(await client.session()).toMatchObject({ userId: "user", signedInAt: "2026-11-20T14:03:11Z" });
    await client.signOut();
    expect(sent[1]?.csrfToken).toBe("of-the-session");
  });

  it("turns a problem document into a failure with its code, identifier and wait", async () => {
    const { client } = scripted({
      "POST /recovery": [problem(429, "authentication.too_many_attempts", { "Retry-After": "90" })],
    });
    const failure = await client.askToRecover("ana@example.com", "en").catch((thrown: unknown) => thrown);
    expect(failure).toBeInstanceOf(Failure);
    expect(failure).toMatchObject({
      code: "authentication.too_many_attempts",
      status: 429,
      requestId: "request-1",
      retryAfterSeconds: 90,
      unreachable: false,
    });
  });

  it("turns an answer that is not a problem document into a failure without a code", async () => {
    const { client } = scripted({
      "POST /registration": [new Response("<html>bad gateway</html>", { status: 502 })],
    });
    const failure = await client.askToRegister("ana@example.com", "en").catch((thrown: unknown) => thrown);
    expect(failure).toMatchObject({ code: null, status: 502 });
  });

  it("says the server is unreachable when no answer comes", async () => {
    const client = new Client("acme", () => Promise.reject(new TypeError("network")));
    const failure = await client.startSignIn().catch((thrown: unknown) => thrown);
    expect(failure).toMatchObject({ unreachable: true });
  });

  it("refuses an answer about a sign-in that it cannot read", async () => {
    const { client } = scripted({ "POST /sign-in": [json(201, { status: "something-new" })] });
    await expect(client.startSignIn()).rejects.toBeInstanceOf(Failure);
  });

  it("sends the name only when one was given", async () => {
    const { client, sent } = scripted({
      "POST /registration/complete": [empty(204), empty(204)],
    });
    await client.completeRegistration("token", "a password", "  ");
    await client.completeRegistration("token", "a password", " Ana ");
    expect(sent[0]?.body).toEqual({ token: "token", password: "a password" });
    expect(sent[1]?.body).toEqual({ token: "token", password: "a password", display_name: "Ana" });
  });

  it("does not mind abandoning a sign-in that is already gone", async () => {
    const { client } = scripted({
      "DELETE /sign-in": [problem(404, "authentication.transaction_not_found")],
    });
    await expect(client.abandonSignIn()).resolves.toBeUndefined();
  });

  it("lists the providers a tenant offers, skipping what it cannot read", async () => {
    const { client } = scripted({
      "GET /sign-in/providers": [
        json(200, {
          providers: [
            { alias: "google", display_name: "Google", kind: "openid_connect" },
            { alias: 7 },
            "nonsense",
            { alias: "x" },
          ],
        }),
      ],
    });
    expect(await client.providers()).toEqual([{ alias: "google", displayName: "Google", isDirectory: false }]);
  });

  it("chooses a provider with the token of the sign-in and answers where to go", async () => {
    const { client, sent } = scripted({
      "POST /sign-in": [json(201, { status: "pending", step: "identifier", csrf_token: "token" })],
      "POST /sign-in/providers/google": [json(200, { redirect: "https://accounts.example.com/authorize?x=1" })],
    });
    await client.startSignIn();
    expect(await client.chooseProvider("google")).toBe("https://accounts.example.com/authorize?x=1");
    expect(sent[1]?.csrfToken).toBe("token");
  });

  it("refuses to be sent anywhere that is not an address of the web", async () => {
    for (const redirect of ["javascript:alert(1)", "data:text/html,x", "/relative", "", 42]) {
      const { client } = scripted({ "POST /sign-in/providers/google": [json(200, { redirect })] });
      await expect(client.chooseProvider("google"), String(redirect)).rejects.toBeInstanceOf(Failure);
    }
  });

  it("finishes with what the provider sent back", async () => {
    const { client, sent } = scripted({
      "POST /sign-in/providers/google/callback": [json(200, { status: "completed" })],
    });
    expect((await client.finishWithProvider("google", "the-code", "the-state")).status).toBe("completed");
    expect(sent[0]?.body).toEqual({ code: "the-code", state: "the-state" });
  });
});
