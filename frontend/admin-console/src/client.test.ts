import { describe, expect, it } from "vitest";
import { Failure } from "./client";
import { ANA, empty, GOOGLE, json, meBody, problem, providerBody, scripted, userBody } from "./testing";

describe("the client of the console interface", () => {
  it("says nobody is there when the server knows no session", async () => {
    const { client } = scripted({ "GET /console/api/me": [problem(401, "console.not_authenticated")] });
    expect(await client.me()).toBeNull();
  });

  it("reads who is asking and what they may do", async () => {
    const { client } = scripted({ "GET /console/api/me": [json(200, meBody(["audit:read"], ["tenant_auditor"]))] });
    const me = await client.me();
    expect(me?.user.identifiers[0]?.value).toBe("ana@example.com");
    expect(me?.roles).toEqual(["tenant_auditor"]);
    expect(me?.permissions).toEqual(["audit:read"]);
    expect(me?.consoleUntil).toBe("2026-11-22T02:03:11Z");
  });

  it("sends the token of the session with what changes something, and only with that", async () => {
    const { client, sent } = scripted({
      "GET /console/api/me": [json(200, meBody())],
      "GET /console/api/users?limit=50": [json(200, { items: [] })],
      "POST /console/api/users": [json(201, userBody(ANA, "new@example.com"))],
      [`POST /console/api/users/${ANA}:suspend`]: [json(200, userBody(ANA, "new@example.com", { status: "suspended" }))],
      "DELETE /console/api/sessions/session-1": [empty(204)],
      "DELETE /interaction/session": [empty(204)],
    });
    await client.me();
    await client.listUsers();
    await client.createUser(" new@example.com ", "  ");
    await client.suspendUser(ANA, " left the company ");
    await client.endSession("session-1");
    await client.signOut();

    expect(sent.map((request) => [request.method, request.csrfToken])).toEqual([
      ["GET", null],
      ["GET", null],
      ["POST", "token-of-the-session"],
      ["POST", "token-of-the-session"],
      ["DELETE", "token-of-the-session"],
      ["DELETE", "token-of-the-session"],
    ]);
    // What was typed is sent without the spaces around it; an empty name is not sent.
    expect(sent[2]?.body).toEqual({ email: "new@example.com" });
    expect(sent[3]?.body).toEqual({ reason: "left the company" });
  });

  it("asks for the next page with the cursor it was given", async () => {
    const { client } = scripted({
      "GET /console/api/audit-records?limit=50": [json(200, { items: [], next_cursor: "42" })],
      "GET /console/api/audit-records?limit=50&cursor=42": [json(200, { items: [] })],
    });
    const first = await client.listAuditRecords();
    expect(first.nextCursor).toBe("42");
    expect((await client.listAuditRecords(first.nextCursor)).nextCursor).toBeNull();
  });

  it("turns a refusal into a failure with its code and request", async () => {
    const { client } = scripted({ "GET /console/api/users?limit=50": [problem(403, "admin.forbidden")] });
    const failure = await client.listUsers().catch((thrown: unknown) => thrown);
    expect(failure).toBeInstanceOf(Failure);
    expect(failure).toMatchObject({ code: "admin.forbidden", status: 403, requestId: "request-1" });
  });

  it("says so when the server cannot be reached", async () => {
    const { client } = scripted({
      "GET /console/api/users?limit=50": [
        () => {
          throw new TypeError("network");
        },
      ],
    });
    expect(await client.listUsers().catch((thrown: unknown) => thrown)).toMatchObject({ status: 0 });
  });

  it("does not make up what an answer lacks", async () => {
    const { client } = scripted({ [`GET /console/api/users/${ANA}`]: [json(200, { id: ANA })] });
    expect(await client.getUser(ANA).catch((thrown: unknown) => thrown)).toBeInstanceOf(Failure);
  });

  it("adds a provider with its secret, and changes only what was changed", async () => {
    const { client, sent } = scripted({
      "GET /console/api/me": [json(200, meBody())],
      "POST /console/api/identity-providers": [json(201, providerBody())],
      [`PATCH /console/api/identity-providers/${GOOGLE}`]: [json(200, providerBody({ creates_users: false }))],
      [`PUT /console/api/identity-providers/${GOOGLE}/client-secret`]: [empty(204)],
      [`POST /console/api/identity-providers/${GOOGLE}:disable`]: [json(200, providerBody({ status: "disabled" }))],
    });
    await client.me();
    const added = await client.addProvider({
      alias: " google ",
      displayName: "Google",
      issuer: "https://accounts.google.com",
      clientId: "1234",
      clientSecret: "the secret",
      scopes: ["openid", "email"],
      createsUsers: true,
    });
    expect(added.callbackAddress).toContain("/providers/google/callback");
    expect(added.scopes).toEqual(["openid", "email", "profile"]);
    await client.changeProvider(GOOGLE, { createsUsers: false });
    await client.replaceClientSecret(GOOGLE, "another secret");
    expect((await client.disableProvider(GOOGLE)).status).toBe("disabled");

    expect(sent[1]?.body).toEqual({
      alias: "google",
      display_name: "Google",
      issuer: "https://accounts.google.com",
      client_id: "1234",
      client_secret: "the secret",
      scopes: ["openid", "email"],
      creates_users: true,
    });
    expect(sent[2]?.body).toEqual({ creates_users: false });
    expect(sent[3]?.body).toEqual({ client_secret: "another secret" });
    expect(sent.slice(1).every((request) => request.csrfToken === "token-of-the-session")).toBe(true);
  });
});
