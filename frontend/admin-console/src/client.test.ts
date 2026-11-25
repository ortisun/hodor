import { describe, expect, it } from "vitest";
import { Failure } from "./client";
import {
  ACME,
  ANA,
  apiKeyBody,
  ASSISTANT,
  BILLING,
  deliveryBody,
  empty,
  endpointBody,
  EXPORT,
  HOOK,
  REPORTS_KEY,
  ROTATED_KEY,
  SET_ASIDE,
  workloadBody,
  ENGINEERING,
  FINANCE,
  GOOGLE,
  json,
  meBody,
  namedBody,
  PAYABLES,
  PLATFORM,
  problem,
  providerBody,
  scripted,
  unitBody,
  userBody,
} from "./testing";

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

  it("names groups and their members, and sends a description only when there is one", async () => {
    const { client, sent } = scripted({
      "GET /console/api/me": [json(200, meBody())],
      "POST /console/api/groups": [json(201, namedBody(FINANCE, "finance"))],
      [`PATCH /console/api/groups/${FINANCE}`]: [
        json(200, namedBody(FINANCE, "finance", { description: "Who pays the bills" })),
      ],
      [`GET /console/api/groups/${FINANCE}/members?limit=50`]: [
        json(200, { items: [{ kind: "user", id: ANA }, { kind: "group", id: PAYABLES }], next_cursor: "2" }),
      ],
      [`POST /console/api/groups/${FINANCE}/members`]: [empty(204)],
      [`POST /console/api/groups/${FINANCE}/members:remove`]: [empty(204)],
      [`GET /console/api/users/${ANA}/groups`]: [json(200, { items: [{ id: FINANCE, direct: false }] })],
    });
    await client.me();
    expect((await client.createGroup({ name: " finance ", description: "  " })).description).toBeNull();
    expect((await client.changeGroup(FINANCE, { name: "finance", description: " Who pays the bills " })).description).toBe(
      "Who pays the bills",
    );
    const members = await client.listGroupMembers(FINANCE);
    expect(members.items).toEqual([
      { kind: "user", id: ANA },
      { kind: "group", id: PAYABLES },
    ]);
    expect(members.nextCursor).toBe("2");
    await client.addGroupMember(FINANCE, { kind: "group", id: ` ${PAYABLES} ` });
    await client.removeGroupMember(FINANCE, { kind: "user", id: ANA });
    expect(await client.groupsOfUser(ANA)).toEqual([{ id: FINANCE, direct: false }]);

    expect(sent[1]?.body).toEqual({ name: "finance" });
    expect(sent[2]?.body).toEqual({ name: "finance", description: "Who pays the bills" });
    expect(sent[4]?.body).toEqual({ kind: "group", id: PAYABLES });
    expect(sent[5]?.body).toEqual({ kind: "user", id: ANA });
  });

  it("manages service accounts and agents under their own paths, and their keys, shown once", async () => {
    const { client, sent } = scripted({
      "GET /console/api/me": [json(200, meBody())],
      "GET /console/api/agents?limit=50": [json(200, { items: [workloadBody(ASSISTANT, "Assistant", { kind: "agent" })] })],
      "POST /console/api/service-accounts": [json(201, workloadBody(EXPORT, "Nightly export"))],
      [`PATCH /console/api/service-accounts/${EXPORT}`]: [json(200, workloadBody(EXPORT, "Nightly export"))],
      [`POST /console/api/agents/${ASSISTANT}:disable`]: [
        json(200, workloadBody(ASSISTANT, "Assistant", { kind: "agent", status: "disabled" })),
      ],
      [`DELETE /console/api/service-accounts/${EXPORT}`]: [empty(204)],
      [`GET /console/api/service-accounts/${EXPORT}/api-keys`]: [
        json(200, { items: [apiKeyBody(REPORTS_KEY, "Reports", { api_key: "never kept" })] }),
      ],
      [`POST /console/api/service-accounts/${EXPORT}/api-keys`]: [
        json(201, { ...apiKeyBody(REPORTS_KEY, "Reports"), api_key: "hodor_ak_made" }),
      ],
      [`POST /console/api/agents/${ASSISTANT}/api-keys/${REPORTS_KEY}:rotate`]: [
        json(201, { ...apiKeyBody(ROTATED_KEY, "Reports"), api_key: "hodor_ak_rotated" }),
      ],
      [`DELETE /console/api/agents/${ASSISTANT}/api-keys/${REPORTS_KEY}`]: [empty(204)],
    });
    await client.me();
    const [agent] = (await client.listWorkloads("agent")).items;
    expect(agent?.kind).toBe("agent");
    expect(agent?.owners).toEqual([ANA]);
    await client.createWorkload("service_account", { name: " Nightly export ", owners: [ANA] });
    await client.changeWorkload("service_account", EXPORT, { name: "Nightly export", owners: [ANA] });
    expect((await client.disableWorkload("agent", ASSISTANT)).status).toBe("disabled");
    await client.deleteWorkload("service_account", EXPORT);
    const [listed] = await client.listApiKeys("service_account", EXPORT);
    // A key is never part of a listed key, even when an answer holds one.
    expect(listed).not.toHaveProperty("secret");
    expect(listed?.hint).toBe("…7c1e");
    const made = await client.createApiKey("service_account", EXPORT, {
      name: " Reports ",
      scopes: ["authz:evaluate"],
      applicationId: BILLING,
      lifetimeDays: 30,
    });
    expect(made.secret).toBe("hodor_ak_made");
    expect((await client.rotateApiKey("agent", ASSISTANT, REPORTS_KEY)).key.id).toBe(ROTATED_KEY);
    await client.revokeApiKey("agent", ASSISTANT, REPORTS_KEY);

    expect(sent[2]?.body).toEqual({ name: "Nightly export", owners: [ANA] });
    expect(sent[7]?.body).toEqual({
      name: "Reports",
      scopes: ["authz:evaluate"],
      application_id: BILLING,
      lifetime_days: 30,
    });
  });

  it("registers endpoints with their secret once, and filters deliveries by endpoint and status", async () => {
    const { client, sent } = scripted({
      "GET /console/api/me": [json(200, meBody())],
      "GET /console/api/webhook-event-types": [json(200, { items: ["identity.user_created", "session.started"] })],
      "POST /console/api/webhook-endpoints": [json(201, { endpoint: endpointBody(), secret: "whsec_made" })],
      [`PUT /console/api/webhook-endpoints/${HOOK}/subscriptions`]: [json(200, endpointBody())],
      [`POST /console/api/webhook-endpoints/${HOOK}:rotate-secret`]: [
        json(201, {
          endpoint: endpointBody({
            secrets: [
              { created_at: "2026-11-25T14:03:11Z", expires_at: null },
              { created_at: "2026-11-24T14:03:11Z", expires_at: "2026-11-26T14:03:11Z" },
            ],
          }),
          secret: "whsec_rotated",
        }),
      ],
      [`DELETE /console/api/webhook-endpoints/${HOOK}`]: [empty(204)],
      [`GET /console/api/webhook-deliveries?limit=50&endpoint_id=${HOOK}&status=set_aside`]: [
        json(200, { items: [deliveryBody({ payload: "never kept" })], next_cursor: "2" }),
      ],
      [`GET /console/api/webhook-deliveries?limit=50&cursor=2&endpoint_id=${HOOK}`]: [json(200, { items: [] })],
      [`POST /console/api/webhook-deliveries/${SET_ASIDE}:redeliver`]: [
        json(200, deliveryBody({ status: "pending", next_attempt_at: "2026-11-24T16:04:00Z", finished_at: null })),
      ],
    });
    await client.me();
    expect(await client.listEventTypes()).toEqual(["identity.user_created", "session.started"]);
    const registered = await client.registerEndpoint({
      url: " https://hooks.example.com/hodor ",
      description: "  ",
      eventTypes: ["session.started"],
    });
    expect(registered.secret).toBe("whsec_made");
    expect(registered.endpoint).not.toHaveProperty("secret");
    await client.replaceSubscriptions(HOOK, ["identity.user_created", "session.started"]);
    const rotated = await client.rotateEndpointSecret(HOOK);
    expect(rotated.endpoint.secrets.map((secret) => secret.expiresAt)).toEqual([null, "2026-11-26T14:03:11Z"]);
    await client.removeEndpoint(HOOK);
    const page = await client.listDeliveries(HOOK, "set_aside");
    expect(page.items[0]).not.toHaveProperty("payload");
    expect(page.items[0]?.lastResponseStatus).toBe(503);
    expect(page.nextCursor).toBe("2");
    expect((await client.listDeliveries(HOOK, null, "2")).items).toEqual([]);
    expect((await client.redeliver(SET_ASIDE)).status).toBe("pending");

    expect(sent[2]?.body).toEqual({ url: "https://hooks.example.com/hodor", event_types: ["session.started"] });
    expect(sent[3]?.body).toEqual({ event_types: ["identity.user_created", "session.started"] });
    expect(sent[4]?.body).toBeNull();
  });

  it("reads the units, members and invitations of an organization, and never a link", async () => {
    const { client, sent } = scripted({
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/organizations/${ACME}/units`]: [
        json(200, { items: [unitBody(ENGINEERING, "Engineering", null), unitBody(PLATFORM, "Platform", ENGINEERING, "department")] }),
      ],
      [`PUT /console/api/organizations/${ACME}/units/${PLATFORM}`]: [json(200, unitBody(PLATFORM, "Platform", null))],
      [`PUT /console/api/organizations/${ACME}/members/${ANA}`]: [
        json(200, { user_id: ANA, unit_ids: [PLATFORM], added_at: "2026-11-23T14:03:11Z" }),
      ],
      [`GET /console/api/organizations/${ACME}/invitations`]: [
        json(200, {
          items: [
            {
              id: "invitation-1",
              email: "caio@example.com",
              unit_ids: [],
              created_at: "2026-11-23T14:03:11Z",
              expires_at: "2026-11-30T14:03:11Z",
              link: "https://auth.example/t/acme/account/accept-invitation#secret",
            },
          ],
        }),
      ],
      [`POST /console/api/organizations/${ACME}/invitations`]: [empty(202)],
    });
    await client.me();
    const units = await client.listUnits(ACME);
    expect(units.map((unit) => [unit.name, unit.parentId, unit.kind])).toEqual([
      ["Engineering", null, "unit"],
      ["Platform", ENGINEERING, "department"],
    ]);
    await client.changeUnit(ACME, PLATFORM, { parentId: null, name: " Platform ", kind: "unit" });
    expect((await client.putOrganizationMember(ACME, ANA, [PLATFORM])).unitIds).toEqual([PLATFORM]);
    const [invitation] = await client.listInvitations(ACME);
    // Only what the client knows is kept: anything else the answer holds is dropped.
    expect(invitation).toEqual({
      id: "invitation-1",
      email: "caio@example.com",
      unitIds: [],
      createdAt: "2026-11-23T14:03:11Z",
      expiresAt: "2026-11-30T14:03:11Z",
    });
    await client.invite(ACME, " caio@example.com ", [PLATFORM], "pt-BR");

    expect(sent[2]?.body).toEqual({ parent_id: null, name: "Platform", kind: "unit" });
    expect(sent[3]?.body).toEqual({ unit_ids: [PLATFORM] });
    expect(sent[5]?.body).toEqual({ email: "caio@example.com", unit_ids: [PLATFORM], locale: "pt-BR" });
  });
});
