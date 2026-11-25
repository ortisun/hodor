import { LayerProvider } from "@astryxdesign/core/Layer";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { placeOf, type Screen } from "./address";
import { App } from "./App";
import { en } from "./messages/en";
import {
  bundleBody,
  CLUSTER,
  KEYS,
  meshTrustDomainBody,
  PROD,
  STAGING,
  trustDomainBody,
  ACME,
  ANA,
  apiKeyBody,
  applicationBody,
  ASSISTANT,
  deliveryBody,
  endpointBody,
  EVENT,
  EXPORT,
  HOOK,
  REPORTS_KEY,
  ROTATED_KEY,
  SET_ASIDE,
  WEBHOOKS,
  workloadBody,
  WORKLOADS,
  BIA,
  BILLING,
  clientBody,
  empty,
  ENGINEERING,
  FINANCE,
  GOOGLE,
  json,
  meBody,
  MEMBERSHIPS,
  namedBody,
  PAYABLES,
  PLATFORM,
  problem,
  providerBody,
  SALES,
  scripted,
  unitBody,
  userBody,
  WEB,
} from "./testing";

afterEach(cleanup);

const USERS = "GET /console/api/users?limit=50";
const twoUsers = () =>
  json(200, { items: [userBody(ANA, "ana@example.com"), userBody(BIA, "bia@example.com", { display_name: "Bia Souza" })] });
const session = {
  session_id: "session-1",
  started_at: "2026-11-21T14:03:11Z",
  last_activity_at: "2026-11-21T15:03:11Z",
  expires_at: "2026-11-22T14:03:11Z",
  address: "203.0.113.9",
  description: "Example Browser",
};

function show(path: string, script: Parameters<typeof scripted>[0]) {
  const { client, sent } = scripted(script);
  const go = vi.fn<(screen: Screen) => void>();
  const leave = vi.fn<(path: string) => void>();
  const place = placeOf(path);
  if (place === null) {
    throw new Error(`${path} is not an address of the console`);
  }
  render(
    <LayerProvider>
      <App place={place} client={client} text={en} mode="dark" changeMode={() => undefined} go={go} leave={leave} />
    </LayerProvider>,
  );
  return { sent, go, leave, user: userEvent.setup() };
}

describe("who may use the console", () => {
  it("sends a person who is not signed in to the sign-in page", async () => {
    const { leave } = show("/t/acme/console/users", {
      "GET /console/api/me": [problem(401, "console.not_authenticated")],
    });
    await waitFor(() => expect(leave).toHaveBeenCalledWith("/t/acme/account/sign-in"));
  });

  it("tells a person without a role that they have no access, and asks for nothing else", async () => {
    show("/t/acme/console/users", { "GET /console/api/me": [json(200, meBody([], []))] });
    expect(await screen.findByRole("heading", { name: en.noAccessTitle })).toBeTruthy();
    expect(screen.getByRole("link", { name: en.goToAccount }).getAttribute("href")).toBe("/t/acme/account");
  });

  it("shows an auditor the audit log and nothing of the users", async () => {
    const { go } = show("/t/acme/console", {
      "GET /console/api/me": [json(200, meBody(["audit:read"], ["tenant_auditor"]))],
    });
    // The start of the console is the first screen the person may open.
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "audit" }));
    expect(screen.queryByRole("link", { name: en.users })).toBeNull();
    expect(screen.getByText(en.roles["tenant_auditor"] ?? "")).toBeTruthy();
  });

  it("treats a screen the person may not open as one that does not exist", async () => {
    show("/t/acme/console/users", {
      "GET /console/api/me": [json(200, meBody(["audit:read"], ["tenant_auditor"]))],
    });
    expect(await screen.findByRole("heading", { name: en.notFoundTitle })).toBeTruthy();
  });
});

describe("the users screen", () => {
  it("lists the users, each a link to its page", async () => {
    const { go, user } = show("/t/acme/console/users", {
      "GET /console/api/me": [json(200, meBody())],
      [USERS]: [twoUsers()],
    });
    const bia = await screen.findByRole("link", { name: "Bia Souza" });
    expect(bia.getAttribute("href")).toBe(`/t/acme/console/users/${BIA}`);
    expect(screen.getByRole("link", { name: "ana@example.com" })).toBeTruthy();
    await user.click(bia);
    expect(go).toHaveBeenCalledWith({ name: "user", id: BIA });
  });

  it("offers to create a user only to those who may", async () => {
    show("/t/acme/console/users", {
      "GET /console/api/me": [json(200, meBody(["users:read"], ["tenant_auditor"]))],
      [USERS]: [twoUsers()],
    });
    await screen.findByRole("link", { name: "Bia Souza" });
    expect(screen.queryByRole("button", { name: en.createUser })).toBeNull();
  });

  it("creates a user and opens their page, or says what is wrong with the address", async () => {
    const { sent, go, user } = show("/t/acme/console/users", {
      "GET /console/api/me": [json(200, meBody())],
      [USERS]: [twoUsers()],
      "POST /console/api/users": [
        problem(409, "identity.identifier_taken"),
        json(201, userBody("0193f1c2-0000-7000-8000-000000000003", "caio@example.com")),
      ],
    });
    await user.click(await screen.findByRole("button", { name: en.createUser }));
    const dialog = await screen.findByRole("dialog");
    const email = within(dialog).getByLabelText(en.emailLabel);
    await user.type(email, "bia@example.com");
    await user.click(within(dialog).getByRole("button", { name: en.createUser }));
    expect(await within(dialog).findByText(en.identifierTaken)).toBeTruthy();

    await user.clear(email);
    await user.type(email, "caio@example.com");
    await user.click(within(dialog).getByRole("button", { name: en.createUser }));
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "user", id: "0193f1c2-0000-7000-8000-000000000003" }));
    expect(sent.at(-1)?.body).toEqual({ email: "caio@example.com" });
  });
});

describe("the page of a user", () => {
  const script = () => ({
    "GET /console/api/me": [json(200, meBody())],
    [`GET /console/api/users/${BIA}`]: [json(200, userBody(BIA, "bia@example.com", { display_name: "Bia Souza" }))],
    [`GET /console/api/users/${BIA}/sessions?`]: [],
    [`GET /console/api/users/${BIA}/sessions`]: [json(200, { items: [session] }), json(200, { items: [] })],
  });

  it("suspends only with a reason and the address typed in full", async () => {
    const { sent, user } = show(`/t/acme/console/users/${BIA}`, {
      ...script(),
      [`POST /console/api/users/${BIA}:suspend`]: [
        json(200, userBody(BIA, "bia@example.com", { status: "suspended", status_reason: "left the company" })),
      ],
    });
    await user.click(await screen.findByRole("button", { name: en.suspendUser }));
    const dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: en.suspendUser });
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    expect(within(dialog).getByText(en.level(2), { exact: false })).toBeTruthy();

    await user.type(within(dialog).getByLabelText(en.reasonLabel), "left the company");
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    await user.type(within(dialog).getByLabelText(en.typeToConfirm("bia@example.com")), "bia@example.com{Enter}");
    // Enter does not take the action: only its button does.
    expect(sent.some((request) => request.method === "POST")).toBe(false);

    await user.click(confirm);
    expect(await screen.findByText(en.suspendedBecause("left the company"))).toBeTruthy();
    expect(sent.find((request) => request.method === "POST")?.body).toEqual({ reason: "left the company" });
    expect(screen.queryByRole("button", { name: en.suspendUser })).toBeNull();
  });

  it("ends a session after a confirmation that names the consequence", async () => {
    const { sent, user } = show(`/t/acme/console/users/${BIA}`, {
      ...script(),
      "DELETE /console/api/sessions/session-1": [new Response(null, { status: 204 })],
    });
    await user.click(await screen.findByRole("button", { name: en.endSession }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.endSessionLead("Example Browser"))).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: en.endSession }));
    expect(await screen.findByText(en.noSessions)).toBeTruthy();
    expect(sent.some((request) => request.method === "DELETE")).toBe(true);
  });

  it("does not offer a person their own suspension", async () => {
    show(`/t/acme/console/users/${ANA}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/users/${ANA}`]: [json(200, userBody(ANA, "ana@example.com"))],
      [`GET /console/api/users/${ANA}/sessions`]: [json(200, { items: [] })],
    });
    expect(await screen.findByRole("heading", { name: en.profile })).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.suspendUser })).toBeNull();
  });
});

describe("the second factors of a user", () => {
  const withCredentials = [
    "users:read",
    "users:write",
    "sessions:read",
    "sessions:revoke",
    "credentials:read",
    "credentials:write",
  ];
  const factors = (more: Record<string, unknown> = {}) =>
    json(200, {
      authenticator_application: { in_use: true },
      keys: [
        { id: "key-1", name: "Blue key", passkey: false, created_at: "2026-11-21T14:05:00Z", last_used_at: null },
      ],
      recovery_codes: { remaining: 8 },
      second_factor_required: true,
      ...more,
    });
  const script = (permissions: string[], answers: Response[]) => ({
    "GET /console/api/me": [json(200, meBody(permissions))],
    [`GET /console/api/users/${BIA}`]: [json(200, userBody(BIA, "bia@example.com", { display_name: "Bia Souza" }))],
    [`GET /console/api/users/${BIA}/sessions`]: [json(200, { items: [] })],
    [`GET /console/api/users/${BIA}/factors`]: answers,
  });

  it("are shown to whoever may see them, and offered for removal only to whoever may remove them", async () => {
    show(`/t/acme/console/users/${BIA}`, script(["users:read", "sessions:read", "credentials:read"], [factors()]));
    expect(await screen.findByText("Blue key")).toBeTruthy();
    expect(screen.getByText(en.inUse)).toBeTruthy();
    expect(screen.getByText(en.recoveryCodesLeft(8))).toBeTruthy();
    expect(screen.getByText(en.secondFactorRequired)).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.remove })).toBeNull();
  });

  it("are not asked for without the permission to see them", async () => {
    const { sent } = show(`/t/acme/console/users/${BIA}`, script(["users:read", "sessions:read"], []));
    expect(await screen.findByRole("heading", { name: en.profile })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: en.factors })).toBeNull();
    expect(sent.some((request) => request.path.endsWith("/factors"))).toBe(false);
  });

  it("are removed only with the address typed in full, and the dialog says what follows", async () => {
    const { sent, user } = show(`/t/acme/console/users/${BIA}`, {
      ...script(withCredentials, [
        factors({ authenticator_application: { in_use: false } }),
        factors({ authenticator_application: { in_use: false }, keys: [], recovery_codes: { remaining: 0 } }),
      ]),
      [`DELETE /console/api/users/${BIA}/factors/keys/key-1`]: [new Response(null, { status: 204 })],
    });
    // The key's button comes first; the recovery codes have their own.
    const [ofTheKey] = await screen.findAllByRole("button", { name: en.remove });
    expect(ofTheKey).toBeTruthy();
    await user.click(ofTheKey as HTMLElement);
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("heading", { name: en.removePersonKeyTitle("Blue key") })).toBeTruthy();
    expect(within(dialog).getByText(en.level(2), { exact: false })).toBeTruthy();
    expect(within(dialog).getByText(en.removeConsequenceLast)).toBeTruthy();
    expect(within(dialog).getByText(en.removeConsequenceLocked)).toBeTruthy();
    expect(within(dialog).getByText(en.removeConsequenceSessionsValue)).toBeTruthy();
    const confirm = within(dialog).getByRole("button", { name: en.remove });
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    await user.type(within(dialog).getByLabelText(en.typeToConfirm("bia@example.com")), "bia@example.com");
    await user.click(confirm);
    expect(await screen.findByText(en.noPersonKeys)).toBeTruthy();
    expect(sent.find((request) => request.method === "DELETE")?.path).toBe(
      `/console/api/users/${BIA}/factors/keys/key-1`,
    );
  });
});

describe("the audit screen", () => {
  it("lists the records and shows one whole, with its hashes", async () => {
    const record = {
      sequence: 42,
      action: "identity.user_suspended",
      occurred_at: "2026-11-20T14:03:11.482913Z",
      recorded_at: "2026-11-20T14:03:11.731002Z",
      actor: { kind: "user", id: ANA },
      correlation_id: "0193f1d0-0000-7000-8000-000000000009",
      details: { reason: "left the company" },
      previous_hash: "9a41",
      hash: "c07e",
    };
    const { user } = show("/t/acme/console/audit", {
      "GET /console/api/me": [json(200, meBody())],
      "GET /console/api/audit-records?limit=50": [json(200, { items: [record] })],
    });
    expect(await screen.findByText("identity.user_suspended")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: en.viewRecord }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("c07e")).toBeTruthy();
    expect(within(dialog).getByText(/left the company/)).toBeTruthy();
  });
});

describe("the identity providers", () => {
  it("are listed, each a link to its page, and an auditor may not add one", async () => {
    show("/t/acme/console/identity-providers", {
      "GET /console/api/me": [json(200, meBody(["identity-providers:read"], ["tenant_auditor"]))],
      "GET /console/api/identity-providers": [json(200, { items: [providerBody()] })],
    });
    const google = await screen.findByRole("link", { name: "Google" });
    expect(google.getAttribute("href")).toBe(`/t/acme/console/identity-providers/${GOOGLE}`);
    expect(screen.getByText(en.createsUsersYes)).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.addProvider })).toBeNull();
  });

  it("are added with a form that says who will be let in before its button", async () => {
    const { sent, go, user } = show("/t/acme/console/identity-providers", {
      "GET /console/api/me": [json(200, meBody())],
      "GET /console/api/identity-providers": [json(200, { items: [] })],
      "POST /console/api/identity-providers": [problem(409, "federation.alias_taken"), json(201, providerBody())],
    });
    expect(await screen.findByText(en.noProviders)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: en.addProvider }));
    const dialog = await screen.findByRole("dialog");
    const add = within(dialog).getByRole("button", { name: en.addProvider });
    expect(add.getAttribute("aria-disabled")).toBe("true");

    await user.type(within(dialog).getByLabelText(en.aliasLabel), "google");
    await user.type(within(dialog).getByLabelText(en.providerNameLabel), "Google");
    await user.type(within(dialog).getByLabelText(en.issuerLabel), "https://accounts.google.com");
    await user.type(within(dialog).getByLabelText(en.clientIdLabel), "1234");
    const secret = within(dialog).getByLabelText(en.clientSecretLabel);
    expect(secret.getAttribute("type")).toBe("password");
    await user.type(secret, "the secret");
    expect(within(dialog).getByText(en.createsUsersOn("Google"))).toBeTruthy();

    await user.click(add);
    expect(await within(dialog).findByText(en.aliasTaken)).toBeTruthy();
    await user.click(add);
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "provider", id: GOOGLE }));
    expect(sent.at(-1)?.body).toMatchObject({ alias: "google", scopes: ["openid", "email", "profile"], creates_users: true });
  });

  it("show the callback address and never a client secret", async () => {
    show(`/t/acme/console/identity-providers/${GOOGLE}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/identity-providers/${GOOGLE}`]: [json(200, providerBody())],
    });
    expect(await screen.findByText("https://auth.example/t/acme/account/providers/google/callback")).toBeTruthy();
    expect(screen.getByText(en.clientSecretSet)).toBeTruthy();
  });

  it("are disabled only with the alias typed in full", async () => {
    const { sent, user } = show(`/t/acme/console/identity-providers/${GOOGLE}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/identity-providers/${GOOGLE}`]: [json(200, providerBody())],
      [`POST /console/api/identity-providers/${GOOGLE}:disable`]: [json(200, providerBody({ status: "disabled" }))],
    });
    await user.click(await screen.findByRole("button", { name: en.disableProvider }));
    const dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: en.disableProvider });
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    await user.type(within(dialog).getByLabelText(en.typeToConfirm("google")), "google");
    await user.click(confirm);
    expect(await screen.findByRole("button", { name: en.enableProvider })).toBeTruthy();
    expect(sent.at(-1)?.path).toBe(`/console/api/identity-providers/${GOOGLE}:disable`);
  });

  it("send only what was changed, and nothing when nothing was", async () => {
    const { sent, user } = show(`/t/acme/console/identity-providers/${GOOGLE}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/identity-providers/${GOOGLE}`]: [json(200, providerBody())],
      [`PATCH /console/api/identity-providers/${GOOGLE}`]: [json(200, providerBody({ creates_users: false }))],
    });
    await user.click(await screen.findByRole("button", { name: en.changeSettings }));
    const dialog = await screen.findByRole("dialog");
    const save = within(dialog).getByRole("button", { name: en.saveSettings });
    expect(save.getAttribute("aria-disabled")).toBe("true");
    await user.click(within(dialog).getByLabelText(en.createsUsersLabel));
    expect(within(dialog).getByText(en.createsUsersOff("Google"))).toBeTruthy();
    await user.click(save);
    expect(await screen.findByText(en.createsUsersOff("Google"))).toBeTruthy();
    expect(sent.at(-1)?.body).toEqual({ creates_users: false });
  });

  it("show a directory, which has no callback address, and leave its settings to the administration interface", async () => {
    const DIRECTORY = "0193f1c2-0000-7000-8000-00000000000b";
    const directory = providerBody({
      id: DIRECTORY,
      alias: "company",
      kind: "ldap",
      display_name: "Company",
      issuer: "ldaps://directory.example",
      client_id: "cn=hodor,dc=example,dc=com",
      scopes: [],
      callback_address: null,
      directory: { base: "ou=people,dc=example,dc=com", filter: "(uid={identifier})" },
    });
    const { user, go } = show("/t/acme/console/identity-providers", {
      "GET /console/api/me": [json(200, meBody())],
      "GET /console/api/identity-providers": [json(200, { items: [providerBody(), directory] })],
    });
    expect(await screen.findByText(en.providerKinds["ldap"] ?? "")).toBeTruthy();
    await user.click(screen.getByRole("link", { name: "Company" }));
    expect(go).toHaveBeenCalledWith({ name: "provider", id: DIRECTORY });
    cleanup();

    show(`/t/acme/console/identity-providers/${DIRECTORY}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/identity-providers/${DIRECTORY}`]: [json(200, directory)],
    });
    expect(await screen.findByText("(uid={identifier})")).toBeTruthy();
    expect(screen.queryByText(en.callbackAddress)).toBeNull();
    expect(screen.getByText(en.managedElsewhere)).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.changeSettings })).toBeNull();
    expect(screen.getByRole("button", { name: en.disableProvider })).toBeTruthy();
  });
});

describe("the applications", () => {
  const SECRET = "hodor_cs_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";

  it("are listed, each a link to its page, and an auditor may not register one", async () => {
    show("/t/acme/console/applications", {
      "GET /console/api/me": [json(200, meBody(["applications:read"], ["tenant_auditor"]))],
      "GET /console/api/applications": [json(200, { items: [applicationBody()] })],
    });
    const billing = await screen.findByRole("link", { name: "Billing" });
    expect(billing.getAttribute("href")).toBe(`/t/acme/console/applications/${BILLING}`);
    expect(screen.getByText(en.firstParty)).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.addApplication })).toBeNull();
  });

  it("are registered with a form that says whether people are asked for consent", async () => {
    const { sent, go, user } = show("/t/acme/console/applications", {
      "GET /console/api/me": [json(200, meBody())],
      "GET /console/api/applications": [json(200, { items: [] })],
      "POST /console/api/applications": [json(201, applicationBody({ first_party: false }))],
    });
    expect(await screen.findByText(en.noApplications)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: en.addApplication }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(en.applicationNameLabel), "Billing");
    expect(within(dialog).getByText(en.consentSkipped("Billing"))).toBeTruthy();
    await user.click(within(dialog).getByRole("switch", { name: en.firstPartyLabel }));
    expect(within(dialog).getByText(en.consentAsked("Billing"))).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: en.addApplication }));
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "application", id: BILLING }));
    expect(sent.at(-1)?.body).toEqual({ name: "Billing", first_party: false });
  });

  it("show a new client's secret once, and the client's page never shows it", async () => {
    const { sent, go, user } = show(`/t/acme/console/applications/${BILLING}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/applications/${BILLING}`]: [json(200, applicationBody())],
      [`GET /console/api/applications/${BILLING}/clients`]: [json(200, { items: [] })],
      "GET /console/api/resource-servers": [json(200, { items: [] })],
      [`POST /console/api/applications/${BILLING}/clients`]: [json(201, { ...clientBody(), client_secret: SECRET })],
    });
    expect(await screen.findByText(en.noClients)).toBeTruthy();
    expect(screen.getByText(en.noResourceServer)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: en.addClient }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(en.clientNameLabel), "Billing web site");
    await user.type(within(dialog).getByLabelText(en.redirectUrisLabel), "https://billing.example.com/callback");
    await user.type(
      within(dialog).getByLabelText(en.postLogoutRedirectUrisLabel),
      "https://billing.example.com/signed-out",
    );
    await user.click(within(dialog).getByRole("button", { name: en.addClient }));

    const shown = await screen.findByTestId("shown-once");
    expect(shown.textContent).toBe(SECRET);
    expect(sent.at(-1)?.body).toEqual({
      name: "Billing web site",
      type: "confidential",
      authentication_method: "client_secret_basic",
      grant_types: ["authorization_code"],
      redirect_uris: ["https://billing.example.com/callback"],
      post_logout_redirect_uris: ["https://billing.example.com/signed-out"],
      allowed_scopes: ["openid"],
      tls_client_certificate_bound_access_tokens: false,
    });
    await user.click(screen.getByRole("button", { name: en.secretKept }));
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "client", id: WEB }));
    expect(screen.queryByText(SECRET)).toBeNull();
  });

  it("offer a public client no secret and no way to act as itself", async () => {
    const { user } = show(`/t/acme/console/applications/${BILLING}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/applications/${BILLING}`]: [json(200, applicationBody())],
      [`GET /console/api/applications/${BILLING}/clients`]: [json(200, { items: [] })],
      "GET /console/api/resource-servers": [json(200, { items: [] })],
    });
    await user.click(await screen.findByRole("button", { name: en.addClient }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.methodLabel)).toBeTruthy();
    await user.click(within(dialog).getByRole("radio", { name: en.clientTypes["public"] ?? "" }));
    expect(within(dialog).queryByText(en.methodLabel)).toBeNull();
    expect(within(dialog).queryByText(en.grants["client_credentials"] ?? "")).toBeNull();
  });

  it("are disabled only with the name typed in full", async () => {
    const { sent, user } = show(`/t/acme/console/applications/${BILLING}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/applications/${BILLING}`]: [json(200, applicationBody())],
      [`GET /console/api/applications/${BILLING}/clients`]: [json(200, { items: [clientBody()] })],
      "GET /console/api/resource-servers": [json(200, { items: [] })],
      [`POST /console/api/applications/${BILLING}:disable`]: [json(200, applicationBody({ status: "disabled" }))],
    });
    expect(await screen.findByRole("link", { name: "Billing web site" })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: en.disableApplication }));
    const dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: en.disableApplication });
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    await user.type(within(dialog).getByLabelText(en.typeToConfirm("Billing")), "Billing");
    await user.click(confirm);
    expect(await screen.findByRole("button", { name: en.enableApplication })).toBeTruthy();
    expect(sent.at(-1)?.path).toBe(`/console/api/applications/${BILLING}:disable`);
  });
});

describe("the page of a client", () => {
  const SECRET = "hodor_cs_fedcba9876543210fedcba9876543210fedcba9876543210fedcba98765432";

  it("shows its settings and secrets by expiry, never a secret", async () => {
    show(`/t/acme/console/clients/${WEB}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/clients/${WEB}`]: [json(200, clientBody())],
    });
    expect(await screen.findByRole("heading", { name: "Billing web site" })).toBeTruthy();
    expect(screen.getByText(WEB)).toBeTruthy();
    expect(screen.getByText("https://billing.example.com/callback")).toBeTruthy();
    expect(screen.getAllByText(en.minutes(5)).length).toBe(2);
    expect(screen.getByText(en.days(30))).toBeTruthy();
    expect(screen.queryByText(/hodor_cs_/)).toBeNull();
  });

  it("gives a new secret only with the name typed in full, and shows it once", async () => {
    const { sent, user } = show(`/t/acme/console/clients/${WEB}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/clients/${WEB}`]: [json(200, clientBody()), json(200, clientBody())],
      [`POST /console/api/clients/${WEB}/secrets`]: [
        json(201, {
          id: "0193f1c2-0000-7000-8000-0000000000d2",
          client_secret: SECRET,
          created_at: "2026-11-22T15:03:11Z",
          expires_at: "2027-11-22T15:03:11Z",
        }),
      ],
    });
    await user.click(await screen.findByRole("button", { name: en.rotateSecret }));
    const dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: en.rotateSecret });
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    await user.type(within(dialog).getByLabelText(en.typeToConfirm("Billing web site")), "Billing web site");
    await user.click(confirm);
    expect((await screen.findByTestId("shown-once")).textContent).toBe(SECRET);
    expect(sent.find((request) => request.method === "POST")?.csrfToken).toBe("token-of-the-session");
    await user.click(screen.getByRole("button", { name: en.secretKept }));
    await waitFor(() => expect(screen.queryByText(SECRET)).toBeNull());
  });

  it("refuses a key that is not JSON before asking the server, and removes a key by its kid", async () => {
    const keyed = clientBody({
      authentication_method: "private_key_jwt",
      secrets: [],
      keys: [{ kid: "2026/11", jwk: { kty: "EC", crv: "P-256", kid: "2026/11" }, added_at: "2026-11-22T14:03:11Z" }],
    });
    const { sent, user } = show(`/t/acme/console/clients/${WEB}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/clients/${WEB}`]: [json(200, keyed), json(200, clientBody({ ...keyed, keys: [] }))],
      [`DELETE /console/api/clients/${WEB}/keys/2026%2F11`]: [new Response(null, { status: 204 })],
    });
    await user.click(await screen.findByRole("button", { name: en.addKey }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(en.keyLabel), "not a key");
    await user.click(within(dialog).getByRole("button", { name: en.addKey }));
    expect(await within(dialog).findByText(en.keyNotJson)).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: en.cancel }));

    await user.click(screen.getByRole("button", { name: en.removeKey }));
    const removing = await screen.findByRole("dialog");
    await user.click(within(removing).getByRole("button", { name: en.removeKey }));
    await waitFor(() => expect(sent.at(-2)?.path).toBe(`/console/api/clients/${WEB}/keys/2026%2F11`));
    expect(sent.some((request) => request.path.endsWith("/keys") && request.method === "POST")).toBe(false);
  });

  it("shows the identity it is bound to, and whether its access tokens are bound to a certificate", async () => {
    show(`/t/acme/console/clients/${WEB}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/clients/${WEB}`]: [
        json(
          200,
          clientBody({
            authentication_method: "spiffe_jwt",
            grant_types: ["client_credentials"],
            redirect_uris: [],
            secrets: [],
            principal: EXPORT,
            spiffe_id: "spiffe://prod.example.com/ns/payroll/sa/nightly-export",
            tls_client_certificate_bound_access_tokens: true,
          }),
        ),
      ],
    });
    expect(await screen.findByText("spiffe://prod.example.com/ns/payroll/sa/nightly-export")).toBeTruthy();
    expect(screen.getByText(en.methods["spiffe_jwt"] ?? "")).toBeTruthy();
    expect(screen.getByText(en.certificateBound)).toBeTruthy();
    expect(screen.queryByText(en.linkerdIdentityLabel)).toBeNull();
    expect(screen.queryByRole("button", { name: en.rotateSecret })).toBeNull();
  });

  it("is created with a workload's identity: its service account, the identity its method takes, and no secret", async () => {
    const SPIFFE_ID = "spiffe://prod.example.com/ns/payroll/sa/nightly-export";
    const { sent, go, user } = show(`/t/acme/console/applications/${BILLING}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/applications/${BILLING}`]: [json(200, applicationBody())],
      [`GET /console/api/applications/${BILLING}/clients`]: [json(200, { items: [] })],
      "GET /console/api/resource-servers": [json(200, { items: [] })],
      [`POST /console/api/applications/${BILLING}/clients`]: [
        problem(409, "oauth.client_spiffe_id_taken"),
        json(
          201,
          clientBody({
            authentication_method: "spiffe_jwt",
            grant_types: ["client_credentials"],
            redirect_uris: [],
            secrets: [],
            principal: EXPORT,
            spiffe_id: SPIFFE_ID,
          }),
        ),
      ],
    });
    await user.click(await screen.findByRole("button", { name: en.addClient }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(en.clientNameLabel), "Nightly export");
    expect(within(dialog).queryByLabelText(en.spiffeIdLabel)).toBeNull();
    await user.click(within(dialog).getByRole("radio", { name: en.methods["spiffe_jwt"] ?? "" }));
    expect(within(dialog).getByText(en.workloadMethodLead)).toBeTruthy();
    // Only client credentials, and no address to send a person back to.
    expect(within(dialog).queryByText(en.grants["authorization_code"] ?? "")).toBeNull();
    expect(within(dialog).queryByLabelText(en.redirectUrisLabel)).toBeNull();
    expect(within(dialog).queryByLabelText(en.linkerdIdentityLabel)).toBeNull();
    const create = within(dialog).getByRole("button", { name: en.addClient });
    expect(create.getAttribute("aria-disabled")).toBe("true");
    await user.type(within(dialog).getByLabelText(en.principalServiceAccountLabel), "Nightly export");
    await user.type(within(dialog).getByLabelText(en.spiffeIdLabel), SPIFFE_ID);
    await user.click(create);
    expect(await within(dialog).findByText(en.principalNotAnIdentifier)).toBeTruthy();
    expect(sent.some((request) => request.method === "POST")).toBe(false);

    const principal = within(dialog).getByLabelText(en.principalServiceAccountLabel);
    await user.clear(principal);
    await user.type(principal, EXPORT);
    await user.click(create);
    expect(await within(dialog).findByText(en.spiffeIdTaken)).toBeTruthy();
    await user.click(create);
    // No secret to show: the client's page opens at once.
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "client", id: WEB }));
    expect(screen.queryByTestId("shown-once")).toBeNull();
    expect(sent.at(-1)?.body).toEqual({
      name: "Nightly export",
      type: "confidential",
      authentication_method: "spiffe_jwt",
      grant_types: ["client_credentials"],
      redirect_uris: [],
      post_logout_redirect_uris: [],
      allowed_scopes: ["openid"],
      principal: EXPORT,
      spiffe_id: SPIFFE_ID,
      tls_client_certificate_bound_access_tokens: false,
    });
  });

  it("is changed to a forwarded certificate naming a Linkerd identity, and a client of a Linkerd identity binds no token", async () => {
    const LINKERD = "web.shop.serviceaccount.identity.linkerd.cluster.local";
    const { sent, user } = show(`/t/acme/console/clients/${WEB}`, {
      "GET /console/api/me": [json(200, meBody())],
      [`GET /console/api/clients/${WEB}`]: [json(200, clientBody())],
      [`PATCH /console/api/clients/${WEB}`]: [
        problem(422, "oauth.client_principal_invalid"),
        json(
          200,
          clientBody({
            authentication_method: "tls_client_auth",
            grant_types: ["client_credentials"],
            redirect_uris: [],
            secrets: [],
            principal: EXPORT,
            linkerd_identity: LINKERD,
            tls_client_certificate_bound_access_tokens: true,
          }),
        ),
      ],
    });
    await user.click(await screen.findByRole("button", { name: en.changeSettings }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("switch", { name: en.certificateBoundLabel })).toBeTruthy();
    await user.click(within(dialog).getByRole("radio", { name: en.methods["linkerd_identity"] ?? "" }));
    expect(within(dialog).getByLabelText(en.linkerdIdentityLabel)).toBeTruthy();
    expect(within(dialog).queryByRole("switch", { name: en.certificateBoundLabel })).toBeNull();

    await user.click(within(dialog).getByRole("radio", { name: en.methods["tls_client_auth"] ?? "" }));
    expect(within(dialog).getByLabelText(en.spiffeIdLabel)).toBeTruthy();
    await user.click(within(dialog).getByRole("radio", { name: en.linkerdIdentityLabel }));
    expect(within(dialog).queryByLabelText(en.spiffeIdLabel)).toBeNull();
    await user.type(within(dialog).getByLabelText(en.linkerdIdentityLabel), LINKERD);
    await user.type(within(dialog).getByLabelText(en.principalServiceAccountLabel), EXPORT);
    await user.click(within(dialog).getByRole("switch", { name: en.certificateBoundLabel }));
    const save = within(dialog).getByRole("button", { name: en.saveClient });
    await user.click(save);
    expect(await within(dialog).findByText(en.valueInvalid["oauth.client_principal_invalid"] ?? "")).toBeTruthy();
    await user.click(save);
    expect(await screen.findByText(LINKERD)).toBeTruthy();
    expect(screen.getByText(en.certificateBound)).toBeTruthy();
    expect(sent.at(-1)?.body).toEqual({
      name: "Billing web site",
      authentication_method: "tls_client_auth",
      grant_types: ["client_credentials"],
      redirect_uris: [],
      post_logout_redirect_uris: [],
      allowed_scopes: ["openid"],
      principal: EXPORT,
      linkerd_identity: LINKERD,
      tls_client_certificate_bound_access_tokens: true,
    });
  });
});

describe("authorization", () => {
  const PAYROLL = "https://payroll.example.com";
  const PAYROLL_SERVER = "0193f1c2-0000-7000-8000-0000000000c1";
  const READS = ["roles:read", "bindings:read", "policies:read", "decisions:read"];
  const roleBody = {
    namespace: PAYROLL,
    name: "approver",
    description: "Approves invoices",
    permissions: [{ name: "invoice:approve", condition: "resource.attributes.amount <= 1000" }],
    includes: [{ namespace: PAYROLL, name: "clerk" }],
    created_at: "2026-11-22T14:03:11Z",
    updated_at: "2026-11-22T14:03:11Z",
  };
  const serverBody = {
    id: PAYROLL_SERVER,
    application_id: BILLING,
    audience: PAYROLL,
    name: "Payroll",
    scopes: [],
    created_at: "2026-11-22T14:03:11Z",
    updated_at: "2026-11-22T14:03:11Z",
  };
  const answers = (permissions: string[]) => ({
    "GET /console/api/me": [json(200, meBody(permissions, ["tenant_auditor"]))],
    "GET /console/api/roles": [json(200, { items: [roleBody] }), json(200, { items: [roleBody] })],
    "GET /console/api/resource-servers": [json(200, { items: [serverBody] }), json(200, { items: [serverBody] })],
    "GET /console/api/bindings": [
      json(200, {
        items: [
          {
            namespace: PAYROLL,
            engine: "open_policy_agent",
            time_limit_milliseconds: 200,
            sensitive: false,
            fail_open_actions: ["read"],
            trust_asserted: false,
            created_at: "2026-11-22T14:03:11Z",
            updated_at: "2026-11-22T14:03:11Z",
          },
        ],
      }),
    ],
    "GET /console/api/policy-status": [
      json(200, {
        latest: { revision: 3, written_by: "operator", published_at: "2026-11-22T14:03:11Z", version: 1 },
        publications: [],
        instances: [{ instance: "shared", own: false, active_revision: "2", current: false }],
        pending_activation: true,
      }),
    ],
    "GET /console/api/decisions?limit=50": [
      json(200, {
        items: [
          {
            decision_id: "decision-1",
            namespace: PAYROLL,
            subject: { kind: "user", id: ANA },
            action: "approve",
            resource: { type: "invoice", id: "42" },
            effect: "deny",
            reason: "condition_not_met",
            decided_at: "2026-11-22T14:03:11Z",
            duration_microseconds: 10,
            input: {},
            masked: [],
          },
        ],
      }),
    ],
  });

  it("shows roles with their conditions, engines, what is published and the latest decisions, and an auditor changes nothing", async () => {
    show("/t/acme/console/authorization", answers(READS));
    expect(await screen.findByText(`${PAYROLL}#approver`)).toBeTruthy();
    expect(screen.getByText(en.conditionShown("resource.attributes.amount <= 1000"), { exact: false })).toBeTruthy();
    expect(await screen.findByText("open_policy_agent")).toBeTruthy();
    expect(screen.getByText("read")).toBeTruthy();
    expect(await screen.findByText(en.activationPending)).toBeTruthy();
    expect(screen.getByText(en.instanceBehind("2"))).toBeTruthy();
    expect(await screen.findByText("condition_not_met")).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.editRole })).toBeNull();
    expect(screen.queryByRole("button", { name: en.unbind })).toBeNull();
  });

  it("changes a role with its conditions written as text, and says what the server refused", async () => {
    const script = {
      ...answers([...READS, "roles:write"]),
      [`PUT /console/api/resource-servers/${PAYROLL_SERVER}/roles/approver`]: [
        problem(422, "authorization.condition_invalid"),
        json(200, roleBody),
      ],
    };
    const { sent, user } = show("/t/acme/console/authorization", script);
    await user.click(await screen.findByRole("button", { name: en.editRole }));
    const dialog = await screen.findByRole("dialog");
    const lines = within(dialog).getByLabelText(en.rolePermissionsLabel);
    expect((lines as HTMLTextAreaElement).value).toBe("invoice:approve if resource.attributes.amount <= 1000");
    await user.clear(lines);
    await user.type(lines, "invoice:approve if resource.attributes.amount <=");
    await user.click(within(dialog).getByRole("button", { name: en.saveRole }));
    expect(await within(dialog).findByText(en.valueInvalid["authorization.condition_invalid"] as string)).toBeTruthy();
    await user.clear(lines);
    await user.type(lines, "invoice:approve if resource.attributes.amount <= 5000");
    await user.click(within(dialog).getByRole("button", { name: en.saveRole }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(sent.filter((request) => request.method === "PUT").at(-1)?.body).toEqual({
      description: "Approves invoices",
      permissions: [{ name: "invoice:approve", condition: "resource.attributes.amount <= 5000" }],
      includes: [{ namespace: PAYROLL, name: "clerk" }],
    });
  });
});

describe("groups", () => {
  const finance = () => json(200, namedBody(FINANCE, "finance", { description: "Who pays the bills" }));
  const page = (script: Parameters<typeof scripted>[0], permissions = MEMBERSHIPS) => ({
    "GET /console/api/me": [json(200, meBody(permissions))],
    [`GET /console/api/groups/${FINANCE}`]: [finance()],
    [`GET /console/api/groups/${FINANCE}/members?limit=50`]: [
      json(200, { items: [{ kind: "user", id: BIA }, { kind: "group", id: PAYABLES }] }),
    ],
    [`GET /console/api/users/${BIA}`]: [json(200, userBody(BIA, "bia@example.com", { display_name: "Bia Souza" }))],
    [`GET /console/api/groups/${PAYABLES}`]: [json(200, namedBody(PAYABLES, "payables"))],
    ...script,
  });

  it("are in the navigation of whoever may read them, and the console starts there without users", async () => {
    const { go } = show("/t/acme/console", {
      "GET /console/api/me": [json(200, meBody(["groups:read", "organizations:read"], ["tenant_auditor"]))],
    });
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "groups" }));
    expect(screen.getByRole("link", { name: en.groups }).getAttribute("href")).toBe("/t/acme/console/groups");
    expect(screen.getByRole("link", { name: en.organizations }).getAttribute("href")).toBe(
      "/t/acme/console/organizations",
    );
    expect(screen.queryByRole("link", { name: en.users })).toBeNull();
  });

  it("are listed a page at a time, each a link to its page, and an auditor may not create one", async () => {
    const { go, user } = show("/t/acme/console/groups", {
      "GET /console/api/me": [json(200, meBody(["groups:read"], ["tenant_auditor"]))],
      "GET /console/api/groups?limit=50": [json(200, { items: [namedBody(FINANCE, "finance")], next_cursor: "1" })],
      "GET /console/api/groups?limit=50&cursor=1": [json(200, { items: [namedBody(PAYABLES, "payables")] })],
    });
    const link = await screen.findByRole("link", { name: "finance" });
    expect(link.getAttribute("href")).toBe(`/t/acme/console/groups/${FINANCE}`);
    expect(screen.getByText(en.noDescription)).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.createGroup })).toBeNull();
    await user.click(screen.getByRole("button", { name: en.loadMore }));
    expect(await screen.findByRole("link", { name: "payables" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.loadMore })).toBeNull();
    await user.click(link);
    expect(go).toHaveBeenCalledWith({ name: "group", id: FINANCE });
  });

  it("are created with a name and an optional description, and a name taken is said in words", async () => {
    const { sent, go, user } = show("/t/acme/console/groups", {
      "GET /console/api/me": [json(200, meBody(MEMBERSHIPS))],
      "GET /console/api/groups?limit=50": [json(200, { items: [] })],
      "POST /console/api/groups": [problem(409, "identity.group_name_taken"), json(201, namedBody(FINANCE, "finance"))],
    });
    expect(await screen.findByText(en.noGroups)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: en.createGroup }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.level(0), { exact: false })).toBeTruthy();
    await user.type(within(dialog).getByLabelText(en.nameLabel), "finance");
    await user.click(within(dialog).getByRole("button", { name: en.createGroup }));
    expect(await within(dialog).findByText(en.groupNameTaken)).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: en.createGroup }));
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "group", id: FINANCE }));
    expect(sent.at(-1)?.body).toEqual({ name: "finance" });
  });

  it("show their direct members, users first, by name", async () => {
    show(`/t/acme/console/groups/${FINANCE}`, page({}));
    expect(await screen.findByRole("heading", { name: "finance" })).toBeTruthy();
    const bia = await screen.findByRole("link", { name: "Bia Souza" });
    expect(bia.getAttribute("href")).toBe(`/t/acme/console/users/${BIA}`);
    const payables = await screen.findByRole("link", { name: "payables" });
    expect(payables.getAttribute("href")).toBe(`/t/acme/console/groups/${PAYABLES}`);
    expect(bia.compareDocumentPosition(payables) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("add a member by identifier, and say in words a group that would be inside itself or too deep", async () => {
    const { sent, user } = show(
      `/t/acme/console/groups/${FINANCE}`,
      page({
        [`POST /console/api/groups/${FINANCE}/members`]: [
          problem(409, "identity.group_cycle"),
          problem(409, "identity.group_nesting_too_deep"),
          empty(204),
        ],
        [`GET /console/api/groups/${FINANCE}/members?limit=50`]: [
          json(200, { items: [] }),
          json(200, { items: [{ kind: "group", id: PAYABLES }] }),
        ],
      }),
    );
    await user.click(await screen.findByRole("button", { name: en.addMember }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.addUserConsequence("finance"))).toBeTruthy();
    await user.click(within(dialog).getByRole("radio", { name: en.memberKinds["group"] ?? "" }));
    expect(within(dialog).getByText(en.addGroupConsequence("finance"))).toBeTruthy();
    const identifier = within(dialog).getByLabelText(en.groupIdentifierLabel);
    await user.type(identifier, "payables");
    const add = within(dialog).getByRole("button", { name: en.addMember });
    await user.click(add);
    // Not an identifier: said before the server is asked.
    expect(await within(dialog).findByText(en.notAnIdentifier)).toBeTruthy();
    expect(sent.some((request) => request.method === "POST")).toBe(false);

    await user.clear(identifier);
    await user.type(identifier, PAYABLES);
    await user.click(add);
    expect(await within(dialog).findByText(en.groupCycle)).toBeTruthy();
    await user.click(add);
    expect(await within(dialog).findByText(en.groupNestingTooDeep)).toBeTruthy();
    await user.click(add);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(sent.filter((request) => request.method === "POST").at(-1)?.body).toEqual({ kind: "group", id: PAYABLES });
  });

  it("take a member out after a dialog that says what follows", async () => {
    const { sent, user } = show(
      `/t/acme/console/groups/${FINANCE}`,
      page({
        [`POST /console/api/groups/${FINANCE}/members:remove`]: [empty(204)],
        [`GET /console/api/groups/${FINANCE}/members?limit=50`]: [
          json(200, { items: [{ kind: "user", id: BIA }] }),
          json(200, { items: [] }),
        ],
      }),
    );
    await screen.findByRole("link", { name: "Bia Souza" });
    await user.click(screen.getByRole("button", { name: en.takeOut }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.removeUserLead("finance"))).toBeTruthy();
    expect(within(dialog).getByText(en.level(1), { exact: false })).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: en.takeOut }));
    expect(await screen.findByText(en.noGroupMembers)).toBeTruthy();
    expect(sent.find((request) => request.path.endsWith("members:remove"))?.body).toEqual({ kind: "user", id: BIA });
  });

  it("are changed with a form, and deleted only with the name typed in full", async () => {
    const { sent, go, user } = show(
      `/t/acme/console/groups/${FINANCE}`,
      page({
        [`PATCH /console/api/groups/${FINANCE}`]: [json(200, namedBody(FINANCE, "finance"))],
        [`DELETE /console/api/groups/${FINANCE}`]: [empty(204)],
      }),
    );
    await user.click(await screen.findByRole("button", { name: en.changeSettings }));
    let dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.identifierKept("finance"))).toBeTruthy();
    await user.clear(within(dialog).getByLabelText(`${en.descriptionLabel} (${en.optional})`));
    await user.click(within(dialog).getByRole("button", { name: en.saveGroup }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    // A missing description removes it.
    expect(sent.find((request) => request.method === "PATCH")?.body).toEqual({ name: "finance" });

    await user.click(screen.getByRole("button", { name: en.deleteGroup }));
    dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: en.deleteGroup });
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    expect(within(dialog).getByText(en.deleteGroupAboveValue)).toBeTruthy();
    await user.type(within(dialog).getByLabelText(en.typeToConfirm("finance")), "finance");
    await user.click(confirm);
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "groups" }));
    expect(sent.some((request) => request.method === "DELETE")).toBe(true);
  });

  it("offer an auditor nothing to change, and show members by identifier to whoever may not read users", async () => {
    const { sent } = show(`/t/acme/console/groups/${FINANCE}`, page({}, ["groups:read"]));
    expect(await screen.findByRole("link", { name: "payables" })).toBeTruthy();
    expect(screen.getByTitle(BIA)).toBeTruthy();
    expect(sent.some((request) => request.path === `/console/api/users/${BIA}`)).toBe(false);
    for (const label of [en.changeSettings, en.deleteGroup, en.addMember, en.takeOut]) {
      expect(screen.queryByRole("button", { name: label })).toBeNull();
    }
  });
});

describe("organizations", () => {
  const INVITATION = "0193f2c0-0000-7000-8000-0000000000a1";
  const units = (more: ReturnType<typeof unitBody>[] = []) =>
    json(200, {
      items: [
        unitBody(SALES, "Sales", null),
        unitBody(PLATFORM, "Platform", ENGINEERING, "department"),
        unitBody(ENGINEERING, "Engineering", null),
        ...more,
      ],
    });
  const page = (script: Parameters<typeof scripted>[0], permissions = MEMBERSHIPS) => ({
    "GET /console/api/me": [json(200, meBody(permissions))],
    [`GET /console/api/organizations/${ACME}`]: [json(200, namedBody(ACME, "Acme"))],
    [`GET /console/api/organizations/${ACME}/units`]: [units()],
    [`GET /console/api/organizations/${ACME}/members?limit=50`]: [
      json(200, { items: [{ user_id: BIA, unit_ids: [PLATFORM], added_at: "2026-11-23T14:03:11Z" }] }),
    ],
    [`GET /console/api/organizations/${ACME}/invitations`]: [
      json(200, {
        items: [
          {
            id: INVITATION,
            email: "caio@example.com",
            unit_ids: [SALES],
            created_at: "2026-11-23T14:03:11Z",
            expires_at: "2026-11-30T14:03:11Z",
            token: "hodor_invitation_secret",
          },
        ],
      }),
    ],
    [`GET /console/api/users/${BIA}`]: [json(200, userBody(BIA, "bia@example.com", { display_name: "Bia Souza" }))],
    ...script,
  });

  it("are listed, each a link to its page, and created with a form", async () => {
    const { sent, go, user } = show("/t/acme/console/organizations", {
      "GET /console/api/me": [json(200, meBody(MEMBERSHIPS))],
      "GET /console/api/organizations?limit=50": [
        json(200, { items: [namedBody(ACME, "Acme", { description: "A customer" })] }),
      ],
      "POST /console/api/organizations": [json(201, namedBody(ENGINEERING, "Globex"))],
    });
    const acme = await screen.findByRole("link", { name: "Acme" });
    expect(acme.getAttribute("href")).toBe(`/t/acme/console/organizations/${ACME}`);
    expect(screen.getByText("A customer")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: en.createOrganization }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(en.nameLabel), "Globex");
    await user.type(within(dialog).getByLabelText(`${en.descriptionLabel} (${en.optional})`), "Another customer");
    await user.click(within(dialog).getByRole("button", { name: en.createOrganization }));
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "organization", id: ENGINEERING }));
    expect(sent.at(-1)?.body).toEqual({ name: "Globex", description: "Another customer" });
  });

  it("show the units as a tree, the members with their units, and invitations without any token", async () => {
    show(`/t/acme/console/organizations/${ACME}`, page({}));
    expect(await screen.findByRole("heading", { name: "Acme" })).toBeTruthy();
    await screen.findByText("Platform");
    const tree = [...document.querySelectorAll(".console-unit")].map((unit) => [
      unit.textContent,
      unit.getAttribute("data-depth"),
    ]);
    expect(tree).toEqual([
      ["Engineering", "1"],
      ["Platform", "2"],
      ["Sales", "1"],
    ]);
    expect(screen.getByText(en.unitKinds["department"] ?? "")).toBeTruthy();
    expect(await screen.findByRole("link", { name: "Bia Souza" })).toBeTruthy();
    expect(screen.getByText("Engineering / Platform")).toBeTruthy();
    expect(screen.getByText("caio@example.com")).toBeTruthy();
    expect(document.body.textContent).not.toContain("hodor_invitation_secret");
  });

  it("create a unit under a parent, and say in words that a unit with units below is not deleted", async () => {
    const PAYMENTS = "0193f2b1-0000-7000-8000-0000000000f5";
    const { sent, user } = show(
      `/t/acme/console/organizations/${ACME}`,
      page({
        [`GET /console/api/organizations/${ACME}/units`]: [
          units(),
          units([unitBody(PAYMENTS, "Payments", ENGINEERING, "department")]),
        ],
        [`POST /console/api/organizations/${ACME}/units`]: [json(201, unitBody(PAYMENTS, "Payments", ENGINEERING))],
        [`DELETE /console/api/organizations/${ACME}/units/${ENGINEERING}`]: [problem(409, "identity.unit_not_empty")],
      }),
    );
    await user.click(await screen.findByRole("button", { name: en.createUnit }));
    let dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(en.nameLabel), "Payments");
    await user.click(within(dialog).getByRole("radio", { name: en.unitKinds["department"] ?? "" }));
    await user.click(within(dialog).getByRole("radio", { name: "Engineering" }));
    await user.click(within(dialog).getByRole("button", { name: en.createUnit }));
    expect(await screen.findByText("Payments")).toBeTruthy();
    expect(sent.find((request) => request.method === "POST")?.body).toEqual({
      parent_id: ENGINEERING,
      name: "Payments",
      kind: "department",
    });

    // The first unit of the tree is Engineering.
    const [ofEngineering] = screen.getAllByRole("button", { name: en.deleteUnit });
    await user.click(ofEngineering as HTMLElement);
    dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.deleteUnitMembersValue)).toBeTruthy();
    const confirm = within(dialog).getByRole("button", { name: en.deleteUnit });
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    await user.type(within(dialog).getByLabelText(en.typeToConfirm("Engineering")), "Engineering");
    await user.click(confirm);
    expect(await within(dialog).findByText(en.unitNotEmpty)).toBeTruthy();
  });

  it("move a unit, never under itself nor a unit below it", async () => {
    const { sent, user } = show(
      `/t/acme/console/organizations/${ACME}`,
      page({
        [`GET /console/api/organizations/${ACME}/units`]: [units(), units()],
        [`PUT /console/api/organizations/${ACME}/units/${ENGINEERING}`]: [
          json(200, unitBody(ENGINEERING, "Engineering", SALES)),
        ],
      }),
    );
    await screen.findByText("Platform");
    const [ofEngineering] = screen.getAllByRole("button", { name: en.changeUnit });
    await user.click(ofEngineering as HTMLElement);
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.moveCarries)).toBeTruthy();
    expect(within(dialog).queryByRole("radio", { name: "Engineering" })).toBeNull();
    expect(within(dialog).queryByRole("radio", { name: "Engineering / Platform" })).toBeNull();
    await user.click(within(dialog).getByRole("radio", { name: "Sales" }));
    await user.click(within(dialog).getByRole("button", { name: en.saveUnit }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(sent.find((request) => request.method === "PUT")?.body).toEqual({
      parent_id: SALES,
      name: "Engineering",
      kind: "unit",
    });
  });

  it("put a member with units, take one out, invite in the language chosen and withdraw an invitation", async () => {
    const CAIO = "0193f1c2-0000-7000-8000-000000000003";
    const { sent, user } = show(
      `/t/acme/console/organizations/${ACME}`,
      page({
        [`PUT /console/api/organizations/${ACME}/members/${CAIO}`]: [
          problem(404, "identity.user_not_found"),
          json(200, { user_id: CAIO, unit_ids: [SALES], added_at: "2026-11-23T14:03:11Z" }),
        ],
        [`GET /console/api/organizations/${ACME}/members?limit=50`]: [
          json(200, { items: [{ user_id: BIA, unit_ids: [PLATFORM], added_at: "2026-11-23T14:03:11Z" }] }),
          json(200, { items: [{ user_id: BIA, unit_ids: [PLATFORM], added_at: "2026-11-23T14:03:11Z" }] }),
          json(200, { items: [] }),
        ],
        [`DELETE /console/api/organizations/${ACME}/members/${BIA}`]: [empty(204)],
        [`POST /console/api/organizations/${ACME}/invitations`]: [problem(422, "identity.email_invalid"), empty(202)],
        [`GET /console/api/organizations/${ACME}/invitations`]: [
          json(200, { items: [] }),
          json(200, {
            items: [
              {
                id: INVITATION,
                email: "dora@example.com",
                unit_ids: [],
                created_at: "2026-11-23T14:03:11Z",
                expires_at: "2026-11-30T14:03:11Z",
              },
            ],
          }),
          json(200, { items: [] }),
        ],
        [`DELETE /console/api/organizations/${ACME}/invitations/${INVITATION}`]: [empty(204)],
      }),
    );
    await user.click(await screen.findByRole("button", { name: en.putMember }));
    let dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(en.userIdentifierLabel), CAIO);
    await user.click(within(dialog).getByRole("checkbox", { name: "Sales" }));
    await user.click(within(dialog).getByRole("button", { name: en.saveMember }));
    expect(await within(dialog).findByText(en.userNotFound)).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: en.saveMember }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(sent.filter((request) => request.method === "PUT").at(-1)?.body).toEqual({ unit_ids: [SALES] });

    await user.click(await screen.findByRole("button", { name: en.takeOut }));
    dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.removeOrganizationMemberLead("Acme"))).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: en.takeOut }));
    expect(await screen.findByText(en.noOrganizationMembers)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: en.invite }));
    dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(en.emailLabel), "dora@example.com");
    expect(within(dialog).getByText(en.inviteConsequence("dora@example.com"))).toBeTruthy();
    await user.click(within(dialog).getByRole("radio", { name: en.messageLanguages["pt-BR"] ?? "" }));
    await user.click(within(dialog).getByRole("button", { name: en.sendInvitation }));
    expect(await within(dialog).findByText(en.emailInvalid)).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: en.sendInvitation }));
    expect(await screen.findByText("dora@example.com")).toBeTruthy();
    expect(sent.filter((request) => request.path.endsWith("/invitations") && request.method === "POST").at(-1)?.body).toEqual({
      email: "dora@example.com",
      unit_ids: [],
      locale: "pt-BR",
    });

    await user.click(screen.getByRole("button", { name: en.withdraw }));
    dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("heading", { name: en.withdrawTitle("dora@example.com") })).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: en.withdraw }));
    expect(await screen.findByText(en.noInvitations)).toBeTruthy();
  });

  it("are deleted only with the name typed in full", async () => {
    const { go, user } = show(
      `/t/acme/console/organizations/${ACME}`,
      page({ [`DELETE /console/api/organizations/${ACME}`]: [empty(204)] }),
    );
    await screen.findByText("caio@example.com");
    await user.click(screen.getByRole("button", { name: en.deleteOrganization }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.deleteOrganizationUnits)).toBeTruthy();
    expect(within(dialog).getByText(en.level(2), { exact: false })).toBeTruthy();
    const confirm = within(dialog).getByRole("button", { name: en.deleteOrganization });
    await user.type(within(dialog).getByLabelText(en.typeToConfirm("Acme")), "acme");
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    await user.clear(within(dialog).getByLabelText(en.typeToConfirm("Acme")));
    await user.type(within(dialog).getByLabelText(en.typeToConfirm("Acme")), "Acme");
    await user.click(confirm);
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "organizations" }));
  });

  it("offer an auditor nothing to change", async () => {
    show(`/t/acme/console/organizations/${ACME}`, page({}, ["users:read", "organizations:read"]));
    await screen.findByText("caio@example.com");
    for (const label of [
      en.changeSettings,
      en.deleteOrganization,
      en.createUnit,
      en.changeUnit,
      en.deleteUnit,
      en.putMember,
      en.changeMemberUnits,
      en.takeOut,
      en.invite,
      en.withdraw,
    ]) {
      expect(screen.queryByRole("button", { name: label })).toBeNull();
    }
  });
});

describe("the groups and organizations of a user", () => {
  const ORGANIZATION = ACME;
  const script = (permissions: string[]) => ({
    "GET /console/api/me": [json(200, meBody(permissions))],
    [`GET /console/api/users/${BIA}`]: [json(200, userBody(BIA, "bia@example.com", { display_name: "Bia Souza" }))],
    [`GET /console/api/users/${BIA}/groups`]: [
      json(200, {
        items: [
          { id: FINANCE, direct: false },
          { id: PAYABLES, direct: true },
        ],
      }),
    ],
    [`GET /console/api/groups/${FINANCE}`]: [json(200, namedBody(FINANCE, "finance"))],
    [`GET /console/api/groups/${PAYABLES}`]: [json(200, namedBody(PAYABLES, "payables"))],
    [`GET /console/api/users/${BIA}/organizations`]: [
      json(200, { items: [{ organization_id: ORGANIZATION, unit_ids: [PLATFORM], added_at: "2026-11-23T14:03:11Z" }] }),
    ],
    [`GET /console/api/organizations/${ORGANIZATION}`]: [json(200, namedBody(ORGANIZATION, "Acme"))],
    [`GET /console/api/organizations/${ORGANIZATION}/units`]: [
      json(200, {
        items: [unitBody(ENGINEERING, "Engineering", null), unitBody(PLATFORM, "Platform", ENGINEERING, "department")],
      }),
    ],
  });

  it("are shown to whoever may read them, each group direct or through another", async () => {
    show(`/t/acme/console/users/${BIA}`, script(["users:read", "groups:read", "organizations:read"]));
    expect(await screen.findByRole("heading", { name: en.userGroups })).toBeTruthy();
    const finance = await screen.findByRole("link", { name: "finance" });
    expect(finance.getAttribute("href")).toBe(`/t/acme/console/groups/${FINANCE}`);
    expect(screen.getByText(en.throughAnother)).toBeTruthy();
    expect(screen.getByText(en.direct)).toBeTruthy();
    expect(await screen.findByRole("link", { name: "Acme" })).toBeTruthy();
    expect(await screen.findByText("Engineering / Platform")).toBeTruthy();
  });

  it("are not asked for without the permission to read them", async () => {
    const { sent } = show(`/t/acme/console/users/${BIA}`, script(["users:read"]));
    expect(await screen.findByRole("heading", { name: en.profile })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: en.userGroups })).toBeNull();
    expect(screen.queryByRole("heading", { name: en.userOrganizations })).toBeNull();
    expect(sent.some((request) => request.path.includes("/groups") || request.path.includes("/organizations"))).toBe(
      false,
    );
  });
});

describe("service accounts and agents", () => {
  const KEY = "hodor_ak_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab";
  const ana = () => json(200, userBody(ANA, "ana@example.com", { display_name: "Ana Lima" }));
  const page = (script: Parameters<typeof scripted>[0], permissions = WORKLOADS) => ({
    "GET /console/api/me": [json(200, meBody(permissions))],
    [`GET /console/api/service-accounts/${EXPORT}`]: [json(200, workloadBody(EXPORT, "Nightly export"))],
    [`GET /console/api/users/${ANA}`]: [ana()],
    [`GET /console/api/service-accounts/${EXPORT}/api-keys`]: [
      json(200, { items: [apiKeyBody(REPORTS_KEY, "Reports", { last_used_at: "2026-11-24T15:03:11Z" })] }),
    ],
    ...script,
  });

  it("are under Directory for whoever may read them, a page at a time, and an auditor may not create one", async () => {
    const { go, user } = show("/t/acme/console/service-accounts", {
      "GET /console/api/me": [json(200, meBody(["workloads:read"], ["tenant_auditor"]))],
      "GET /console/api/service-accounts?limit=50": [
        json(200, { items: [workloadBody(EXPORT, "Nightly export")], next_cursor: "1" }),
      ],
      "GET /console/api/service-accounts?limit=50&cursor=1": [
        json(200, { items: [workloadBody(ASSISTANT, "Old export", { status: "disabled" })] }),
      ],
    });
    const link = await screen.findByRole("link", { name: "Nightly export" });
    expect(link.getAttribute("href")).toBe(`/t/acme/console/service-accounts/${EXPORT}`);
    expect(screen.getByRole("link", { name: en.agents }).getAttribute("href")).toBe("/t/acme/console/agents");
    expect(screen.getByText(en.ownerCount(1))).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.createWorkload.service_account })).toBeNull();
    await user.click(screen.getByRole("button", { name: en.loadMore }));
    expect(await screen.findByText(en.status["disabled"] ?? "")).toBeTruthy();
    await user.click(link);
    expect(go).toHaveBeenCalledWith({ name: "serviceAccount", id: EXPORT });
  });

  it("are created with a name and owners by identifier, and an owner that is not one is said before asking", async () => {
    const { sent, go, user } = show("/t/acme/console/agents", {
      "GET /console/api/me": [json(200, meBody(WORKLOADS))],
      "GET /console/api/agents?limit=50": [json(200, { items: [] })],
      "POST /console/api/agents": [
        problem(422, "identity.workload_owner_invalid"),
        json(201, workloadBody(ASSISTANT, "Assistant", { kind: "agent" })),
      ],
    });
    expect(await screen.findByText(en.noWorkloads.agent)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: en.createWorkload.agent }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.level(0), { exact: false })).toBeTruthy();
    await user.type(within(dialog).getByLabelText(en.nameLabel), "Assistant");
    const owners = within(dialog).getByLabelText(en.ownersLabel);
    await user.type(owners, "ana@example.com");
    const create = within(dialog).getByRole("button", { name: en.createWorkload.agent });
    await user.click(create);
    expect(await within(dialog).findByText(en.ownersNotIdentifiers)).toBeTruthy();
    expect(sent.some((request) => request.method === "POST")).toBe(false);

    await user.clear(owners);
    await user.type(owners, `${ANA}{enter}{enter}`);
    await user.click(create);
    expect(await within(dialog).findByText(en.valueInvalid["identity.workload_owner_invalid"] ?? "")).toBeTruthy();
    await user.click(create);
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "agent", id: ASSISTANT }));
    expect(sent.at(-1)?.body).toEqual({ name: "Assistant", owners: [ANA] });
  });

  it("show their owners by name, their keys by their last characters only, and the roles they hold", async () => {
    show(
      `/t/acme/console/service-accounts/${EXPORT}`,
      page({ [`GET /console/api/users/${EXPORT}/role-assignments`]: [json(200, { items: [] })] }, [
        ...WORKLOADS,
        "roles:read",
      ]),
    );
    expect(await screen.findByRole("heading", { name: "Nightly export" })).toBeTruthy();
    const owner = await screen.findByRole("link", { name: "Ana Lima" });
    expect(owner.getAttribute("href")).toBe(`/t/acme/console/users/${ANA}`);
    expect(await screen.findByText(en.apiKeyHint("…7c1e"))).toBeTruthy();
    expect(screen.getByText("users:read")).toBeTruthy();
    expect(screen.getByText(en.workloadClients)).toBeTruthy();
    expect(await screen.findByText(en.noHeldRoles)).toBeTruthy();
    expect(screen.queryByText(/hodor_ak_[0-9a-f]{8}/)).toBeNull();
  });

  it("are disabled and deleted only with the name typed in full, and enabled after a dialog", async () => {
    const { sent, go, user } = show(
      `/t/acme/console/service-accounts/${EXPORT}`,
      page({
        [`POST /console/api/service-accounts/${EXPORT}:disable`]: [
          json(200, workloadBody(EXPORT, "Nightly export", { status: "disabled" })),
        ],
        [`POST /console/api/service-accounts/${EXPORT}:enable`]: [json(200, workloadBody(EXPORT, "Nightly export"))],
        [`DELETE /console/api/service-accounts/${EXPORT}`]: [empty(204)],
      }),
    );
    await user.click(await screen.findByRole("button", { name: en.disableWorkload }));
    let dialog = await screen.findByRole("dialog");
    let confirm = within(dialog).getByRole("button", { name: en.disableWorkload });
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    expect(within(dialog).getByText(en.workloadTokensStopped)).toBeTruthy();
    await user.type(within(dialog).getByLabelText(en.typeToConfirm("Nightly export")), "Nightly export");
    await user.click(confirm);
    await user.click(await screen.findByRole("button", { name: en.enableWorkload }));
    dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.level(1), { exact: false })).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: en.enableWorkload }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    await user.click(screen.getByRole("button", { name: en.deleteWorkload }));
    dialog = await screen.findByRole("dialog");
    confirm = within(dialog).getByRole("button", { name: en.deleteWorkload });
    expect(within(dialog).getByText(en.workloadForeverValue)).toBeTruthy();
    await user.type(within(dialog).getByLabelText(en.typeToConfirm("Nightly export")), "Nightly export");
    await user.click(confirm);
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "serviceAccounts" }));
    expect(sent.filter((request) => request.method !== "GET").map((request) => request.method)).toEqual([
      "POST",
      "POST",
      "DELETE",
    ]);
  });

  it("make a key shown once, rotate one shown once, and revoke one only with its name typed in full", async () => {
    const listed = (items: unknown[]) => json(200, { items });
    const { sent, user } = show(
      `/t/acme/console/service-accounts/${EXPORT}`,
      page({
        [`GET /console/api/service-accounts/${EXPORT}/api-keys`]: [
          listed([apiKeyBody(REPORTS_KEY, "Reports")]),
          listed([apiKeyBody(ROTATED_KEY, "Payroll checks"), apiKeyBody(REPORTS_KEY, "Reports")]),
          listed([apiKeyBody(ROTATED_KEY, "Reports"), apiKeyBody(REPORTS_KEY, "Reports", { replaced_by: ROTATED_KEY })]),
          listed([apiKeyBody(ROTATED_KEY, "Reports", { status: "revoked", revoked_at: "2026-11-24T18:03:11Z" })]),
        ],
        [`POST /console/api/service-accounts/${EXPORT}/api-keys`]: [
          problem(422, "authorization.scope_needs_application"),
          json(201, { ...apiKeyBody(ROTATED_KEY, "Payroll checks"), api_key: KEY }),
        ],
        [`POST /console/api/service-accounts/${EXPORT}/api-keys/${REPORTS_KEY}:rotate`]: [
          json(201, { ...apiKeyBody(ROTATED_KEY, "Reports"), api_key: KEY }),
        ],
        [`DELETE /console/api/service-accounts/${EXPORT}/api-keys/${ROTATED_KEY}`]: [empty(204)],
      }),
    );
    await user.click(await screen.findByRole("button", { name: en.createApiKey }));
    let dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.apiKeyShownOnceConsequence)).toBeTruthy();
    await user.type(within(dialog).getByLabelText(en.nameLabel), "Payroll checks");
    await user.type(within(dialog).getByLabelText(en.apiKeyScopesLabel), "authz:evaluate{enter}users:read");
    const make = within(dialog).getByRole("button", { name: en.createApiKey });
    await user.click(make);
    expect(await within(dialog).findByText(en.valueInvalid["authorization.scope_needs_application"] ?? "")).toBeTruthy();
    await user.type(within(dialog).getByLabelText(`${en.apiKeyApplicationLabel} (${en.optional})`), BILLING);
    await user.click(make);
    expect((await screen.findByTestId("shown-once")).textContent).toBe(KEY);
    expect(sent.filter((request) => request.method === "POST").at(-1)?.body).toEqual({
      name: "Payroll checks",
      scopes: ["authz:evaluate", "users:read"],
      application_id: BILLING,
      lifetime_days: 90,
    });
    await user.click(screen.getByRole("button", { name: en.secretKept }));
    await waitFor(() => expect(screen.queryByText(KEY)).toBeNull());

    const reports = await screen.findByRole("row", { name: /Reports/ });
    await user.click(within(reports).getByRole("button", { name: en.rotateApiKey }));
    dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.rotateApiKeyOldValue)).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: en.rotateApiKey }));
    expect((await screen.findByTestId("shown-once")).textContent).toBe(KEY);
    await user.click(screen.getByRole("button", { name: en.secretKept }));
    // The replaced key is not rotated again.
    expect(await screen.findByText(en.keyReplaced)).toBeTruthy();

    const revoke = screen.getAllByRole("button", { name: en.revokeApiKey })[0];
    if (revoke === undefined) {
      throw new Error("no key to revoke");
    }
    await user.click(revoke);
    dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: en.revokeApiKey });
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    await user.type(within(dialog).getByLabelText(en.typeToConfirm("Reports")), "Reports");
    await user.click(confirm);
    expect(await screen.findByText(en.apiKeyStatus["revoked"] ?? "")).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.revokeApiKey })).toBeNull();
  });

  it("offer an auditor nothing to change", async () => {
    show(`/t/acme/console/service-accounts/${EXPORT}`, page({}, ["users:read", "workloads:read"]));
    expect(await screen.findByText(en.apiKeyHint("…7c1e"))).toBeTruthy();
    for (const label of [en.changeSettings, en.disableWorkload, en.deleteWorkload, en.createApiKey, en.rotateApiKey]) {
      expect(screen.queryByRole("button", { name: label })).toBeNull();
    }
  });

  it("are named on the page of a client that acts as one", async () => {
    show(`/t/acme/console/clients/${WEB}`, {
      "GET /console/api/me": [json(200, meBody([...WORKLOADS, "applications:read"]))],
      [`GET /console/api/clients/${WEB}`]: [
        json(200, clientBody({ grant_types: ["client_credentials"], redirect_uris: [], principal: ASSISTANT })),
      ],
      [`GET /console/api/service-accounts/${ASSISTANT}`]: [problem(404, "identity.workload_not_found")],
      [`GET /console/api/agents/${ASSISTANT}`]: [json(200, workloadBody(ASSISTANT, "Assistant", { kind: "agent" }))],
    });
    const agent = await screen.findByRole("link", { name: "Assistant" });
    expect(agent.getAttribute("href")).toBe(`/t/acme/console/agents/${ASSISTANT}`);
  });
});

describe("webhooks", () => {
  const SECRET = "whsec_c2VjcmV0IG9mIHRoZSBlbmRwb2ludCBmb3IgdGhlIHRlc3Q=";
  const CATALOG = ["identity.user_created", "identity.group_created", "session.started", "authentication.succeeded"];
  const page = (script: Parameters<typeof scripted>[0], permissions = WEBHOOKS) => ({
    "GET /console/api/me": [json(200, meBody(permissions))],
    [`GET /console/api/webhook-endpoints/${HOOK}`]: [json(200, endpointBody())],
    [`GET /console/api/webhook-deliveries?limit=50&endpoint_id=${HOOK}`]: [
      json(200, { items: [deliveryBody(), deliveryBody({ id: EVENT, status: "delivered", attempts: 1, last_response_status: 204 })] }),
    ],
    ...script,
  });

  it("are under Audit for whoever may read them, and an auditor may not register one", async () => {
    const { go } = show("/t/acme/console", {
      "GET /console/api/me": [json(200, meBody(["webhooks:read"], ["tenant_auditor"]))],
      "GET /console/api/webhook-endpoints?limit=50": [json(200, { items: [endpointBody()] })],
    });
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "webhooks" }));
    expect(screen.getByRole("link", { name: en.webhooks }).getAttribute("href")).toBe("/t/acme/console/webhooks");
    cleanup();
    show("/t/acme/console/webhooks", {
      "GET /console/api/me": [json(200, meBody(["webhooks:read"], ["tenant_auditor"]))],
      "GET /console/api/webhook-endpoints?limit=50": [json(200, { items: [endpointBody()] })],
    });
    const link = await screen.findByRole("link", { name: "https://hooks.example.com/hodor" });
    expect(link.getAttribute("href")).toBe(`/t/acme/console/webhooks/${HOOK}`);
    expect(screen.getByText(en.eventTypeCount(1))).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.registerEndpoint })).toBeNull();
  });

  it("are registered with event types from the catalog, the secret shown once and never on the endpoint's page", async () => {
    const { sent, go, user } = show("/t/acme/console/webhooks", {
      "GET /console/api/me": [json(200, meBody(WEBHOOKS))],
      "GET /console/api/webhook-endpoints?limit=50": [json(200, { items: [] })],
      "GET /console/api/webhook-event-types": [json(200, { items: CATALOG })],
      "POST /console/api/webhook-endpoints": [
        problem(422, "webhooks.endpoint_address_forbidden"),
        json(201, { endpoint: endpointBody(), secret: SECRET }),
      ],
    });
    expect(await screen.findByText(en.noEndpoints)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: en.registerEndpoint }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.registerEndpointConsequence)).toBeTruthy();
    expect(within(dialog).getByText(en.eventGroups["memberships"] ?? "")).toBeTruthy();
    await user.type(within(dialog).getByLabelText(en.endpointAddressLabel), "https://hooks.example.com/hodor");
    const register = within(dialog).getByRole("button", { name: en.registerEndpoint });
    expect(register.getAttribute("aria-disabled")).toBe("true");
    await user.click(await within(dialog).findByRole("checkbox", { name: "session.started" }));
    await user.click(within(dialog).getByRole("checkbox", { name: "identity.user_created" }));
    await user.click(register);
    expect(await within(dialog).findByText(en.valueInvalid["webhooks.endpoint_address_forbidden"] ?? "")).toBeTruthy();
    await user.click(register);
    expect((await screen.findByTestId("shown-once")).textContent).toBe(SECRET);
    expect(screen.getByText(en.signingSecretLabel)).toBeTruthy();
    // Sent in the order of the catalog.
    expect(sent.filter((request) => request.method === "POST").at(-1)?.body).toEqual({
      url: "https://hooks.example.com/hodor",
      event_types: ["identity.user_created", "session.started"],
    });
    await user.click(screen.getByRole("button", { name: en.secretKept }));
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "webhook", id: HOOK }));
    expect(screen.queryByText(SECRET)).toBeNull();
  });

  it("show the deliveries filtered by status, and deliver a set-aside one again after a dialog", async () => {
    const { sent, user } = show(
      `/t/acme/console/webhooks/${HOOK}`,
      page({
        [`GET /console/api/webhook-deliveries?limit=50&endpoint_id=${HOOK}&status=set_aside`]: [
          json(200, { items: [deliveryBody()] }),
          json(200, { items: [] }),
        ],
        [`POST /console/api/webhook-deliveries/${SET_ASIDE}:redeliver`]: [
          json(200, deliveryBody({ status: "pending", finished_at: null, next_attempt_at: "2026-11-24T16:04:00Z" })),
        ],
      }),
    );
    expect(await screen.findByText(en.signingCurrent, { exact: false })).toBeTruthy();
    expect(await screen.findByText(en.answeredWith(503))).toBeTruthy();
    expect(screen.getByText(en.answeredWith(204))).toBeTruthy();
    await user.click(screen.getByRole("radio", { name: en.deliveryStatus["set_aside"] ?? "" }));
    await waitFor(() => expect(screen.queryByText(en.answeredWith(204))).toBeNull());
    await user.click(screen.getByRole("button", { name: en.redeliver }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.redeliverLead)).toBeTruthy();
    expect(within(dialog).getByText(en.level(1), { exact: false })).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: en.redeliver }));
    expect(await screen.findByText(en.noDeliveries)).toBeTruthy();
    expect(sent.some((request) => request.path.endsWith(":redeliver"))).toBe(true);
  });

  it("change their event types, rotate the secret shown once and are removed, both only with the address typed", async () => {
    const address = "https://hooks.example.com/hodor";
    const { sent, go, user } = show(
      `/t/acme/console/webhooks/${HOOK}`,
      page({
        "GET /console/api/webhook-event-types": [json(200, { items: CATALOG })],
        [`PUT /console/api/webhook-endpoints/${HOOK}/subscriptions`]: [
          json(200, endpointBody({ event_types: ["session.started", "authentication.succeeded"] })),
        ],
        [`POST /console/api/webhook-endpoints/${HOOK}:rotate-secret`]: [
          json(201, {
            endpoint: endpointBody({
              secrets: [
                { created_at: "2026-11-25T14:03:11Z", expires_at: null },
                { created_at: "2026-11-24T14:03:11Z", expires_at: "2026-11-26T14:03:11Z" },
              ],
            }),
            secret: SECRET,
          }),
        ],
        [`DELETE /console/api/webhook-endpoints/${HOOK}`]: [empty(204)],
      }),
    );
    await user.click(await screen.findByRole("button", { name: en.changeSubscriptions }));
    let dialog = await screen.findByRole("dialog");
    const save = within(dialog).getByRole("button", { name: en.saveSubscriptions });
    expect(save.getAttribute("aria-disabled")).toBe("true");
    await user.click(await within(dialog).findByRole("checkbox", { name: "authentication.succeeded" }));
    await user.click(save);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(sent.find((request) => request.method === "PUT")?.body).toEqual({
      event_types: ["session.started", "authentication.succeeded"],
    });

    await user.click(screen.getByRole("button", { name: en.rotateEndpointSecret }));
    dialog = await screen.findByRole("dialog");
    let confirm = within(dialog).getByRole("button", { name: en.rotateEndpointSecret });
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    expect(within(dialog).getByText(en.rotateEndpointPreviousValue)).toBeTruthy();
    await user.type(within(dialog).getByLabelText(en.typeToConfirm(address)), address);
    await user.click(confirm);
    expect((await screen.findByTestId("shown-once")).textContent).toBe(SECRET);
    await user.click(screen.getByRole("button", { name: en.secretKept }));
    expect(await screen.findByText(/Stops signing/)).toBeTruthy();
    expect(screen.queryByText(SECRET)).toBeNull();

    await user.click(screen.getByRole("button", { name: en.removeEndpoint }));
    dialog = await screen.findByRole("dialog");
    confirm = within(dialog).getByRole("button", { name: en.removeEndpoint });
    await user.type(within(dialog).getByLabelText(en.typeToConfirm(address)), address);
    await user.click(confirm);
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "webhooks" }));
    expect(sent.some((request) => request.method === "DELETE")).toBe(true);
  });

  it("offer an auditor nothing to change", async () => {
    show(`/t/acme/console/webhooks/${HOOK}`, page({}, ["webhooks:read"]));
    expect(await screen.findByText(en.answeredWith(503))).toBeTruthy();
    for (const label of [en.changeSubscriptions, en.rotateEndpointSecret, en.removeEndpoint, en.redeliver]) {
      expect(screen.queryByRole("button", { name: label })).toBeNull();
    }
  });
});

describe("trust domains", () => {
  const BUNDLE = { spiffe_sequence: 1, keys: [{ use: "jwt-svid", kty: "EC", crv: "P-256", kid: "jwt-1", x: "x", y: "y" }] };
  const failing = () =>
    trustDomainBody({
      id: STAGING,
      name: "staging.example.com",
      refresh: {
        fetched_at: null,
        next_at: "2026-11-25T15:08:11Z",
        failing_since: "2026-11-25T14:58:11Z",
        last_error: "keys.bundle_endpoint_unreachable",
      },
    });
  const page = (script: Parameters<typeof scripted>[0], permissions = KEYS) => ({
    "GET /console/api/me": [json(200, meBody(permissions))],
    [`GET /console/api/trust-domains/${PROD}`]: [json(200, trustDomainBody())],
    ...script,
  });

  it("are under Security for whoever may read them, a page at a time, and an auditor may not add one", async () => {
    const { go } = show("/t/acme/console", {
      "GET /console/api/me": [json(200, meBody(["keys:read"], ["tenant_auditor"]))],
      "GET /console/api/trust-domains?limit=50": [json(200, { items: [] })],
    });
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "trustDomains" }));
    expect(screen.getByText(en.security)).toBeTruthy();
    expect(screen.getByRole("link", { name: en.trustDomains }).getAttribute("href")).toBe("/t/acme/console/trust-domains");
    cleanup();

    const { user } = show("/t/acme/console/trust-domains", {
      "GET /console/api/me": [json(200, meBody(["keys:read"], ["tenant_auditor"]))],
      "GET /console/api/trust-domains?limit=50": [
        json(200, { items: [trustDomainBody(), meshTrustDomainBody()], next_cursor: "2" }),
      ],
      "GET /console/api/trust-domains?limit=50&cursor=2": [
        json(200, { items: [trustDomainBody({ id: STAGING, name: "partner.example.com", source: "uploaded", bundle_endpoint_url: undefined, refresh: undefined }), failing()] }),
      ],
    });
    const prod = await screen.findByRole("link", { name: "prod.example.com" });
    expect(prod.getAttribute("href")).toBe(`/t/acme/console/trust-domains/${PROD}`);
    expect(screen.getByRole("link", { name: "cluster.local" }).getAttribute("href")).toBe(
      `/t/acme/console/trust-domains/${CLUSTER}`,
    );
    expect(screen.getByText(en.bundleInForce)).toBeTruthy();
    expect(screen.getByText(en.noBundle)).toBeTruthy();
    expect(screen.getByText(en.meshHasNoBundle)).toBeTruthy();
    expect(screen.getByText(en.nothingToFetch)).toBeTruthy();
    expect(screen.getByText(/^Fetched /)).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.addTrustDomain })).toBeNull();
    await user.click(screen.getByRole("button", { name: en.loadMore }));
    expect(await screen.findByText(en.bundleFailing)).toBeTruthy();
    expect(screen.getByText(en.trustDomainSources["uploaded"] ?? "")).toBeTruthy();
    expect(screen.getByText(en.replacedByHand)).toBeTruthy();
    expect(screen.getByText(en.neverFetched)).toBeTruthy();
    expect(screen.getByText(en.bundleFailures["keys.bundle_endpoint_unreachable"] ?? "", { exact: false })).toBeTruthy();
  });

  it("are added with each of the three sources, and every refusal is said in words", async () => {
    const { sent, go, user } = show("/t/acme/console/trust-domains", {
      "GET /console/api/me": [json(200, meBody(KEYS))],
      "GET /console/api/trust-domains?limit=50": [json(200, { items: [] })],
      "POST /console/api/trust-domains": [
        problem(422, "keys.bundle_endpoint_unreachable"),
        problem(409, "keys.trust_domain_name_taken"),
        json(201, trustDomainBody()),
        json(201, trustDomainBody({ id: STAGING, name: "partner.example.com", source: "uploaded" })),
        json(201, meshTrustDomainBody()),
      ],
    });
    expect(await screen.findByText(en.noTrustDomains)).toBeTruthy();
    const posted = () => sent.filter((request) => request.method === "POST");

    // A bundle endpoint, fetched by the server before anything is kept.
    await user.click(screen.getByRole("button", { name: en.addTrustDomain }));
    let dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.level(1), { exact: false })).toBeTruthy();
    expect(within(dialog).getByText(en.addTrustDomainConsequence)).toBeTruthy();
    let add = within(dialog).getByRole("button", { name: en.addTrustDomain });
    expect(add.getAttribute("aria-disabled")).toBe("true");
    await user.type(within(dialog).getByLabelText(en.nameLabel), "prod.example.com");
    await user.type(within(dialog).getByLabelText(en.bundleEndpointLabel), "https://spire.example.com/bundle");
    await user.click(add);
    expect(await within(dialog).findByText(en.valueInvalid["keys.bundle_endpoint_unreachable"] ?? "")).toBeTruthy();
    await user.click(add);
    expect(await within(dialog).findByText(en.trustDomainNameTaken)).toBeTruthy();
    await user.click(add);
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "trustDomain", id: PROD }));
    expect(posted().at(-1)?.body).toEqual({
      name: "prod.example.com",
      source: "bundle_endpoint",
      bundle_endpoint_url: "https://spire.example.com/bundle",
    });

    // A bundle given here, refused before asking when it is not JSON.
    await user.click(screen.getByRole("button", { name: en.addTrustDomain }));
    dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(en.nameLabel), "partner.example.com");
    await user.click(within(dialog).getByRole("radio", { name: en.trustDomainSources["uploaded"] ?? "" }));
    expect(within(dialog).queryByLabelText(en.bundleEndpointLabel)).toBeNull();
    const bundle = within(dialog).getByLabelText(en.bundleLabel);
    await user.click(bundle);
    await user.paste("keys: none");
    add = within(dialog).getByRole("button", { name: en.addTrustDomain });
    await user.click(add);
    expect(await within(dialog).findByText(en.bundleNotJson)).toBeTruthy();
    expect(posted().length).toBe(3);
    await user.clear(bundle);
    await user.click(bundle);
    await user.paste(JSON.stringify(BUNDLE));
    await user.click(add);
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "trustDomain", id: STAGING }));
    expect(posted().at(-1)?.body).toEqual({ name: "partner.example.com", source: "uploaded", bundle: BUNDLE });

    // The mesh, with no bundle.
    await user.click(screen.getByRole("button", { name: en.addTrustDomain }));
    dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(en.nameLabel), "cluster.local");
    await user.click(within(dialog).getByRole("radio", { name: en.trustDomainSources["mesh"] ?? "" }));
    expect(within(dialog).queryByLabelText(en.bundleLabel)).toBeNull();
    await user.click(within(dialog).getByRole("button", { name: en.addTrustDomain }));
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "trustDomain", id: CLUSTER }));
    expect(posted().at(-1)?.body).toEqual({ name: "cluster.local", source: "mesh" });
  });

  it("show the bundle in force summarized, and the refresh with why it fails in words", async () => {
    show(
      `/t/acme/console/trust-domains/${STAGING}`,
      page({
        [`GET /console/api/trust-domains/${STAGING}`]: [
          json(200, { ...failing(), bundle: bundleBody({ spiffe_refresh_hint: undefined }) }),
        ],
      }),
    );
    expect(await screen.findByRole("heading", { name: "staging.example.com" })).toBeTruthy();
    expect(screen.getByText("https://spire.example.com/bundle")).toBeTruthy();
    expect(screen.getByText("12")).toBeTruthy();
    expect(screen.getByText(en.notGiven)).toBeTruthy();
    expect(screen.getByText(en.x509AuthoritiesLabel)).toBeTruthy();
    expect(screen.getAllByText("1").length).toBe(2);
    expect(screen.getByText(en.bundleFailing)).toBeTruthy();
    expect(screen.getByText(en.neverFetched)).toBeTruthy();
    expect(screen.getByText(en.bundleFailures["keys.bundle_endpoint_unreachable"] ?? "")).toBeTruthy();
    // The keys themselves are never shown.
    expect(screen.queryByText(/x-of-the-key|MIIB/)).toBeNull();
    cleanup();

    show(`/t/acme/console/trust-domains/${CLUSTER}`, {
      "GET /console/api/me": [json(200, meBody(KEYS))],
      [`GET /console/api/trust-domains/${CLUSTER}`]: [json(200, meshTrustDomainBody())],
    });
    expect(await screen.findByText(en.meshLead)).toBeTruthy();
    expect(screen.queryByText(en.refreshTitle)).toBeNull();
    expect(screen.queryByText(en.sequenceLabel)).toBeNull();
  });

  it("replace their source with a form, and are removed only with the name typed in full", async () => {
    const { sent, go, user } = show(
      `/t/acme/console/trust-domains/${PROD}`,
      page({
        [`PUT /console/api/trust-domains/${PROD}`]: [
          problem(422, "keys.trust_bundle_invalid"),
          json(200, trustDomainBody({ source: "uploaded", bundle_endpoint_url: undefined, refresh: undefined, bundle: BUNDLE })),
        ],
        [`DELETE /console/api/trust-domains/${PROD}`]: [empty(204)],
      }),
    );
    await user.click(await screen.findByRole("button", { name: en.replaceTrustDomain }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(en.replaceTrustDomainConsequence)).toBeTruthy();
    // The name never changes, so it is not asked for.
    expect(within(dialog).queryByLabelText(en.nameLabel)).toBeNull();
    expect((within(dialog).getByLabelText(en.bundleEndpointLabel) as HTMLInputElement).value).toBe(
      "https://spire.example.com/bundle",
    );
    await user.click(within(dialog).getByRole("radio", { name: en.trustDomainSources["uploaded"] ?? "" }));
    await user.click(within(dialog).getByLabelText(en.bundleLabel));
    await user.paste(JSON.stringify(BUNDLE));
    const save = within(dialog).getByRole("button", { name: en.saveTrustDomain });
    await user.click(save);
    expect(await within(dialog).findByText(en.valueInvalid["keys.trust_bundle_invalid"] ?? "")).toBeTruthy();
    await user.click(save);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    // A bundle given here is not fetched, so the page no longer says how it is refreshed.
    expect(screen.queryByText(en.refreshTitle)).toBeNull();
    expect(screen.getAllByText(en.trustDomainSources["uploaded"] ?? "").length).toBeGreaterThan(0);
    expect(sent.find((request) => request.method === "PUT")?.body).toEqual({ source: "uploaded", bundle: BUNDLE });

    await user.click(screen.getByRole("button", { name: en.removeTrustDomain }));
    const removing = await screen.findByRole("dialog");
    const confirm = within(removing).getByRole("button", { name: en.removeTrustDomain });
    expect(confirm.getAttribute("aria-disabled")).toBe("true");
    expect(within(removing).getByText(en.removeTrustDomainWorkloadsValue)).toBeTruthy();
    await user.type(within(removing).getByLabelText(en.typeToConfirm("prod.example.com")), "prod.example.com");
    await user.click(confirm);
    await waitFor(() => expect(go).toHaveBeenCalledWith({ name: "trustDomains" }));
    expect(sent.at(-1)?.method).toBe("DELETE");
  });

  it("offer an auditor nothing to change", async () => {
    show(`/t/acme/console/trust-domains/${PROD}`, page({}, ["keys:read"]));
    expect(await screen.findByRole("heading", { name: "prod.example.com" })).toBeTruthy();
    for (const label of [en.replaceTrustDomain, en.removeTrustDomain]) {
      expect(screen.queryByRole("button", { name: label })).toBeNull();
    }
  });
});
