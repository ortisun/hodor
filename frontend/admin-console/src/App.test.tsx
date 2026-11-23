import { LayerProvider } from "@astryxdesign/core/Layer";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { placeOf, type Screen } from "./address";
import { App } from "./App";
import { en } from "./messages/en";
import {
  ANA,
  applicationBody,
  BIA,
  BILLING,
  clientBody,
  GOOGLE,
  json,
  meBody,
  problem,
  providerBody,
  scripted,
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
