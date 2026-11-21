import { LayerProvider } from "@astryxdesign/core/Layer";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { placeOf, type Screen } from "./address";
import { App } from "./App";
import { en } from "./messages/en";
import { ANA, BIA, json, meBody, problem, scripted, userBody } from "./testing";

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
