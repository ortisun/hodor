import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { pathOf, type PageName } from "../address";
import { en } from "../messages/en";
import { empty, json, problem, scripted } from "../testing";
import { AccountPage } from "./AccountPage";
import { AskPage } from "./AskPage";
import { FinishPage } from "./FinishPage";
import { SignInPage } from "./SignInPage";

afterEach(cleanup);

const nobody = () => problem(401, "session.not_authenticated");
const noSignIn = () => problem(404, "authentication.transaction_not_found");
const unreachable = (): Response => {
  throw new TypeError("network");
};
const pending = (step: string) => json(200, { status: "pending", step, csrf_token: "token" });

/**
 * The alerts the page shows. The design system also keeps one region for
 * announcements outside the page, which is not something shown.
 */
const shown = () => within(screen.getByRole("main")).getAllByRole("alert");

function page(script: Parameters<typeof scripted>[0]) {
  const { client, sent } = scripted(script);
  const go = vi.fn();
  const props = { tenant: "acme", client, text: en, go, path: (name: PageName) => pathOf("acme", name) };
  return { props, sent, go, user: userEvent.setup() };
}

describe("the sign-in page", () => {
  it("starts a sign-in and walks the steps the server names", async () => {
    const { props, sent, go, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [noSignIn],
      "POST /sign-in": [pending("identifier")],
      "POST /sign-in/steps/identifier": [pending("password")],
      "POST /sign-in/steps/password": [json(200, { status: "completed" })],
    });
    render(<SignInPage {...props} notice={null} />);

    const identifier = await screen.findByLabelText(en.identifierLabel);
    expect(document.activeElement).toBe(identifier);
    await user.type(identifier, "ana@example.com{Enter}");

    const password = await screen.findByLabelText(en.passwordLabel);
    expect(document.activeElement).toBe(password);
    expect(screen.getByText(en.signingInAs("ana@example.com"))).toBeTruthy();
    await user.type(password, "correct horse{Enter}");

    await waitFor(() => expect(go).toHaveBeenCalledWith("account"));
    expect(sent.at(-1)?.body).toEqual({ password: "correct horse" });
  });

  it("continues a sign-in that is already in progress", async () => {
    const { props } = page({ "GET /session": [nobody], "GET /sign-in": [pending("password")] });
    render(<SignInPage {...props} notice={null} />);
    expect(await screen.findByLabelText(en.passwordLabel)).toBeTruthy();
  });

  it("sends a person who is already signed in to the account page", async () => {
    const { props, go } = page({
      "GET /session": [
        json(200, { user_id: "u", session_id: "s", signed_in_at: "2026-11-20T14:03:11Z", expires_at: "2026-11-20T15:03:11Z" }),
      ],
    });
    render(<SignInPage {...props} notice={null} />);
    await waitFor(() => expect(go).toHaveBeenCalledWith("account"));
  });

  it("shows a rejection with one message and an empty password field", async () => {
    const { props, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("password")],
      "POST /sign-in/steps/password": [
        json(200, { status: "rejected", step: "password", attempts_left: 4, csrf_token: "token" }),
      ],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.type(await screen.findByLabelText(en.passwordLabel), "a wrong guess{Enter}");

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe(`${en.rejected} ${en.attemptsLeft(4)}`);
    const again = screen.getByLabelText<HTMLInputElement>(en.passwordLabel);
    expect(again.value).toBe("");
    expect(document.activeElement).toBe(again);
  });

  it("starts again, and says so, when the sign-in expired while the person typed", async () => {
    const { props, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("password")],
      "POST /sign-in/steps/password": [noSignIn],
      "POST /sign-in": [pending("identifier")],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.type(await screen.findByLabelText(en.passwordLabel), "a password{Enter}");

    expect(await screen.findByText(en.signInExpired)).toBeTruthy();
    expect(screen.getByLabelText(en.identifierLabel)).toBeTruthy();
  });

  it("keeps the form and says how long to wait when attempts are limited", async () => {
    const { props, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("password")],
      "POST /sign-in/steps/password": [problem(429, "authentication.too_many_attempts", { "Retry-After": "45" })],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.type(await screen.findByLabelText(en.passwordLabel), "a password{Enter}");

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe(`${en.tooManyAttempts} ${en.tryAgainInSeconds(45)}`);
    expect(screen.getByLabelText(en.passwordLabel)).toBeTruthy();
  });

  it("does not guess at a step it does not know", async () => {
    const { props } = page({ "GET /session": [nobody], "GET /sign-in": [pending("fingerprint")] });
    render(<SignInPage {...props} notice={null} />);
    expect(await screen.findByText(en.unknownStep)).toBeTruthy();
    expect(screen.queryByRole("textbox")).toBeNull();
  });

  it("offers to start again when a sign-in has failed", async () => {
    const { props, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("password")],
      "POST /sign-in/steps/password": [json(200, { status: "failed" })],
      "DELETE /sign-in": [noSignIn],
      "POST /sign-in": [pending("identifier")],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.type(await screen.findByLabelText(en.passwordLabel), "a password{Enter}");
    await user.click(await screen.findByRole("button", { name: en.startAgain }));
    expect(await screen.findByLabelText(en.identifierLabel)).toBeTruthy();
  });

  it("tells the person what the page before had to say", async () => {
    const { props } = page({ "GET /session": [nobody], "GET /sign-in": [pending("identifier")] });
    render(<SignInPage {...props} notice="registered" />);
    expect(await screen.findByText(en.noticeRegistered)).toBeTruthy();
  });
});

describe("the page that asks for a link", () => {
  it("answers the same thing whatever the address, in the language of the page", async () => {
    const { props, sent, user } = page({ "POST /registration": [json(202, { status: "accepted" })] });
    render(<AskPage {...props} purpose="registration" />);
    await user.type(screen.getByLabelText(en.emailLabel), " ana@example.com {Enter}");

    expect(document.activeElement).toBe(await screen.findByRole("heading", { name: en.checkMailboxTitle }));
    expect(screen.getByText(en.checkMailbox("ana@example.com"))).toBeTruthy();
    expect(sent[0]?.body).toEqual({ email: "ana@example.com", locale: "en" });
  });

  it("says so when the tenant does not accept registrations", async () => {
    const { props, user } = page({
      "POST /registration": [problem(403, "authentication.registration_closed")],
    });
    render(<AskPage {...props} purpose="registration" />);
    await user.type(screen.getByLabelText(en.emailLabel), "ana@example.com{Enter}");
    expect((await screen.findByRole("alert")).textContent).toBe(en.registrationClosed);
  });

  it("asks for recovery on the recovery route", async () => {
    const { props, sent, user } = page({ "POST /recovery": [json(202, { status: "accepted" })] });
    render(<AskPage {...props} purpose="recovery" />);
    await user.type(screen.getByLabelText(en.emailLabel), "ana@example.com{Enter}");
    await screen.findByRole("heading", { name: en.checkMailboxTitle });
    expect(sent[0]?.path).toBe("/recovery");
  });

  it("sends nothing for an empty address", async () => {
    const { props, sent, user } = page({});
    render(<AskPage {...props} purpose="recovery" />);
    await user.click(screen.getByRole("button", { name: en.sendLink }));
    expect(sent).toEqual([]);
  });
});

describe("the page that finishes", () => {
  const token = "ab12".repeat(16);

  it("finishes a registration with the token of the link and sends the person to sign in", async () => {
    const { props, sent, go, user } = page({ "POST /registration/complete": [empty(204)] });
    render(<FinishPage {...props} purpose="registration" token={token} />);
    await user.type(screen.getByLabelText(`${en.displayNameLabel} (${en.optional})`), "Ana");
    await user.type(screen.getByLabelText(en.newPasswordLabel), "correct horse battery{Enter}");

    await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in", "registered"));
    expect(sent[0]?.body).toEqual({ token, password: "correct horse battery", display_name: "Ana" });
  });

  it("says what is wrong with the password, next to the field, and keeps the link good", async () => {
    const { props, go, user } = page({
      "POST /recovery/complete": [problem(422, "credential.password_too_short"), empty(204)],
    });
    render(<FinishPage {...props} purpose="recovery" token={token} />);
    const password = screen.getByLabelText<HTMLInputElement>(en.newPasswordLabel);
    await user.type(password, "short{Enter}");

    expect(await screen.findByText(en.passwordTooShort)).toBeTruthy();
    expect(password.getAttribute("aria-invalid")).toBe("true");
    const described = (password.getAttribute("aria-describedby") ?? "").split(" ");
    expect(described.map((id) => document.getElementById(id)?.textContent).join(" ")).toContain(en.passwordTooShort);

    await user.type(password, " but longer now{Enter}");
    await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in", "password-changed"));
  });

  it("says the link cannot be used when the server refuses the token", async () => {
    const { props, user } = page({
      "POST /recovery/complete": [problem(404, "authentication.verification_token_invalid")],
    });
    render(<FinishPage {...props} purpose="recovery" token={token} />);
    await user.type(screen.getByLabelText(en.newPasswordLabel), "correct horse battery{Enter}");

    expect(await screen.findByRole("heading", { name: en.linkInvalidTitle })).toBeTruthy();
    expect(screen.getByRole("link", { name: en.askForNewRecoveryLink }).getAttribute("href")).toBe(
      "/t/acme/account/recover",
    );
  });

  it("asks for nothing when the address carries no token", () => {
    const { props, sent } = page({});
    render(<FinishPage {...props} purpose="registration" token={null} />);
    expect(screen.getByRole("heading", { name: en.linkInvalidTitle })).toBeTruthy();
    expect(screen.queryByLabelText(en.newPasswordLabel)).toBeNull();
    expect(sent).toEqual([]);
  });

  it("lets the person read the password they are choosing", async () => {
    const { props, user } = page({});
    render(<FinishPage {...props} purpose="recovery" token={token} />);
    const password = screen.getByLabelText<HTMLInputElement>(en.newPasswordLabel);
    expect(password.type).toBe("password");
    await user.click(screen.getByLabelText(en.showPassword));
    expect(password.type).toBe("text");
  });
});

describe("the account page", () => {
  const session = () =>
    json(200, {
      user_id: "u",
      session_id: "s",
      signed_in_at: "2026-11-20T14:03:11Z",
      expires_at: "2026-11-20T15:03:11Z",
      csrf_token: "of-the-session",
    });

  it("sends a person who is not signed in to sign in", async () => {
    const { props, go } = page({ "GET /session": [nobody] });
    render(<AccountPage {...props} />);
    await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in"));
  });

  it("signs out and says so on the sign-in page", async () => {
    const { props, sent, go, user } = page({ "GET /session": [session], "DELETE /session": [empty(204)] });
    render(<AccountPage {...props} />);
    await user.click(await screen.findByRole("button", { name: en.signOut }));

    await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in", "signed-out"));
    expect(sent.at(-1)).toMatchObject({ method: "DELETE", path: "/session", csrfToken: "of-the-session" });
  });
});

describe("the sign-in page when the server cannot be reached", () => {
  it("says so once, and offers to try again", async () => {
    const { props, user } = page({
      "GET /session": [unreachable, nobody],
      "DELETE /sign-in": [unreachable, noSignIn],
      "POST /sign-in": [pending("identifier")],
    });
    render(<SignInPage {...props} notice="registered" />);

    const again = await screen.findByRole("button", { name: en.startAgain });
    expect(shown().map((alert) => alert.textContent)).toEqual([en.unreachable]);
    // What the page before had to say is not shown over a failure.
    expect(screen.queryByText(en.noticeRegistered)).toBeNull();

    await user.click(again);
    expect(shown()).toHaveLength(1);

    await user.click(screen.getByRole("button", { name: en.startAgain }));
    expect(await screen.findByLabelText(en.identifierLabel)).toBeTruthy();
  });
});
