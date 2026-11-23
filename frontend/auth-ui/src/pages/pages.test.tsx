import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { pathOf, type PageName } from "../address";
import { en } from "../messages/en";
import { empty, json, problem, scripted } from "../testing";
import { AccountPage } from "./AccountPage";
import { AskPage } from "./AskPage";
import { ComingBackPage } from "./ComingBackPage";
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
/** The alert the page shows, once it shows one. */
const alertShown = () => within(screen.getByRole("main")).findByRole("alert");

function page(script: Parameters<typeof scripted>[0]) {
  const { client, sent } = scripted(script);
  const go = vi.fn();
  const leave = vi.fn();
  const props = { tenant: "acme", client, text: en, go, leave, path: (name: PageName) => pathOf("acme", name) };
  return { props, sent, go, leave, user: userEvent.setup() };
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

  it("asks a person with an authenticator application for its code after the password", async () => {
    const { props, sent, go, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [noSignIn],
      "POST /sign-in": [pending("identifier")],
      "POST /sign-in/steps/identifier": [pending("password")],
      "POST /sign-in/steps/password": [pending("totp")],
      "POST /sign-in/steps/totp": [
        json(200, { status: "rejected", step: "totp", attempts_left: 4, csrf_token: "token" }),
        json(200, { status: "completed" }),
      ],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.type(await screen.findByLabelText(en.identifierLabel), "ana@example.com{Enter}");
    await user.type(await screen.findByLabelText(en.passwordLabel), "correct horse{Enter}");

    const code = await screen.findByLabelText<HTMLInputElement>(en.totpLabel, { exact: false });
    expect(document.activeElement).toBe(code);
    expect(code.getAttribute("autocomplete")).toBe("one-time-code");
    expect(code.getAttribute("inputmode")).toBe("numeric");
    expect(screen.getByText(en.totpHint)).toBeTruthy();
    await user.type(code, "000000{Enter}");

    const alert = await alertShown();
    expect(alert.textContent).toBe(`${en.rejected} ${en.attemptsLeft(4)}`);
    const again = screen.getByLabelText<HTMLInputElement>(en.totpLabel, { exact: false });
    expect(again.value).toBe("");
    await user.type(again, "123 456{Enter}");

    await waitFor(() => expect(go).toHaveBeenCalledWith("account"));
    expect(sent.at(-1)?.body).toEqual({ code: "123 456" });
  });

  it("lets a person who lost their application give a recovery code instead, and go back", async () => {
    const { props, sent, go, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [noSignIn],
      "POST /sign-in": [pending("identifier")],
      "POST /sign-in/steps/identifier": [pending("password")],
      "POST /sign-in/steps/password": [pending("totp")],
      "POST /sign-in/steps/recovery_code": [
        json(200, { status: "rejected", step: "totp", attempts_left: 4, csrf_token: "token" }),
        json(200, { status: "completed" }),
      ],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.type(await screen.findByLabelText(en.identifierLabel), "ana@example.com{Enter}");
    await user.type(await screen.findByLabelText(en.passwordLabel), "correct horse{Enter}");
    await screen.findByLabelText(en.totpLabel, { exact: false });

    await user.click(screen.getByRole("button", { name: en.useRecoveryCode }));
    const field = await screen.findByLabelText<HTMLInputElement>(en.recoveryCodeLabel, { exact: false });
    await waitFor(() => expect(document.activeElement).toBe(field));
    expect(field.getAttribute("inputmode")).toBeNull();
    expect(field.getAttribute("autocapitalize")).toBe("none");
    expect(screen.getByText(en.recoveryCodeHint)).toBeTruthy();
    expect(screen.queryByLabelText(en.totpLabel, { exact: false })).toBeNull();

    // Going back shows the code of the application again.
    await user.click(screen.getByRole("button", { name: en.useAuthenticatorApplication }));
    const back = await screen.findByLabelText<HTMLInputElement>(en.totpLabel, { exact: false });
    await waitFor(() => expect(document.activeElement).toBe(back));
    await user.click(screen.getByRole("button", { name: en.useRecoveryCode }));

    await user.type(
      await screen.findByLabelText(en.recoveryCodeLabel, { exact: false }),
      "aaaa-aaaa-aaaa-aaaa{Enter}",
    );
    const alert = await alertShown();
    expect(alert.textContent).toBe(`${en.rejected} ${en.attemptsLeft(4)}`);
    const again = screen.getByLabelText<HTMLInputElement>(en.recoveryCodeLabel, { exact: false });
    expect(again.value).toBe("");
    await user.type(again, "7k2m qx9d 4hvn r8ta{Enter}");

    await waitFor(() => expect(go).toHaveBeenCalledWith("account"));
    expect(sent.at(-1)?.body).toEqual({ code: "7k2m qx9d 4hvn r8ta" });
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

  it("goes on to the application's request when the sign-in says so", async () => {
    const { props, go, leave, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("password")],
      "POST /sign-in/steps/password": [json(200, { status: "completed", continue: "/t/acme/oauth2/authorize/resume" })],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.type(await screen.findByLabelText(en.passwordLabel), "correct horse{Enter}");
    await waitFor(() => expect(leave).toHaveBeenCalledWith("/t/acme/oauth2/authorize/resume"));
    expect(go).not.toHaveBeenCalled();
  });

  it("signs a person in again when an application asked for it, even when signed in", async () => {
    const { props, go, sent } = page({
      "GET /session": [
        json(200, { user_id: "u", session_id: "s", signed_in_at: "2026-11-20T14:03:11Z", expires_at: "2026-11-20T15:03:11Z" }),
      ],
      "GET /sign-in": [noSignIn],
      "POST /sign-in": [pending("identifier")],
    });
    render(<SignInPage {...props} notice={null} signInAgain />);
    expect(await screen.findByLabelText(en.identifierLabel)).toBeTruthy();
    expect(go).not.toHaveBeenCalled();
    expect(sent.map((request) => `${request.method} ${request.path}`)).not.toContain("GET /session");
  });

  it("starts with the identifier an application suggested", async () => {
    const { props } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("identifier")],
    });
    render(<SignInPage {...props} notice={null} signInAgain loginHint="ana@example.com" />);
    const field = await screen.findByLabelText<HTMLInputElement>(en.identifierLabel);
    expect(field.value).toBe("ana@example.com");
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

    const alert = await alertShown();
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

    const alert = await alertShown();
    expect(alert.textContent).toBe(`${en.tooManyAttempts} ${en.tryAgainInSeconds(45)}`);
    expect(screen.getByLabelText(en.passwordLabel)).toBeTruthy();
  });

  it("asks the security key for the WebAuthn step and sends its answer", async () => {
    const bytes = (...values: number[]) => new Uint8Array(values).buffer;
    const get = vi.fn().mockResolvedValue({
      rawId: bytes(1, 2),
      response: { clientDataJSON: bytes(3), authenticatorData: bytes(4), signature: bytes(5), userHandle: null },
    });
    vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
    Object.defineProperty(navigator, "credentials", { value: { get }, configurable: true });
    const { props, sent, go, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("webauthn")],
      "POST /sign-in/steps/webauthn/options": [
        json(200, { public_key: { challenge: "AQI", rpId: "auth.example", allowCredentials: [] } }),
      ],
      "POST /sign-in/steps/webauthn": [json(200, { status: "completed" })],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.click(await screen.findByRole("button", { name: en.useSecurityKey }));
    await waitFor(() => expect(go).toHaveBeenCalledWith("account"));
    expect(get).toHaveBeenCalledOnce();
    expect(sent.at(-1)?.body).toEqual({
      credential_id: "AQI",
      client_data: "Aw",
      authenticator_data: "BA",
      signature: "BQ",
      user_handle: null,
    });
    vi.unstubAllGlobals();
  });

  it("lets a person who lost their security key give a recovery code, and the choice ends with the step", async () => {
    vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
    const { props, sent, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("webauthn")],
      "POST /sign-in/steps/recovery_code": [pending("totp")],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.click(await screen.findByRole("button", { name: en.useRecoveryCode }));
    const field = await screen.findByLabelText<HTMLInputElement>(en.recoveryCodeLabel, { exact: false });
    await waitFor(() => expect(document.activeElement).toBe(field));
    expect(screen.queryByRole("button", { name: en.useSecurityKey })).toBeNull();

    // Back to the key, and to the code again.
    await user.click(screen.getByRole("button", { name: en.useSecurityKeyInstead }));
    expect(await screen.findByRole("button", { name: en.useSecurityKey })).toBeTruthy();
    await user.click(screen.getByRole("button", { name: en.useRecoveryCode }));

    await user.type(
      await screen.findByLabelText(en.recoveryCodeLabel, { exact: false }),
      "7K2M-QX9D-4HVN-R8TA{Enter}",
    );
    expect(sent.at(-1)?.path).toBe("/sign-in/steps/recovery_code");
    // The next step is asked for as it is, not with a recovery code.
    expect(await screen.findByLabelText(en.totpLabel, { exact: false })).toBeTruthy();
    expect(screen.queryByLabelText(en.recoveryCodeLabel, { exact: false })).toBeNull();
    vi.unstubAllGlobals();
  });

  it("sends nothing and says so when the security key gives no answer", async () => {
    const get = vi.fn().mockRejectedValue(new DOMException("cancelled", "NotAllowedError"));
    vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
    Object.defineProperty(navigator, "credentials", { value: { get }, configurable: true });
    const { props, sent, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("webauthn")],
      "POST /sign-in/steps/webauthn/options": [json(200, { public_key: { challenge: "AQI", rpId: "auth.example" } })],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.click(await screen.findByRole("button", { name: en.useSecurityKey }));
    expect((await alertShown()).textContent).toContain(en.securityKeyNoAnswer);
    expect(sent.some((request) => request.path === "/sign-in/steps/webauthn")).toBe(false);
    vi.unstubAllGlobals();
  });

  it("offers a passkey on the identifier step and signs in with it alone", async () => {
    const bytes = (...values: number[]) => new Uint8Array(values).buffer;
    const get = vi.fn().mockResolvedValue({
      rawId: bytes(1, 2),
      response: { clientDataJSON: bytes(3), authenticatorData: bytes(4), signature: bytes(5), userHandle: bytes(6) },
    });
    vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
    Object.defineProperty(navigator, "credentials", { value: { get }, configurable: true });
    const { props, sent, go, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/steps/passkey/options": [
        json(200, {
          public_key: { challenge: "AQI", rpId: "auth.example", allowCredentials: [], userVerification: "required" },
        }),
      ],
      "POST /sign-in/steps/passkey": [json(200, { status: "completed" })],
    });
    render(<SignInPage {...props} notice={null} />);
    const identifier = await screen.findByLabelText(en.identifierLabel);
    expect(identifier.getAttribute("autocomplete")).toBe("username webauthn");
    await user.click(screen.getByRole("button", { name: en.signInWithPasskey }));
    await waitFor(() => expect(go).toHaveBeenCalledWith("account"));
    expect(get).toHaveBeenCalledOnce();
    expect(get.mock.calls[0]?.[0].publicKey.userVerification).toBe("required");
    expect(sent.at(-1)).toMatchObject({
      path: "/sign-in/steps/passkey",
      body: { credential_id: "AQI", client_data: "Aw", authenticator_data: "BA", signature: "BQ", user_handle: "Bg" },
    });
    vi.unstubAllGlobals();
  });

  it("sends nothing and still asks for the identifier when the passkey gives no answer", async () => {
    const get = vi.fn().mockRejectedValue(new DOMException("cancelled", "NotAllowedError"));
    vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
    Object.defineProperty(navigator, "credentials", { value: { get }, configurable: true });
    const { props, sent, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/steps/passkey/options": [json(200, { public_key: { challenge: "AQI", rpId: "auth.example" } })],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.click(await screen.findByRole("button", { name: en.signInWithPasskey }));
    expect((await alertShown()).textContent).toContain(en.passkeyNoAnswer);
    expect(screen.getByLabelText(en.identifierLabel)).toBeTruthy();
    expect(sent.some((request) => request.path === "/sign-in/steps/passkey")).toBe(false);
    vi.unstubAllGlobals();
  });

  it("offers the passkeys the browser holds in the identifier field, where it can", async () => {
    const bytes = (...values: number[]) => new Uint8Array(values).buffer;
    const get = vi.fn().mockResolvedValue({
      rawId: bytes(1, 2),
      response: { clientDataJSON: bytes(3), authenticatorData: bytes(4), signature: bytes(5), userHandle: bytes(6) },
    });
    const PublicKeyCredential = Object.assign(function PublicKeyCredential() {}, {
      isConditionalMediationAvailable: () => Promise.resolve(true),
    });
    vi.stubGlobal("PublicKeyCredential", PublicKeyCredential);
    Object.defineProperty(navigator, "credentials", { value: { get }, configurable: true });
    const { props, go } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/steps/passkey/options": [json(200, { public_key: { challenge: "AQI", rpId: "auth.example" } })],
      "POST /sign-in/steps/passkey": [json(200, { status: "completed" })],
    });
    render(<SignInPage {...props} notice={null} />);
    await waitFor(() => expect(go).toHaveBeenCalledWith("account"));
    expect(get.mock.calls[0]?.[0].mediation).toBe("conditional");
    expect(get.mock.calls[0]?.[0].signal).toBeInstanceOf(AbortSignal);
    vi.unstubAllGlobals();
  });

  it("abandons offering passkeys once the person types an identifier", async () => {
    let signal: AbortSignal | undefined;
    const get = vi.fn().mockImplementation((asked: { signal?: AbortSignal }) => {
      signal = asked.signal;
      return new Promise((_, reject) =>
        asked.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))),
      );
    });
    const PublicKeyCredential = Object.assign(function PublicKeyCredential() {}, {
      isConditionalMediationAvailable: () => Promise.resolve(true),
    });
    vi.stubGlobal("PublicKeyCredential", PublicKeyCredential);
    Object.defineProperty(navigator, "credentials", { value: { get }, configurable: true });
    const { props, sent, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/steps/passkey/options": [json(200, { public_key: { challenge: "AQI", rpId: "auth.example" } })],
      "POST /sign-in/steps/identifier": [pending("password")],
    });
    render(<SignInPage {...props} notice={null} />);
    await waitFor(() => expect(get).toHaveBeenCalledOnce());
    await user.type(screen.getByLabelText(en.identifierLabel), "ana@example.com{Enter}");
    await screen.findByLabelText(en.passwordLabel);
    expect(signal?.aborted).toBe(true);
    expect(sent.some((request) => request.path === "/sign-in/steps/passkey")).toBe(false);
    vi.unstubAllGlobals();
  });

  it("says so when the browser cannot use security keys", async () => {
    const { props } = page({ "GET /session": [nobody], "GET /sign-in": [pending("webauthn")] });
    render(<SignInPage {...props} notice={null} />);
    expect((await alertShown()).textContent).toContain(en.securityKeyUnavailable);
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
    expect((await alertShown()).textContent).toBe(en.registrationClosed);
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

    // The message next to the field. Astryx also announces it in a hidden
    // live region, at a moment of its own, so that copy is left out.
    expect(
      await screen.findByText(en.passwordTooShort, { ignore: "script, style, [data-astryx-live-region]" }),
    ).toBeTruthy();
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

describe("identity providers on the sign-in page", () => {
  const offered = () => json(200, { providers: [{ alias: "google", display_name: "Google", kind: "openid_connect" }] });

  it("offers the providers of the tenant and leaves for the one chosen", async () => {
    const { props, sent, leave, user } = page({
      "GET /sign-in/providers": [offered],
      "GET /session": [nobody],
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/providers/google": [json(200, { redirect: "https://accounts.example.com/authorize?state=s" })],
    });
    render(<SignInPage {...props} notice={null} />);

    await user.click(await screen.findByRole("button", { name: en.continueWith("Google") }));

    await waitFor(() => expect(leave).toHaveBeenCalledWith("https://accounts.example.com/authorize?state=s"));
    expect(sent.at(-1)).toMatchObject({ method: "POST", path: "/sign-in/providers/google", csrfToken: "token" });
  });

  it("offers none once the sign-in is past its first step, and none when the tenant has none", async () => {
    const past = page({
      "GET /sign-in/providers": [offered],
      "GET /session": [nobody],
      "GET /sign-in": [pending("password")],
    });
    render(<SignInPage {...past.props} notice={null} />);
    await screen.findByLabelText(en.passwordLabel);
    expect(screen.queryByRole("button", { name: en.continueWith("Google") })).toBeNull();
    cleanup();

    const none = page({
      "GET /sign-in/providers": [json(200, { providers: [] })],
      "GET /session": [nobody],
      "GET /sign-in": [pending("identifier")],
    });
    render(<SignInPage {...none.props} notice={null} />);
    await screen.findByLabelText(en.identifierLabel);
    expect(screen.queryByText(en.or)).toBeNull();
  });

  it("says so, and stays, when the provider cannot be used", async () => {
    const { props, leave, user } = page({
      "GET /sign-in/providers": [offered],
      "GET /session": [nobody],
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/providers/google": [problem(503, "federation.provider_unavailable")],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.click(await screen.findByRole("button", { name: en.continueWith("Google") }));

    expect((await alertShown()).textContent).toContain(en.somethingWentWrong);
    expect(leave).not.toHaveBeenCalled();
    expect(screen.getByLabelText(en.identifierLabel)).toBeTruthy();
  });

  it("tells a person who came back refused, as bad news", async () => {
    const { props } = page({ "GET /session": [nobody], "GET /sign-in": [pending("identifier")] });
    render(<SignInPage {...props} notice="provider-refused" />);
    expect((await alertShown()).textContent).toBe(en.noticeProviderRefused);
  });
});

describe("the page a provider sends people back to", () => {
  const answer = { code: "the-code", state: "the-state", error: null, binding: null, receipt: null };
  const saml = { code: null, state: "the-state", error: null, binding: "saml" as const, receipt: "the-receipt" };

  it("presents the state and the receipt of a SAML response, and no code", async () => {
    const { props, sent, go } = page({
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/providers/corp/callback": [json(200, { status: "completed" })],
    });
    render(<ComingBackPage {...props} provider="corp" answer={saml} />);
    await waitFor(() => expect(go).toHaveBeenCalledWith("account"));
    expect(sent.at(-1)).toMatchObject({
      path: "/sign-in/providers/corp/callback",
      body: { state: "the-state", receipt: "the-receipt" },
    });
    expect(sent.at(-1)?.body).not.toHaveProperty("code");
  });

  it("asks the server nothing for a SAML answer without a receipt, and says it did not work", async () => {
    for (const without of [{ ...saml, receipt: null }, { ...saml, state: null }]) {
      const { props, sent: requests, go } = page({});
      render(<ComingBackPage {...props} provider="corp" answer={without} />);
      await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in", "provider-refused"));
      expect(requests).toEqual([]);
      cleanup();
    }
  });

  it("presents what the provider sent and goes on to the account", async () => {
    const { props, sent, go } = page({
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/providers/google/callback": [json(200, { status: "completed" })],
    });
    render(<ComingBackPage {...props} provider="google" answer={answer} />);

    await waitFor(() => expect(go).toHaveBeenCalledWith("account"));
    expect(sent.at(-1)).toMatchObject({
      path: "/sign-in/providers/google/callback",
      body: { code: "the-code", state: "the-state" },
      csrfToken: "token",
    });
  });

  it("goes on to the application's request after a provider, when the sign-in says so", async () => {
    const { props, go, leave } = page({
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/providers/google/callback": [
        json(200, { status: "completed", continue: "/t/acme/oauth2/authorize/resume" }),
      ],
    });
    render(<ComingBackPage {...props} provider="google" answer={answer} />);
    await waitFor(() => expect(leave).toHaveBeenCalledWith("/t/acme/oauth2/authorize/resume"));
    expect(go).not.toHaveBeenCalled();
  });

  it("goes back to sign in, saying it did not work, when the server refuses", async () => {
    const { props, go } = page({
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/providers/google/callback": [
        json(200, { status: "rejected", step: "identifier", attempts_left: 4, csrf_token: "token" }),
      ],
    });
    render(<ComingBackPage {...props} provider="google" answer={answer} />);
    await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in", "provider-refused"));
  });

  it("asks the server nothing when the provider sent no code", async () => {
    for (const sent of [
      { ...answer, code: null, error: "access_denied" },
      { ...answer, state: null },
      { ...answer, error: "server_error" },
    ]) {
      const { props, sent: requests, go } = page({});
      render(<ComingBackPage {...props} provider="google" answer={sent} />);
      await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in", "provider-cancelled"));
      expect(requests).toEqual([]);
      cleanup();
    }
  });

  it("goes back to sign in when this browser has no sign-in to finish", async () => {
    const { props, sent, go } = page({ "GET /sign-in": [noSignIn] });
    render(<ComingBackPage {...props} provider="google" answer={answer} />);
    await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in", "provider-refused"));
    expect(sent.map((request) => request.path)).toEqual(["/sign-in"]);
  });

  it("says so, and offers the way back, when the server cannot be reached", async () => {
    const { props, go } = page({ "GET /sign-in": [unreachable] });
    render(<ComingBackPage {...props} provider="google" answer={answer} />);
    expect((await alertShown()).textContent).toBe(en.unreachable);
    expect(screen.getByRole("link", { name: en.backToSignIn })).toBeTruthy();
    expect(go).not.toHaveBeenCalled();
  });
});

describe("a directory on the sign-in page", () => {
  const offered = () =>
    json(200, {
      providers: [
        { alias: "company", display_name: "Company", kind: "ldap" },
        { alias: "google", display_name: "Google", kind: "openid_connect" },
      ],
    });

  it("asks for a username and a password here, and never leaves", async () => {
    const { props, sent, go, leave, user } = page({
      "GET /sign-in/providers": [offered],
      "GET /session": [nobody],
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/providers/company/password": [json(200, { status: "completed" })],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.click(await screen.findByRole("button", { name: en.continueWith("Company") }));

    const identifier = screen.getByLabelText(en.directoryIdentifierLabel("Company"));
    expect(document.activeElement).toBe(identifier);
    // The other ways are put away while the directory's form is shown.
    expect(screen.queryByRole("button", { name: en.continueWith("Google") })).toBeNull();
    await user.type(identifier, "dora");
    await user.type(screen.getByLabelText(en.passwordLabel), "her password{Enter}");

    await waitFor(() => expect(go).toHaveBeenCalledWith("account"));
    expect(leave).not.toHaveBeenCalled();
    expect(sent.at(-1)).toMatchObject({
      path: "/sign-in/providers/company/password",
      body: { identifier: "dora", password: "her password" },
      csrfToken: "token",
    });
  });

  it("shows a refusal in the same words as for a password, and keeps the form", async () => {
    const { props, user } = page({
      "GET /sign-in/providers": [offered],
      "GET /session": [nobody],
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/providers/company/password": [
        json(200, { status: "rejected", step: "identifier", attempts_left: 4, csrf_token: "token" }),
      ],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.click(await screen.findByRole("button", { name: en.continueWith("Company") }));
    await user.type(screen.getByLabelText(en.directoryIdentifierLabel("Company")), "dora");
    await user.type(screen.getByLabelText(en.passwordLabel), "wrong{Enter}");

    expect((await alertShown()).textContent).toBe(`${en.rejected} ${en.attemptsLeft(4)}`);
    expect(screen.getByLabelText<HTMLInputElement>(en.passwordLabel).value).toBe("");
    expect(screen.getByLabelText(en.directoryIdentifierLabel("Company"))).toBeTruthy();
  });

  it("goes back to the other ways of signing in", async () => {
    const { props, user } = page({
      "GET /sign-in/providers": [offered],
      "GET /session": [nobody],
      "GET /sign-in": [pending("identifier")],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.click(await screen.findByRole("button", { name: en.continueWith("Company") }));
    await user.click(screen.getByRole("button", { name: en.otherWays }));
    expect(screen.getByLabelText(en.identifierLabel)).toBeTruthy();
    expect(screen.getByRole("button", { name: en.continueWith("Google") })).toBeTruthy();
  });
});
