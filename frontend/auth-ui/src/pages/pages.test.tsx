import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { pathOf, type PageName } from "../address";
import { en } from "../messages/en";
import { empty, json, problem, scripted } from "../testing";
import { AcceptInvitationPage } from "./AcceptInvitationPage";
import { AccountPage } from "./AccountPage";
import { AskPage } from "./AskPage";
import { ComingBackPage } from "./ComingBackPage";
import { ConsentPage } from "./ConsentPage";
import { FinishPage } from "./FinishPage";
import { SecurityPage } from "./SecurityPage";
import { SignInPage } from "./SignInPage";
import { SignOutPage } from "./SignOutPage";

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

  it("sends the identifier once more when the sign-in changed at the same moment", async () => {
    const { props, sent, user } = page({
      "GET /session": [nobody],
      "GET /sign-in": [noSignIn],
      "POST /sign-in": [pending("identifier")],
      "POST /sign-in/steps/identifier": [
        problem(409, "authentication.transaction_modified_concurrently"),
        pending("password"),
      ],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.type(await screen.findByLabelText(en.identifierLabel), "ana@example.com{Enter}");

    expect(await screen.findByLabelText(en.passwordLabel)).toBeTruthy();
    const identifiers = sent.filter((request) => request.path === "/sign-in/steps/identifier");
    expect(identifiers).toHaveLength(2);
    expect(identifiers[1]?.body).toEqual({ identifier: "ana@example.com" });
  });

  it("sends the identifier no more than twice", async () => {
    const changed = () => problem(409, "authentication.transaction_modified_concurrently");
    const { props, sent, user } = page({
      "GET /session": [nobody, nobody],
      "GET /sign-in": [noSignIn, pending("identifier")],
      "POST /sign-in": [pending("identifier")],
      "POST /sign-in/steps/identifier": [changed(), changed()],
    });
    render(<SignInPage {...props} notice={null} />);
    await user.type(await screen.findByLabelText(en.identifierLabel), "ana@example.com{Enter}");

    // Then the page asks where the sign-in stands, as for any answer out of step.
    await waitFor(() =>
      expect(sent.filter((request) => request.method === "GET" && request.path === "/sign-in")).toHaveLength(2),
    );
    expect(sent.filter((request) => request.path === "/sign-in/steps/identifier")).toHaveLength(2);
    expect(await screen.findByLabelText(en.identifierLabel)).toBeTruthy();
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

  it("goes back to the security page after signing in again for a change", async () => {
    const { props, go } = page({
      "GET /sign-in": [noSignIn],
      "POST /sign-in": [pending("identifier")],
      "POST /sign-in/steps/identifier": [pending("password")],
      "POST /sign-in/steps/password": [json(200, { status: "completed" })],
    });
    const user = userEvent.setup();
    render(<SignInPage {...props} notice={null} signInAgain afterSignIn="security" />);
    await user.type(await screen.findByLabelText(en.identifierLabel), "ana@example.com{Enter}");
    await user.type(await screen.findByLabelText(en.passwordLabel), "correct horse{Enter}");
    await waitFor(() => expect(go).toHaveBeenCalledWith("security"));
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
    const { props, sent, go, user } = page({
      "GET /session": [session],
      "GET /consents": [json(200, { consents: [] })],
      "DELETE /session": [empty(204)],
    });
    render(<AccountPage {...props} />);
    await user.click(await screen.findByRole("button", { name: en.signOut }));

    await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in", "signed-out"));
    expect(sent.at(-1)).toMatchObject({ method: "DELETE", path: "/session", csrfToken: "of-the-session" });
  });

  it("lists the applications the person let in and withdraws one", async () => {
    const { props, sent, user } = page({
      "GET /session": [session],
      "GET /consents": [
        json(200, {
          consents: [
            {
              client_id: "c-1",
              application: "Billing",
              scopes: ["openid", "invoices:read"],
              given_at: "2026-11-20T14:03:11Z",
              expires_at: "2027-11-20T14:03:11Z",
            },
          ],
        }),
      ],
      "DELETE /consents/c-1": [empty(204)],
    });
    render(<AccountPage {...props} />);
    await user.click(await screen.findByRole("button", { name: en.withdrawConsent("Billing") }));

    expect(await screen.findByText(en.consentWithdrawn("Billing"))).toBeTruthy();
    expect(screen.getByText(en.givenConsentsNone)).toBeTruthy();
    expect(sent.at(-1)).toMatchObject({ method: "DELETE", path: "/consents/c-1", csrfToken: "of-the-session" });
  });

  it("says when no application was let in", async () => {
    const { props } = page({ "GET /session": [session], "GET /consents": [json(200, { consents: [] })] });
    render(<AccountPage {...props} />);
    expect(await screen.findByText(en.givenConsentsNone)).toBeTruthy();
  });
});

describe("the consent page", () => {
  const session = () =>
    json(200, {
      user_id: "u",
      session_id: "s",
      signed_in_at: "2026-11-20T14:03:11Z",
      expires_at: "2026-11-20T15:03:11Z",
      csrf_token: "of-the-session",
    });
  const question = (offline = false) =>
    json(200, {
      application: "Billing",
      scopes: [
        { scope: "openid", kind: "openid" },
        { scope: "email", kind: "openid" },
        {
          scope: "invoices:read",
          kind: "resource",
          description: "<b>Read your invoices</b>",
          resource_server: "Invoices",
        },
      ],
      offline_access: offline,
      csrf_token: "of-the-session",
    });

  it("names the application and what it asks for, then goes where the answer says", async () => {
    const { props, sent, leave, user } = page({
      "GET /session": [session],
      "GET /consent": [question(true)],
      "POST /consent": [json(200, { continue: "/t/acme/oauth2/authorize/resume" })],
    });
    render(<ConsentPage {...props} />);

    const heading = await screen.findByRole("heading", { name: en.consentTitle("Billing") });
    expect(document.activeElement).toBe(heading);
    expect(screen.getByText(en.consentScopeOpenid)).toBeTruthy();
    expect(screen.getByText(en.consentScopeEmail)).toBeTruthy();
    // The administrator's words are text, never markup.
    expect(screen.getByText(en.consentScopeOfResource("<b>Read your invoices</b>", "Invoices"))).toBeTruthy();
    expect(document.querySelector("main b")).toBeNull();
    expect(screen.getByText(en.consentOffline)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: en.consentAllow }));
    await waitFor(() => expect(leave).toHaveBeenCalledWith("/t/acme/oauth2/authorize/resume"));
    expect(sent.at(-1)).toMatchObject({
      method: "POST",
      path: "/consent",
      body: { decision: "allow" },
      csrfToken: "of-the-session",
    });
  });

  it("sends a refusal and goes back to the application", async () => {
    const { props, sent, leave, user } = page({
      "GET /session": [session],
      "GET /consent": [question()],
      "POST /consent": [json(200, { continue: "/t/acme/oauth2/authorize/resume" })],
    });
    render(<ConsentPage {...props} />);
    expect(screen.queryByText(en.consentOffline)).toBeNull();
    await user.click(await screen.findByRole("button", { name: en.consentDeny }));
    await waitFor(() => expect(leave).toHaveBeenCalledWith("/t/acme/oauth2/authorize/resume"));
    expect(sent.at(-1)?.body).toEqual({ decision: "deny" });
  });

  it("goes nowhere that is not the tenant's own authorization endpoint", async () => {
    const { props, leave, user } = page({
      "GET /session": [session],
      "GET /consent": [question()],
      "POST /consent": [json(200, { continue: "https://evil.example/steal" })],
    });
    render(<ConsentPage {...props} />);
    await user.click(await screen.findByRole("button", { name: en.consentAllow }));
    expect(await alertShown()).toBeTruthy();
    expect(leave).not.toHaveBeenCalled();
  });

  it("says there is nothing to answer when no request waits", async () => {
    const { props } = page({
      "GET /session": [session],
      "GET /consent": [problem(404, "oauth.consent_request_not_found")],
    });
    render(<ConsentPage {...props} />);
    expect(await screen.findByRole("heading", { name: en.consentNothingTitle })).toBeTruthy();
    expect(screen.getByRole("link", { name: en.goToAccount }).getAttribute("href")).toBe("/t/acme/account");
  });

  it("sends a person who is not signed in to sign in", async () => {
    const { props, go } = page({ "GET /session": [nobody] });
    render(<ConsentPage {...props} />);
    await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in"));
  });
});

describe("the sign-out page", () => {
  const session = () =>
    json(200, {
      user_id: "u",
      session_id: "s",
      signed_in_at: "2026-11-20T14:03:11Z",
      expires_at: "2026-11-20T15:03:11Z",
      csrf_token: "of-the-session",
    });
  const finish = "/t/acme/oauth2/logout/finish";

  it("goes on at once when nobody is signed in", async () => {
    const { props, leave } = page({ "GET /session": [nobody] });
    render(<SignOutPage {...props} />);
    await waitFor(() => expect(leave).toHaveBeenCalledWith(finish));
    expect(screen.queryByRole("button", { name: en.signOut })).toBeNull();
  });

  it("asks, signs out and goes on to the finish", async () => {
    const { props, sent, leave, user } = page({ "GET /session": [session], "DELETE /session": [empty(204)] });
    render(<SignOutPage {...props} />);
    expect(await screen.findByText(en.signOutQuestion("acme"))).toBeTruthy();
    expect(leave).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: en.signOut }));
    await waitFor(() => expect(leave).toHaveBeenCalledWith(finish));
    expect(sent.at(-1)).toMatchObject({ method: "DELETE", path: "/session", csrfToken: "of-the-session" });
  });

  it("stays signed in when the person says so, and the application is not told", async () => {
    const { props, sent, go, leave, user } = page({ "GET /session": [session] });
    render(<SignOutPage {...props} />);
    await user.click(await screen.findByRole("button", { name: en.staySignedIn }));
    expect(go).toHaveBeenCalledWith("account");
    expect(leave).not.toHaveBeenCalled();
    expect(sent.some((request) => request.method === "DELETE")).toBe(false);
  });

  it("counts a session that ended in the meantime as signed out", async () => {
    const { props, leave, user } = page({ "GET /session": [session], "DELETE /session": [nobody] });
    render(<SignOutPage {...props} />);
    await user.click(await screen.findByRole("button", { name: en.signOut }));
    await waitFor(() => expect(leave).toHaveBeenCalledWith(finish));
  });

  it("says what went wrong and stays when signing out fails", async () => {
    const { props, leave, user } = page({ "GET /session": [session], "DELETE /session": [unreachable] });
    render(<SignOutPage {...props} />);
    await user.click(await screen.findByRole("button", { name: en.signOut }));
    expect((await alertShown()).textContent).toBe(en.unreachable);
    expect(leave).not.toHaveBeenCalled();
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

  it("goes to the sign-in page, saying nothing against the provider, when a second factor is asked next", async () => {
    const { props, go } = page({
      "GET /sign-in": [pending("identifier")],
      "POST /sign-in/providers/google/callback": [json(200, { status: "pending", step: "totp", csrf_token: "token" })],
    });
    render(<ComingBackPage {...props} provider="google" answer={answer} />);
    await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in"));
    expect(go).not.toHaveBeenCalledWith("sign-in", "provider-refused");
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

describe("the security page", () => {
  const signedIn = () =>
    json(200, {
      user_id: "u",
      session_id: "s",
      signed_in_at: "2026-11-20T14:03:11Z",
      expires_at: "2999-01-01T00:00:00Z",
      csrf_token: "session-token",
    });
  const factors = (overrides: Record<string, unknown> = {}) =>
    json(200, {
      authenticator_application: { in_use: false },
      keys: [],
      recovery_codes: { remaining: 0 },
      second_factor_required: false,
      recent_sign_in_until: "2999-01-01T00:00:00Z",
      ...overrides,
    });
  const blueKey = {
    id: "k1",
    name: "Blue key",
    passkey: false,
    created_at: "2026-11-20T14:05:00Z",
    last_used_at: null,
  };
  const codes = Array.from({ length: 10 }, (_, index) => `7K2M-QX9D-4HVN-R8T${index}`);

  function securityPage(script: Parameters<typeof scripted>[0]) {
    const opened = page(script);
    const reauthenticate = vi.fn();
    render(<SecurityPage {...opened.props} reauthenticate={reauthenticate} />);
    return { ...opened, reauthenticate };
  }

  it("sends a person who is not signed in to sign in", async () => {
    const { go } = securityPage({ "GET /session": [nobody] });
    await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in"));
  });

  it("asks the person to sign in again before any change, and offers none until then", async () => {
    const { reauthenticate, user } = securityPage({
      "GET /session": [signedIn],
      "GET /factors": [factors({ recent_sign_in_until: null, keys: [blueKey], recovery_codes: { remaining: 8 } })],
    });
    expect(await screen.findByText("Blue key")).toBeTruthy();
    expect(screen.getByText(en.recoveryRemaining(8))).toBeTruthy();
    expect(screen.queryByRole("button", { name: en.setUpApplication })).toBeNull();
    expect(screen.queryByRole("button", { name: en.removeKey("Blue key") })).toBeNull();
    expect(screen.queryByRole("button", { name: en.generateCodes })).toBeNull();
    await user.click(screen.getByRole("button", { name: en.signInAgain }));
    expect(reauthenticate).toHaveBeenCalledOnce();
  });

  it("sets up an authenticator application and shows the recovery codes that come with it once", async () => {
    const { sent, user } = securityPage({
      "GET /session": [signedIn],
      "GET /factors": [
        factors(),
        factors(),
        factors({ authenticator_application: { in_use: true }, recovery_codes: { remaining: 10 } }),
      ],
      "POST /factors/authenticator-application": [
        json(201, {
          secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
          uri: "otpauth://totp/acme:ana%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=acme",
        }),
      ],
      "POST /factors/authenticator-application/confirmation": [json(200, { recovery_codes: codes })],
    });
    await user.click(await screen.findByRole("button", { name: en.setUpApplication }));
    expect(await screen.findByRole("img", { name: en.qrLabel })).toBeTruthy();
    expect(screen.getByText("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP")).toBeTruthy();
    await user.type(screen.getByLabelText(en.totpLabel), "123 456{Enter}");
    expect(await screen.findByRole("heading", { name: en.codesTitle })).toBeTruthy();
    for (const one of codes) {
      expect(screen.getByText(one)).toBeTruthy();
    }
    expect(sent.find((request) => request.path === "/factors/authenticator-application/confirmation")).toMatchObject({
      body: { code: "123456" },
      csrfToken: "session-token",
    });
    await user.click(screen.getByRole("button", { name: en.codesKept }));
    expect(await screen.findByText(en.applicationInUse)).toBeTruthy();
    expect(screen.queryByText(codes[0] ?? "")).toBeNull();
  });

  it("says what is wrong with a code and lets the person try again", async () => {
    const { user } = securityPage({
      "GET /session": [signedIn],
      "GET /factors": [factors(), factors()],
      "POST /factors/authenticator-application": [json(201, { secret: "JBSWY3DP", uri: "otpauth://totp/a:b?secret=JBSWY3DP" })],
      "POST /factors/authenticator-application/confirmation": [problem(422, "credential.totp_code_wrong")],
    });
    await user.click(await screen.findByRole("button", { name: en.setUpApplication }));
    await user.type(await screen.findByLabelText(en.totpLabel), "000000{Enter}");
    expect((await alertShown()).textContent).toContain(en.totpCodeWrong);
    expect(screen.getByRole("img", { name: en.qrLabel })).toBeTruthy();
  });

  it("removes a key after the person confirms, and renames one", async () => {
    const renamed = { ...blueKey, name: "Office key" };
    const { sent, user } = securityPage({
      "GET /session": [signedIn],
      "GET /factors": [
        factors({ keys: [blueKey] }),
        factors({ keys: [renamed] }),
        factors({ keys: [] }),
      ],
      "PATCH /factors/keys/k1": [json(200, renamed)],
      "DELETE /factors/keys/k1": [empty(204)],
    });
    await user.click(await screen.findByRole("button", { name: en.renameKey("Blue key") }));
    const name = screen.getByLabelText(en.keyNameLabel);
    await user.clear(name);
    await user.type(name, "Office key{Enter}");
    expect(await screen.findByText("Office key")).toBeTruthy();
    expect(sent.find((request) => request.method === "PATCH")?.body).toEqual({ name: "Office key" });

    await user.click(screen.getByRole("button", { name: en.removeKey("Office key") }));
    expect(screen.getByRole("heading", { name: en.removeTitle("Office key") })).toBeTruthy();
    expect(screen.getByText(en.removeLastLead)).toBeTruthy();
    // Keeping it is offered first.
    await user.click(screen.getByRole("button", { name: en.removeKey("Office key") }));
    expect(await screen.findByText(en.noKeys)).toBeTruthy();
    expect(sent.some((request) => request.method === "DELETE" && request.path === "/factors/keys/k1")).toBe(true);
  });

  it("says the last second factor cannot go when the organization requires one", async () => {
    const { user } = securityPage({
      "GET /session": [signedIn],
      "GET /factors": [
        factors({ keys: [blueKey], second_factor_required: true }),
        factors({ keys: [blueKey], second_factor_required: true }),
      ],
      "DELETE /factors/keys/k1": [problem(422, "authentication.last_second_factor")],
    });
    await user.click(await screen.findByRole("button", { name: en.removeKey("Blue key") }));
    await user.click(screen.getByRole("button", { name: en.removeKey("Blue key") }));
    expect((await alertShown()).textContent).toContain(en.lastSecondFactor);
    expect(screen.getByText("Blue key")).toBeTruthy();
  });

  it("asks the person to sign in again when the server says the sign-in is no longer recent", async () => {
    const { user } = securityPage({
      "GET /session": [signedIn],
      "GET /factors": [factors({ keys: [blueKey] }), factors({ keys: [blueKey], recent_sign_in_until: null })],
      "POST /factors/recovery-codes": [problem(403, "authentication.recent_sign_in_required")],
    });
    await user.click(await screen.findByRole("button", { name: en.generateCodes }));
    expect(screen.getByText(en.generateCodesLead)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: en.generateCodes }));
    expect((await alertShown()).textContent).toContain(en.recentSignInRequired);
    expect(await screen.findByRole("button", { name: en.signInAgain })).toBeTruthy();
  });

  it("adds a passkey with the name given and shows the codes of a first factor", async () => {
    const bytes = (...values: number[]) => new Uint8Array(values).buffer;
    const create = vi.fn().mockResolvedValue({
      rawId: bytes(1),
      response: { clientDataJSON: bytes(3), attestationObject: bytes(4), getTransports: () => ["internal"] },
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    });
    vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
    Object.defineProperty(navigator, "credentials", { value: { create }, configurable: true });
    const { sent, user } = securityPage({
      "GET /session": [signedIn],
      "GET /factors": [factors(), factors({ keys: [{ ...blueKey, name: "Phone", passkey: true }] })],
      "POST /webauthn/registrations": [
        json(201, {
          registration_id: "r1",
          public_key: {
            rp: { id: "auth.example", name: "Hodor" },
            user: { id: "AQI", name: "ana@example.com", displayName: "Ana (acme)" },
            challenge: "BQY",
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            authenticatorSelection: { residentKey: "required", userVerification: "required" },
          },
        }),
      ],
      "POST /webauthn/registrations/r1": [json(201, { id: "k1", name: "Phone", created_at: "2026-11-20T14:05:00Z", recovery_codes: codes })],
    });
    await user.type(await screen.findByLabelText(en.keyNameLabel), "Phone");
    await user.click(screen.getByRole("button", { name: en.addPasskey }));
    expect(await screen.findByRole("heading", { name: en.codesTitle })).toBeTruthy();
    expect(sent.find((request) => request.path === "/webauthn/registrations")?.body).toEqual({ passkey: true });
    expect(sent.find((request) => request.path === "/webauthn/registrations/r1")?.body).toEqual({
      client_data: "Aw",
      attestation_object: "BA",
      transports: ["internal"],
      discoverable: true,
      name: "Phone",
    });
    const asked = create.mock.calls[0]?.[0] as { publicKey: PublicKeyCredentialCreationOptions };
    expect(asked.publicKey.authenticatorSelection?.residentKey).toBe("required");
    expect(asked.publicKey.authenticatorSelection?.userVerification).toBe("required");
    vi.unstubAllGlobals();
  });
});

describe("the page of an invitation", () => {
  const token = "cd34".repeat(16);
  const described = (hasAccount: boolean) =>
    json(200, {
      organization_name: "Initech",
      email: "ana@example.com",
      has_account: hasAccount,
      expires_at: "2026-12-01T12:00:00Z",
    });
  const someone = () =>
    json(200, {
      user_id: "u",
      session_id: "s",
      signed_in_at: "2026-11-20T14:03:11Z",
      expires_at: "2999-01-01T00:00:00Z",
      methods: ["password"],
      assurance: "single_factor",
      csrf_token: "session-token",
    });

  it("creates the account of an address that has none and sends the person to sign in", async () => {
    const { props, sent, go, user } = page({
      "POST /invitations/describe": [described(false)],
      "POST /invitations/accept": [empty(204)],
    });
    render(<AcceptInvitationPage {...props} token={token} />);
    expect(await screen.findByText(en.invitationFor("ana@example.com"))).toBeTruthy();
    expect(screen.getByRole("heading", { name: en.acceptInvitationTitle("Initech") })).toBeTruthy();
    await user.type(screen.getByLabelText(en.newPasswordLabel), "correct horse battery{Enter}");
    await waitFor(() => expect(go).toHaveBeenCalledWith("sign-in", "registered"));
    expect(sent.at(-1)?.body).toEqual({ token, password: "correct horse battery" });
  });

  it("joins as the person signed in with the invited address", async () => {
    const { props, sent, go, user } = page({
      "POST /invitations/describe": [described(true)],
      "GET /session": [someone()],
      "POST /invitations/accept": [empty(204)],
    });
    render(<AcceptInvitationPage {...props} token={token} />);
    await user.click(await screen.findByRole("button", { name: en.join }));
    await waitFor(() => expect(go).toHaveBeenCalledWith("account"));
    expect(sent.at(-1)?.body).toEqual({ token });
  });

  it("asks to sign in first, and says when another account is signed in", async () => {
    const first = page({ "POST /invitations/describe": [described(true)], "GET /session": [nobody()] });
    render(<AcceptInvitationPage {...first.props} token={token} />);
    expect(await screen.findByText(en.invitationSignIn("ana@example.com"))).toBeTruthy();
    cleanup();

    const second = page({
      "POST /invitations/describe": [described(true)],
      "GET /session": [someone()],
      "POST /invitations/accept": [problem(403, "authentication.invitation_for_someone_else")],
    });
    render(<AcceptInvitationPage {...second.props} token={token} />);
    await second.user.click(await screen.findByRole("button", { name: en.join }));
    expect(await screen.findByText(en.invitationOtherAccount("ana@example.com"))).toBeTruthy();
  });

  it("says a link that no longer works cannot be used, whatever the reason", async () => {
    const { props } = page({ "POST /invitations/describe": [problem(404, "identity.invitation_invalid")] });
    render(<AcceptInvitationPage {...props} token={token} />);
    expect(await screen.findByText(en.linkInvalid)).toBeTruthy();
    cleanup();
    render(<AcceptInvitationPage {...props} token={null} />);
    expect(screen.getByText(en.linkInvalid)).toBeTruthy();
  });
});
