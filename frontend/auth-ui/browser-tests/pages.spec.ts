import { expect } from "@playwright/test";
import { ptBR } from "../src/messages/pt-BR";
import {
  PASSWORD,
  at,
  en,
  expectAccessible,
  messageTo,
  newAddress,
  register,
  signIn,
  test,
} from "./support";

test("a person registers, reads the message, signs in and signs out", async ({ page }) => {
  const address = newAddress();

  // From the sign-in page to the page that asks for the address.
  await page.goto(at("sign-in"));
  await expect(page.getByRole("heading", { name: en.signInTitle })).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("link", { name: en.register }).click();
  await expect(page.getByRole("heading", { name: en.registerTitle })).toBeVisible();
  await expectAccessible(page);

  await page.getByLabel(en.emailLabel, { exact: true }).fill(address);
  await page.getByRole("button", { name: en.sendLink }).click();
  await expect(page.getByRole("heading", { name: en.checkMailboxTitle })).toBeFocused();
  await expect(page.getByText(en.checkMailbox(address))).toBeVisible();
  await expectAccessible(page);

  // The message, and the page its link leads to.
  const message = await messageTo(address);
  expect(message.subject).toContain("Confirm your email address");
  await page.goto(message.link);
  await expect(page.getByRole("heading", { name: en.completeRegistrationTitle })).toBeVisible();
  await expectAccessible(page);
  await page.getByLabel(`${en.displayNameLabel} (${en.optional})`, { exact: true }).fill("Ana Example");

  // A password the server refuses is explained next to the field, and the link stays good.
  const password = page.getByLabel(en.newPasswordLabel, { exact: true });
  await password.fill("short");
  await page.getByRole("button", { name: en.createAccount }).click();
  // Next to the field. The design system also announces it, outside the page.
  await expect(page.getByRole("main").getByText(en.passwordTooShort)).toBeVisible();
  await expect(password).toHaveAttribute("aria-invalid", "true");
  await expectAccessible(page);
  await password.fill(PASSWORD);
  await page.getByRole("button", { name: en.createAccount }).click();

  // Sent to sign in, told the account is ready; the address no longer says so.
  await expect(page.getByText(en.noticeRegistered)).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`${at("sign-in")}$`));
  await expectAccessible(page);

  await signIn(page, address, PASSWORD);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`${at("")}$`));
  await expectAccessible(page);

  // Signed in is a fact of the server: it survives a reload, and the sign-in page knows it.
  await page.reload();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  await page.goto(at("sign-in"));
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();

  await page.getByRole("button", { name: en.signOut }).click();
  await expect(page.getByText(en.noticeSignedOut)).toBeVisible();

  // Signed out is a fact of the server too.
  await page.goto(at(""));
  await expect(page).toHaveURL(new RegExp(`${at("sign-in")}$`));
  await expect(page.getByLabel(en.identifierLabel, { exact: true })).toBeVisible();
});

test("the link in a message works once", async ({ page }) => {
  const address = newAddress();
  await register(page, address);

  const message = await messageTo(address);
  await page.goto(message.link);
  await page.getByLabel(en.newPasswordLabel, { exact: true }).fill("another password entirely");
  await page.getByRole("button", { name: en.createAccount }).click();

  await expect(page.getByRole("heading", { name: en.linkInvalidTitle })).toBeVisible();
  await expectAccessible(page);

  // The first password is still the one.
  await signIn(page, address, PASSWORD);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
});

test("a wrong password and an unknown address are refused in the same words", async ({ page }) => {
  const address = newAddress();
  await register(page, address);

  await signIn(page, address, "not the password at all");
  const refusal = page.getByRole("alert");
  await expect(refusal).toContainText(en.rejected);
  await expectAccessible(page);
  const said = await refusal.textContent();
  await expect(page.getByLabel(en.passwordLabel, { exact: true })).toBeFocused();
  await expect(page.getByLabel(en.passwordLabel, { exact: true })).toHaveValue("");

  await page.getByRole("button", { name: en.useAnotherIdentifier }).click();
  await signIn(page, newAddress(), "not the password at all");
  await expect(page.getByRole("alert")).toHaveText(said ?? "");

  // Nobody was signed in by any of it.
  await page.goto(at(""));
  await expect(page).toHaveURL(new RegExp(`${at("sign-in")}$`));
});

test("a person who forgot the password chooses a new one", async ({ page }) => {
  const address = newAddress();
  const renewed = "a brand new password to remember";
  await register(page, address);

  await page.getByRole("link", { name: en.forgotPassword }).click();
  await expect(page.getByRole("heading", { name: en.recoverTitle })).toBeVisible();
  await expectAccessible(page);
  await page.getByLabel(en.emailLabel, { exact: true }).fill(address);
  await page.getByRole("button", { name: en.sendLink }).click();
  await expect(page.getByRole("heading", { name: en.checkMailboxTitle })).toBeVisible();

  // The registration message came first; this is the second one.
  const message = await messageTo(address, 2);
  expect(message.link).toContain(at("reset-password"));
  await page.goto(message.link);
  await expect(page.getByRole("heading", { name: en.resetPasswordTitle })).toBeVisible();
  await expectAccessible(page);
  await page.getByLabel(en.newPasswordLabel, { exact: true }).fill(renewed);
  await page.getByRole("button", { name: en.changePassword }).click();
  await expect(page.getByText(en.noticePasswordChanged)).toBeVisible();

  // The old password no longer opens the door; the new one does.
  await signIn(page, address, PASSWORD);
  await expect(page.getByRole("alert")).toContainText(en.rejected);
  await page.getByLabel(en.passwordLabel, { exact: true }).fill(renewed);
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
});

test("asking to recover says the same for an address nobody has", async ({ page }) => {
  const stranger = newAddress();
  await page.goto(at("recover"));
  await page.getByLabel(en.emailLabel, { exact: true }).fill(stranger);
  await page.getByRole("button", { name: en.sendLink }).click();
  await expect(page.getByRole("heading", { name: en.checkMailboxTitle })).toBeVisible();
  await expect(page.getByText(en.checkMailbox(stranger))).toBeVisible();
});

test("a person signs in and out with the keyboard alone", async ({ page }) => {
  const address = newAddress();
  await register(page, address);
  await page.goto(at("sign-in"));

  // The field to type in has focus as the page opens; what follows is in reading order.
  const identifier = page.getByLabel(en.identifierLabel, { exact: true });
  await expect(identifier).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: en.continue, exact: true })).toBeFocused();
  // Then every way to sign in that the tenant offers, in the order shown.
  const offered = page.getByRole("button", { name: /^Continue with / });
  const ways = await offered.count();
  expect(ways).toBeGreaterThan(0);
  for (let way = 0; way < ways; way += 1) {
    await page.keyboard.press("Tab");
    await expect(offered.nth(way)).toBeFocused();
  }
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: en.forgotPassword })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: en.register })).toBeFocused();
  for (let step = 0; step < ways + 3; step += 1) {
    await page.keyboard.press("Shift+Tab");
  }
  await expect(identifier).toBeFocused();

  await page.keyboard.type(address);
  await page.keyboard.press("Enter");
  const password = page.getByLabel(en.passwordLabel, { exact: true });
  await expect(password).toBeFocused();
  await page.keyboard.type(PASSWORD);

  // The password can be shown and hidden without a pointer.
  await page.keyboard.press("Tab");
  await expect(page.getByLabel(en.showPassword)).toBeFocused();
  await page.keyboard.press("Space");
  await expect(password).toHaveAttribute("type", "text");
  await page.keyboard.press("Space");
  await expect(password).toHaveAttribute("type", "password");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: en.signIn, exact: true })).toBeFocused();
  await page.keyboard.press("Enter");

  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: en.signOut })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByText(en.noticeSignedOut)).toBeVisible();
});

test("a page is sent with the policy that keeps everything else out", async ({ page, misbehavior }) => {
  const response = await page.goto(at("sign-in"));
  const policy = response?.headers()["content-security-policy"] ?? "";
  expect(policy).toContain("default-src 'none'");
  expect(policy).toContain("script-src 'self'");
  expect(policy).toContain("require-trusted-types-for 'script'");
  await expect(page.getByLabel(en.identifierLabel, { exact: true })).toBeVisible();

  // The policy is in force, not only sent: a script written into the page does not run.
  const ran = await page.evaluate(() => {
    const script = document.createElement("script");
    try {
      script.textContent = "window.intruded = true";
    } catch {
      // Refused outright where text may not become script.
    }
    document.body.append(script);
    return "intruded" in window;
  });
  expect(ran).toBe(false);

  // The browser reported the attempt, which is the one thing this test set out to cause.
  expect(misbehavior.join("\n")).toContain("policy violation: require-trusted-types-for");
  misbehavior.length = 0;
});

test.describe("in Portuguese", () => {
  test.use({ locale: "pt-BR" });

  test("the pages and the message speak the language of the browser", async ({ page }) => {
    const address = newAddress();
    await page.goto(at("register"));
    await expect(page.locator("html")).toHaveAttribute("lang", "pt-BR");
    await expect(page.getByRole("heading", { name: ptBR.registerTitle })).toBeVisible();
    await expectAccessible(page);

    await page.getByLabel(ptBR.emailLabel, { exact: true }).fill(address);
    await page.getByRole("button", { name: ptBR.sendLink }).click();
    await expect(page.getByRole("heading", { name: ptBR.checkMailboxTitle })).toBeVisible();

    const message = await messageTo(address);
    expect(message.subject).toContain("Confirme seu endereço de email");
    await page.goto(message.link);
    await expect(page.getByRole("heading", { name: ptBR.completeRegistrationTitle })).toBeVisible();
  });
});
