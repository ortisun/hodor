import { expect, type Page } from "@playwright/test";
import { randomUUID } from "node:crypto";
import {
  at,
  en,
  expectAccessible,
  fromBase32,
  type Identity,
  newAddress,
  phone,
  PROVIDER_NAME,
  signInThroughProvider,
  test,
} from "./support";

/** The authenticator built into a device, in Chromium: it keeps passkeys and verifies the person. */
async function addVirtualPlatformAuthenticator(page: Page): Promise<void> {
  const session = await page.context().newCDPSession(page);
  await session.send("WebAuthn.enable");
  await session.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

/**
 * A new person, signed in a moment ago, on the security page. They are
 * made through the development identity provider rather than by
 * registering: asking to register is limited by the address requests come
 * from, which every test of the run shares.
 */
async function onTheSecurityPage(page: Page): Promise<Identity> {
  const identity = { subject: `subject-${randomUUID()}`, email: newAddress() };
  await signInThroughProvider(page, identity);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  await page.getByRole("link", { name: en.securityLink }).click();
  await expect(page.getByRole("heading", { name: en.securityTitle })).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`${at("security")}$`));
  return identity;
}

/** The codes shown once, after which the person says they kept them. */
async function keptCodes(page: Page): Promise<string[]> {
  await expect(page.getByRole("heading", { name: en.codesTitle })).toBeVisible();
  const codes = await page.getByRole("list", { name: en.codesTitle }).getByRole("listitem").allInnerTexts();
  expect(codes).toHaveLength(10);
  for (const code of codes) {
    expect(code.trim()).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$/);
  }
  await expectAccessible(page);
  await page.getByRole("button", { name: en.codesKept }).click();
  return codes.map((code) => code.trim());
}

test("a person sets up an authenticator application and is asked for its code from then on", async ({ page }) => {
  const identity = await onTheSecurityPage(page);
  await expect(page.getByText(en.applicationNotInUse)).toBeVisible();
  await expect(page.getByText(en.recoveryNone)).toBeVisible();
  await expectAccessible(page);

  await page.getByRole("button", { name: en.setUpApplication }).click();
  await expect(page.getByRole("img", { name: en.qrLabel })).toBeVisible();
  const shown = await page.locator(".auth-code").first().innerText();
  const secret = fromBase32(shown);
  expect(secret.length).toBe(20);
  await expectAccessible(page);
  await page.getByLabel(en.totpLabel).fill(phone(secret));
  await page.getByRole("button", { name: en.confirmApplication }).click();
  await keptCodes(page);
  await expect(page.getByText(en.applicationInUse)).toBeVisible();
  await expect(page.getByText(en.recoveryRemaining(10))).toBeVisible();

  // Signing in again, through the provider, asks for a code of the
  // application after it.
  await page.goto(at(""));
  await page.getByRole("button", { name: en.signOut }).click();
  await expect(page.getByText(en.noticeSignedOut)).toBeVisible();
  await signInThroughProvider(page, identity);
  // The page the provider sends the person back to goes on to the sign-in
  // page, which asks for the code; nothing says the provider did not work.
  await expect(page).toHaveURL(new RegExp(`${at("sign-in")}$`));
  const code = page.getByLabel(en.totpLabel);
  await expect(code).toBeFocused();
  await expect(page.getByText(en.noticeProviderRefused)).toHaveCount(0);
  await code.fill(phone(secret, 1));
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
});

test("a person signs in again for a change, adds a passkey, renames and removes it", async ({ page }) => {
  const identity = await onTheSecurityPage(page);
  await addVirtualPlatformAuthenticator(page);

  // Signing in again is offered to someone signed in already. Through a
  // provider the person comes back to the account page, not to this one.
  await page.goto(`${at("sign-in")}?continue=security`);
  await expect(page.getByRole("button", { name: en.continueWith(PROVIDER_NAME) })).toBeVisible();
  await signInThroughProvider(page, identity);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  await page.goto(at("security"));
  await expect(page.getByRole("heading", { name: en.securityTitle })).toBeVisible();

  await page.getByLabel(en.keyNameLabel, { exact: true }).fill("Laptop");
  await page.getByRole("button", { name: en.addPasskey }).click();
  const first = await keptCodes(page);
  await expect(page.getByText("Laptop", { exact: true })).toBeVisible();
  await expect(page.getByText(new RegExp(`^${en.keyKindPasskey}\\.`))).toBeVisible();

  // New codes replace the old ones, after the person confirms.
  await page.getByRole("button", { name: en.generateCodes }).click();
  await expect(page.getByText(en.generateCodesLead)).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("button", { name: en.generateCodes }).last().click();
  const second = await keptCodes(page);
  expect(second).not.toEqual(first);

  await page.getByRole("button", { name: en.renameKey("Laptop") }).click();
  const name = page.getByLabel(en.keyNameLabel, { exact: true }).first();
  await expect(name).toBeFocused();
  await name.fill("Work laptop");
  await page.getByRole("button", { name: en.save }).click();
  await expect(page.getByText("Work laptop", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: en.removeKey("Work laptop") }).click();
  await expect(page.getByRole("heading", { name: en.removeTitle("Work laptop") })).toBeVisible();
  await expect(page.getByText(en.removeLastLead)).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("button", { name: en.removeKey("Work laptop") }).click();
  await expect(page.getByText(en.noKeys)).toBeVisible();
  // The last factor took the codes with it.
  await expect(page.getByText(en.recoveryNone)).toBeVisible();
});

test("the security page works with the keyboard alone", async ({ page }) => {
  await onTheSecurityPage(page);
  const setUp = page.getByRole("button", { name: en.setUpApplication });
  for (let presses = 0; presses < 12 && !(await setUp.evaluate((element) => element === document.activeElement)); presses += 1) {
    await page.keyboard.press("Tab");
  }
  await expect(setUp).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("img", { name: en.qrLabel })).toBeVisible();
  const secret = fromBase32(await page.locator(".auth-code").first().innerText());
  const code = page.getByLabel(en.totpLabel);
  for (let presses = 0; presses < 12 && !(await code.evaluate((element) => element === document.activeElement)); presses += 1) {
    await page.keyboard.press("Tab");
  }
  await expect(code).toBeFocused();
  await page.keyboard.type(phone(secret));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: en.codesTitle })).toBeVisible();
});
