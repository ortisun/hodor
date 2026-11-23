import { expect, type Page } from "@playwright/test";
import { createHmac, randomUUID } from "node:crypto";
import {
  at,
  en,
  expectAccessible,
  type Identity,
  newAddress,
  PROVIDER_NAME,
  signInThroughProvider,
  test,
} from "./support";

/** Base32 of RFC 4648, as the key is shown, without the spaces between groups. */
function fromBase32(text: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of text.replace(/\s/g, "")) {
    buffer = (buffer << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

/** What an authenticator application shows for this secret, `steps` steps of thirty seconds from now. */
function phone(secret: Buffer, steps = 0): string {
  const step = Math.floor(Date.now() / 1000 / 30) + steps;
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", secret).update(counter).digest();
  const offset = mac.readUInt8(19) & 0x0f;
  const binary = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, "0");
}

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
  await signInThroughProvider(page, identity);
  await page.getByLabel(en.totpLabel).fill(phone(secret, 1));
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
