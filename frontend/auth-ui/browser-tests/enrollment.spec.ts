import { expect, type Page } from "@playwright/test";
import {
  PASSWORD,
  at,
  en,
  expectAccessible,
  fromBase32,
  newAddress,
  newTenant,
  phone,
  register,
  signIn,
  test,
} from "./support";

// Setting up a second factor while signing in (Issue-103). Each test has a
// tenant of its own that requires a second factor, which every other test's
// person would otherwise be asked for.

/** A tenant that requires a second factor, and a person registered in it who has none. */
async function aPersonWithNoFactor(page: Page): Promise<{ tenant: string; address: string }> {
  const tenant = newTenant(["second-factor", "--policy", "required"]);
  const address = newAddress();
  await register(page, address, PASSWORD, tenant);
  return { tenant, address };
}

/** The codes shown once, after which the person says they kept them. */
async function keptCodes(page: Page): Promise<string[]> {
  await expect(page.getByRole("heading", { name: en.codesTitle })).toBeVisible();
  const codes = await page.getByRole("list", { name: en.codesTitle }).getByRole("listitem").allInnerTexts();
  expect(codes).toHaveLength(10);
  await expectAccessible(page);
  await page.getByRole("button", { name: en.codesKept }).click();
  return codes.map((code) => code.trim());
}

async function sessionOf(page: Page, tenant: string): Promise<{ status: number; methods?: string[]; assurance?: string }> {
  const answer = await page.request.get(`/t/${tenant}/interaction/session`);
  if (answer.status() !== 200) {
    return { status: answer.status() };
  }
  return { status: 200, ...((await answer.json()) as { methods: string[]; assurance: string }) };
}

test("under the policy, a person with no factor sets up an authenticator application from its QR code while signing in", async ({
  page,
}) => {
  const { tenant, address } = await aPersonWithNoFactor(page);

  await signIn(page, address, PASSWORD, tenant);
  await expect(page.getByText(en.enrollLead)).toBeVisible();
  await expectAccessible(page);
  // The password alone signed nobody in.
  expect((await sessionOf(page, tenant)).status).toBe(401);

  await page.getByRole("button", { name: en.setUpApplication }).click();
  await expect(page.getByRole("img", { name: en.qrLabel })).toBeVisible();
  const secret = fromBase32(await page.locator(".auth-code").first().innerText());
  expect(secret.length).toBe(20);
  const field = page.getByLabel(en.totpLabel);
  await expect(field).toBeFocused();
  await expectAccessible(page);

  // A mistyped code is a rejection, and the same secret is still being set up.
  await field.fill("000000");
  await page.getByRole("button", { name: en.confirmAndSignIn }).click();
  await expect(page.getByRole("main").getByRole("alert")).toContainText(en.rejected);
  expect(fromBase32(await page.locator(".auth-code").first().innerText())).toEqual(secret);

  await page.getByLabel(en.totpLabel).fill(phone(secret));
  await page.getByRole("button", { name: en.confirmAndSignIn }).click();
  await keptCodes(page);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  const session = await sessionOf(page, tenant);
  expect(session.methods).toEqual(["password", "enrollment"]);
  expect(session.assurance).toBe("multi_factor");

  // From then on, the code of the application is asked for.
  await page.context().clearCookies();
  await signIn(page, address, PASSWORD, tenant);
  await expect(page.getByLabel(en.totpLabel)).toBeFocused();
  await page.getByLabel(en.totpLabel).fill(phone(secret, 1));
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`${at("", tenant)}$`));
});

/** A security key in Chromium, which answers without anyone touching it. */
async function addVirtualKey(page: Page): Promise<void> {
  const session = await page.context().newCDPSession(page);
  await session.send("WebAuthn.enable");
  await session.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "usb",
      hasResidentKey: true,
      hasUserVerification: false,
      automaticPresenceSimulation: true,
    },
  });
}

test("under the policy, a person with no factor adds a security key while signing in", async ({ page }) => {
  await addVirtualKey(page);
  const { tenant, address } = await aPersonWithNoFactor(page);

  await signIn(page, address, PASSWORD, tenant);
  await expect(page.getByText(en.enrollKeysLead)).toBeVisible();
  await page.getByLabel(en.keyNameLabel).fill("Desk key");
  await page.getByRole("button", { name: en.addSecurityKey }).click();
  await keptCodes(page);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  expect((await sessionOf(page, tenant)).methods).toEqual(["password", "enrollment"]);

  // The next sign-in asks for the key.
  await page.context().clearCookies();
  await signIn(page, address, PASSWORD, tenant);
  await expect(page.getByText(en.securityKeyLead)).toBeVisible();
  await page.getByRole("button", { name: en.useSecurityKey }).click();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  expect((await sessionOf(page, tenant)).methods).toEqual(["password", "webauthn"]);
});
