import { expect, type Page } from "@playwright/test";
import { PASSWORD, at, en, expectAccessible, mailTo, messageTo, newAddress, newTenant, register, test } from "./support";

// Signing in with a code or a link sent by email (Issue-101). Each test has
// a tenant of its own that offers both, so that no other test's sign-in
// page shows the two buttons.

/** A tenant that offers a code and a link by email, and a person registered in it. */
async function aPersonWhoMayAskByEmail(page: Page): Promise<{ tenant: string; address: string }> {
  const tenant = newTenant(["email-sign-in", "--code", "on", "--link", "on"]);
  const address = newAddress();
  await register(page, address, PASSWORD, tenant);
  return { tenant, address };
}

/** From the first step of the sign-in page, asks for a code or a link to be sent to `address`. */
async function askByEmail(page: Page, tenant: string, address: string, button: string): Promise<void> {
  await page.goto(at("sign-in", tenant));
  await page.getByLabel(en.identifierLabel, { exact: true }).fill(address);
  await page.getByRole("button", { name: button }).click();
}

/** The code in message number `count` to `address`. */
async function codeIn(address: string, count: number): Promise<string> {
  const { text } = await mailTo(address, count);
  const found = /^\s*(\d{6})\s*$/m.exec(text);
  if (found?.[1] === undefined) {
    throw new Error(`message ${count} to ${address} carries no code:\n${text}`);
  }
  return found[1];
}

test("a person signs in with a code sent by email, which works once", async ({ page }) => {
  const { tenant, address } = await aPersonWhoMayAskByEmail(page);

  await askByEmail(page, tenant, address, en.emailMeACode);
  await expect(page.getByText(en.emailCodeSent(address))).toBeVisible();
  const field = page.getByLabel(en.emailCodeLabel);
  await expect(field).toBeFocused();
  await expect(field).toHaveAttribute("autocomplete", "one-time-code");
  await expect(field).toHaveAttribute("inputmode", "numeric");
  await expectAccessible(page);

  // The registration's message is the first; the code is in the second.
  const code = await codeIn(address, 2);
  await field.fill(code);
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  const session = await page.request.get(`/t/${tenant}/interaction/session`);
  expect(((await session.json()) as { methods: string[] }).methods).toEqual(["email_code"]);

  // The same code, typed again in a new sign-in, is a rejection; the new
  // code the new sign-in asked for works.
  await page.context().clearCookies();
  await askByEmail(page, tenant, address, en.emailMeACode);
  await page.getByLabel(en.emailCodeLabel).fill(code);
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
  await expect(page.getByRole("main").getByRole("alert")).toContainText(en.rejected);
  await expectAccessible(page);
  await page.getByLabel(en.emailCodeLabel).fill(await codeIn(address, 3));
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
});

test("a link sent by email signs in only the browser that asked, once", async ({ page, browser }) => {
  const { tenant, address } = await aPersonWhoMayAskByEmail(page);

  await askByEmail(page, tenant, address, en.emailMeALink);
  await expect(page.getByText(en.emailLinkSent(address))).toBeVisible();
  await expectAccessible(page);
  const { link } = await messageTo(address, 2);
  expect(link).toMatch(new RegExp(`^${at("sign-in-link", tenant)}#token=[0-9a-f]{64}$`));

  // Opened in another browser, the link says where it works and signs
  // nothing in.
  const elsewhere = await browser.newContext();
  const other = await elsewhere.newPage();
  await other.goto(link);
  await expect(other.getByText(en.signInLinkElsewhere)).toBeVisible();
  await expectAccessible(other);
  const nobody = await other.request.get(`/t/${tenant}/interaction/session`);
  expect(nobody.status()).toBe(401);
  await elsewhere.close();

  // In the browser that asked, it finishes the sign-in.
  await page.goto(link);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  const session = await page.request.get(`/t/${tenant}/interaction/session`);
  expect(((await session.json()) as { methods: string[] }).methods).toEqual(["email_link"]);

  // A second time, within a new sign-in of the same browser, it is refused.
  await page.context().clearCookies();
  await page.goto(at("sign-in", tenant));
  await expect(page.getByLabel(en.identifierLabel, { exact: true })).toBeVisible();
  await page.goto(link);
  await expect(page.getByText(en.signInLinkRefused)).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("link", { name: en.goToSignIn }).click();
  await expect(page.getByLabel(en.identifierLabel, { exact: true })).toBeVisible();
});
