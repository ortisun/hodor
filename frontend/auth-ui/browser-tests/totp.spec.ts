import { expect } from "@playwright/test";
import {
  PASSWORD,
  TENANT,
  at,
  en,
  expectAccessible,
  fromBase32,
  newAddress,
  operator,
  phone,
  register,
  signIn,
  test,
} from "./support";

test("a person with an authenticator application gives a code after the password", async ({ page }) => {
  const address = newAddress();
  await register(page, address);

  // The operator enrolls the application, which the person's phone confirms.
  const printed = operator("totp", "enroll", "--tenant", TENANT, "--login", address);
  const secret = fromBase32(/^secret (\S+)$/m.exec(printed)?.[1] ?? "");
  expect(secret.length).toBe(20);
  const confirmed = operator("totp", "confirm", "--tenant", TENANT, "--login", address, "--code", phone(secret));
  expect(confirmed.split("\n")[0]).toBe("confirmed");

  await signIn(page, address, PASSWORD);
  const code = page.getByLabel(en.totpLabel);
  await expect(code).toBeFocused();
  await expect(code).toHaveAttribute("autocomplete", "one-time-code");
  await expect(code).toHaveAttribute("inputmode", "numeric");
  await expectAccessible(page);

  // A wrong code is a rejection like a wrong password.
  await code.fill("000000");
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
  await expect(page.getByRole("main").getByRole("alert")).toContainText(en.rejected);
  await expectAccessible(page);

  // The code that confirmed the application is used; the next one is not.
  await page.getByLabel(en.totpLabel).fill(phone(secret, 1));
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`${at("")}$`));
});

test("the code form works with the keyboard alone", async ({ page }) => {
  const address = newAddress();
  await register(page, address);
  const printed = operator("totp", "enroll", "--tenant", TENANT, "--login", address);
  const secret = fromBase32(/^secret (\S+)$/m.exec(printed)?.[1] ?? "");
  operator("totp", "confirm", "--tenant", TENANT, "--login", address, "--code", phone(secret));

  await page.goto(at("sign-in"));
  await expect(page.getByLabel(en.identifierLabel, { exact: true })).toBeFocused();
  await page.keyboard.type(address);
  await page.keyboard.press("Enter");
  await expect(page.getByLabel(en.passwordLabel, { exact: true })).toBeFocused();
  await page.keyboard.type(PASSWORD);
  await page.keyboard.press("Enter");
  await expect(page.getByLabel(en.totpLabel)).toBeFocused();
  await page.keyboard.type(phone(secret, 1));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
});

/** Enrolls an application for a new person and answers its secret and the recovery codes printed with it. */
async function enrolledWithCodes(page: Parameters<typeof register>[0]): Promise<{ address: string; secret: Buffer; codes: string[] }> {
  const address = newAddress();
  await register(page, address);
  const printed = operator("totp", "enroll", "--tenant", TENANT, "--login", address);
  const secret = fromBase32(/^secret (\S+)$/m.exec(printed)?.[1] ?? "");
  const confirmed = operator("totp", "confirm", "--tenant", TENANT, "--login", address, "--code", phone(secret));
  const codes = confirmed.split("\n").filter((line) => /^[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$/.test(line));
  expect(codes).toHaveLength(10);
  return { address, secret, codes };
}

test("a person who lost their application signs in with a recovery code, once", async ({ page }) => {
  const { address, codes } = await enrolledWithCodes(page);
  const [written] = codes;

  await signIn(page, address, PASSWORD);
  await expect(page.getByLabel(en.totpLabel)).toBeFocused();
  await page.getByRole("button", { name: en.useRecoveryCode }).click();
  const field = page.getByLabel(en.recoveryCodeLabel);
  await expect(field).toBeFocused();
  await expect(field).not.toHaveAttribute("inputmode", "numeric");
  await expect(field).toHaveAttribute("autocapitalize", "none");
  await expectAccessible(page);

  // A code that is not one of the person's is a rejection, shown on the same form.
  await field.fill("AAAA-AAAA-AAAA-AAAA");
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
  await expect(page.getByRole("main").getByRole("alert")).toContainText(en.rejected);
  await expect(page.getByLabel(en.recoveryCodeLabel)).toBeVisible();
  await expectAccessible(page);

  // Typed in lowercase with spaces, as someone copying it from paper might.
  await page.getByLabel(en.recoveryCodeLabel).fill((written ?? "").toLowerCase().replaceAll("-", " "));
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();

  // The same code does not let anyone in a second time.
  await page.context().clearCookies();
  await signIn(page, address, PASSWORD);
  await page.getByRole("button", { name: en.useRecoveryCode }).click();
  await page.getByLabel(en.recoveryCodeLabel).fill(written ?? "");
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
  await expect(page.getByRole("main").getByRole("alert")).toContainText(en.rejected);
  expect(operator("recovery-codes", "count", "--tenant", TENANT, "--login", address)).toBe("unused 9");
});

test("the recovery code form works with the keyboard alone, and leads back to the application", async ({ page }) => {
  const { address, secret, codes } = await enrolledWithCodes(page);

  await signIn(page, address, PASSWORD);
  await expect(page.getByLabel(en.totpLabel)).toBeFocused();
  const toRecovery = page.getByRole("button", { name: en.useRecoveryCode });
  await toRecovery.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByLabel(en.recoveryCodeLabel)).toBeFocused();

  const back = page.getByRole("button", { name: en.useAuthenticatorApplication });
  await back.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByLabel(en.totpLabel)).toBeFocused();
  await page.keyboard.type(phone(secret, 1));
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  expect(codes).toHaveLength(10);
});
