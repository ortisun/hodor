import { expect } from "@playwright/test";
import { at, en, expectAccessible, test } from "./support";

const DIRECTORY_NAME = "Company directory";
// The one person of the development directory, deploy/dev-directory/people.ldif.
const DORA = { uid: "dora", password: "dora-directory-password" };

test("a person signs in through the directory without leaving the page", async ({ page }) => {
  await page.goto(at("sign-in"));
  await page.getByRole("button", { name: en.continueWith(DIRECTORY_NAME) }).click();

  // The directory's form, here, with focus where the person types.
  const identifier = page.getByLabel(en.directoryIdentifierLabel(DIRECTORY_NAME), { exact: true });
  await expect(identifier).toBeFocused();
  await expect(page).toHaveURL(new RegExp(`${at("sign-in")}$`));
  await expectAccessible(page);

  await identifier.fill(DORA.uid);
  await page.getByLabel(en.passwordLabel, { exact: true }).fill(DORA.password);
  await page.getByRole("button", { name: en.signIn, exact: true }).click();

  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  await page.getByRole("button", { name: en.signOut }).click();
  await expect(page.getByText(en.noticeSignedOut)).toBeVisible();

  // Signing in again is the same person, and works the same way.
  await page.getByRole("button", { name: en.continueWith(DIRECTORY_NAME) }).click();
  await page.getByLabel(en.directoryIdentifierLabel(DIRECTORY_NAME), { exact: true }).fill(DORA.uid);
  await page.getByLabel(en.passwordLabel, { exact: true }).fill(DORA.password);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
});

test("a wrong password at the directory is refused like any other", async ({ page }) => {
  await page.goto(at("sign-in"));
  await page.getByRole("button", { name: en.continueWith(DIRECTORY_NAME) }).click();
  await page.getByLabel(en.directoryIdentifierLabel(DIRECTORY_NAME), { exact: true }).fill(DORA.uid);
  await page.getByLabel(en.passwordLabel, { exact: true }).fill("not her password");
  await page.getByRole("button", { name: en.signIn, exact: true }).click();

  await expect(page.getByRole("alert")).toContainText(en.rejected);
  await expectAccessible(page);
  await expect(page.getByLabel(en.passwordLabel, { exact: true })).toHaveValue("");

  // And the other ways are a click away.
  await page.getByRole("button", { name: en.otherWays }).click();
  await expect(page.getByLabel(en.identifierLabel, { exact: true })).toBeVisible();
});
