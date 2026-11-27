import { expect } from "@playwright/test";
import { PASSWORD, en, expectAccessible, newAddress, newTenant, register, signIn, test } from "./support";

test("a person gives their details on the profile page and they are kept", async ({ page }) => {
  // A tenant of its own: the shared tenant counts the run's sign-ins from one address, and the
  // tests of passkeys come last.
  const tenant = newTenant();
  const address = newAddress();
  await register(page, address, PASSWORD, tenant);
  await signIn(page, address, PASSWORD, tenant);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();

  await page.getByRole("link", { name: en.profileLink }).click();
  await expect(page.getByRole("heading", { name: en.profileTitle })).toBeVisible();
  await expectAccessible(page);
  await page.getByLabel(en.claimLabel("given_name"), { exact: true }).fill("Ana");
  await page.getByLabel(en.claimLabel("phone_number"), { exact: true }).fill("+55 11 91234 5678");
  await page.getByLabel(en.claimLabel("address.locality"), { exact: true }).fill("São Paulo");
  await page.getByRole("button", { name: en.profileSave }).click();
  await expect(page.getByText(en.profileSaved)).toBeVisible();
  // Kept as E.164, and nobody vouched for it.
  await expect(page.getByLabel(en.claimLabel("phone_number"), { exact: true })).toHaveValue("+5511912345678");
  await expect(page.getByText(en.phoneNotVerified)).toBeVisible();

  // A date the server cannot keep is refused next to its field.
  const birthdate = page.getByLabel(en.claimLabel("birthdate"), { exact: true });
  await birthdate.fill("12/04/1990");
  await page.getByRole("button", { name: en.profileSave }).click();
  await expect(birthdate).toHaveAttribute("aria-invalid", "true");
  await expectAccessible(page);

  // What was kept is there after a reload.
  await page.reload();
  await expect(page.getByLabel(en.claimLabel("given_name"), { exact: true })).toHaveValue("Ana");
  await expect(page.getByLabel(en.claimLabel("address.locality"), { exact: true })).toHaveValue("São Paulo");
});
