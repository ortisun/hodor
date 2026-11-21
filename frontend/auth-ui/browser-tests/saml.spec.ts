import { randomUUID } from "node:crypto";
import { expect, type Page } from "@playwright/test";
import { at, en, expectAccessible, newAddress, test } from "./support";

/** What the development SAML provider is called on the sign-in page. */
const SAML_PROVIDER_NAME = "Development SAML provider";

interface SamlIdentity {
  subject: string;
  email: string;
}

/** Leaves for the development SAML provider and signs in there as `identity`. */
async function signInThroughSaml(page: Page, identity: SamlIdentity, decision = "Sign in"): Promise<void> {
  if (!page.url().includes(at("sign-in"))) {
    await page.goto(at("sign-in"));
  }
  await page.getByRole("button", { name: en.continueWith(SAML_PROVIDER_NAME) }).click();
  // The identity provider's own page, on its own origin.
  await expect(page.getByRole("heading", { name: SAML_PROVIDER_NAME })).toBeVisible();
  await page.getByLabel("Name identifier").fill(identity.subject);
  await page.getByLabel("Email address").fill(identity.email);
  // Its next page posts the response to Hodor by itself.
  await page.getByRole("button", { name: decision }).click();
}

test("a person signs in through a SAML identity provider and is the same person the next time", async ({ page }) => {
  const identity = { subject: `saml-${randomUUID()}`, email: newAddress() };

  await page.goto(at("sign-in"));
  await expect(page.getByRole("button", { name: en.continueWith(SAML_PROVIDER_NAME) })).toBeVisible();
  await signInThroughSaml(page, identity);

  // Back at Hodor, signed in, and the address keeps neither the state nor
  // the receipt.
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`${at("")}$`));
  await expectAccessible(page);

  await page.getByRole("button", { name: en.signOut }).click();
  await expect(page.getByText(en.noticeSignedOut)).toBeVisible();
  await signInThroughSaml(page, identity);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
});

test("a person who cancels at the SAML identity provider is told it did not work", async ({ page }) => {
  await signInThroughSaml(page, { subject: `saml-${randomUUID()}`, email: newAddress() }, "Cancel");

  // The identity provider said the sign-in did not succeed; Hodor refused it.
  await expect(page.getByRole("alert")).toHaveText(en.noticeProviderRefused);
  await expect(page).toHaveURL(new RegExp(`${at("sign-in")}$`));
  await expect(page.getByLabel(en.identifierLabel, { exact: true })).toBeVisible();
});
