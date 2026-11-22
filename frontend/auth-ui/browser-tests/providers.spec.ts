import { randomUUID } from "node:crypto";
import { expect } from "@playwright/test";
import {
  at,
  en,
  expectAccessible,
  newAddress,
  PASSWORD,
  PROVIDER,
  PROVIDER_NAME,
  register,
  signIn,
  signInThroughProvider,
  test,
} from "./support";

const newSubject = () => `subject-${randomUUID()}`;

test("a person signs in through an identity provider and is created on the first visit", async ({ page }) => {
  const identity = { subject: newSubject(), email: newAddress() };

  await page.goto(at("sign-in"));
  await expect(page.getByRole("button", { name: en.continueWith(PROVIDER_NAME) })).toBeVisible();
  await expectAccessible(page);

  await signInThroughProvider(page, identity);

  // Back at Hodor, signed in, and the address shows nothing the provider sent.
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`${at("")}$`));
  await expectAccessible(page);

  // The session is the server's: it survives a reload and ends on sign-out.
  await page.reload();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  await page.getByRole("button", { name: en.signOut }).click();
  await expect(page.getByText(en.noticeSignedOut)).toBeVisible();

  // The second visit is the same person: no new account, straight in.
  await signInThroughProvider(page, identity);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
});

test("an identity provider does not open an account that already exists with the same address", async ({ page }) => {
  // Ana registers with a password.
  const address = newAddress();
  await register(page, address);

  // Somebody arrives from the provider with her address, vouched for.
  await signInThroughProvider(page, { subject: newSubject(), email: address });

  await expect(page.getByRole("alert")).toHaveText(en.noticeProviderRefused);
  await expect(page).toHaveURL(new RegExp(`${at("sign-in")}$`));
  await expectAccessible(page);
  await page.goto(at(""));
  await expect(page).toHaveURL(new RegExp(`${at("sign-in")}$`), { timeout: 10_000 });

  // Her own way in still works.
  await signIn(page, address, PASSWORD);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
});

test("an address the provider does not vouch for creates nobody", async ({ page }) => {
  const address = newAddress();
  await signInThroughProvider(page, { subject: newSubject(), email: address, vouched: false });
  await expect(page.getByRole("alert")).toHaveText(en.noticeProviderRefused);

  // Nobody was created: the address can still be registered.
  await register(page, address);
});

test("a person who cancels at the provider is told so and can sign in another way", async ({ page }) => {
  await page.goto(at("sign-in"));
  await page.getByRole("button", { name: en.continueWith(PROVIDER_NAME) }).click();
  await page.getByRole("button", { name: "Cancel" }).click();

  await expect(page.getByRole("alert")).toHaveText(en.noticeProviderCancelled);
  await expect(page.getByLabel(en.identifierLabel, { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: en.continueWith(PROVIDER_NAME) })).toBeVisible();
});

test("the code a provider sent does not stay in the address or work a second time", async ({ page }) => {
  const identity = { subject: newSubject(), email: newAddress() };
  const seen: string[] = [];
  page.on("framenavigated", (frame) => {
    if (frame === page.mainFrame()) {
      seen.push(frame.url());
    }
  });

  await signInThroughProvider(page, identity);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  const arrived = seen.find((url) => url.includes(`/providers/${PROVIDER}/callback`) && url.includes("code="));
  expect(arrived, "the provider sent the browser back with a code").toBeDefined();
  await page.getByRole("button", { name: en.signOut }).click();
  await expect(page.getByText(en.noticeSignedOut)).toBeVisible();

  // Whoever finds that address later gets nothing from it.
  await page.goto(arrived ?? "");
  await expect(page.getByRole("alert")).toHaveText(en.noticeProviderRefused);
  await page.goto(at(""));
  await expect(page).toHaveURL(new RegExp(`${at("sign-in")}$`), { timeout: 10_000 });
});

test("a person reaches the provider and comes back with the keyboard alone", async ({ page }) => {
  await page.goto(at("sign-in"));
  await expect(page.getByLabel(en.identifierLabel, { exact: true })).toBeFocused();
  // The field, the button that continues, then the providers in the
  // order they are offered, the development provider among them.
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: en.continue, exact: true })).toBeFocused();
  const provider = page.getByRole("button", { name: en.continueWith(PROVIDER_NAME) });
  const offered = await page.getByRole("button", { name: /^Continue with / }).count();
  for (let pressed = 0; pressed < offered; pressed += 1) {
    await page.keyboard.press("Tab");
    if (await provider.evaluate((button) => button === document.activeElement)) {
      break;
    }
  }
  await expect(provider).toBeFocused();
  await page.keyboard.press("Enter");

  await expect(page.getByRole("heading", { name: PROVIDER_NAME })).toBeVisible();
  await page.getByLabel("Subject").fill(newSubject());
  await page.getByLabel("Email address").fill(newAddress());
  await page.keyboard.press("Enter");

  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeFocused();
});
