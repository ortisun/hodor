import { expect, type Page } from "@playwright/test";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { PASSWORD, en, expectAccessible, messageTo, newAddress, test } from "./support";

/** The root of the repository, where the Compose file of the stack is. */
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));

/**
 * The tenant of these tests, made for them. Every sign-in and registration
 * counts against the address the tests run from, with each tenant's own
 * limits; a tenant of their own keeps them from spending the limits of the
 * tenant the other tests share.
 */
const TENANT = `consent-${randomUUID().slice(0, 8)}`;

/** The path of a page of the tenant of these tests. */
function at(page: string): string {
  return page === "" ? `/t/${TENANT}/account` : `/t/${TENANT}/account/${page}`;
}

/** Where the application of these tests wants the person back. Nothing answers there: the test reads the request. */
const REDIRECT = "https://billing.example.test/callback";

/**
 * Runs `hodor-cli` in the development stack, as an operator does, and
 * answers what it printed. `COMPOSE_FILE` and `COMPOSE_PROJECT_NAME`, when
 * set, name a stack started another way.
 */
function operator(...arguments_: string[]): string {
  return execFileSync(
    "docker",
    [
      "compose",
      "run",
      "--rm",
      "--no-deps",
      "--entrypoint",
      "/usr/local/bin/hodor-cli",
      "-e",
      "HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor",
      "server",
      ...arguments_,
    ],
    {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
      env: { ...process.env, COMPOSE_FILE: process.env["COMPOSE_FILE"] ?? "deploy/docker/compose.yaml" },
    },
  ).trim();
}

/** Registers a person in the tenant of these tests, and signs them in. */
async function signedIn(page: Page): Promise<void> {
  const address = newAddress();
  await page.goto(at("register"));
  await page.getByLabel(en.emailLabel, { exact: true }).fill(address);
  await page.getByRole("button", { name: en.sendLink }).click();
  await expect(page.getByRole("heading", { name: en.checkMailboxTitle })).toBeVisible();
  await page.goto((await messageTo(address)).link);
  await page.getByLabel(en.newPasswordLabel, { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: en.createAccount }).click();
  await expect(page.getByText(en.noticeRegistered)).toBeVisible();
  await page.getByLabel(en.identifierLabel, { exact: true }).fill(address);
  await page.getByRole("button", { name: en.continue, exact: true }).click();
  await page.getByLabel(en.passwordLabel, { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
}

test.beforeAll(() => {
  operator("tenant", "create", "--slug", TENANT, "--name", "Consent", "--open-registration");
});

/** A third-party application with a public client that may ask for `openid` and `email`. Answers the client. */
function thirdPartyClient(): string {
  const application = /^application (\S+)/.exec(
    operator("application", "add", "--tenant", TENANT, "--name", "Billing"),
  )?.[1];
  expect(application).toBeTruthy();
  const client = /^client (\S+)/.exec(
    operator(
      "client",
      "add",
      "--tenant",
      TENANT,
      "--application",
      application ?? "",
      "--name",
      "Billing web",
      "--type",
      "public",
      "--grant",
      "authorization_code",
      "--redirect-uri",
      REDIRECT,
      "--scope",
      "openid",
      "--scope",
      "email",
    ),
  )?.[1];
  expect(client).toBeTruthy();
  return client ?? "";
}

/** The authorization request of the application, as the browser is sent to it. */
function authorizeAddress(client: string): string {
  const verifier = randomBytes(32).toString("base64url");
  const query = new URLSearchParams({
    response_type: "code",
    client_id: client,
    redirect_uri: REDIRECT,
    scope: "openid email",
    state: "the state",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
  });
  return `/t/${TENANT}/oauth2/authorize?${query.toString()}`;
}

/** Sends the browser to the authorization endpoint as the application would, when it is sent to Hodor's page. */
async function askAsTheApplication(page: Page, client: string): Promise<void> {
  await page.goto(authorizeAddress(client));
}

/**
 * What the browser is sent back to the application with, after `action`.
 * The application's address does not exist: the request to it is read,
 * and the failed navigation that follows is no failure of the test. The
 * browser's error page is waited for, so that it does not interrupt the
 * test's next navigation.
 */
async function sentBack(page: Page, action: () => Promise<unknown>): Promise<URLSearchParams> {
  const request = page.waitForRequest((sent) => sent.url().startsWith(REDIRECT));
  const errorPage = page.waitForEvent(
    "framenavigated",
    (frame) => frame === page.mainFrame() && frame.url().startsWith("chrome-error:"),
  );
  await action().catch(() => undefined);
  const sent = await request;
  await errorPage;
  return new URL(sent.url()).searchParams;
}

test("a person is asked once before a third-party application gets in", async ({ page }) => {
  const client = thirdPartyClient();
  await signedIn(page);

  await askAsTheApplication(page, client);
  await expect(page).toHaveURL(new RegExp(`${at("consent")}$`));
  const heading = page.getByRole("heading", { name: en.consentTitle("Billing") });
  await expect(heading).toBeFocused();
  await expect(page.getByText(en.consentScopeOpenid)).toBeVisible();
  await expect(page.getByText(en.consentScopeEmail)).toBeVisible();
  await expectAccessible(page);

  // With the keyboard alone: the first button is the one that allows.
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: en.consentAllow })).toBeFocused();
  const answer = await sentBack(page, () => page.keyboard.press("Enter"));
  expect(answer.get("code")).toBeTruthy();
  expect(answer.get("state")).toBe("the state");

  // Agreed once, not asked again.
  const again = await sentBack(page, () => page.goto(authorizeAddress(client)));
  expect(again.get("code")).toBeTruthy();

  // The account page lists the application, and withdrawing it means the
  // application asks again.
  await page.goto(at(""));
  await page.getByRole("button", { name: en.withdrawConsent("Billing") }).click();
  await expect(page.getByText(en.consentWithdrawn("Billing"))).toBeVisible();
  await expectAccessible(page);
  await askAsTheApplication(page, client);
  await expect(page).toHaveURL(new RegExp(`${at("consent")}$`));
});

test("a person who denies sends the application away with nothing", async ({ page }) => {
  const client = thirdPartyClient();
  await signedIn(page);

  await askAsTheApplication(page, client);
  const answer = await sentBack(page, () => page.getByRole("button", { name: en.consentDeny }).click());
  expect(answer.get("error")).toBe("access_denied");
  expect(answer.get("code")).toBeNull();

  // Coming back to the page has nothing to answer.
  await page.goto(at("consent"));
  await expect(page.getByRole("heading", { name: en.consentNothingTitle })).toBeVisible();
  await expectAccessible(page);
});
