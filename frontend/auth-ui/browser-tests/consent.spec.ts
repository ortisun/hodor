import { expect, type Page } from "@playwright/test";
import { createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { PASSWORD, TENANT, at, en, expectAccessible, newAddress, register, signIn, test } from "./support";

/** The root of the repository, where the Compose file of the stack is. */
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));

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
 * and the failed navigation that follows is no failure of the test.
 */
async function sentBack(page: Page, action: () => Promise<unknown>): Promise<URLSearchParams> {
  const request = page.waitForRequest((sent) => sent.url().startsWith(REDIRECT));
  await action().catch(() => undefined);
  return new URL((await request).url()).searchParams;
}

test("a person is asked once before a third-party application gets in", async ({ page }) => {
  const client = thirdPartyClient();
  const address = newAddress();
  await register(page, address);
  await signIn(page, address, PASSWORD);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();

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
  const address = newAddress();
  await register(page, address);
  await signIn(page, address, PASSWORD);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();

  await askAsTheApplication(page, client);
  const answer = await sentBack(page, () => page.getByRole("button", { name: en.consentDeny }).click());
  expect(answer.get("error")).toBe("access_denied");
  expect(answer.get("code")).toBeNull();

  // Coming back to the page has nothing to answer.
  await page.goto(at("consent"));
  await expect(page.getByRole("heading", { name: en.consentNothingTitle })).toBeVisible();
  await expectAccessible(page);
});
