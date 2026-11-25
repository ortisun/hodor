import { expect, type Page, type Request } from "@playwright/test";
import { createHash, randomBytes } from "node:crypto";
import { SERVER } from "./stack";
import { PASSWORD, at, en, newAddress, newTenant, operator, register, signIn, test } from "./support";

/** Where the application of these tests wants the person back. The test answers there itself. */
const REDIRECT = "https://shop.example.test/callback";

/** A state that would end an attribute and add markup if the page did not escape it. */
const STATE = `"><script>alert("state")</script>&amp;`;

/** A first-party application with a public client that may ask for `openid`. Answers the client. */
function firstPartyClient(tenant: string): string {
  const application = /^application (\S+)/.exec(
    operator("application", "add", "--tenant", tenant, "--name", "Shop", "--first-party"),
  )?.[1];
  expect(application).toBeTruthy();
  const client = /^client (\S+)/.exec(
    operator(
      "client",
      "add",
      "--tenant",
      tenant,
      "--application",
      application ?? "",
      "--name",
      "Shop web",
      "--type",
      "public",
      "--grant",
      "authorization_code",
      "--redirect-uri",
      REDIRECT,
      "--scope",
      "openid",
    ),
  )?.[1];
  expect(client).toBeTruthy();
  return client ?? "";
}

/** The authorization request of the application, answered with `form_post`. */
function authorizeAddress(tenant: string, client: string): string {
  const verifier = randomBytes(32).toString("base64url");
  const query = new URLSearchParams({
    response_type: "code",
    response_mode: "form_post",
    client_id: client,
    redirect_uri: REDIRECT,
    scope: "openid",
    state: STATE,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
  });
  return `${SERVER}/t/${tenant}/oauth2/authorize?${query.toString()}`;
}

/** A person registered in a tenant of their own, signed in there. Answers the tenant. */
async function signedIn(page: Page): Promise<string> {
  const tenant = newTenant();
  const address = newAddress();
  await register(page, address, PASSWORD, tenant);
  await signIn(page, address, PASSWORD, tenant);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`${at("", tenant)}$`));
  return tenant;
}

/**
 * The request the browser sends the application after `action`, which the
 * test answers with a page of the application's own.
 */
async function sentToTheApplication(page: Page, action: () => Promise<unknown>): Promise<Request> {
  await page.route(`${REDIRECT}**`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/html; charset=utf-8",
      body: "<!doctype html><html lang=en><title>Shop</title><h1>Back at the shop</h1></html>",
    }),
  );
  const request = page.waitForRequest((sent) => sent.url().startsWith(REDIRECT));
  // The page posts its form at once, which interrupts the navigation that
  // brought it: that is no failure.
  await action().catch(() => undefined);
  return request;
}

/** The fields of a form the browser posted, in their order. */
function fields(request: Request): [string, string][] {
  expect(request.method()).toBe("POST");
  return [...new URLSearchParams(request.postData() ?? "").entries()];
}

test("the application gets its code in a form the page posts, and nothing else", async ({ page }) => {
  const tenant = await signedIn(page);
  const client = firstPartyClient(tenant);

  const hodorsPage = page.waitForResponse((answer) => answer.url().includes(`/t/${tenant}/oauth2/authorize`));
  const request = await sentToTheApplication(page, () => page.goto(authorizeAddress(tenant, client)));
  const answer = await hodorsPage;

  // The page was Hodor's, with the headers that keep it to itself.
  expect(answer.status()).toBe(200);
  const headers = answer.headers();
  expect(headers["content-security-policy"]).toMatch(/^default-src 'none'; script-src 'sha256-[A-Za-z0-9+/]+=*';/);
  expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(headers["cache-control"]).toBe("no-store");
  expect(headers["referrer-policy"]).toBe("no-referrer");

  // The browser posted the code, the state as it was given and the issuer,
  // as a form, without saying where it came from, and nothing else.
  expect(request.url()).toBe(REDIRECT);
  expect(await request.headerValue("content-type")).toBe("application/x-www-form-urlencoded");
  expect(await request.headerValue("referer")).toBeNull();
  const posted = fields(request);
  expect(posted.map(([name]) => name)).toEqual(["code", "state", "iss"]);
  expect(posted[0]?.[1]).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(posted[1]?.[1]).toBe(STATE);
  expect(posted[2]?.[1]).toBe(`${SERVER}/t/${tenant}`);
  await expect(page.getByRole("heading", { name: "Back at the shop" })).toBeVisible();
});

test("without scripts the person sends the form with a button, by the keyboard alone", async ({ browser, page }) => {
  const tenant = await signedIn(page);
  const client = firstPartyClient(tenant);

  // The same person, in a browser that runs no script.
  const context = await browser.newContext({
    javaScriptEnabled: false,
    storageState: await page.context().storageState(),
  });
  try {
    const quiet = await context.newPage();
    await quiet.goto(authorizeAddress(tenant, client));
    await expect(quiet.getByText("If you are not taken back to the application, continue.")).toBeVisible();
    const button = quiet.getByRole("button", { name: "Continue" });
    await quiet.keyboard.press("Tab");
    await expect(button).toBeFocused();
    const request = await sentToTheApplication(quiet, () => quiet.keyboard.press("Enter"));
    const posted = fields(request);
    expect(posted.map(([name]) => name)).toEqual(["code", "state", "iss"]);
    expect(posted[1]?.[1]).toBe(STATE);
  } finally {
    await context.close();
  }
});

test("an error is posted to the application in the same way", async ({ page }) => {
  const tenant = await signedIn(page);
  const client = firstPartyClient(tenant);

  const address = new URL(authorizeAddress(tenant, client));
  address.searchParams.set("scope", "openid payroll:write");
  const request = await sentToTheApplication(page, () => page.goto(address.toString()));
  const posted = Object.fromEntries(fields(request));
  expect(Object.keys(posted).sort()).toEqual(["error", "error_description", "iss", "state"]);
  expect(posted["error"]).toBe("invalid_scope");
  expect(posted["state"]).toBe(STATE);
});
