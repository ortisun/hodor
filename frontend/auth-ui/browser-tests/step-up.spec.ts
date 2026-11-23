import { expect } from "@playwright/test";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { SERVER } from "./stack";
import {
  TENANT,
  at,
  en,
  expectAccessible,
  fromBase32,
  newAddress,
  operator,
  phone,
  signInThroughProvider,
  test,
} from "./support";

const MULTI_FACTOR = "urn:hodor:acr:mfa";

function base64url(bytes: Buffer): string {
  return bytes.toString("base64url");
}

/** The claims of a JSON Web Token, without checking it: the server tests check signatures. */
function claims(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString()) as Record<string, unknown>;
}

/** Where the application waits for the browser to come back: a page of its own on this machine. */
async function theApplicationsPage(): Promise<{ server: Server; address: string }> {
  const server = createServer((_, response) => {
    response.writeHead(200, { "Content-Type": "text/html" }).end("<!doctype html><title>Billing</title><h1>Billing</h1>");
  });
  await new Promise<void>((listening) => server.listen(0, "127.0.0.1", listening));
  return { server, address: `http://127.0.0.1:${(server.address() as AddressInfo).port}/callback` };
}

/** A first-party application of the tenant with a confidential client, registered by the operator. */
function anApplication(redirectUri: string): { clientId: string; secret: string } {
  // The tenant signs tokens with a key of its own; the rotation job would
  // make the first one within ten minutes, the operator makes it now.
  operator("keys", "rotate", "--tenant", TENANT);
  const application = operator("application", "add", "--tenant", TENANT, "--name", `Billing ${randomUUID()}`, "--first-party").split(" ")[1] ?? "";
  const printed = operator(
    "client", "add", "--tenant", TENANT, "--application", application, "--name", "Billing web",
    "--type", "confidential", "--grant", "authorization_code", "--redirect-uri", redirectUri, "--scope", "openid",
  );
  return {
    clientId: /^client (\S+)$/m.exec(printed)?.[1] ?? "",
    secret: /^secret (\S+)$/m.exec(printed)?.[1] ?? "",
  };
}

test("an application asks for more in the middle of a session and gets it after the code alone", async ({ page }) => {
  const { server, address: REDIRECT_URI } = await theApplicationsPage();
  // Nothing keeps the run waiting for it, whatever happens to the test.
  server.unref();
  const client = anApplication(REDIRECT_URI);

  // A person signed in through the development identity provider, who
  // sets up an authenticator application on the security page.
  await signInThroughProvider(page, { subject: `subject-${randomUUID()}`, email: newAddress() });
  await page.getByRole("link", { name: en.securityLink }).click();
  await page.getByRole("button", { name: en.setUpApplication }).click();
  const secret = fromBase32(await page.locator(".auth-code").first().innerText());
  await page.getByLabel(en.totpLabel).fill(phone(secret));
  await page.getByRole("button", { name: en.confirmApplication }).click();
  await page.getByRole("button", { name: en.codesKept }).click();
  await expect(page.getByText(en.applicationInUse)).toBeVisible();

  // The application asks for a multi-factor sign-in. The session has one
  // factor, so the person is asked for the code of the application, and
  // for nothing else: not the identifier, not the provider again.
  const verifier = base64url(randomBytes(32));
  const state = base64url(randomBytes(12));
  const query = new URLSearchParams({
    response_type: "code",
    client_id: client.clientId,
    redirect_uri: REDIRECT_URI,
    scope: "openid",
    state,
    nonce: base64url(randomBytes(12)),
    code_challenge: base64url(createHash("sha256").update(verifier).digest()),
    code_challenge_method: "S256",
    acr_values: MULTI_FACTOR,
  });
  await page.goto(`/t/${TENANT}/oauth2/authorize?${query}`);
  await expect(page).toHaveURL(new RegExp(`${at("sign-in")}\\?continue=authorization$`));
  const code = page.getByLabel(en.totpLabel);
  await expect(code).toBeFocused();
  await expect(page.getByLabel(en.identifierLabel)).toHaveCount(0);
  await expectAccessible(page);
  await code.fill(phone(secret, 1));
  await page.getByRole("button", { name: en.signIn, exact: true }).click();

  // The browser goes back to the application with a code, which the
  // application exchanges for tokens that say what the person proved.
  await page.waitForURL((address) => address.href.startsWith(REDIRECT_URI));
  const back = new URL(page.url());
  expect(back.searchParams.get("state")).toBe(state);
  const answer = await fetch(`${SERVER}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${Buffer.from(`${encodeURIComponent(client.clientId)}:${encodeURIComponent(client.secret)}`).toString("base64")}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: back.searchParams.get("code") ?? "",
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    }),
  });
  expect(answer.status).toBe(200);
  const tokens = (await answer.json()) as { id_token: string; access_token: string };
  const identity = claims(tokens.id_token);
  expect(identity["acr"]).toBe(MULTI_FACTOR);
  expect(identity["amr"]).toEqual(expect.arrayContaining(["otp", "mfa"]));
  expect(claims(tokens.access_token)["acr"]).toBe(MULTI_FACTOR);
  server.close();
});
