// What the browser tests share: a browser that fails the test when a page
// misbehaves, the mailbox, and the steps a person repeats.

import AxeBuilder from "@axe-core/playwright";
import { expect, test as base, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { createHmac, randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { en } from "../src/messages/en";
import { MAIL, PROVIDER, TENANT } from "./stack";

export { en, PROVIDER, TENANT };

/** What the development provider is called on the sign-in page. */
export const PROVIDER_NAME = "Development provider";

export const PASSWORD = "correct horse battery staple";

/** The root of the repository, where the Compose file of the stack is. */
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));

/**
 * Runs `hodor-cli` in the development stack, as an operator does, and
 * answers what it printed. `COMPOSE_FILE` and `COMPOSE_PROJECT_NAME`, when
 * set, name a stack started another way.
 */
export function operator(...arguments_: string[]): string {
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

/** Base32 of RFC 4648, as a secret is printed or shown, ignoring the spaces between groups. */
export function fromBase32(text: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of text.replace(/\s/g, "")) {
    buffer = (buffer << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

/** What an authenticator application shows for this secret, `steps` steps of thirty seconds from now. */
export function phone(secret: Buffer, steps = 0): string {
  const step = Math.floor(Date.now() / 1000 / 30) + steps;
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", secret).update(counter).digest();
  const offset = mac.readUInt8(19) & 0x0f;
  const binary = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, "0");
}

/** The path of a page of the tenant under test, or of another tenant. */
export function at(page: string, tenant = TENANT): string {
  return page === "" ? `/t/${tenant}/account` : `/t/${tenant}/account/${page}`;
}

/** An address nobody has used before. */
export function newAddress(): string {
  return `person-${randomUUID()}@example.com`;
}

/**
 * A tenant of its own, open to registration, for a test that changes a
 * policy every other test of the run would feel, or that would spend the
 * shared tenant's count of requests from one address, which the run is
 * written to stay under. The operator makes it
 * with the command-line tool and then runs each of `settings`, the
 * arguments of `hodor-cli tenant` after the slug, such as
 * `["second-factor", "--policy", "required"]`. Answers its slug.
 */
export function newTenant(...settings: string[][]): string {
  const slug = `browser-${randomUUID().slice(0, 8)}`;
  operator("tenant", "create", "--slug", slug, "--name", "Initech", "--open-registration");
  for (const [command, ...rest] of settings) {
    operator("tenant", command ?? "", "--slug", slug, ...rest);
  }
  return slug;
}

/**
 * Every test gets a page that is watched: a violation of the Content
 * Security Policy, an error thrown by a script or an error written to the
 * console fails the test, whatever else it was about.
 */
export const test = base.extend<{ misbehavior: string[] }>({
  misbehavior: [
    async ({ page }, use) => {
      const seen: string[] = [];
      await page.addInitScript(() => {
        document.addEventListener("securitypolicyviolation", (event) => {
          console.error(`policy violation: ${event.violatedDirective} by ${event.blockedURI || "inline"}`);
        });
      });
      page.on("pageerror", (error) => seen.push(`script error: ${error.message}`));
      page.on("console", (message) => {
        // A request the server refused is written to the console by the
        // browser. Asking who is signed in is refused whenever nobody is,
        // which is no misbehavior of the page.
        if (message.type() === "error" && !message.text().startsWith("Failed to load resource")) {
          seen.push(`console: ${message.text()}`);
        }
      });
      await use(seen);
      expect(seen, "the pages misbehaved").toEqual([]);
    },
    { auto: true },
  ],
});

/** Fails if the page shown breaks a rule of the accessibility guidelines the checker can test. */
export async function expectAccessible(page: Page): Promise<void> {
  // What is measured is what a person is left looking at: a message that
  // is still fading in has, for a moment, colors nobody is meant to read.
  await page.evaluate(() => Promise.all(document.getAnimations().map((animation) => animation.finished)));
  const found = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  const violations = found.violations.map(
    (violation) => `${violation.id}: ${violation.nodes.map((node) => node.target.join(" ")).join(", ")}`,
  );
  expect(violations, `accessibility at ${page.url()}`).toEqual([]);
}

interface Summary {
  ID: string;
  Subject: string;
}

export interface Mail {
  subject: string;
  text: string;
}

export interface Message extends Mail {
  /** The path and fragment of the link in the message, to open on the server under test. */
  link: string;
}

/**
 * Reads the mailbox of `address` on the development mail server, as a
 * person would, waiting for message number `count` to arrive.
 */
export async function mailTo(address: string, count = 1): Promise<Mail> {
  let summaries: Summary[] = [];
  await expect
    .poll(
      async () => {
        const query = encodeURIComponent(`to:"${address}"`);
        const response = await fetch(`${MAIL}/api/v1/search?query=${query}`);
        summaries = ((await response.json()) as { messages: Summary[] }).messages;
        return summaries.length;
      },
      { message: `message ${count} to ${address}`, timeout: 20_000 },
    )
    .toBeGreaterThanOrEqual(count);
  // Newest first.
  const summary = summaries[summaries.length - count];
  if (summary === undefined) {
    throw new Error(`no message ${count} to ${address}`);
  }
  const response = await fetch(`${MAIL}/api/v1/message/${summary.ID}`);
  const { Text: text } = (await response.json()) as { Text: string };
  return { subject: summary.Subject, text };
}

/** Message number `count` to `address`, as `mailTo` reads it, with the link it carries. */
export async function messageTo(address: string, count = 1): Promise<Message> {
  const { subject, text } = await mailTo(address, count);
  const found = /https?:\/\/\S+#token=[0-9a-f]+/.exec(text);
  if (found === null) {
    throw new Error(`the message to ${address} carries no link:\n${text}`);
  }
  const link = new URL(found[0]);
  return { subject, text, link: link.pathname + link.hash };
}

/** Registers a person through the pages, up to the sign-in page that says the account is ready. */
export async function register(page: Page, address: string, password = PASSWORD, tenant = TENANT): Promise<void> {
  await page.goto(at("register", tenant));
  await page.getByLabel(en.emailLabel, { exact: true }).fill(address);
  await page.getByRole("button", { name: en.sendLink }).click();
  await expect(page.getByRole("heading", { name: en.checkMailboxTitle })).toBeVisible();

  const message = await messageTo(address);
  await page.goto(message.link);
  await page.getByLabel(en.newPasswordLabel, { exact: true }).fill(password);
  await page.getByRole("button", { name: en.createAccount }).click();
  await expect(page.getByText(en.noticeRegistered)).toBeVisible();
}

/** Signs in through the pages, up to the answer to the password. */
export async function signIn(page: Page, identifier: string, password: string, tenant = TENANT): Promise<void> {
  if (!page.url().includes(at("sign-in", tenant))) {
    await page.goto(at("sign-in", tenant));
  }
  await page.getByLabel(en.identifierLabel, { exact: true }).fill(identifier);
  await page.getByRole("button", { name: en.continue, exact: true }).click();
  await page.getByLabel(en.passwordLabel, { exact: true }).fill(password);
  await page.getByRole("button", { name: en.signIn, exact: true }).click();
}

/** Who a person says they are at the development provider. */
export interface Identity {
  subject: string;
  email: string;
  /** Whether the provider vouches for the address. */
  vouched?: boolean;
}

/**
 * From the sign-in page, leaves for the development provider, says who
 * the person is there, and comes back.
 */
export async function signInThroughProvider(page: Page, identity: Identity): Promise<void> {
  if (!page.url().includes(at("sign-in"))) {
    await page.goto(at("sign-in"));
  }
  await page.getByRole("button", { name: en.continueWith(PROVIDER_NAME) }).click();
  // The provider's own page, on its own origin.
  await expect(page.getByRole("heading", { name: PROVIDER_NAME })).toBeVisible();
  await page.getByLabel("Subject").fill(identity.subject);
  await page.getByLabel("Email address").fill(identity.email);
  await page.getByLabel("The provider vouches for this address").setChecked(identity.vouched ?? true);
  await page.getByRole("button", { name: "Sign in" }).click();
}
