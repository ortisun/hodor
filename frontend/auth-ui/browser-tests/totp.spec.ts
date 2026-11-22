import { expect } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import { PASSWORD, TENANT, at, en, expectAccessible, newAddress, register, signIn, test } from "./support";

/** The root of the repository, where the Compose file of the stack is. */
const ROOT = fileURLToPath(new URL("../../../", import.meta.url));

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

/** Base32 of RFC 4648, as the secret is printed. */
function fromBase32(text: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of text) {
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
function phone(secret: Buffer, steps = 0): string {
  const step = Math.floor(Date.now() / 1000 / 30) + steps;
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", secret).update(counter).digest();
  const offset = mac.readUInt8(19) & 0x0f;
  const binary = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, "0");
}

test("a person with an authenticator application gives a code after the password", async ({ page }) => {
  const address = newAddress();
  await register(page, address);

  // The operator enrolls the application, which the person's phone confirms.
  const printed = operator("totp", "enroll", "--tenant", TENANT, "--login", address);
  const secret = fromBase32(/^secret (\S+)$/m.exec(printed)?.[1] ?? "");
  expect(secret.length).toBe(20);
  expect(operator("totp", "confirm", "--tenant", TENANT, "--login", address, "--code", phone(secret))).toBe(
    "confirmed",
  );

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
