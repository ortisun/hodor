import { expect, type Page } from "@playwright/test";
import { TENANT } from "./stack";
import { PASSWORD, en, expectAccessible, newAddress, register, signIn, test } from "./support";

/** A security key in Chromium, which answers without anyone touching it. */
async function addVirtualKey(page: Page): Promise<void> {
  const session = await page.context().newCDPSession(page);
  await session.send("WebAuthn.enable");
  await session.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "usb",
      hasResidentKey: true,
      hasUserVerification: false,
      automaticPresenceSimulation: true,
    },
  });
}

/** The authenticator built into a device, in Chromium: it keeps passkeys and verifies the person. */
async function addVirtualPlatformAuthenticator(page: Page): Promise<void> {
  const session = await page.context().newCDPSession(page);
  await session.send("WebAuthn.enable");
  await session.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

/**
 * Registers the key through the interaction interface, from a page of
 * Hodor's origin, as the pages of Issue-70 will. Answers the status of the
 * request that finishes.
 */
async function registerKey(page: Page, passkey = false): Promise<number> {
  return page.evaluate(async ([base, passkey]) => {
    const encode = (bytes: ArrayBuffer) =>
      btoa(String.fromCharCode(...new Uint8Array(bytes)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    const decode = (text: string) =>
      Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4)), (c) =>
        c.charCodeAt(0),
      );
    const session = await (await fetch(`${base}/session`)).json();
    const headers = { "Content-Type": "application/json", "X-CSRF-Token": session.csrf_token };
    const begun = await (
      await fetch(`${base}/webauthn/registrations`, { method: "POST", headers, body: JSON.stringify({ passkey }) })
    ).json();
    const options = begun.public_key;
    const credential = (await navigator.credentials.create({
      publicKey: {
        ...options,
        challenge: decode(options.challenge),
        user: { ...options.user, id: decode(options.user.id) },
        excludeCredentials: options.excludeCredentials.map((known: { id: string }) => ({
          ...known,
          id: decode(known.id),
        })),
      },
    })) as PublicKeyCredential;
    const response = credential.response as AuthenticatorAttestationResponse;
    const finished = await fetch(`${base}/webauthn/registrations/${begun.registration_id}`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_data: encode(response.clientDataJSON),
        attestation_object: encode(response.attestationObject),
        transports: response.getTransports(),
        discoverable: credential.getClientExtensionResults().credProps?.rk,
        name: "Virtual key",
      }),
    });
    return finished.status;
  }, [`/t/${TENANT}/interaction`, passkey] as const);
}

test("a person with a security key signs in with the password and the key", async ({ page }) => {
  await addVirtualKey(page);
  const address = newAddress();
  await register(page, address);
  await signIn(page, address, PASSWORD);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  expect(await registerKey(page)).toBe(201);

  await page.getByRole("button", { name: en.signOut }).click();
  await expect(page.getByText(en.noticeSignedOut)).toBeVisible();

  // The password is not enough any more: the key is asked for.
  await signIn(page, address, PASSWORD);
  await expect(page.getByText(en.securityKeyLead)).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("button", { name: en.useSecurityKey }).click();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();

  const methods = await page.evaluate(
    async (base) => (await (await fetch(`${base}/session`)).json()).methods,
    `/t/${TENANT}/interaction`,
  );
  expect(methods).toEqual(["password", "webauthn"]);
});

/** Registers a person and a passkey, and signs them out. */
async function registeredWithPasskey(page: Page): Promise<void> {
  const address = newAddress();
  await register(page, address);
  await signIn(page, address, PASSWORD);
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  expect(await registerKey(page, true)).toBe(201);
  await page.getByRole("button", { name: en.signOut }).click();
}

async function sessionOf(page: Page): Promise<{ methods: string[]; assurance: string }> {
  return page.evaluate(
    async (base) => (await (await fetch(`${base}/session`)).json()) as { methods: string[]; assurance: string },
    `/t/${TENANT}/interaction`,
  );
}

test("a person with a passkey signs in with it alone, from the button", async ({ page }) => {
  // The virtual authenticator answers a passkey offered in the field at once, as if the person
  // chose it; here the browser is made to offer none, so that the button is what is tried.
  await page.addInitScript(() => {
    Object.defineProperty(window.PublicKeyCredential, "isConditionalMediationAvailable", {
      value: () => Promise.resolve(false),
    });
  });
  await addVirtualPlatformAuthenticator(page);
  await registeredWithPasskey(page);
  await expect(page.getByText(en.noticeSignedOut)).toBeVisible();

  // No identifier and no password: the passkey names the person and is enough.
  await expectAccessible(page);
  await page.getByRole("button", { name: en.signInWithPasskey }).click();
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  const session = await sessionOf(page);
  expect(session.methods).toEqual(["passkey"]);
  expect(session.assurance).toBe("multi_factor");
});

test("a person with a passkey signs in with the one the browser offers in the field", async ({ page }) => {
  await addVirtualPlatformAuthenticator(page);
  await registeredWithPasskey(page);
  // The sign-in page offers the passkey in the identifier field, and the virtual authenticator
  // takes the offer: the person is signed in without typing anything.
  await expect(page.getByRole("heading", { name: en.accountTitle })).toBeVisible();
  const session = await sessionOf(page);
  expect(session.methods).toEqual(["passkey"]);
});
