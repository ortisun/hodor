// Turning what the interaction interface says about WebAuthn into what the
// browser takes, and the browser's answer back. Byte strings travel in
// base64url without padding. See docs/api/interaction-api.md, "The
// WebAuthn step".

/** What the WebAuthn step is submitted with. */
export interface WebAuthnAnswer {
  credential_id: string;
  client_data: string;
  authenticator_data: string;
  signature: string;
  user_handle: string | null;
}

export function toBase64url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (const byte of view) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64url(text: string): Uint8Array<ArrayBuffer> {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function field(options: Record<string, unknown>, name: string): string {
  const value = options[name];
  if (typeof value !== "string") {
    throw new TypeError(`the options lack ${name}`);
  }
  return value;
}

/** The options the interface gave, as `navigator.credentials.get` takes them. */
export function requestOptions(options: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  const allowed = Array.isArray(options["allowCredentials"]) ? options["allowCredentials"] : [];
  const timeout = options["timeout"];
  const verification = options["userVerification"];
  return {
    challenge: fromBase64url(field(options, "challenge")),
    rpId: field(options, "rpId"),
    allowCredentials: allowed.flatMap((entry: unknown) => {
      const fields = typeof entry === "object" && entry !== null ? (entry as Record<string, unknown>) : {};
      const id = fields["id"];
      if (typeof id !== "string") {
        return [];
      }
      const transports = Array.isArray(fields["transports"])
        ? (fields["transports"].filter((transport) => typeof transport === "string") as AuthenticatorTransport[])
        : [];
      return [{ type: "public-key" as const, id: fromBase64url(id), transports }];
    }),
    userVerification:
      verification === "required" || verification === "preferred" || verification === "discouraged"
        ? verification
        : "discouraged",
    timeout: typeof timeout === "number" ? timeout : undefined,
  };
}

/** The browser's answer, as the step is submitted with it. */
export function answerOf(credential: PublicKeyCredential): WebAuthnAnswer {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    credential_id: toBase64url(credential.rawId),
    client_data: toBase64url(response.clientDataJSON),
    authenticator_data: toBase64url(response.authenticatorData),
    signature: toBase64url(response.signature),
    user_handle: response.userHandle === null ? null : toBase64url(response.userHandle),
  };
}

/** Whether this browser can use security keys at all. */
export function webAuthnAvailable(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function";
}

/** Whether this browser can offer passkeys in a field, as a conditional request. */
export async function conditionalMediationAvailable(): Promise<boolean> {
  if (!webAuthnAvailable()) {
    return false;
  }
  const probe = (
    window.PublicKeyCredential as unknown as { isConditionalMediationAvailable?: () => Promise<boolean> }
  ).isConditionalMediationAvailable;
  try {
    return typeof probe === "function" ? await probe.call(window.PublicKeyCredential) : false;
  } catch {
    return false;
  }
}

/** How the authenticator is asked: by the person pressing a button, or offered in a field. */
export interface Asking {
  mediation?: CredentialMediationRequirement;
  signal?: AbortSignal;
}

/**
 * Asks the person's authenticator to answer the challenge. Answers `null`
 * when it gave no answer: the person cancelled, it timed out, or the
 * request was abandoned.
 */
export async function askAuthenticator(
  options: Record<string, unknown>,
  credentials: Pick<CredentialsContainer, "get"> = navigator.credentials,
  asking: Asking = {},
): Promise<WebAuthnAnswer | null> {
  try {
    const credential = await credentials.get({ publicKey: requestOptions(options), ...asking });
    return credential !== null && "rawId" in credential ? answerOf(credential as PublicKeyCredential) : null;
  } catch (thrown) {
    if (thrown instanceof DOMException) {
      return null;
    }
    throw thrown;
  }
}
