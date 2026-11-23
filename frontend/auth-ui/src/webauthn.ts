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

/** What finishing a registration is sent with, as the interface takes it. */
export interface KeyRegistration {
  client_data: string;
  attestation_object: string;
  transports: string[];
  discoverable?: boolean;
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

/** The options the interface gave for a registration, as `navigator.credentials.create` takes them. */
export function creationOptions(options: Record<string, unknown>): PublicKeyCredentialCreationOptions {
  const party = record(options["rp"]);
  const user = record(options["user"]);
  const selection = record(options["authenticatorSelection"]);
  const timeout = options["timeout"];
  const parameters = Array.isArray(options["pubKeyCredParams"]) ? options["pubKeyCredParams"] : [];
  const excluded = Array.isArray(options["excludeCredentials"]) ? options["excludeCredentials"] : [];
  const level = (value: unknown): UserVerificationRequirement | undefined =>
    value === "required" || value === "preferred" || value === "discouraged" ? value : undefined;
  const resident = selection["residentKey"];
  return {
    rp: { id: field(party, "id"), name: field(party, "name") },
    user: {
      id: fromBase64url(field(user, "id")),
      name: field(user, "name"),
      displayName: field(user, "displayName"),
    },
    challenge: fromBase64url(field(options, "challenge")),
    pubKeyCredParams: parameters.flatMap((entry: unknown) => {
      const algorithm = record(entry)["alg"];
      return typeof algorithm === "number" ? [{ type: "public-key" as const, alg: algorithm }] : [];
    }),
    excludeCredentials: excluded.flatMap((entry: unknown) => {
      const id = record(entry)["id"];
      return typeof id === "string" ? [{ type: "public-key" as const, id: fromBase64url(id) }] : [];
    }),
    authenticatorSelection: {
      residentKey: resident === "required" || resident === "preferred" || resident === "discouraged" ? resident : undefined,
      requireResidentKey: resident === "required",
      userVerification: level(selection["userVerification"]),
    },
    attestation: "none",
    extensions: { credProps: true },
    timeout: typeof timeout === "number" ? timeout : undefined,
  };
}

/** The browser's answer to a registration, as finishing it is sent. */
export function registrationOf(credential: PublicKeyCredential): KeyRegistration {
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports =
    typeof response.getTransports === "function" ? response.getTransports().filter((name) => typeof name === "string") : [];
  const properties = record(record(credential.getClientExtensionResults())["credProps"]);
  const discoverable = properties["rk"];
  return {
    client_data: toBase64url(response.clientDataJSON),
    attestation_object: toBase64url(response.attestationObject),
    transports,
    ...(typeof discoverable === "boolean" ? { discoverable } : {}),
  };
}

/**
 * Asks the person's authenticator to make a credential. Answers `null`
 * when it made none: the person cancelled, it timed out, or it holds one
 * of the credentials it was told about already.
 */
export async function askToCreate(
  options: Record<string, unknown>,
  credentials: Pick<CredentialsContainer, "create"> = navigator.credentials,
): Promise<KeyRegistration | null> {
  try {
    const credential = await credentials.create({ publicKey: creationOptions(options) });
    return credential !== null && "rawId" in credential ? registrationOf(credential as PublicKeyCredential) : null;
  } catch (thrown) {
    if (thrown instanceof DOMException) {
      return null;
    }
    throw thrown;
  }
}
