import { describe, expect, it, vi } from "vitest";
import { askAuthenticator, fromBase64url, requestOptions, toBase64url } from "./webauthn";

describe("WebAuthn in the pages", () => {
  it("writes and reads base64url without padding", () => {
    for (const bytes of [[], [0], [0xfb, 0xff], [1, 2, 3, 4, 5]]) {
      const text = toBase64url(new Uint8Array(bytes));
      expect(text).not.toMatch(/[+/=]/);
      expect([...fromBase64url(text)]).toEqual(bytes);
    }
    expect(toBase64url(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
  });

  it("turns the options of the interface into what the browser takes", () => {
    const options = requestOptions({
      challenge: "AQI",
      rpId: "auth.example",
      allowCredentials: [{ type: "public-key", id: "AwQ", transports: ["usb", 7] }, { id: 3 }],
      userVerification: "something else",
      timeout: 300000,
    });
    expect([...new Uint8Array(options.challenge as ArrayBuffer)]).toEqual([1, 2]);
    expect(options.rpId).toBe("auth.example");
    expect(options.allowCredentials).toHaveLength(1);
    expect([...new Uint8Array(options.allowCredentials?.[0]?.id as ArrayBuffer)]).toEqual([3, 4]);
    expect(options.allowCredentials?.[0]?.transports).toEqual(["usb"]);
    expect(options.userVerification).toBe("discouraged");
    expect(options.timeout).toBe(300000);
  });

  it("answers nothing when the person cancels, and the answer when there is one", async () => {
    const options = { challenge: "AQI", rpId: "auth.example" };
    const cancelled = { get: vi.fn().mockRejectedValue(new DOMException("cancelled", "NotAllowedError")) };
    expect(await askAuthenticator(options, cancelled)).toBeNull();

    const bytes = (...values: number[]) => new Uint8Array(values).buffer;
    const answered = {
      get: vi.fn().mockResolvedValue({
        rawId: bytes(9),
        response: {
          clientDataJSON: bytes(1),
          authenticatorData: bytes(2),
          signature: bytes(3),
          userHandle: bytes(4),
        },
      }),
    };
    expect(await askAuthenticator(options, answered)).toEqual({
      credential_id: "CQ",
      client_data: "AQ",
      authenticator_data: "Ag",
      signature: "Aw",
      user_handle: "BA",
    });
  });
});
