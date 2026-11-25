import { describe, expect, it } from "vitest";
import {
  continuationOf,
  loginHintOf,
  noticeOf,
  pathOf,
  placeOf,
  providerAnswerOf,
  signInAgainPath,
  tokenOf,
  uiLocalesOf,
} from "./address";

describe("placeOf", () => {
  it("reads the tenant and the page from the path", () => {
    expect(placeOf("/t/acme/account/sign-in")).toEqual({ tenant: "acme", page: "sign-in" });
    expect(placeOf("/t/acme-corp/account/reset-password")).toEqual({
      tenant: "acme-corp",
      page: "reset-password",
    });
  });

  it("takes /account, with or without a final slash, as the account page", () => {
    expect(placeOf("/t/acme/account")).toEqual({ tenant: "acme", page: "account" });
    expect(placeOf("/t/acme/account/consent")).toEqual({ tenant: "acme", page: "consent" });
    expect(placeOf("/t/acme/account/")).toEqual({ tenant: "acme", page: "account" });
    expect(placeOf("/t/acme/account/sign-out")).toEqual({ tenant: "acme", page: "sign-out" });
    expect(placeOf("/t/acme/account/sign-in-link")).toEqual({ tenant: "acme", page: "sign-in-link" });
  });

  it("knows the tenant but no page for a name it does not have", () => {
    expect(placeOf("/t/acme/account/elsewhere")).toEqual({ tenant: "acme", page: null });
    expect(placeOf("/t/acme/account/account")).toEqual({ tenant: "acme", page: null });
  });

  it("refuses anything that is not a tenant's account path", () => {
    for (const path of ["/", "/t/acme", "/t/Acme/account", "/t/a/account", "/x/acme/account", "/t/acme/account/a/b"]) {
      expect(placeOf(path), path).toBeNull();
    }
  });
});

describe("pathOf", () => {
  it("is what placeOf reads", () => {
    expect(pathOf("acme", "sign-in")).toBe("/t/acme/account/sign-in");
    expect(pathOf("acme", "account")).toBe("/t/acme/account");
    expect(pathOf("acme", "sign-in", "registered")).toBe("/t/acme/account/sign-in?notice=registered");
  });
});

describe("noticeOf", () => {
  it("accepts only the notices the pages know", () => {
    expect(noticeOf("?notice=signed-out")).toBe("signed-out");
    expect(noticeOf("?notice=<script>")).toBeNull();
    expect(noticeOf("")).toBeNull();
  });
});

describe("tokenOf", () => {
  const token = "ab12".repeat(16);

  it("reads the token after the hash sign", () => {
    expect(tokenOf(`#token=${token}`)).toBe(token);
  });

  it("refuses what cannot be a token", () => {
    expect(tokenOf("")).toBeNull();
    expect(tokenOf("#token=")).toBeNull();
    expect(tokenOf("#token=not-hexadecimal")).toBeNull();
    expect(tokenOf(`#other=${token}`)).toBeNull();
  });
});

describe("the page a provider sends people back to", () => {
  it("is read from the path, with the provider's alias", () => {
    expect(placeOf("/t/acme/account/providers/google/callback")).toEqual({
      tenant: "acme",
      page: "provider-callback",
      provider: "google",
    });
    expect(placeOf("/t/acme/account/providers/entra-id/callback/")?.provider).toBe("entra-id");
  });

  it("is no page when the alias could not be one", () => {
    for (const path of [
      "/t/acme/account/providers/Google/callback",
      "/t/acme/account/providers//callback",
      "/t/acme/account/providers/a/b/callback",
      "/t/acme/account/providers/google",
    ]) {
      expect(placeOf(path)?.page ?? null, path).toBeNull();
    }
  });

  it("reads what the provider put in the address", () => {
    const nothing = { code: null, state: null, error: null, binding: null, receipt: null };
    expect(providerAnswerOf("?code=abc&state=def")).toEqual({ ...nothing, code: "abc", state: "def" });
    expect(providerAnswerOf("?error=access_denied&state=def")).toEqual({
      ...nothing,
      state: "def",
      error: "access_denied",
    });
    expect(providerAnswerOf("")).toEqual(nothing);
    expect(providerAnswerOf("?binding=saml&state=def&receipt=ghi")).toEqual({
      ...nothing,
      state: "def",
      binding: "saml",
      receipt: "ghi",
    });
    expect(providerAnswerOf("?binding=other&state=def").binding).toBeNull();
  });
});

describe("what an application asked of the sign-in", () => {
  it("reads the login hint, and nothing for an empty or long one", () => {
    expect(loginHintOf("?continue=authorization&login_hint=ana%40example.com")).toBe("ana@example.com");
    expect(loginHintOf("?continue=authorization")).toBeNull();
    expect(loginHintOf("?login_hint=%20")).toBeNull();
    expect(loginHintOf(`?login_hint=${"a".repeat(256)}`)).toBeNull();
  });

  it("reads the languages in the order they were asked for", () => {
    expect(uiLocalesOf("?ui_locales=pt-BR%20en")).toEqual(["pt-BR", "en"]);
    expect(uiLocalesOf("?ui_locales=pt-BR+en")).toEqual(["pt-BR", "en"]);
    expect(uiLocalesOf("?continue=authorization")).toEqual([]);
  });
});

describe("signing in again", () => {
  it("knows the security page and what a sign-in continues", () => {
    expect(placeOf("/t/acme/account/security")).toEqual({ tenant: "acme", page: "security" });
    expect(continuationOf("?continue=authorization")).toBe("authorization");
    expect(continuationOf("?continue=security")).toBe("security");
    expect(continuationOf("?continue=https://elsewhere.example")).toBeNull();
    expect(continuationOf("")).toBeNull();
    expect(signInAgainPath("acme")).toBe("/t/acme/account/sign-in?continue=security");
  });
});
