import { describe, expect, it } from "vitest";
import { noticeOf, pathOf, placeOf, tokenOf } from "./address";

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
    expect(placeOf("/t/acme/account/")).toEqual({ tenant: "acme", page: "account" });
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
