import { describe, expect, it } from "vitest";
import { isIdentifier, pathOf, placeOf } from "./address";

const ID = "0193f1c2-0000-7000-8000-000000000001";

describe("placeOf", () => {
  it("reads the tenant and the screen from the address", () => {
    expect(placeOf("/t/acme/console")).toEqual({ tenant: "acme", screen: { name: "home" } });
    expect(placeOf("/t/acme/console/")).toEqual({ tenant: "acme", screen: { name: "home" } });
    expect(placeOf("/t/acme/console/users")).toEqual({ tenant: "acme", screen: { name: "users" } });
    expect(placeOf(`/t/acme/console/users/${ID}`)).toEqual({ tenant: "acme", screen: { name: "user", id: ID } });
    expect(placeOf("/t/acme/console/audit")).toEqual({ tenant: "acme", screen: { name: "audit" } });
  });

  it("names no screen for an address of the console that has none", () => {
    expect(placeOf("/t/acme/console/keys")).toEqual({ tenant: "acme", screen: null });
    expect(placeOf("/t/acme/console/users/not-an-identifier")).toEqual({ tenant: "acme", screen: null });
    expect(placeOf(`/t/acme/console/users/${ID}/more`)).toEqual({ tenant: "acme", screen: null });
  });

  it("is not the console's when the address is elsewhere", () => {
    expect(placeOf("/t/acme/account")).toBeNull();
    expect(placeOf("/console")).toBeNull();
    expect(placeOf("/t/Not A Tenant/console")).toBeNull();
  });
});

describe("pathOf", () => {
  it("writes the address placeOf reads", () => {
    for (const screen of [{ name: "home" }, { name: "users" }, { name: "user", id: ID }, { name: "audit" }] as const) {
      expect(placeOf(pathOf("acme", screen))).toEqual({ tenant: "acme", screen });
    }
  });
});

describe("isIdentifier", () => {
  it("knows the shape of an identifier", () => {
    expect(isIdentifier(ID)).toBe(true);
    expect(isIdentifier("ana@example.com")).toBe(false);
  });
});
