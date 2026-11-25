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
    expect(placeOf("/t/acme/console/identity-providers")).toEqual({ tenant: "acme", screen: { name: "providers" } });
    expect(placeOf(`/t/acme/console/identity-providers/${ID}`)).toEqual({
      tenant: "acme",
      screen: { name: "provider", id: ID },
    });
    expect(placeOf(`/t/acme/console/service-accounts/${ID}`)).toEqual({
      tenant: "acme",
      screen: { name: "serviceAccount", id: ID },
    });
    expect(placeOf(`/t/acme/console/agents/${ID}`)).toEqual({ tenant: "acme", screen: { name: "agent", id: ID } });
    expect(placeOf(`/t/acme/console/webhooks/${ID}`)).toEqual({ tenant: "acme", screen: { name: "webhook", id: ID } });
    expect(placeOf("/t/acme/console/trust-domains")).toEqual({ tenant: "acme", screen: { name: "trustDomains" } });
    expect(placeOf(`/t/acme/console/trust-domains/${ID}`)).toEqual({
      tenant: "acme",
      screen: { name: "trustDomain", id: ID },
    });
  });

  it("names no screen for an address of the console that has none", () => {
    expect(placeOf("/t/acme/console/keys")).toEqual({ tenant: "acme", screen: null });
    expect(placeOf("/t/acme/console/users/not-an-identifier")).toEqual({ tenant: "acme", screen: null });
    expect(placeOf(`/t/acme/console/users/${ID}/more`)).toEqual({ tenant: "acme", screen: null });
    expect(placeOf("/t/acme/console/groups/finance")).toEqual({ tenant: "acme", screen: null });
    expect(placeOf(`/t/acme/console/organizations/${ID}/units`)).toEqual({ tenant: "acme", screen: null });
    expect(placeOf(`/t/acme/console/service-accounts/${ID}/api-keys`)).toEqual({ tenant: "acme", screen: null });
    expect(placeOf("/t/acme/console/agents/helper")).toEqual({ tenant: "acme", screen: null });
    expect(placeOf("/t/acme/console/webhook-endpoints")).toEqual({ tenant: "acme", screen: null });
    expect(placeOf("/t/acme/console/trust-domains/cluster.local")).toEqual({ tenant: "acme", screen: null });
    expect(placeOf(`/t/acme/console/trust-domains/${ID}/bundle`)).toEqual({ tenant: "acme", screen: null });
  });

  it("is not the console's when the address is elsewhere", () => {
    expect(placeOf("/t/acme/account")).toBeNull();
    expect(placeOf("/console")).toBeNull();
    expect(placeOf("/t/Not A Tenant/console")).toBeNull();
  });
});

describe("pathOf", () => {
  it("writes the address placeOf reads", () => {
    const screens = [
      { name: "home" },
      { name: "users" },
      { name: "user", id: ID },
      { name: "audit" },
      { name: "providers" },
      { name: "provider", id: ID },
      { name: "groups" },
      { name: "group", id: ID },
      { name: "organizations" },
      { name: "organization", id: ID },
      { name: "serviceAccounts" },
      { name: "serviceAccount", id: ID },
      { name: "agents" },
      { name: "agent", id: ID },
      { name: "webhooks" },
      { name: "webhook", id: ID },
      { name: "trustDomains" },
      { name: "trustDomain", id: ID },
    ] as const;
    for (const screen of screens) {
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
