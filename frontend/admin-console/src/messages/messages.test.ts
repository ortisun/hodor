import { describe as group, expect, it } from "vitest";
import { Failure } from "../client";
import { chooseMessages, describe, LANGUAGES } from "./index";
import { en } from "./en";

group("the copy", () => {
  it("has the same messages in every language", () => {
    for (const language of LANGUAGES) {
      expect(Object.keys(language).sort(), language.locale).toEqual(Object.keys(en).sort());
      for (const [name, message] of Object.entries(language)) {
        const original = en[name as keyof typeof en];
        expect(typeof message, `${language.locale}.${name}`).toBe(typeof original);
        if (typeof message === "string") {
          expect(message.trim(), `${language.locale}.${name}`).not.toBe("");
        }
        if (typeof message === "object" && typeof original === "object") {
          expect(Object.keys(message).sort(), `${language.locale}.${name}`).toEqual(Object.keys(original).sort());
        }
      }
    }
  });
});

group("chooseMessages", () => {
  it("takes the first preferred language the console has, or one of its family", () => {
    expect(chooseMessages(["fr-FR", "pt-BR", "en"]).locale).toBe("pt-BR");
    expect(chooseMessages(["pt-PT"]).locale).toBe("pt-BR");
    expect(chooseMessages(["de"]).locale).toBe("en");
  });
});

group("describe", () => {
  it("says what the server refused in the person's words", () => {
    expect(describe(new Failure("identity.identifier_taken", 409), en)).toBe(en.identifierTaken);
    expect(describe(new Failure(null, 0), en)).toBe(en.unreachable);
  });

  it("says every refusal of trust domains and of a client's workload identity in words, in every language", () => {
    const codes = [
      "keys.trust_domain_not_found",
      "keys.trust_domain_name_taken",
      "keys.too_many_trust_domains",
      "keys.trust_domain_changed",
      "keys.trust_domain_name_invalid",
      "keys.trust_domain_source_invalid",
      "keys.trust_bundle_invalid",
      "keys.bundle_endpoint_invalid",
      "keys.bundle_endpoint_forbidden",
      "keys.bundle_endpoint_unresolvable",
      "keys.bundle_endpoint_unreachable",
      "oauth.client_spiffe_id_invalid",
      "oauth.client_spiffe_id_taken",
      "oauth.client_linkerd_identity_invalid",
      "oauth.client_linkerd_identity_taken",
      "oauth.client_certificate_bound_access_tokens_invalid",
      "oauth.client_principal_invalid",
    ];
    for (const language of LANGUAGES) {
      for (const code of codes) {
        expect(describe(new Failure(code, 422, "request-7"), language), `${language.locale} ${code}`).not.toContain(
          "request-7",
        );
      }
    }
  });

  it("gives the request to quote when it has nothing better to say", () => {
    expect(describe(new Failure("something.new", 500, "request-7"), en)).toContain("request-7");
  });
});
