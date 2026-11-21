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

  it("gives the request to quote when it has nothing better to say", () => {
    expect(describe(new Failure("something.new", 500, "request-7"), en)).toContain("request-7");
  });
});
