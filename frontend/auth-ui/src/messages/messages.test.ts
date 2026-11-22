import { describe as group, expect, it } from "vitest";
import { Failure } from "../client";
import { chooseMessages, describe, fieldProblem, LANGUAGES } from "./index";
import { en } from "./en";
import { ptBR } from "./pt-BR";

group("the copy", () => {
  it("has the same messages in every language", () => {
    for (const language of LANGUAGES) {
      expect(Object.keys(language).sort(), language.locale).toEqual(Object.keys(en).sort());
      for (const [name, message] of Object.entries(language)) {
        expect(typeof message, `${language.locale}.${name}`).toBe(
          typeof en[name as keyof typeof en],
        );
        if (typeof message === "string") {
          expect(message.trim(), `${language.locale}.${name}`).not.toBe("");
        }
      }
    }
  });
});

group("chooseMessages", () => {
  it("takes the first preferred language the pages have", () => {
    expect(chooseMessages(["fr-FR", "pt-BR", "en"]).locale).toBe("pt-BR");
    expect(chooseMessages(["en-GB", "pt-BR"]).locale).toBe("en");
  });

  it("takes a language of the same family", () => {
    expect(chooseMessages(["pt-PT"]).locale).toBe("pt-BR");
    expect(chooseMessages(["pt"]).locale).toBe("pt-BR");
  });

  it("falls back to English", () => {
    expect(chooseMessages(["ja"]).locale).toBe("en");
    expect(chooseMessages([]).locale).toBe("en");
  });
});

group("describe", () => {
  it("says when to try again, from the wait the server gave", () => {
    const text = describe(new Failure("authentication.too_many_attempts", 429, null, 90), en);
    expect(text).toBe("Too many attempts. Try again in 2 minutes.");
    expect(describe(new Failure("authentication.too_many_attempts", 429, null, 30), ptBR)).toBe(
      "Tentativas demais. Tente de novo em 30 segundos.",
    );
    expect(describe(new Failure("authentication.too_many_attempts", 429), en)).toBe(
      "Too many attempts. Try again later.",
    );
  });

  it("has words for a server that cannot be reached", () => {
    expect(describe(new Failure(null, 0), en)).toBe(en.unreachable);
  });

  it("quotes the request identifier for a code it has no words for", () => {
    const text = describe(new Failure("something.new", 500, "request-7"), en);
    expect(text).toContain(en.somethingWentWrong);
    expect(text).toContain("request-7");
  });
});

group("fieldProblem", () => {
  it("names the field a failure is about", () => {
    expect(fieldProblem(new Failure("credential.password_too_short", 422), en)).toEqual({
      field: "password",
      message: en.passwordTooShort,
    });
    expect(fieldProblem(new Failure("identity.display_name_invalid", 422), en)?.field).toBe("displayName");
    expect(fieldProblem(new Failure("authentication.too_many_attempts", 429), en)).toBeNull();
  });
});
