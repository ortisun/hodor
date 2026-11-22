import { Failure } from "../client";
import { en, type Messages } from "./en";
import { ptBR } from "./pt-BR";

export type { Messages };

export const LANGUAGES: readonly Messages[] = [en, ptBR];

/**
 * The first of the browser's preferred languages that the pages have.
 * Anything else falls back to English.
 */
export function chooseMessages(preferred: readonly string[]): Messages {
  for (const tag of preferred) {
    const wanted = tag.toLowerCase();
    const exact = LANGUAGES.find((language) => language.locale.toLowerCase() === wanted);
    if (exact) {
      return exact;
    }
    const primary = wanted.split("-")[0];
    const close = LANGUAGES.find((language) => language.locale.toLowerCase().split("-")[0] === primary);
    if (close) {
      return close;
    }
  }
  return en;
}

/** What is wrong with a field, when a failure is about one. */
export interface FieldProblem {
  field: "password" | "displayName";
  message: string;
}

export function fieldProblem(failure: Failure, text: Messages): FieldProblem | null {
  switch (failure.code) {
    case "credential.password_too_short":
      return { field: "password", message: text.passwordTooShort };
    case "credential.password_too_long":
      return { field: "password", message: text.passwordTooLong };
    case "credential.password_is_own_name":
      return { field: "password", message: text.passwordIsOwnName };
    case "credential.password_reused":
      return { field: "password", message: text.passwordReused };
    case "identity.display_name_invalid":
      return { field: "displayName", message: text.displayNameInvalid };
    default:
      return null;
  }
}

function wait(seconds: number | null, text: Messages): string {
  if (seconds === null) {
    return text.tryAgainLater;
  }
  return seconds < 60
    ? text.tryAgainInSeconds(Math.ceil(seconds))
    : text.tryAgainInMinutes(Math.ceil(seconds / 60));
}

/**
 * The pages' own words for a failure, chosen by its code. The server's
 * `detail` is never shown.
 */
export function describe(failure: Failure, text: Messages): string {
  if (failure.unreachable) {
    return text.unreachable;
  }
  switch (failure.code) {
    case "authentication.too_many_attempts":
      return `${text.tooManyAttempts} ${wait(failure.retryAfterSeconds, text)}`;
    case "authentication.registration_closed":
      return text.registrationClosed;
    case "authentication.verification_token_invalid":
      return text.linkInvalid;
    case "credential.hashing_overloaded":
      return text.serverBusy;
    default: {
      const quote = failure.requestId ? ` ${text.requestIdentifier(failure.requestId)}` : "";
      return text.somethingWentWrong + quote;
    }
  }
}
