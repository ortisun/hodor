import { Failure } from "../client";
import { en, type Messages } from "./en";
import { ptBR } from "./pt-BR";

export type { Messages };

export const LANGUAGES: readonly Messages[] = [en, ptBR];

/**
 * The first of the browser's preferred languages that the console has.
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

/** What to tell a person about a failure, in their language. */
export function describe(failure: Failure, text: Messages): string {
  if (failure.status === 0) {
    return text.unreachable;
  }
  switch (failure.code) {
    case "admin.forbidden":
      return text.forbidden;
    case "identity.identifier_taken":
      return text.identifierTaken;
    case "identity.email_invalid":
      return text.emailInvalid;
    case "identity.user_not_found":
      return text.userNotFound;
    case "identity.invalid_transition":
      return text.notActive;
    case "federation.provider_not_found":
      return text.providerNotFound;
    case "federation.alias_taken":
      return text.aliasTaken;
    case "federation.too_many_providers":
      return text.tooManyProviders;
    case "federation.not_configured":
      return text.providersNotConfigured;
    case "federation.provider_modified_concurrently":
      return text.modifiedConcurrently;
    default:
      if (failure.code !== null && text.valueInvalid[failure.code] !== undefined) {
        return text.valueInvalid[failure.code] ?? text.somethingWrong;
      }
      return failure.requestId === null
        ? text.somethingWrong
        : `${text.somethingWrong} ${text.requestIdentifier(failure.requestId)}`;
  }
}

/** A moment, as a person of this language reads it. */
export function moment(written: string, text: Messages): string {
  const date = new Date(written);
  return Number.isNaN(date.getTime())
    ? written
    : new Intl.DateTimeFormat(text.locale, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

/** The name of a status, a role or anything else the server names, or the name itself when unknown. */
export function named(names: Record<string, string>, name: string): string {
  return names[name] ?? name;
}
