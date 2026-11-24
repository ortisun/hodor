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
    case "oauth.application_modified_concurrently":
    case "oauth.client_modified_concurrently":
    case "oauth.resource_server_modified_concurrently":
      return text.changedConcurrently;
    case "oauth.application_not_found":
      return text.applicationNotFound;
    case "oauth.client_not_found":
      return text.clientNotFound;
    case "oauth.too_many_applications":
      return text.tooManyApplications;
    case "oauth.too_many_clients":
      return text.tooManyClients;
    case "oauth.audience_taken":
      return text.audienceTaken;
    case "oauth.client_key_taken":
      return text.keyTaken;
    case "oauth.client_too_many_keys":
      return text.tooManyKeys;
    case "identity.group_not_found":
      return text.groupNotFound;
    case "identity.group_name_taken":
      return text.groupNameTaken;
    case "identity.group_cycle":
      return text.groupCycle;
    case "identity.group_nesting_too_deep":
      return text.groupNestingTooDeep;
    case "identity.group_modified_concurrently":
    case "identity.organization_modified_concurrently":
      return text.changedConcurrently;
    case "identity.organization_not_found":
      return text.organizationNotFound;
    case "identity.unit_not_found":
      return text.unitNotFound;
    case "identity.membership_not_found":
      return text.membershipNotFound;
    case "identity.invitation_invalid":
      return text.invitationInvalid;
    case "identity.organization_name_taken":
      return text.organizationNameTaken;
    case "identity.unit_name_taken":
      return text.unitNameTaken;
    case "identity.unit_cycle":
      return text.unitCycle;
    case "identity.unit_tree_too_deep":
      return text.unitTreeTooDeep;
    case "identity.unit_not_empty":
      return text.unitNotEmpty;
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

/** How long something lives, in the largest whole unit that fits. */
export function lifetime(seconds: number, text: Messages): string {
  if (seconds % 86400 === 0) {
    return text.days(seconds / 86400);
  }
  if (seconds % 3600 === 0) {
    return text.hours(seconds / 3600);
  }
  return text.minutes(Math.round(seconds / 60));
}
