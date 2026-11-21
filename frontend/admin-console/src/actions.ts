// The action catalog: every action of the console that changes something,
// with its level on the dangerous action ladder and the permission it
// needs. The level is decided here, once, and the confirmation an action
// gets follows from it (docs/design/design-system.md, section 6.2).

import type { Permission } from "./client";

export type Level = 0 | 1 | 2 | 3 | 4;

export interface Action {
  level: Level;
  permission: Permission;
}

export const ACTIONS = {
  /** A form is its own confirmation. */
  createUser: { level: 0, permission: "users:write" },
  /** One device signs in again. */
  endSession: { level: 1, permission: "sessions:revoke" },
  /** A person can no longer sign in, and every session of theirs ends. */
  suspendUser: { level: 2, permission: "users:write" },
  /** People with an account at the provider can sign in, and may be created. */
  addProvider: { level: 1, permission: "identity-providers:write" },
  /** Changes who the provider lets in, or whether they are created. */
  changeProvider: { level: 1, permission: "identity-providers:write" },
  /** Sign-ins use the new secret at once. */
  replaceClientSecret: { level: 1, permission: "identity-providers:write" },
  /** The provider is offered on the sign-in page again. */
  enableProvider: { level: 1, permission: "identity-providers:write" },
  /** Nobody signs in through the provider until it is enabled again. */
  disableProvider: { level: 2, permission: "identity-providers:write" },
} as const satisfies Record<string, Action>;

export type ActionName = keyof typeof ACTIONS;

/** Whether a person with these permissions may take an action. */
export function may(permissions: readonly string[], action: ActionName): boolean {
  return permissions.includes(ACTIONS[action].permission);
}
