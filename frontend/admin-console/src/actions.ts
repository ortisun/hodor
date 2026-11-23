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
  /**
   * A person can no longer use the factor; their last one takes their
   * recovery codes with it, and under a policy that requires one they
   * cannot sign in until one is enrolled for them.
   */
  removeFactor: { level: 2, permission: "credentials:write" },
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
  /** A first-party application's people are not asked for consent. */
  addApplication: { level: 1, permission: "applications:write" },
  /** Changes its name, or whether people are asked for consent. */
  changeApplication: { level: 1, permission: "applications:write" },
  /** Its clients get tokens again. */
  enableApplication: { level: 1, permission: "applications:write" },
  /** None of its clients gets a token until it is enabled again. */
  disableApplication: { level: 2, permission: "applications:write" },
  /** A client can ask for tokens; one with a secret gets it, shown once. */
  addClient: { level: 1, permission: "applications:write" },
  /** Changes where people are sent back to, what it may ask for and how it proves itself. */
  changeClient: { level: 1, permission: "applications:write" },
  /** Registers or changes the interface that accepts its tokens. */
  changeResourceServer: { level: 1, permission: "applications:write" },
  /** Every older secret but the newest stops at once. */
  rotateSecret: { level: 2, permission: "applications:write" },
  /** Whatever still uses the secret stops getting tokens at once. */
  revokeSecret: { level: 2, permission: "applications:write" },
  /** Assertions signed with the key are accepted. */
  addKey: { level: 1, permission: "applications:write" },
  /** Assertions signed with the key are refused from now on. */
  removeKey: { level: 1, permission: "applications:write" },
  /** It gets tokens again. */
  enableClient: { level: 1, permission: "applications:write" },
  /** It gets no token until it is enabled again. */
  disableClient: { level: 2, permission: "applications:write" },
  /** Changes what the role allows, and so what everyone holding it may do. */
  defineRole: { level: 1, permission: "roles:write" },
  /** What the role allowed them is denied from the next decision. */
  revokeRole: { level: 2, permission: "roles:write" },
  /** Every decision about the resource server is denied until it is bound again. */
  unbind: { level: 2, permission: "bindings:write" },
} as const satisfies Record<string, Action>;

export type ActionName = keyof typeof ACTIONS;

/** Whether a person with these permissions may take an action. */
export function may(permissions: readonly string[], action: ActionName): boolean {
  return permissions.includes(ACTIONS[action].permission);
}
