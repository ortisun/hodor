import { Button } from "@astryxdesign/core/Button";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Heading } from "@astryxdesign/core/Heading";
import { Table } from "@astryxdesign/core/Table";
import { VStack } from "@astryxdesign/core/VStack";
import { useCallback, useState } from "react";
import { may } from "../actions";
import type { Client, Me, RoleAssignment } from "../client";
import type { Messages } from "../messages";
import { moment } from "../messages";
import { Confirm, Consequence } from "../parts/Confirm";
import { Failed, useLoaded, Waiting } from "../parts/Loaded";

/** The roles a user or a client holds, each of which can be taken away. */
export function RoleAssignments({
  kind,
  id,
  client,
  me,
  text,
  say,
}: {
  kind: "user" | "client";
  id: string;
  client: Client;
  me: Me;
  text: Messages;
  say: (message: string) => void;
}) {
  const load = useCallback(() => client.listAssignments(kind, id), [client, kind, id]);
  const [held, again] = useLoaded<RoleAssignment[]>(load);
  const [revoking, setRevoking] = useState<RoleAssignment | null>(null);
  const name = (assignment: RoleAssignment) => `${assignment.role.namespace}#${assignment.role.name}`;

  return (
    <VStack gap={3}>
      <Heading level={2}>{text.heldRolesTitle}</Heading>
      {held.state === "loading" ? <Waiting text={text} /> : null}
      {held.state === "failed" ? <Failed failure={held.failure} again={again} text={text} /> : null}
      {held.state === "loaded" ? (
        <Table<{ id: string; assignment: RoleAssignment }>
          data={held.value.map((assignment) => ({
            id: `${name(assignment)} ${assignment.applicationId ?? ""}`,
            assignment,
          }))}
          idKey="id"
          emptyState={<EmptyState title={text.noHeldRoles} isCompact />}
          columns={[
            {
              key: "role",
              header: text.columnRole,
              renderCell: ({ assignment }) => <span className="console-mono">{name(assignment)}</span>,
            },
            {
              key: "where",
              header: text.columnWhere,
              renderCell: ({ assignment }) =>
                assignment.applicationId === null ? text.wholeTenant : text.oneApplication(assignment.applicationId),
            },
            {
              key: "until",
              header: text.columnUntil,
              renderCell: ({ assignment }) =>
                assignment.validUntil === null ? "—" : moment(assignment.validUntil, text),
            },
            {
              key: "revoke",
              header: "",
              renderCell: ({ assignment }) =>
                may(me.permissions, "revokeRole") ? (
                  <Button label={text.revokeRole} onClick={() => setRevoking(assignment)} />
                ) : null,
            },
          ]}
        />
      ) : null}

      {revoking !== null ? (
        <Confirm
          action="revokeRole"
          title={text.revokeRoleTitle(name(revoking))}
          confirmLabel={text.revokeRole}
          typed={revoking.role.name}
          text={text}
          onClose={() => setRevoking(null)}
          onConfirm={async () => {
            await client.revokeAssignment(revoking);
            setRevoking(null);
            say(text.roleRevoked(name(revoking)));
            again();
          }}
        >
          <ul className="console-facts">
            <Consequence what={text.revokeConsequence} value={text.revokeConsequenceValue} />
          </ul>
        </Confirm>
      ) : null}
    </VStack>
  );
}
