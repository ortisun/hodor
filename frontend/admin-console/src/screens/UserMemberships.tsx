import { Badge } from "@astryxdesign/core/Badge";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Heading } from "@astryxdesign/core/Heading";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { useCallback, useEffect, useState } from "react";
import type { GroupOfUser, OrganizationOfUser } from "../client";
import { moment } from "../messages";
import { Failed, useLoaded, Waiting } from "../parts/Loaded";
import { NameOf, useNames } from "./names";
import { treeOf } from "./OrganizationForms";
import type { ScreenProps } from "./shared";

type Props = Pick<ScreenProps, "client" | "me" | "text" | "go" | "path"> & { id: string };

/** The groups a user is in, each marked as direct or through another group. */
export function UserGroups({ id, ...props }: Props) {
  const names = { ...props, known: useNames() };
  const { client, text } = props;
  const load = useCallback(() => client.groupsOfUser(id), [client, id]);
  const [groups, again] = useLoaded<GroupOfUser[]>(load);

  return (
    <VStack gap={3}>
      <Heading level={2}>{text.userGroups}</Heading>
      {groups.state === "loading" ? <Waiting text={text} /> : null}
      {groups.state === "failed" ? <Failed failure={groups.failure} again={again} text={text} /> : null}
      {groups.state === "loaded" ? (
        <Table<{ id: string; group: GroupOfUser }>
          data={groups.value.map((group) => ({ id: group.id, group }))}
          idKey="id"
          emptyState={<EmptyState title={text.inNoGroup} isCompact />}
          columns={[
            {
              key: "group",
              header: text.columnGroup,
              renderCell: ({ group }) => <NameOf of="group" id={group.id} {...names} />,
            },
            {
              key: "how",
              header: text.columnHow,
              renderCell: ({ group }) =>
                group.direct ? <Badge variant="info" label={text.direct} /> : <Badge label={text.throughAnother} />,
            },
          ]}
        />
      ) : null}
    </VStack>
  );
}

/** The units of one organization a user is in, named by their place in its tree. */
function UnitsOf({ membership, client, text }: { membership: OrganizationOfUser } & Pick<Props, "client" | "text">) {
  const [paths, setPaths] = useState<string[] | null>(null);
  const { organizationId, unitIds } = membership;

  useEffect(() => {
    if (unitIds.length === 0) {
      return;
    }
    let current = true;
    client.listUnits(organizationId).then(
      (units) => {
        if (current) {
          setPaths(treeOf(units).filter((placed) => unitIds.includes(placed.unit.id)).map((placed) => placed.path));
        }
      },
      () => {
        // Without the organization's units, the units are counted, not named.
      },
    );
    return () => {
      current = false;
    };
  }, [client, organizationId, unitIds]);

  if (unitIds.length === 0) {
    return <Text color="secondary">{text.noUnit}</Text>;
  }
  if (paths === null) {
    return <Text color="secondary">{unitIds.length}</Text>;
  }
  return (
    <VStack gap={1}>
      {paths.map((shown) => (
        <Text key={shown}>{shown}</Text>
      ))}
    </VStack>
  );
}

/** The organizations a user is a member of, with their units. */
export function UserOrganizations({ id, ...props }: Props) {
  const names = { ...props, known: useNames() };
  const { client, text } = props;
  const load = useCallback(() => client.organizationsOfUser(id), [client, id]);
  const [memberships, again] = useLoaded<OrganizationOfUser[]>(load);

  return (
    <VStack gap={3}>
      <Heading level={2}>{text.userOrganizations}</Heading>
      {memberships.state === "loading" ? <Waiting text={text} /> : null}
      {memberships.state === "failed" ? <Failed failure={memberships.failure} again={again} text={text} /> : null}
      {memberships.state === "loaded" ? (
        <Table<{ id: string; membership: OrganizationOfUser }>
          data={memberships.value.map((membership) => ({ id: membership.organizationId, membership }))}
          idKey="id"
          emptyState={<EmptyState title={text.inNoOrganization} isCompact />}
          columns={[
            {
              key: "organization",
              header: text.columnOrganization,
              renderCell: ({ membership }) => <NameOf of="organization" id={membership.organizationId} {...names} />,
            },
            {
              key: "units",
              header: text.columnUnits,
              renderCell: ({ membership }) => <UnitsOf membership={membership} client={client} text={text} />,
            },
            {
              key: "since",
              header: text.columnMemberSince,
              renderCell: ({ membership }) => moment(membership.addedAt, text),
            },
          ]}
        />
      ) : null}
    </VStack>
  );
}
