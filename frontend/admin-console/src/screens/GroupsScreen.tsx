import { useMemo } from "react";
import { type Listed, NamedList } from "./NamedList";
import type { ScreenProps } from "./shared";

/** The groups of the tenant, oldest first, and the form that creates one. */
export function GroupsScreen({ client, text, ...rest }: ScreenProps) {
  const listed = useMemo<Listed>(
    () => ({
      one: "group",
      title: text.groups,
      lead: text.groupsLead,
      create: "createGroup",
      createLabel: text.createGroup,
      createTitle: text.createGroupTitle,
      empty: text.noGroups,
      emptyHint: text.noGroupsHint,
      created: text.groupCreated,
      list: (cursor) => client.listGroups(cursor),
      add: (settings) => client.createGroup(settings),
    }),
    [client, text],
  );
  return <NamedList listed={listed} text={text} {...rest} />;
}
