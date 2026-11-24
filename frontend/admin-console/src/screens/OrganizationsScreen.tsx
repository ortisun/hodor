import { useMemo } from "react";
import { type Listed, NamedList } from "./NamedList";
import type { ScreenProps } from "./shared";

/** The organizations of the tenant, oldest first, and the form that creates one. */
export function OrganizationsScreen({ client, text, ...rest }: ScreenProps) {
  const listed = useMemo<Listed>(
    () => ({
      one: "organization",
      title: text.organizations,
      lead: text.organizationsLead,
      create: "createOrganization",
      createLabel: text.createOrganization,
      createTitle: text.createOrganizationTitle,
      empty: text.noOrganizations,
      emptyHint: text.noOrganizationsHint,
      created: text.organizationCreated,
      list: (cursor) => client.listOrganizations(cursor),
      add: (settings) => client.createOrganization(settings),
    }),
    [client, text],
  );
  return <NamedList listed={listed} text={text} {...rest} />;
}
