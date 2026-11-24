import { Badge } from "@astryxdesign/core/Badge";
import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { useCallback, useState } from "react";
import { may } from "../actions";
import type {
  Failure,
  Invitation,
  Organization,
  OrganizationMember,
  Page as Paged,
  Unit,
} from "../client";
import { moment, named, type Messages } from "../messages";
import { Confirm, Consequence } from "../parts/Confirm";
import { Identifier } from "../parts/Identifier";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";
import { NamedForm } from "./NamedForm";
import { NameOf, useNames } from "./names";
import { InviteForm, MemberForm, type Placed, treeOf, UnitForm } from "./OrganizationForms";
import { follow, Page, type ScreenProps } from "./shared";

type Open =
  | { kind: "change" }
  | { kind: "delete" }
  | { kind: "createUnit" }
  | { kind: "changeUnit"; unit: Unit }
  | { kind: "deleteUnit"; unit: Unit }
  | { kind: "putMember" }
  | { kind: "changeMember"; member: OrganizationMember }
  | { kind: "removeMember"; member: OrganizationMember }
  | { kind: "invite" }
  | { kind: "withdraw"; invitation: Invitation }
  | null;

/** The names of some units, each by its place in the tree, in the order of the tree. */
function UnitNames({ ids, placed, text }: { ids: readonly string[]; placed: readonly Placed[]; text: Messages }) {
  const shown = placed.filter((place) => ids.includes(place.unit.id));
  if (shown.length === 0) {
    return <Text color="secondary">{text.noUnit}</Text>;
  }
  return (
    <VStack gap={1}>
      {shown.map((place) => (
        <Text key={place.unit.id}>{place.path}</Text>
      ))}
    </VStack>
  );
}

/**
 * One organization: its name and description, its units as a tree, its
 * members with their units, and its pending invitations.
 */
export function OrganizationScreen({ id, client, me, text, go, path, say }: ScreenProps & { id: string }) {
  const loadOrganization = useCallback(() => client.getOrganization(id), [client, id]);
  const [organization, againOrganization, replaceOrganization] = useLoaded<Organization>(loadOrganization);
  const loadUnits = useCallback(() => client.listUnits(id), [client, id]);
  const [units, againUnits] = useLoaded<Unit[]>(loadUnits);
  const loadMembers = useCallback(() => client.listOrganizationMembers(id), [client, id]);
  const [members, againMembers, replaceMembers] = useLoaded<Paged<OrganizationMember>>(loadMembers);
  const loadInvitations = useCallback(() => client.listInvitations(id), [client, id]);
  const [invitations, againInvitations] = useLoaded<Invitation[]>(loadInvitations);
  const [more, setMore] = useState<{ busy: boolean; failure: Failure | null }>({ busy: false, failure: null });
  const [open, setOpen] = useState<Open>(null);
  const close = () => setOpen(null);
  const known = useNames();

  const above = (
    <Breadcrumbs variant="supporting">
      <BreadcrumbItem
        href={path({ name: "organizations" })}
        onClick={(event) => follow(event, go, { name: "organizations" })}
      >
        {text.organizations}
      </BreadcrumbItem>
      <BreadcrumbItem>{text.organizationTitle}</BreadcrumbItem>
    </Breadcrumbs>
  );

  if (organization.state !== "loaded") {
    return (
      <Page title={text.organizationTitle} above={above}>
        {organization.state === "loading" ? (
          <Waiting text={text} />
        ) : (
          <Failed failure={organization.failure} again={againOrganization} text={text} />
        )}
      </Page>
    );
  }

  const shown = organization.value;
  const allUnits = units.state === "loaded" ? units.value : [];
  const placed = treeOf(allUnits);
  const names = { client, me, text, go, path, known };

  async function loadMore(page: Paged<OrganizationMember>) {
    if (more.busy || page.nextCursor === null) {
      return;
    }
    setMore({ busy: true, failure: null });
    try {
      const next = await client.listOrganizationMembers(id, page.nextCursor);
      replaceMembers({ items: [...page.items, ...next.items], nextCursor: next.nextCursor });
      setMore({ busy: false, failure: null });
    } catch (thrown) {
      setMore({ busy: false, failure: asFailure(thrown) });
    }
  }

  return (
    <Page
      title={shown.name}
      above={above}
      lead={shown.description ?? undefined}
      actions={
        may(me.permissions, "changeOrganization") ? (
          <>
            <Button label={text.changeSettings} onClick={() => setOpen({ kind: "change" })} />
            {may(me.permissions, "deleteOrganization") ? (
              <Button
                variant="destructive"
                label={text.deleteOrganization}
                onClick={() => setOpen({ kind: "delete" })}
              />
            ) : null}
          </>
        ) : null
      }
    >
      <Card>
        <VStack gap={3}>
          <Heading level={2}>{text.settings}</Heading>
          <MetadataList>
            <MetadataListItem label={text.identifierLabel}>
              <Identifier value={shown.id} whole text={text} />
            </MetadataListItem>
            <MetadataListItem label={text.descriptionLabel}>{shown.description ?? text.noDescription}</MetadataListItem>
            <MetadataListItem label={text.created}>{moment(shown.createdAt, text)}</MetadataListItem>
            <MetadataListItem label={text.changed}>{moment(shown.updatedAt, text)}</MetadataListItem>
          </MetadataList>
        </VStack>
      </Card>

      <Card>
        <VStack gap={3}>
          <HStack justify="between" vAlign="center">
            <Heading level={2}>{text.units}</Heading>
            {may(me.permissions, "createUnit") && units.state === "loaded" ? (
              <Button label={text.createUnit} onClick={() => setOpen({ kind: "createUnit" })} />
            ) : null}
          </HStack>
          {units.state === "loading" ? <Waiting text={text} /> : null}
          {units.state === "failed" ? <Failed failure={units.failure} again={againUnits} text={text} /> : null}
          {units.state === "loaded" ? (
            <Table<{ id: string; place: Placed }>
              data={placed.map((place) => ({ id: place.unit.id, place }))}
              idKey="id"
              emptyState={<EmptyState title={text.noUnits} description={text.noUnitsHint} isCompact />}
              columns={[
                {
                  key: "unit",
                  header: text.columnUnit,
                  renderCell: ({ place }) => (
                    <span className="console-unit" data-depth={Math.min(place.depth, 10)}>
                      {place.unit.name}
                    </span>
                  ),
                },
                {
                  key: "kind",
                  header: text.columnKind,
                  renderCell: ({ place }) => <Badge label={named(text.unitKinds, place.unit.kind)} />,
                },
                {
                  key: "actions",
                  header: "",
                  align: "end",
                  renderCell: ({ place }) => (
                    <HStack gap={2} justify="end">
                      {may(me.permissions, "changeUnit") ? (
                        <Button
                          size="sm"
                          label={text.changeUnit}
                          onClick={() => setOpen({ kind: "changeUnit", unit: place.unit })}
                        />
                      ) : null}
                      {may(me.permissions, "deleteUnit") ? (
                        <Button
                          size="sm"
                          label={text.deleteUnit}
                          onClick={() => setOpen({ kind: "deleteUnit", unit: place.unit })}
                        />
                      ) : null}
                    </HStack>
                  ),
                },
              ]}
            />
          ) : null}
        </VStack>
      </Card>

      <Card>
        <VStack gap={3}>
          <HStack justify="between" vAlign="center">
            <Heading level={2}>{text.members}</Heading>
            {may(me.permissions, "putOrganizationMember") && units.state === "loaded" ? (
              <Button label={text.putMember} onClick={() => setOpen({ kind: "putMember" })} />
            ) : null}
          </HStack>
          {members.state === "loading" ? <Waiting text={text} /> : null}
          {members.state === "failed" ? <Failed failure={members.failure} again={againMembers} text={text} /> : null}
          {members.state === "loaded" ? (
            <VStack gap={4}>
              <Table<{ id: string; member: OrganizationMember }>
                data={members.value.items.map((member) => ({ id: member.userId, member }))}
                idKey="id"
                emptyState={
                  <EmptyState title={text.noOrganizationMembers} description={text.noOrganizationMembersHint} isCompact />
                }
                columns={[
                  {
                    key: "member",
                    header: text.columnMember,
                    renderCell: ({ member }) => <NameOf of="user" id={member.userId} {...names} />,
                  },
                  {
                    key: "units",
                    header: text.columnUnits,
                    renderCell: ({ member }) => <UnitNames ids={member.unitIds} placed={placed} text={text} />,
                  },
                  {
                    key: "added",
                    header: text.columnAdded,
                    renderCell: ({ member }) => moment(member.addedAt, text),
                  },
                  {
                    key: "actions",
                    header: "",
                    align: "end",
                    renderCell: ({ member }) => (
                      <HStack gap={2} justify="end">
                        {may(me.permissions, "putOrganizationMember") && units.state === "loaded" ? (
                          <Button
                            size="sm"
                            label={text.changeMemberUnits}
                            onClick={() => setOpen({ kind: "changeMember", member })}
                          />
                        ) : null}
                        {may(me.permissions, "removeOrganizationMember") ? (
                          <Button
                            size="sm"
                            label={text.takeOut}
                            onClick={() => setOpen({ kind: "removeMember", member })}
                          />
                        ) : null}
                      </HStack>
                    ),
                  },
                ]}
              />
              {more.failure !== null ? <Failed failure={more.failure} text={text} /> : null}
              {members.value.nextCursor !== null ? (
                <HStack justify="center">
                  <Button label={text.loadMore} isLoading={more.busy} onClick={() => void loadMore(members.value)} />
                </HStack>
              ) : null}
            </VStack>
          ) : null}
        </VStack>
      </Card>

      <Card>
        <VStack gap={3}>
          <HStack justify="between" vAlign="center">
            <Heading level={2}>{text.invitations}</Heading>
            {may(me.permissions, "invite") && units.state === "loaded" ? (
              <Button label={text.invite} onClick={() => setOpen({ kind: "invite" })} />
            ) : null}
          </HStack>
          {invitations.state === "loading" ? <Waiting text={text} /> : null}
          {invitations.state === "failed" ? (
            <Failed failure={invitations.failure} again={againInvitations} text={text} />
          ) : null}
          {invitations.state === "loaded" ? (
            <Table<{ id: string; invitation: Invitation }>
              data={invitations.value.map((invitation) => ({ id: invitation.id, invitation }))}
              idKey="id"
              emptyState={<EmptyState title={text.noInvitations} description={text.noInvitationsHint} isCompact />}
              columns={[
                {
                  key: "address",
                  header: text.emailLabel,
                  renderCell: ({ invitation }) => <Text>{invitation.email}</Text>,
                },
                {
                  key: "units",
                  header: text.columnUnits,
                  renderCell: ({ invitation }) => <UnitNames ids={invitation.unitIds} placed={placed} text={text} />,
                },
                {
                  key: "expires",
                  header: text.columnExpires,
                  renderCell: ({ invitation }) => moment(invitation.expiresAt, text),
                },
                {
                  key: "withdraw",
                  header: "",
                  align: "end",
                  renderCell: ({ invitation }) =>
                    may(me.permissions, "withdrawInvitation") ? (
                      <Button size="sm" label={text.withdraw} onClick={() => setOpen({ kind: "withdraw", invitation })} />
                    ) : null,
                },
              ]}
            />
          ) : null}
        </VStack>
      </Card>

      {open?.kind === "change" ? (
        <NamedForm
          current={shown}
          action="changeOrganization"
          title={text.changeSettingsTitle(shown.name)}
          confirmLabel={text.saveOrganization}
          text={text}
          submit={(settings) => client.changeOrganization(shown.id, settings)}
          onClose={close}
          onDone={(changed) => {
            replaceOrganization(changed);
            close();
            say(text.organizationChanged(changed.name));
          }}
        />
      ) : null}

      {open?.kind === "delete" ? (
        <Confirm
          action="deleteOrganization"
          title={text.deleteOrganizationTitle(shown.name)}
          confirmLabel={text.deleteOrganization}
          typed={shown.name}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.deleteOrganization(shown.id);
            close();
            say(text.organizationDeleted(shown.name));
            go({ name: "organizations" });
          }}
        >
          <ul className="console-facts">
            {units.state === "loaded" ? (
              <Consequence what={text.deleteOrganizationUnits} value={units.value.length} />
            ) : null}
            <Consequence what={text.deleteOrganizationMembers} value={text.deleteOrganizationMembersValue} />
            {invitations.state === "loaded" ? (
              <Consequence what={text.deleteOrganizationInvitations} value={invitations.value.length} />
            ) : null}
          </ul>
        </Confirm>
      ) : null}

      {open?.kind === "createUnit" || open?.kind === "changeUnit" ? (
        <UnitForm
          current={open.kind === "changeUnit" ? open.unit : null}
          units={allUnits}
          text={text}
          submit={(settings) =>
            open.kind === "changeUnit"
              ? client.changeUnit(shown.id, open.unit.id, settings)
              : client.createUnit(shown.id, settings)
          }
          onClose={close}
          onDone={(saved) => {
            close();
            say(open.kind === "changeUnit" ? text.unitChanged(saved.name) : text.unitCreated(saved.name));
            againUnits();
          }}
        />
      ) : null}

      {open?.kind === "deleteUnit" ? (
        <Confirm
          action="deleteUnit"
          title={text.deleteUnitTitle(open.unit.name)}
          confirmLabel={text.deleteUnit}
          typed={open.unit.name}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.deleteUnit(shown.id, open.unit.id);
            close();
            say(text.unitDeleted(open.unit.name));
            againUnits();
            againMembers();
            againInvitations();
          }}
        >
          <ul className="console-facts">
            <Consequence what={text.deleteUnitMembers} value={text.deleteUnitMembersValue} />
          </ul>
        </Confirm>
      ) : null}

      {open?.kind === "putMember" || open?.kind === "changeMember" ? (
        <MemberForm
          organization={shown.name}
          current={
            open.kind === "changeMember"
              ? {
                  userId: open.member.userId,
                  unitIds: open.member.unitIds,
                  shown: <NameOf of="user" id={open.member.userId} {...names} />,
                }
              : null
          }
          units={allUnits}
          text={text}
          onClose={close}
          submit={async (userId, unitIds) => {
            await client.putOrganizationMember(shown.id, userId, unitIds);
            close();
            say(text.memberSaved);
            againMembers();
          }}
        />
      ) : null}

      {open?.kind === "removeMember" ? (
        <Confirm
          action="removeOrganizationMember"
          title={text.removeOrganizationMemberTitle(shown.name)}
          confirmLabel={text.takeOut}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.removeOrganizationMember(shown.id, open.member.userId);
            close();
            say(text.memberRemoved);
            againMembers();
          }}
        >
          <Text>
            <NameOf of="user" id={open.member.userId} {...names} />
          </Text>
          <Text>{text.removeOrganizationMemberLead(shown.name)}</Text>
        </Confirm>
      ) : null}

      {open?.kind === "invite" ? (
        <InviteForm
          organization={shown.name}
          units={allUnits}
          text={text}
          onClose={close}
          submit={async (email, unitIds, locale) => {
            await client.invite(shown.id, email, unitIds, locale);
            close();
            say(text.invitationSent(email));
            againInvitations();
          }}
        />
      ) : null}

      {open?.kind === "withdraw" ? (
        <Confirm
          action="withdrawInvitation"
          title={text.withdrawTitle(open.invitation.email)}
          confirmLabel={text.withdraw}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.withdrawInvitation(shown.id, open.invitation.id);
            close();
            say(text.invitationWithdrawn);
            againInvitations();
          }}
        >
          <Text>{text.withdrawLead}</Text>
        </Confirm>
      ) : null}
    </Page>
  );
}
