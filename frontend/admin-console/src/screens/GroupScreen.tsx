import { Banner } from "@astryxdesign/core/Banner";
import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useCallback, useState } from "react";
import { may } from "../actions";
import { isIdentifier } from "../address";
import type { Failure, Group, GroupMember, Page as Paged } from "../client";
import { describe, moment, named, type Messages } from "../messages";
import { Confirm, Consequence, Ladder } from "../parts/Confirm";
import { Identifier } from "../parts/Identifier";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";
import { NamedForm } from "./NamedForm";
import { NameOf, useNames } from "./names";
import { follow, Page, type ScreenProps } from "./shared";

type Open = { kind: "change" } | { kind: "delete" } | { kind: "add" } | { kind: "remove"; member: GroupMember } | null;
type Row = { id: string; member: GroupMember };

/** One group: its name and description, and its direct members, users first. */
export function GroupScreen({ id, client, me, text, go, path, say }: ScreenProps & { id: string }) {
  const loadGroup = useCallback(() => client.getGroup(id), [client, id]);
  const [group, againGroup, replaceGroup] = useLoaded<Group>(loadGroup);
  const loadMembers = useCallback(() => client.listGroupMembers(id), [client, id]);
  const [members, againMembers, replaceMembers] = useLoaded<Paged<GroupMember>>(loadMembers);
  const [more, setMore] = useState<{ busy: boolean; failure: Failure | null }>({ busy: false, failure: null });
  const [open, setOpen] = useState<Open>(null);
  const close = () => setOpen(null);
  const known = useNames();

  const above = (
    <Breadcrumbs variant="supporting">
      <BreadcrumbItem href={path({ name: "groups" })} onClick={(event) => follow(event, go, { name: "groups" })}>
        {text.groups}
      </BreadcrumbItem>
      <BreadcrumbItem>{text.groupTitle}</BreadcrumbItem>
    </Breadcrumbs>
  );

  if (group.state !== "loaded") {
    return (
      <Page title={text.groupTitle} above={above}>
        {group.state === "loading" ? (
          <Waiting text={text} />
        ) : (
          <Failed failure={group.failure} again={againGroup} text={text} />
        )}
      </Page>
    );
  }

  const shown = group.value;
  const mayChange = may(me.permissions, "changeGroup");
  const names = { client, me, text, go, path, known };

  async function loadMore(page: Paged<GroupMember>) {
    if (more.busy || page.nextCursor === null) {
      return;
    }
    setMore({ busy: true, failure: null });
    try {
      const next = await client.listGroupMembers(id, page.nextCursor);
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
        mayChange ? (
          <>
            <Button label={text.changeSettings} onClick={() => setOpen({ kind: "change" })} />
            {may(me.permissions, "deleteGroup") ? (
              <Button variant="destructive" label={text.deleteGroup} onClick={() => setOpen({ kind: "delete" })} />
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
            <VStack gap={1}>
              <Heading level={2}>{text.members}</Heading>
              <Text type="supporting" color="secondary">
                {text.groupMembersLead}
              </Text>
            </VStack>
            {may(me.permissions, "addGroupMember") ? (
              <Button label={text.addMember} onClick={() => setOpen({ kind: "add" })} />
            ) : null}
          </HStack>
          {members.state === "loading" ? <Waiting text={text} /> : null}
          {members.state === "failed" ? <Failed failure={members.failure} again={againMembers} text={text} /> : null}
          {members.state === "loaded" ? (
            <VStack gap={4}>
              <Table<Row>
                data={members.value.items.map((member) => ({ id: `${member.kind} ${member.id}`, member }))}
                idKey="id"
                emptyState={<EmptyState title={text.noGroupMembers} description={text.noGroupMembersHint} isCompact />}
                columns={[
                  {
                    key: "member",
                    header: text.columnMember,
                    renderCell: ({ member }) => <NameOf of={member.kind} id={member.id} {...names} />,
                  },
                  {
                    key: "kind",
                    header: text.columnKind,
                    renderCell: ({ member }) => named(text.memberKinds, member.kind),
                  },
                  {
                    key: "remove",
                    header: "",
                    align: "end",
                    renderCell: ({ member }) =>
                      may(me.permissions, "removeGroupMember") ? (
                        <Button size="sm" label={text.takeOut} onClick={() => setOpen({ kind: "remove", member })} />
                      ) : null,
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

      {open?.kind === "change" ? (
        <NamedForm
          current={shown}
          action="changeGroup"
          title={text.changeSettingsTitle(shown.name)}
          confirmLabel={text.saveGroup}
          text={text}
          submit={(settings) => client.changeGroup(shown.id, settings)}
          onClose={close}
          onDone={(changed) => {
            replaceGroup(changed);
            close();
            say(text.groupChanged(changed.name));
          }}
        />
      ) : null}

      {open?.kind === "delete" ? (
        <Confirm
          action="deleteGroup"
          title={text.deleteGroupTitle(shown.name)}
          confirmLabel={text.deleteGroup}
          typed={shown.name}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.deleteGroup(shown.id);
            close();
            say(text.groupDeleted(shown.name));
            go({ name: "groups" });
          }}
        >
          <ul className="console-facts">
            <Consequence what={text.deleteGroupMembers} value={text.deleteGroupMembersValue} />
            <Consequence what={text.deleteGroupAbove} value={text.deleteGroupAboveValue} />
          </ul>
        </Confirm>
      ) : null}

      {open?.kind === "add" ? (
        <AddMember
          group={shown}
          text={text}
          add={(member) => client.addGroupMember(shown.id, member)}
          onClose={close}
          onAdded={() => {
            close();
            say(text.memberAdded);
            againMembers();
          }}
        />
      ) : null}

      {open?.kind === "remove" ? (
        <Confirm
          action="removeGroupMember"
          title={text.removeGroupMemberTitle(shown.name)}
          confirmLabel={text.takeOut}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.removeGroupMember(shown.id, open.member);
            close();
            say(text.memberRemoved);
            againMembers();
          }}
        >
          <Text>
            <NameOf of={open.member.kind} id={open.member.id} {...names} />
          </Text>
          <Text>{open.member.kind === "user" ? text.removeUserLead(shown.name) : text.removeGroupLead(shown.name)}</Text>
        </Confirm>
      ) : null}
    </Page>
  );
}

interface AddMemberProps {
  group: Group;
  text: Messages;
  add: (member: GroupMember) => Promise<void>;
  onClose: () => void;
  onAdded: () => void;
}

/**
 * Adds a user or a group by its identifier. Level 1: before its button
 * the form says who will be in the group.
 */
function AddMember({ group, text, add, onClose, onAdded }: AddMemberProps) {
  const [kind, setKind] = useState<GroupMember["kind"]>("user");
  const [identifier, setIdentifier] = useState("");
  const [busy, setBusy] = useState(false);
  // What went wrong, in words: said before asking the server when the identifier is not one.
  const [message, setMessage] = useState<string | null>(null);
  const wanted = identifier.trim().toLowerCase();

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || wanted === "") {
      return;
    }
    if (!isIdentifier(wanted)) {
      setMessage(text.notAnIdentifier);
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      await add({ kind, id: wanted });
      onAdded();
    } catch (thrown) {
      setMessage(describe(asFailure(thrown), text));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={520} purpose="form">
      <DialogHeader title={text.addMemberTitle(group.name)} subtitle={<Ladder action="addGroupMember" text={text} />} />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {message !== null ? <Banner status="error" title={message} role="alert" /> : null}
          <VStack gap={1}>
            <Text>{text.memberKindLabel}</Text>
            <SegmentedControl
              label={text.memberKindLabel}
              value={kind}
              onChange={(value) => setKind(value === "group" ? "group" : "user")}
            >
              <SegmentedControlItem value="user" label={named(text.memberKinds, "user")} />
              <SegmentedControlItem value="group" label={named(text.memberKinds, "group")} />
            </SegmentedControl>
          </VStack>
          <TextInput
            label={kind === "user" ? text.userIdentifierLabel : text.groupIdentifierLabel}
            description={text.memberIdentifierHint}
            value={identifier}
            onChange={setIdentifier}
            autoComplete="off"
            autoCapitalize="none"
            hasSpellCheck={false}
            hasAutoFocus
            width="100%"
          />
          <Text color="secondary">
            {kind === "user" ? text.addUserConsequence(group.name) : text.addGroupConsequence(group.name)}
          </Text>
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button
              type="submit"
              variant="primary"
              label={text.addMember}
              isDisabled={wanted === ""}
              isLoading={busy}
            />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
