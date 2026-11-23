import { Badge } from "@astryxdesign/core/Badge";
import { Banner } from "@astryxdesign/core/Banner";
import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type MouseEvent, useCallback, useState } from "react";
import { may } from "../actions";
import type { PersonFactors, PersonKey, Session, User } from "../client";
import { moment, named } from "../messages";
import { Confirm, Consequence } from "../parts/Confirm";
import { RoleAssignments } from "./RoleAssignments";
import { Identifier } from "../parts/Identifier";
import { Failed, useLoaded, Waiting } from "../parts/Loaded";
import { Page, type ScreenProps } from "./shared";
import { nameOf, StatusBadge } from "./UsersScreen";

type Row = { id: string; session: Session };
type KeyRow = { id: string; key: PersonKey };

/** What is being removed from a person, when the dialog is open. */
type Removing = { kind: "application" } | { kind: "key"; key: PersonKey } | { kind: "codes" };

export function UserScreen({ id, client, me, text, go, path, say }: ScreenProps & { id: string }) {
  const loadUser = useCallback(() => client.getUser(id), [client, id]);
  const [user, againUser, replaceUser] = useLoaded<User>(loadUser);
  const maySeeSessions = me.permissions.includes("sessions:read");
  const loadSessions = useCallback(
    () => (maySeeSessions ? client.listSessions(id) : Promise.resolve([])),
    [client, id, maySeeSessions],
  );
  const [sessions, againSessions] = useLoaded<Session[]>(loadSessions);
  const maySeeFactors = me.permissions.includes("credentials:read");
  const loadFactors = useCallback(
    () =>
      maySeeFactors
        ? client.listFactors(id)
        : Promise.resolve<PersonFactors>({
            authenticatorApplication: null,
            keys: [],
            recoveryCodesRemaining: 0,
            secondFactorRequired: false,
          }),
    [client, id, maySeeFactors],
  );
  const [factors, againFactors] = useLoaded<PersonFactors>(loadFactors);
  const [removing, setRemoving] = useState<Removing | null>(null);
  const [suspending, setSuspending] = useState(false);
  const [reason, setReason] = useState("");
  const [ending, setEnding] = useState<Session | null>(null);

  function back(event: MouseEvent) {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    go({ name: "users" });
  }

  const above = (
    <Breadcrumbs variant="supporting">
      <BreadcrumbItem href={path({ name: "users" })} onClick={back}>
        {text.users}
      </BreadcrumbItem>
      <BreadcrumbItem>{text.userTitle}</BreadcrumbItem>
    </Breadcrumbs>
  );

  if (user.state !== "loaded") {
    return (
      <Page title={text.userTitle} above={above}>
        {user.state === "loading" ? <Waiting text={text} /> : <Failed failure={user.failure} again={againUser} text={text} />}
      </Page>
    );
  }

  const shown = user.value;
  const who = nameOf(shown, text);
  // What the person types to confirm: the address, or the identifier when there is none.
  const typed = shown.identifiers.find((identifier) => identifier.primary)?.value ?? shown.id;
  const active = sessions.state === "loaded" ? sessions.value : [];
  const shownFactors = factors.state === "loaded" ? factors.value : null;
  const secondFactors =
    shownFactors === null
      ? 0
      : (shownFactors.authenticatorApplication?.inUse === true ? 1 : 0) + shownFactors.keys.length;
  const mayRemove = may(me.permissions, "removeFactor");

  return (
    <Page
      title={who}
      above={above}
      lead={<StatusBadge status={shown.status} text={text} />}
      actions={
        may(me.permissions, "suspendUser") && shown.status === "active" && shown.id !== me.user.id ? (
          <Button variant="destructive" label={text.suspendUser} onClick={() => setSuspending(true)} />
        ) : null
      }
    >
      {shown.status === "suspended" && shown.statusReason !== null ? (
        <Banner status="warning" title={text.suspendedBecause(shown.statusReason)} />
      ) : null}

      <div className="console-split">
        <Card>
          <VStack gap={3}>
            <Heading level={2}>{text.profile}</Heading>
            <MetadataList>
              <MetadataListItem label={text.identifierLabel}>
                <Identifier value={shown.id} whole text={text} />
              </MetadataListItem>
              <MetadataListItem label={text.kind}>{named(text.kinds, shown.kind)}</MetadataListItem>
              <MetadataListItem label={text.displayNameLabel}>{shown.displayName ?? text.unnamed}</MetadataListItem>
              <MetadataListItem label={text.language}>{shown.locale ?? "—"}</MetadataListItem>
              <MetadataListItem label={text.created}>{moment(shown.createdAt, text)}</MetadataListItem>
              <MetadataListItem label={text.changed}>{moment(shown.updatedAt, text)}</MetadataListItem>
            </MetadataList>
          </VStack>
        </Card>

        <Card>
          <VStack gap={3}>
            <Heading level={2}>{text.identifiers}</Heading>
            {shown.identifiers.map((identifier) => (
              <HStack key={identifier.id} gap={2} vAlign="center" wrap="wrap">
                <Text>{identifier.value}</Text>
                <Badge
                  variant={identifier.verified ? "success" : "warning"}
                  label={identifier.verified ? text.verified : text.notVerified}
                />
                {identifier.primary ? <Badge label={text.primary} /> : null}
              </HStack>
            ))}
          </VStack>
        </Card>
      </div>

      {maySeeSessions ? (
        <Card>
          <VStack gap={3}>
            <Heading level={2}>{text.sessions}</Heading>
            {sessions.state === "loading" ? <Waiting text={text} /> : null}
            {sessions.state === "failed" ? <Failed failure={sessions.failure} again={againSessions} text={text} /> : null}
            {sessions.state === "loaded" ? (
              <Table<Row>
                data={active.map((session) => ({ id: session.sessionId, session }))}
                idKey="id"
                emptyState={<EmptyState title={text.noSessions} description={text.noSessionsHint} isCompact />}
                columns={[
                  {
                    key: "device",
                    header: text.columnDevice,
                    renderCell: ({ session }) => session.description ?? text.unknownDevice,
                  },
                  {
                    key: "address",
                    header: text.columnAddress,
                    renderCell: ({ session }) => <span className="console-mono">{session.address ?? "—"}</span>,
                  },
                  {
                    key: "started",
                    header: text.columnStarted,
                    renderCell: ({ session }) => moment(session.startedAt, text),
                  },
                  {
                    key: "last",
                    header: text.columnLastActivity,
                    renderCell: ({ session }) => moment(session.lastActivityAt, text),
                  },
                  {
                    key: "end",
                    header: "",
                    align: "end",
                    renderCell: ({ session }) =>
                      may(me.permissions, "endSession") ? (
                        <Button size="sm" label={text.endSession} onClick={() => setEnding(session)} />
                      ) : null,
                  },
                ]}
              />
            ) : null}
          </VStack>
        </Card>
      ) : null}

      {maySeeFactors ? (
        <Card>
          <VStack gap={3}>
            <Heading level={2}>{text.factors}</Heading>
            {factors.state === "loading" ? <Waiting text={text} /> : null}
            {factors.state === "failed" ? <Failed failure={factors.failure} again={againFactors} text={text} /> : null}
            {shownFactors !== null ? (
              <VStack gap={3}>
                {shownFactors.secondFactorRequired ? <Badge variant="info" label={text.secondFactorRequired} /> : null}
                <HStack gap={2} vAlign="center" wrap="wrap">
                  <Text weight="semibold">{text.authenticatorApplication}</Text>
                  {shownFactors.authenticatorApplication === null ? (
                    <Text color="secondary">{text.noFactorsOffered}</Text>
                  ) : (
                    <>
                      <Badge
                        variant={shownFactors.authenticatorApplication.inUse ? "success" : "neutral"}
                        label={shownFactors.authenticatorApplication.inUse ? text.inUse : text.notInUse}
                      />
                      {shownFactors.authenticatorApplication.inUse && mayRemove ? (
                        <Button size="sm" label={text.remove} onClick={() => setRemoving({ kind: "application" })} />
                      ) : null}
                    </>
                  )}
                </HStack>
                <Table<KeyRow>
                  data={shownFactors.keys.map((key) => ({ id: key.id, key }))}
                  idKey="id"
                  emptyState={<EmptyState title={text.noPersonKeys} description={text.noPersonKeysHint} isCompact />}
                  columns={[
                    { key: "name", header: text.columnKey, renderCell: ({ key }) => key.name },
                    {
                      key: "kind",
                      header: text.columnKind,
                      renderCell: ({ key }) => (key.passkey ? text.passkey : text.securityKey),
                    },
                    { key: "added", header: text.columnAdded, renderCell: ({ key }) => moment(key.createdAt, text) },
                    {
                      key: "used",
                      header: text.columnLastUsed,
                      renderCell: ({ key }) => (key.lastUsedAt === null ? text.never : moment(key.lastUsedAt, text)),
                    },
                    {
                      key: "remove",
                      header: "",
                      align: "end",
                      renderCell: ({ key }) =>
                        mayRemove ? (
                          <Button size="sm" label={text.remove} onClick={() => setRemoving({ kind: "key", key })} />
                        ) : null,
                    },
                  ]}
                />
                <HStack gap={2} vAlign="center" wrap="wrap">
                  <Text weight="semibold">{text.recoveryCodes}</Text>
                  <Text>{text.recoveryCodesLeft(shownFactors.recoveryCodesRemaining)}</Text>
                  {shownFactors.recoveryCodesRemaining > 0 && mayRemove ? (
                    <Button size="sm" label={text.remove} onClick={() => setRemoving({ kind: "codes" })} />
                  ) : null}
                </HStack>
              </VStack>
            ) : null}
          </VStack>
        </Card>
      ) : null}

      {me.permissions.includes("roles:read") ? (
        <Card padding={5}>
          <RoleAssignments kind="user" id={id} client={client} me={me} text={text} say={say} />
        </Card>
      ) : null}

      {removing !== null && shownFactors !== null ? (
        <Confirm
          action="removeFactor"
          title={
            removing.kind === "application"
              ? text.removeApplicationTitle
              : removing.kind === "key"
                ? text.removePersonKeyTitle(removing.key.name)
                : text.removeCodesTitle
          }
          confirmLabel={text.remove}
          typed={typed}
          text={text}
          onClose={() => setRemoving(null)}
          onConfirm={async () => {
            if (removing.kind === "application") {
              await client.removeAuthenticatorApplication(shown.id);
            } else if (removing.kind === "key") {
              await client.removePersonKey(shown.id, removing.key.id);
            } else {
              await client.removeRecoveryCodes(shown.id);
            }
            setRemoving(null);
            say(text.factorRemoved);
            againFactors();
          }}
        >
          <ul className="console-facts">
            {removing.kind !== "codes" ? (
              <Consequence what={text.removeConsequenceUse} value={text.removeConsequenceUseValue} />
            ) : null}
            {removing.kind !== "codes" && secondFactors === 1 ? (
              <Consequence what={text.removeConsequenceLast} value={shownFactors.recoveryCodesRemaining} />
            ) : null}
            {removing.kind !== "codes" && secondFactors === 1 && shownFactors.secondFactorRequired ? (
              <Consequence what={text.removeConsequenceLocked} value={text.removeConsequenceLockedValue} />
            ) : null}
            <Consequence what={text.removeConsequenceSessions} value={text.removeConsequenceSessionsValue} />
          </ul>
        </Confirm>
      ) : null}

      {suspending ? (
        <Confirm
          action="suspendUser"
          title={text.suspendTitle(who)}
          confirmLabel={text.suspendUser}
          typed={typed}
          ready={reason.trim() !== ""}
          text={text}
          onClose={() => setSuspending(false)}
          onConfirm={async () => {
            replaceUser(await client.suspendUser(shown.id, reason));
            setSuspending(false);
            setReason("");
            say(text.userSuspended(who));
            againSessions();
          }}
        >
          <ul className="console-facts">
            <Consequence what={text.suspendConsequenceSignIn} value={text.suspendConsequenceSignInValue} />
            {maySeeSessions && sessions.state === "loaded" ? (
              <Consequence what={text.suspendConsequenceSessions} value={active.length} />
            ) : null}
            <Consequence what={text.suspendConsequenceUndo} value={text.suspendConsequenceUndoValue} />
          </ul>
          <TextInput
            label={text.reasonLabel}
            description={text.reasonHint}
            value={reason}
            onChange={setReason}
            autoComplete="off"
            hasAutoFocus
            width="100%"
          />
        </Confirm>
      ) : null}

      {ending !== null ? (
        <Confirm
          action="endSession"
          title={text.endSessionTitle}
          confirmLabel={text.endSession}
          text={text}
          onClose={() => setEnding(null)}
          onConfirm={async () => {
            await client.endSession(ending.sessionId);
            setEnding(null);
            say(text.sessionEnded);
            againSessions();
          }}
        >
          <Text>{text.endSessionLead(ending.description ?? text.unknownDevice)}</Text>
        </Confirm>
      ) : null}
    </Page>
  );
}
