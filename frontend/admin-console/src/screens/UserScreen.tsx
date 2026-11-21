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
import type { Session, User } from "../client";
import { moment, named } from "../messages";
import { Confirm, Consequence } from "../parts/Confirm";
import { Identifier } from "../parts/Identifier";
import { Failed, useLoaded, Waiting } from "../parts/Loaded";
import { Page, type ScreenProps } from "./shared";
import { nameOf, StatusBadge } from "./UsersScreen";

type Row = { id: string; session: Session };

export function UserScreen({ id, client, me, text, go, path, say }: ScreenProps & { id: string }) {
  const loadUser = useCallback(() => client.getUser(id), [client, id]);
  const [user, againUser, replaceUser] = useLoaded<User>(loadUser);
  const maySeeSessions = me.permissions.includes("sessions:read");
  const loadSessions = useCallback(
    () => (maySeeSessions ? client.listSessions(id) : Promise.resolve([])),
    [client, id, maySeeSessions],
  );
  const [sessions, againSessions] = useLoaded<Session[]>(loadSessions);
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
