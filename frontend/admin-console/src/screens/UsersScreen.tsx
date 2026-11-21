import { Badge } from "@astryxdesign/core/Badge";
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { HStack } from "@astryxdesign/core/HStack";
import { Icon } from "@astryxdesign/core/Icon";
import { Link } from "@astryxdesign/core/Link";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { UserPlus } from "lucide-react";
import { type FormEvent, type MouseEvent, useCallback, useState } from "react";
import { may } from "../actions";
import type { Failure, Page as Paged, User } from "../client";
import { describe, moment, named, type Messages } from "../messages";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";
import { Page, type ScreenProps } from "./shared";

/** The name a user goes by in a list: their name, or their first address. */
export function nameOf(user: User, text: Messages): string {
  return user.displayName ?? user.identifiers.find((identifier) => identifier.primary)?.value ?? text.unnamed;
}

const tone = { active: "success", suspended: "error", pending: "info" } as const;

export function StatusBadge({ status, text }: { status: string; text: Messages }) {
  return <Badge variant={tone[status as keyof typeof tone] ?? "neutral"} label={named(text.status, status)} />;
}

type Row = { id: string; user: User };

export function UsersScreen({ client, me, text, go, path, say }: ScreenProps) {
  const first = useCallback(() => client.listUsers(), [client]);
  const [loading, again, replace] = useLoaded<Paged<User>>(first);
  const [creating, setCreating] = useState(false);
  const [more, setMore] = useState<{ busy: boolean; failure: Failure | null }>({ busy: false, failure: null });

  async function loadMore(shown: Paged<User>) {
    if (more.busy || shown.nextCursor === null) {
      return;
    }
    setMore({ busy: true, failure: null });
    try {
      const next = await client.listUsers(shown.nextCursor);
      replace({ items: [...shown.items, ...next.items], nextCursor: next.nextCursor });
      setMore({ busy: false, failure: null });
    } catch (thrown) {
      setMore({ busy: false, failure: asFailure(thrown) });
    }
  }

  function open(event: MouseEvent, user: User) {
    // A plain click stays in the console; a click that asks for a new tab gets one.
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    go({ name: "user", id: user.id });
  }

  return (
    <Page
      title={text.users}
      lead={text.usersLead}
      actions={
        may(me.permissions, "createUser") ? (
          <Button
            variant="primary"
            label={text.createUser}
            icon={<Icon icon={UserPlus} />}
            onClick={() => setCreating(true)}
          />
        ) : null
      }
    >
      {loading.state === "loading" ? <Waiting text={text} /> : null}
      {loading.state === "failed" ? <Failed failure={loading.failure} again={again} text={text} /> : null}
      {loading.state === "loaded" ? (
        <VStack gap={4}>
          <Table<Row>
            data={loading.value.items.map((user) => ({ id: user.id, user }))}
            idKey="id"
            hasHover
            emptyState={<EmptyState title={text.noUsers} description={text.noUsersHint} isCompact />}
            columns={[
              {
                key: "user",
                header: text.columnUser,
                renderCell: ({ user }) => (
                  <Link href={path({ name: "user", id: user.id })} onClick={(event) => open(event, user)}>
                    {nameOf(user, text)}
                  </Link>
                ),
              },
              {
                key: "status",
                header: text.columnStatus,
                renderCell: ({ user }) => <StatusBadge status={user.status} text={text} />,
              },
              {
                key: "identifiers",
                header: text.columnIdentifiers,
                renderCell: ({ user }) => (
                  <VStack gap={1}>
                    {user.identifiers.map((identifier) => (
                      <HStack key={identifier.id} gap={2} vAlign="center">
                        <Text>{identifier.value}</Text>
                        {identifier.verified ? null : <Badge variant="warning" label={text.notVerified} />}
                      </HStack>
                    ))}
                  </VStack>
                ),
              },
              {
                key: "created",
                header: text.columnCreated,
                renderCell: ({ user }) => <Text color="secondary">{moment(user.createdAt, text)}</Text>,
              },
            ]}
          />
          {more.failure !== null ? <Failed failure={more.failure} text={text} /> : null}
          {loading.value.nextCursor !== null ? (
            <HStack justify="center">
              <Button label={text.loadMore} isLoading={more.busy} onClick={() => void loadMore(loading.value)} />
            </HStack>
          ) : null}
        </VStack>
      ) : null}

      {creating ? (
        <CreateUser
          text={text}
          create={(email, name) => client.createUser(email, name)}
          onClose={() => setCreating(false)}
          onCreated={(user) => {
            setCreating(false);
            say(text.userCreated(nameOf(user, text)));
            go({ name: "user", id: user.id });
          }}
        />
      ) : null}
    </Page>
  );
}

interface CreateUserProps {
  text: Messages;
  create: (email: string, displayName: string) => Promise<User>;
  onClose: () => void;
  onCreated: (user: User) => void;
}

/** Level 0 on the ladder: the form is its own confirmation. */
function CreateUser({ text, create, onClose, onCreated }: CreateUserProps) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || email.trim() === "") {
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      onCreated(await create(email, name));
    } catch (thrown) {
      setFailure(asFailure(thrown));
      setBusy(false);
    }
  }

  const aboutEmail = failure?.code === "identity.identifier_taken" || failure?.code === "identity.email_invalid";

  return (
    <Dialog isOpen onOpenChange={onClose} width={480} purpose="form">
      <DialogHeader title={text.createUserTitle} />
      <form noValidate onSubmit={(event) => void submit(event)}>
        <VStack gap={4} padding={4}>
          <Text color="secondary">{text.createUserLead}</Text>
          {failure !== null && !aboutEmail ? (
            <Banner status="error" title={describe(failure, text)} role="alert" />
          ) : null}
          <TextInput
            label={text.emailLabel}
            type="email"
            htmlName="email"
            autoComplete="off"
            autoCapitalize="none"
            hasSpellCheck={false}
            hasAutoFocus
            value={email}
            onChange={setEmail}
            status={failure !== null && aboutEmail ? { type: "error", message: describe(failure, text) } : undefined}
            statusVariant="detached"
            width="100%"
          />
          <TextInput
            label={`${text.displayNameLabel} (${text.optional})`}
            htmlName="name"
            autoComplete="off"
            value={name}
            onChange={setName}
            width="100%"
          />
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button type="submit" variant="primary" label={text.createUser} isLoading={busy} />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
