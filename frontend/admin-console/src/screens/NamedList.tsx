import { Button } from "@astryxdesign/core/Button";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { HStack } from "@astryxdesign/core/HStack";
import { Icon } from "@astryxdesign/core/Icon";
import { Link } from "@astryxdesign/core/Link";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { Plus } from "lucide-react";
import { useCallback, useState } from "react";
import { type ActionName, may } from "../actions";
import type { Failure, Named, NamedSettings, Page as Paged } from "../client";
import { moment } from "../messages";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";
import { NamedForm } from "./NamedForm";
import { follow, Page, type ScreenProps } from "./shared";

/** What tells the screen of groups from the screen of organizations. */
export interface Listed {
  /** The screen of one of them. */
  one: "group" | "organization";
  title: string;
  lead: string;
  create: ActionName;
  createLabel: string;
  createTitle: string;
  empty: string;
  emptyHint: string;
  created: (name: string) => string;
  list: (cursor: string | null) => Promise<Paged<Named>>;
  add: (settings: NamedSettings) => Promise<Named>;
}

type Row = { id: string; named: Named };

/** A table of groups or organizations, oldest first, a page at a time, and the form that creates one. */
export function NamedList({ listed, me, text, go, path, say }: Omit<ScreenProps, "client"> & { listed: Listed }) {
  const { list } = listed;
  const first = useCallback(() => list(null), [list]);
  const [loading, again, replace] = useLoaded<Paged<Named>>(first);
  const [creating, setCreating] = useState(false);
  const [more, setMore] = useState<{ busy: boolean; failure: Failure | null }>({ busy: false, failure: null });

  async function loadMore(shown: Paged<Named>) {
    if (more.busy || shown.nextCursor === null) {
      return;
    }
    setMore({ busy: true, failure: null });
    try {
      const next = await list(shown.nextCursor);
      replace({ items: [...shown.items, ...next.items], nextCursor: next.nextCursor });
      setMore({ busy: false, failure: null });
    } catch (thrown) {
      setMore({ busy: false, failure: asFailure(thrown) });
    }
  }

  return (
    <Page
      title={listed.title}
      lead={listed.lead}
      actions={
        may(me.permissions, listed.create) ? (
          <Button
            variant="primary"
            label={listed.createLabel}
            icon={<Icon icon={Plus} />}
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
            data={loading.value.items.map((named) => ({ id: named.id, named }))}
            idKey="id"
            hasHover
            emptyState={<EmptyState title={listed.empty} description={listed.emptyHint} isCompact />}
            columns={[
              {
                key: "name",
                header: text.columnName,
                renderCell: ({ named }) => {
                  const screen = { name: listed.one, id: named.id };
                  return (
                    <Link href={path(screen)} onClick={(event) => follow(event, go, screen)}>
                      {named.name}
                    </Link>
                  );
                },
              },
              {
                key: "description",
                header: text.columnDescription,
                renderCell: ({ named }) =>
                  named.description === null ? (
                    <Text color="secondary">{text.noDescription}</Text>
                  ) : (
                    <Text>{named.description}</Text>
                  ),
              },
              {
                key: "created",
                header: text.columnCreated,
                renderCell: ({ named }) => <Text color="secondary">{moment(named.createdAt, text)}</Text>,
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
        <NamedForm
          current={null}
          action={listed.create}
          title={listed.createTitle}
          confirmLabel={listed.createLabel}
          text={text}
          submit={listed.add}
          onClose={() => setCreating(false)}
          onDone={(named) => {
            setCreating(false);
            say(listed.created(named.name));
            go({ name: listed.one, id: named.id });
          }}
        />
      ) : null}
    </Page>
  );
}
