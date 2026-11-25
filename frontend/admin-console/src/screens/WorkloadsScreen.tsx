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
import { may } from "../actions";
import type { Screen } from "../address";
import type { Failure, Page as Paged, Workload, WorkloadKind } from "../client";
import { moment } from "../messages";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";
import { StatusBadge } from "./UsersScreen";
import { ofKind, WorkloadForm } from "./WorkloadForm";
import { follow, Page, type ScreenProps } from "./shared";

/** The screen of one workload of a kind. */
export function screenOf(kind: WorkloadKind, id: string): Screen {
  return kind === "agent" ? { name: "agent", id } : { name: "serviceAccount", id };
}

type Row = { id: string; workload: Workload };

/** The service accounts, or the agents, of the tenant, oldest first, and the form that creates one. */
export function WorkloadsScreen({ kind, client, me, text, go, path, say }: ScreenProps & { kind: WorkloadKind }) {
  const first = useCallback(() => client.listWorkloads(kind), [client, kind]);
  const [loading, again, replace] = useLoaded<Paged<Workload>>(first);
  const [creating, setCreating] = useState(false);
  const [more, setMore] = useState<{ busy: boolean; failure: Failure | null }>({ busy: false, failure: null });

  async function loadMore(shown: Paged<Workload>) {
    if (more.busy || shown.nextCursor === null) {
      return;
    }
    setMore({ busy: true, failure: null });
    try {
      const next = await client.listWorkloads(kind, shown.nextCursor);
      replace({ items: [...shown.items, ...next.items], nextCursor: next.nextCursor });
      setMore({ busy: false, failure: null });
    } catch (thrown) {
      setMore({ busy: false, failure: asFailure(thrown) });
    }
  }

  return (
    <Page
      title={ofKind(kind, text.workloadsTitle)}
      lead={ofKind(kind, text.workloadsLead)}
      actions={
        may(me.permissions, "createWorkload") ? (
          <Button
            variant="primary"
            label={ofKind(kind, text.createWorkload)}
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
            data={loading.value.items.map((workload) => ({ id: workload.id, workload }))}
            idKey="id"
            hasHover
            emptyState={
              <EmptyState
                title={ofKind(kind, text.noWorkloads)}
                description={ofKind(kind, text.noWorkloadsHint)}
                isCompact
              />
            }
            columns={[
              {
                key: "name",
                header: text.columnName,
                renderCell: ({ workload }) => {
                  const screen = screenOf(kind, workload.id);
                  return (
                    <Link href={path(screen)} onClick={(event) => follow(event, go, screen)}>
                      {workload.name}
                    </Link>
                  );
                },
              },
              {
                key: "status",
                header: text.columnStatus,
                renderCell: ({ workload }) => <StatusBadge status={workload.status} text={text} />,
              },
              {
                key: "owners",
                header: text.columnOwners,
                renderCell: ({ workload }) => <Text color="secondary">{text.ownerCount(workload.owners.length)}</Text>,
              },
              {
                key: "created",
                header: text.columnCreated,
                renderCell: ({ workload }) => <Text color="secondary">{moment(workload.createdAt, text)}</Text>,
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
        <WorkloadForm
          kind={kind}
          current={null}
          text={text}
          submit={(settings) => client.createWorkload(kind, settings)}
          onClose={() => setCreating(false)}
          onDone={(made) => {
            setCreating(false);
            say(text.workloadCreated(made.name));
            go(screenOf(kind, made.id));
          }}
        />
      ) : null}
    </Page>
  );
}
