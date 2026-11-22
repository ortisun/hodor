import { Button } from "@astryxdesign/core/Button";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { HStack } from "@astryxdesign/core/HStack";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { useCallback, useState } from "react";
import type { AuditRecord, Failure, Page as Paged } from "../client";
import { moment, type Messages } from "../messages";
import { Identifier } from "../parts/Identifier";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";
import { Page, type ScreenProps } from "./shared";

type Row = { id: string; record: AuditRecord };

function Actor({ record, text }: { record: AuditRecord; text: Messages }) {
  const kinds: Record<string, string> = { system: text.actorSystem, anonymous: text.actorAnonymous };
  return record.actor.id === null ? (
    <Text>{kinds[record.actor.kind] ?? record.actor.kind}</Text>
  ) : (
    <Identifier value={record.actor.id} text={text} />
  );
}

export function AuditScreen({ client, text }: ScreenProps) {
  const first = useCallback(() => client.listAuditRecords(), [client]);
  const [loading, again, replace] = useLoaded<Paged<AuditRecord>>(first);
  const [more, setMore] = useState<{ busy: boolean; failure: Failure | null }>({ busy: false, failure: null });
  const [viewing, setViewing] = useState<AuditRecord | null>(null);

  async function loadMore(shown: Paged<AuditRecord>) {
    if (more.busy || shown.nextCursor === null) {
      return;
    }
    setMore({ busy: true, failure: null });
    try {
      const next = await client.listAuditRecords(shown.nextCursor);
      replace({ items: [...shown.items, ...next.items], nextCursor: next.nextCursor });
      setMore({ busy: false, failure: null });
    } catch (thrown) {
      setMore({ busy: false, failure: asFailure(thrown) });
    }
  }

  return (
    <Page title={text.auditRecords} lead={text.auditLead}>
      {loading.state === "loading" ? <Waiting text={text} /> : null}
      {loading.state === "failed" ? <Failed failure={loading.failure} again={again} text={text} /> : null}
      {loading.state === "loaded" ? (
        <VStack gap={4}>
          <Table<Row>
            data={loading.value.items.map((record) => ({ id: String(record.sequence), record }))}
            idKey="id"
            density="compact"
            hasHover
            emptyState={<EmptyState title={text.noRecords} description={text.noRecordsHint} isCompact />}
            columns={[
              { key: "sequence", header: text.columnSequence, width: { type: "pixel", value: 96 }, renderCell: ({ record }) => record.sequence },
              {
                key: "action",
                header: text.columnAction,
                // The longest action is read whole.
                width: { type: "pixel", value: 360 },
                renderCell: ({ record }) => <span className="console-mono console-whole">{record.action}</span>,
              },
              {
                key: "actor",
                header: text.columnActor,
                renderCell: ({ record }) => <Actor record={record} text={text} />,
              },
              {
                key: "occurred",
                header: text.columnOccurred,
                renderCell: ({ record }) => moment(record.occurredAt, text),
              },
              {
                key: "view",
                header: "",
                align: "end",
                renderCell: ({ record }) => (
                  <Button variant="ghost" size="sm" label={text.viewRecord} onClick={() => setViewing(record)} />
                ),
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

      {viewing !== null ? (
        <Dialog isOpen onOpenChange={() => setViewing(null)} width={640}>
          <DialogHeader title={text.recordTitle(viewing.sequence)} onOpenChange={() => setViewing(null)} />
          <VStack gap={4} padding={4}>
            <MetadataList>
              <MetadataListItem label={text.columnAction}>
                <span className="console-mono">{viewing.action}</span>
              </MetadataListItem>
              <MetadataListItem label={text.columnActor}>
                <Actor record={viewing} text={text} />
              </MetadataListItem>
              <MetadataListItem label={text.columnOccurred}>{moment(viewing.occurredAt, text)}</MetadataListItem>
              <MetadataListItem label={text.recorded}>{moment(viewing.recordedAt, text)}</MetadataListItem>
              <MetadataListItem label={text.correlation}>
                <Identifier value={viewing.correlationId} text={text} />
              </MetadataListItem>
            </MetadataList>
            <VStack gap={1}>
              <Text type="label">{text.details}</Text>
              <pre className="console-code">{JSON.stringify(viewing.details, null, 2)}</pre>
            </VStack>
            <VStack gap={1}>
              <Text type="label">{text.previousHash}</Text>
              <span className="console-mono console-wrap">{viewing.previousHash}</span>
            </VStack>
            <VStack gap={1}>
              <Text type="label">{text.hash}</Text>
              <span className="console-mono console-wrap">{viewing.hash}</span>
            </VStack>
          </VStack>
        </Dialog>
      ) : null}
    </Page>
  );
}
