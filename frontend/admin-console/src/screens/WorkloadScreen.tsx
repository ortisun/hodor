import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Heading } from "@astryxdesign/core/Heading";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { useCallback, useState } from "react";
import { may } from "../actions";
import type { Workload, WorkloadKind } from "../client";
import { moment } from "../messages";
import { Confirm, Consequence } from "../parts/Confirm";
import { Identifier } from "../parts/Identifier";
import { Failed, useLoaded, Waiting } from "../parts/Loaded";
import { ApiKeys } from "./ApiKeys";
import { NameOf, useNames } from "./names";
import { RoleAssignments } from "./RoleAssignments";
import { StatusBadge } from "./UsersScreen";
import { ofKind, WorkloadForm } from "./WorkloadForm";
import { follow, Page, type ScreenProps } from "./shared";

type Open = { what: "change" | "disable" | "enable" | "delete" } | null;

/**
 * One service account or agent: its owners, its API keys and the roles it
 * holds, and what an administrator does to it.
 */
export function WorkloadScreen({ kind, id, client, me, text, go, path, say }: ScreenProps & { kind: WorkloadKind; id: string }) {
  const load = useCallback(() => client.getWorkload(kind, id), [client, kind, id]);
  const [loading, again, replace] = useLoaded<Workload>(load);
  const [open, setOpen] = useState<Open>(null);
  const known = useNames();
  const close = () => setOpen(null);
  const list = kind === "agent" ? ({ name: "agents" } as const) : ({ name: "serviceAccounts" } as const);

  const above = (
    <Breadcrumbs variant="supporting">
      <BreadcrumbItem href={path(list)} onClick={(event) => follow(event, go, list)}>
        {ofKind(kind, text.workloadsTitle)}
      </BreadcrumbItem>
      <BreadcrumbItem>{ofKind(kind, text.workloadTitle)}</BreadcrumbItem>
    </Breadcrumbs>
  );

  if (loading.state !== "loaded") {
    return (
      <Page title={ofKind(kind, text.workloadTitle)} above={above}>
        {loading.state === "loading" ? (
          <Waiting text={text} />
        ) : (
          <Failed failure={loading.failure} again={again} text={text} />
        )}
      </Page>
    );
  }

  const shown = loading.value;
  const active = shown.status === "active";
  const names = { client, me, text, go, path, known };

  return (
    <Page
      title={shown.name}
      above={above}
      lead={<StatusBadge status={shown.status} text={text} />}
      actions={
        may(me.permissions, "changeWorkload") ? (
          <>
            <Button label={text.changeSettings} onClick={() => setOpen({ what: "change" })} />
            {active ? (
              <Button variant="destructive" label={text.disableWorkload} onClick={() => setOpen({ what: "disable" })} />
            ) : (
              <Button variant="primary" label={text.enableWorkload} onClick={() => setOpen({ what: "enable" })} />
            )}
            {may(me.permissions, "deleteWorkload") ? (
              <Button variant="destructive" label={text.deleteWorkload} onClick={() => setOpen({ what: "delete" })} />
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
            <MetadataListItem label={text.ownersTitle}>
              <VStack gap={1}>
                {shown.owners.map((owner) => (
                  <NameOf key={owner} of="user" id={owner} {...names} />
                ))}
              </VStack>
            </MetadataListItem>
            <MetadataListItem label={text.created}>{moment(shown.createdAt, text)}</MetadataListItem>
            <MetadataListItem label={text.changed}>{moment(shown.updatedAt, text)}</MetadataListItem>
          </MetadataList>
          <Text type="supporting" color="secondary">
            {text.workloadClients}
          </Text>
        </VStack>
      </Card>

      <Card padding={5}>
        <ApiKeys workload={shown} client={client} me={me} text={text} say={say} />
      </Card>

      {me.permissions.includes("roles:read") ? (
        <Card padding={5}>
          <RoleAssignments kind="user" id={shown.id} client={client} me={me} text={text} say={say} />
        </Card>
      ) : null}

      {open?.what === "change" ? (
        <WorkloadForm
          kind={kind}
          current={shown}
          text={text}
          submit={(settings) => client.changeWorkload(kind, shown.id, settings)}
          onClose={close}
          onDone={(changed) => {
            replace(changed);
            close();
            say(text.workloadChanged(changed.name));
          }}
        />
      ) : null}

      {open?.what === "disable" ? (
        <Confirm
          action="disableWorkload"
          title={text.disableWorkloadTitle(shown.name)}
          confirmLabel={text.disableWorkload}
          typed={shown.name}
          text={text}
          onClose={close}
          onConfirm={async () => {
            replace(await client.disableWorkload(kind, shown.id));
            close();
            say(text.workloadDisabled(shown.name));
          }}
        >
          <ul className="console-facts">
            <Consequence what={text.workloadTokens} value={text.workloadTokensStopped} />
            <Consequence what={text.apiKeysTitle} value={text.workloadKeysStopped} />
          </ul>
        </Confirm>
      ) : null}

      {open?.what === "enable" ? (
        <Confirm
          action="enableWorkload"
          title={text.enableWorkloadTitle(shown.name)}
          confirmLabel={text.enableWorkload}
          isDestructive={false}
          text={text}
          onClose={close}
          onConfirm={async () => {
            replace(await client.enableWorkload(kind, shown.id));
            close();
            say(text.workloadEnabled(shown.name));
          }}
        >
          <Text>{text.enableWorkloadLead}</Text>
        </Confirm>
      ) : null}

      {open?.what === "delete" ? (
        <Confirm
          action="deleteWorkload"
          title={text.deleteWorkloadTitle(shown.name)}
          confirmLabel={text.deleteWorkload}
          typed={shown.name}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.deleteWorkload(kind, shown.id);
            close();
            say(text.workloadDeleted(shown.name));
            go(list);
          }}
        >
          <ul className="console-facts">
            <Consequence what={text.workloadTokens} value={text.workloadTokensRevoked} />
            <Consequence what={text.workloadForever} value={text.workloadForeverValue} />
          </ul>
        </Confirm>
      ) : null}
    </Page>
  );
}
