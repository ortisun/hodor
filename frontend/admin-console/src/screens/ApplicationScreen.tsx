import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { Link } from "@astryxdesign/core/Link";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { type MouseEvent, useCallback, useState } from "react";
import { may } from "../actions";
import type { Application, ApplicationClient, ResourceServer } from "../client";
import { moment, named } from "../messages";
import { Confirm } from "../parts/Confirm";
import { Identifier } from "../parts/Identifier";
import { Failed, useLoaded, Waiting } from "../parts/Loaded";
import { ShownOnce } from "../parts/ShownOnce";
import { ApplicationForm } from "./ApplicationForm";
import { ClientForm } from "./ClientForm";
import { ProviderStatus } from "./ProvidersScreen";
import { ResourceServerForm } from "./ResourceServerForm";
import { Page, type ScreenProps } from "./shared";

interface Shown {
  application: Application;
  clients: ApplicationClient[];
  /** The resource server it exposes, if any. */
  server: ResourceServer | null;
}

type Open = "change" | "disable" | "enable" | "client" | "server" | null;
type Row = { id: string; client: ApplicationClient };

export function ApplicationScreen({ id, client, me, text, go, path, say }: ScreenProps & { id: string }) {
  const load = useCallback(async (): Promise<Shown> => {
    const [application, clients, servers] = await Promise.all([
      client.getApplication(id),
      client.listClients(id),
      client.listResourceServers(),
    ]);
    return { application, clients, server: servers.find((server) => server.applicationId === id) ?? null };
  }, [client, id]);
  const [loading, again, replace] = useLoaded<Shown>(load);
  const [open, setOpen] = useState<Open>(null);
  // A new client's first secret, until the person has kept it.
  const [secret, setSecret] = useState<{ secret: string; clientId: string } | null>(null);

  function follow(event: MouseEvent, screen: Parameters<typeof go>[0]) {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    go(screen);
  }

  const above = (
    <Breadcrumbs variant="supporting">
      <BreadcrumbItem href={path({ name: "applications" })} onClick={(event) => follow(event, { name: "applications" })}>
        {text.applications}
      </BreadcrumbItem>
      <BreadcrumbItem>{text.applicationTitle}</BreadcrumbItem>
    </Breadcrumbs>
  );

  if (loading.state !== "loaded") {
    return (
      <Page title={text.applicationTitle} above={above}>
        {loading.state === "loading" ? (
          <Waiting text={text} />
        ) : (
          <Failed failure={loading.failure} again={again} text={text} />
        )}
      </Page>
    );
  }

  const shown = loading.value;
  const { application, clients, server } = shown;
  const mayChange = may(me.permissions, "changeApplication");
  const enabled = application.status === "enabled";
  const close = () => setOpen(null);

  return (
    <Page
      title={application.name}
      above={above}
      lead={<ProviderStatus status={application.status} text={text} />}
      actions={
        mayChange ? (
          <>
            <Button label={text.changeSettings} onClick={() => setOpen("change")} />
            {enabled ? (
              <Button variant="destructive" label={text.disableApplication} onClick={() => setOpen("disable")} />
            ) : (
              <Button variant="primary" label={text.enableApplication} onClick={() => setOpen("enable")} />
            )}
          </>
        ) : null
      }
    >
      <Card>
        <VStack gap={3}>
          <Heading level={2}>{text.settings}</Heading>
          <MetadataList>
            <MetadataListItem label={text.columnParty}>
              {application.firstParty ? text.consentSkipped(application.name) : text.consentAsked(application.name)}
            </MetadataListItem>
            <MetadataListItem label={text.created}>{moment(application.createdAt, text)}</MetadataListItem>
            <MetadataListItem label={text.changed}>{moment(application.updatedAt, text)}</MetadataListItem>
          </MetadataList>
        </VStack>
      </Card>

      <Card>
        <VStack gap={3}>
          <HStack justify="between" vAlign="center">
            <Heading level={2}>{text.clients}</Heading>
            {may(me.permissions, "addClient") ? (
              <Button label={text.addClient} onClick={() => setOpen("client")} />
            ) : null}
          </HStack>
          <Table<Row>
            data={clients.map((found) => ({ id: found.id, client: found }))}
            idKey="id"
            hasHover
            emptyState={<EmptyState title={text.noClients} description={text.noClientsHint} isCompact />}
            columns={[
              {
                key: "name",
                header: text.columnClient,
                renderCell: ({ client: row }) => (
                  <Link
                    href={path({ name: "client", id: row.id })}
                    onClick={(event) => follow(event, { name: "client", id: row.id })}
                  >
                    {row.name}
                  </Link>
                ),
              },
              {
                key: "id",
                header: text.clientIdentifier,
                renderCell: ({ client: row }) => <Identifier value={row.id} text={text} />,
              },
              {
                key: "type",
                header: text.columnType,
                renderCell: ({ client: row }) => named(text.clientTypes, row.type),
              },
              {
                key: "method",
                header: text.columnMethod,
                renderCell: ({ client: row }) => named(text.methods, row.authenticationMethod),
              },
              {
                key: "status",
                header: text.columnStatus,
                renderCell: ({ client: row }) => <ProviderStatus status={row.status} text={text} />,
              },
            ]}
          />
        </VStack>
      </Card>

      <Card>
        <VStack gap={3}>
          <HStack justify="between" vAlign="center">
            <Heading level={2}>{text.resourceServer}</Heading>
            {may(me.permissions, "changeResourceServer") ? (
              <Button
                label={server === null ? text.addResourceServer : text.changeResourceServer}
                onClick={() => setOpen("server")}
              />
            ) : null}
          </HStack>
          {server === null ? (
            <Text color="secondary">{text.noResourceServer}</Text>
          ) : (
            <MetadataList>
              <MetadataListItem label={text.audienceLabel}>
                <span className="console-mono console-wrap">{server.audience}</span>
              </MetadataListItem>
              <MetadataListItem label={text.resourceServerNameLabel}>{server.name}</MetadataListItem>
              <MetadataListItem label={text.definedScopesLabel}>
                {server.scopes.length === 0 ? (
                  text.noScopes
                ) : (
                  <VStack gap={1}>
                    {server.scopes.map((scope) => (
                      <span key={scope.name}>
                        <span className="console-mono">{scope.name}</span>
                        {scope.description === "" ? null : ` · ${scope.description}`}
                      </span>
                    ))}
                  </VStack>
                )}
              </MetadataListItem>
            </MetadataList>
          )}
        </VStack>
      </Card>

      {open === "change" ? (
        <ApplicationForm
          current={application}
          text={text}
          submit={(settings) => client.changeApplication(application.id, settings)}
          onClose={close}
          onDone={(changed) => {
            replace({ ...shown, application: changed });
            close();
            say(text.applicationChanged(changed.name));
          }}
        />
      ) : null}

      {open === "disable" ? (
        <Confirm
          action="disableApplication"
          title={text.disableApplicationTitle(application.name)}
          confirmLabel={text.disableApplication}
          typed={application.name}
          text={text}
          onClose={close}
          onConfirm={async () => {
            replace({ ...shown, application: await client.disableApplication(application.id) });
            close();
            say(text.applicationDisabled(application.name));
          }}
        >
          <Text>{text.disableApplicationLead}</Text>
        </Confirm>
      ) : null}

      {open === "enable" ? (
        <Confirm
          action="enableApplication"
          title={text.enableApplicationTitle(application.name)}
          confirmLabel={text.enableApplication}
          isDestructive={false}
          text={text}
          onClose={close}
          onConfirm={async () => {
            replace({ ...shown, application: await client.enableApplication(application.id) });
            close();
            say(text.applicationEnabled(application.name));
          }}
        >
          <Text>{text.enableApplicationLead}</Text>
        </Confirm>
      ) : null}

      {open === "client" ? (
        <ClientForm
          current={null}
          text={text}
          onClose={close}
          submit={async (type, settings) => {
            const created = await client.addClient(application.id, type, settings);
            replace({ ...shown, clients: [...clients, created.client] });
            close();
            say(text.clientAdded(created.client.name));
            if (created.secret !== null) {
              setSecret({ secret: created.secret, clientId: created.client.id });
            } else {
              go({ name: "client", id: created.client.id });
            }
          }}
        />
      ) : null}

      {open === "server" ? (
        <ResourceServerForm
          current={server}
          text={text}
          onClose={close}
          submit={(audience, name, scopes) =>
            server === null
              ? client.addResourceServer(application.id, audience, name, scopes)
              : client.changeResourceServer(server.id, name, scopes)
          }
          onDone={(saved) => {
            replace({ ...shown, server: saved });
            close();
            say(text.resourceServerSaved(saved.name));
          }}
        />
      ) : null}

      {secret !== null ? (
        <ShownOnce
          secret={secret.secret}
          text={text}
          onClose={() => {
            const clientId = secret.clientId;
            // Forgotten as the dialog closes.
            setSecret(null);
            go({ name: "client", id: clientId });
          }}
        />
      ) : null}
    </Page>
  );
}
