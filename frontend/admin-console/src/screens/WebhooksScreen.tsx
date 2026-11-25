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
import type { Failure, Page as Paged, SignedEndpoint, WebhookEndpoint } from "../client";
import { moment } from "../messages";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";
import { ShownOnce } from "../parts/ShownOnce";
import { EndpointForm } from "./WebhookForms";
import { follow, Page, type ScreenProps } from "./shared";

type Row = { id: string; endpoint: WebhookEndpoint };

/** The tenant's webhook endpoints, oldest first, and the form that registers one. */
export function WebhooksScreen({ client, me, text, go, path, say }: ScreenProps) {
  const first = useCallback(() => client.listEndpoints(), [client]);
  const [loading, again, replace] = useLoaded<Paged<WebhookEndpoint>>(first);
  const [registering, setRegistering] = useState(false);
  // A new endpoint and its secret, until the person has kept it.
  const [registered, setRegistered] = useState<SignedEndpoint | null>(null);
  const [more, setMore] = useState<{ busy: boolean; failure: Failure | null }>({ busy: false, failure: null });

  async function loadMore(shown: Paged<WebhookEndpoint>) {
    if (more.busy || shown.nextCursor === null) {
      return;
    }
    setMore({ busy: true, failure: null });
    try {
      const next = await client.listEndpoints(shown.nextCursor);
      replace({ items: [...shown.items, ...next.items], nextCursor: next.nextCursor });
      setMore({ busy: false, failure: null });
    } catch (thrown) {
      setMore({ busy: false, failure: asFailure(thrown) });
    }
  }

  return (
    <Page
      title={text.webhooks}
      lead={text.webhooksLead}
      actions={
        may(me.permissions, "registerEndpoint") ? (
          <Button
            variant="primary"
            label={text.registerEndpoint}
            icon={<Icon icon={Plus} />}
            onClick={() => setRegistering(true)}
          />
        ) : null
      }
    >
      {loading.state === "loading" ? <Waiting text={text} /> : null}
      {loading.state === "failed" ? <Failed failure={loading.failure} again={again} text={text} /> : null}
      {loading.state === "loaded" ? (
        <VStack gap={4}>
          <Table<Row>
            data={loading.value.items.map((endpoint) => ({ id: endpoint.id, endpoint }))}
            idKey="id"
            hasHover
            emptyState={<EmptyState title={text.noEndpoints} description={text.noEndpointsHint} isCompact />}
            columns={[
              {
                key: "address",
                header: text.columnAddress,
                renderCell: ({ endpoint }) => {
                  const screen = { name: "webhook", id: endpoint.id } as const;
                  return (
                    <Link href={path(screen)} onClick={(event) => follow(event, go, screen)}>
                      <span className="console-mono console-wrap">{endpoint.url}</span>
                    </Link>
                  );
                },
              },
              {
                key: "description",
                header: text.columnDescription,
                renderCell: ({ endpoint }) =>
                  endpoint.description === null ? (
                    <Text color="secondary">{text.noDescription}</Text>
                  ) : (
                    <Text>{endpoint.description}</Text>
                  ),
              },
              {
                key: "types",
                header: text.columnEventTypes,
                renderCell: ({ endpoint }) => <Text color="secondary">{text.eventTypeCount(endpoint.eventTypes.length)}</Text>,
              },
              {
                key: "created",
                header: text.columnCreated,
                renderCell: ({ endpoint }) => <Text color="secondary">{moment(endpoint.createdAt, text)}</Text>,
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

      {registering ? (
        <EndpointForm
          client={client}
          text={text}
          onClose={() => setRegistering(false)}
          submit={async (settings) => {
            const made = await client.registerEndpoint(settings);
            setRegistering(false);
            setRegistered(made);
          }}
        />
      ) : null}

      {registered !== null ? (
        <ShownOnce
          secret={registered.secret}
          title={text.signingSecretShownOnceTitle}
          lead={text.signingSecretShownOnceLead}
          label={text.signingSecretLabel}
          text={text}
          onClose={() => {
            // Forgotten as the dialog closes; the endpoint's page never shows it.
            const id = registered.endpoint.id;
            setRegistered(null);
            say(text.endpointRegistered);
            go({ name: "webhook", id });
          }}
        />
      ) : null}
    </Page>
  );
}
