import { Badge } from "@astryxdesign/core/Badge";
import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { useCallback, useState } from "react";
import { may } from "../actions";
import type { DeliveryStatus, Failure, Page as Paged, WebhookDelivery, WebhookEndpoint } from "../client";
import { moment, named, type Messages } from "../messages";
import { Confirm, Consequence } from "../parts/Confirm";
import { Identifier } from "../parts/Identifier";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";
import { ShownOnce } from "../parts/ShownOnce";
import { SubscriptionsForm } from "./WebhookForms";
import { follow, Page, type ScreenProps } from "./shared";

type Open =
  | { what: "subscriptions" | "rotate" | "remove" }
  | { what: "redeliver"; delivery: WebhookDelivery }
  | null;

type Filter = DeliveryStatus | "all";

const tone = { pending: "info", delivered: "success", set_aside: "error" } as const;

export function DeliveryBadge({ status, text }: { status: DeliveryStatus; text: Messages }) {
  return <Badge variant={tone[status]} label={named(text.deliveryStatus, status)} />;
}

/** What the last attempt of a delivery got back, in words. */
function lastAnswer(delivery: WebhookDelivery, text: Messages): string {
  if (delivery.lastResponseStatus !== null) {
    return text.answeredWith(delivery.lastResponseStatus);
  }
  return delivery.lastError ?? text.notTriedYet;
}

/**
 * One webhook endpoint: its event types, the secrets that sign for it, and
 * its deliveries, newest first, filtered by status.
 */
export function WebhookScreen({ id, client, me, text, go, path, say }: ScreenProps & { id: string }) {
  const loadEndpoint = useCallback(() => client.getEndpoint(id), [client, id]);
  const [endpoint, againEndpoint, replaceEndpoint] = useLoaded<WebhookEndpoint>(loadEndpoint);
  const [filter, setFilter] = useState<Filter>("all");
  const loadDeliveries = useCallback(
    () => client.listDeliveries(id, filter === "all" ? null : filter),
    [client, id, filter],
  );
  const [deliveries, againDeliveries, replaceDeliveries] = useLoaded<Paged<WebhookDelivery>>(loadDeliveries);
  const [more, setMore] = useState<{ busy: boolean; failure: Failure | null }>({ busy: false, failure: null });
  const [open, setOpen] = useState<Open>(null);
  // A new secret, until the person has kept it.
  const [secret, setSecret] = useState<string | null>(null);
  const close = () => setOpen(null);

  const above = (
    <Breadcrumbs variant="supporting">
      <BreadcrumbItem href={path({ name: "webhooks" })} onClick={(event) => follow(event, go, { name: "webhooks" })}>
        {text.webhooks}
      </BreadcrumbItem>
      <BreadcrumbItem>{text.endpointTitle}</BreadcrumbItem>
    </Breadcrumbs>
  );

  if (endpoint.state !== "loaded") {
    return (
      <Page title={text.endpointTitle} above={above}>
        {endpoint.state === "loading" ? (
          <Waiting text={text} />
        ) : (
          <Failed failure={endpoint.failure} again={againEndpoint} text={text} />
        )}
      </Page>
    );
  }

  const shown = endpoint.value;

  async function loadMore(page: Paged<WebhookDelivery>) {
    if (more.busy || page.nextCursor === null) {
      return;
    }
    setMore({ busy: true, failure: null });
    try {
      const next = await client.listDeliveries(id, filter === "all" ? null : filter, page.nextCursor);
      replaceDeliveries({ items: [...page.items, ...next.items], nextCursor: next.nextCursor });
      setMore({ busy: false, failure: null });
    } catch (thrown) {
      setMore({ busy: false, failure: asFailure(thrown) });
    }
  }

  return (
    <Page
      title={text.endpointTitle}
      above={above}
      lead={<span className="console-mono console-wrap">{shown.url}</span>}
      actions={
        may(me.permissions, "changeSubscriptions") ? (
          <>
            <Button label={text.changeSubscriptions} onClick={() => setOpen({ what: "subscriptions" })} />
            <Button label={text.rotateEndpointSecret} onClick={() => setOpen({ what: "rotate" })} />
            <Button variant="destructive" label={text.removeEndpoint} onClick={() => setOpen({ what: "remove" })} />
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
            <MetadataListItem label={text.endpointAddressLabel}>
              <span className="console-mono console-wrap">{shown.url}</span>
            </MetadataListItem>
            <MetadataListItem label={text.descriptionLabel}>{shown.description ?? text.noDescription}</MetadataListItem>
            <MetadataListItem label={text.eventTypesLabel}>
              <VStack gap={1}>
                {shown.eventTypes.map((type) => (
                  <span key={type} className="console-mono">
                    {type}
                  </span>
                ))}
              </VStack>
            </MetadataListItem>
            <MetadataListItem label={text.created}>{moment(shown.createdAt, text)}</MetadataListItem>
            <MetadataListItem label={text.changed}>{moment(shown.updatedAt, text)}</MetadataListItem>
          </MetadataList>
        </VStack>
      </Card>

      <Card>
        <VStack gap={3}>
          <VStack gap={1}>
            <Heading level={2}>{text.signingSecretsTitle}</Heading>
            <Text type="supporting" color="secondary">
              {text.signingSecretsLead}
            </Text>
          </VStack>
          {shown.secrets.map((kept) => (
            <Text key={kept.createdAt}>
              {text.signingSince(moment(kept.createdAt, text))} ·{" "}
              {kept.expiresAt === null ? text.signingCurrent : text.signingUntil(moment(kept.expiresAt, text))}
            </Text>
          ))}
        </VStack>
      </Card>

      <Card>
        <VStack gap={3}>
          <HStack justify="between" vAlign="center" wrap="wrap" gap={3}>
            <VStack gap={1}>
              <Heading level={2}>{text.deliveriesTitle}</Heading>
              <Text type="supporting" color="secondary">
                {text.deliveriesLead}
              </Text>
            </VStack>
            <SegmentedControl
              label={text.deliveryFilter}
              value={filter}
              onChange={(value) => {
                setMore({ busy: false, failure: null });
                setFilter(value === "pending" || value === "delivered" || value === "set_aside" ? value : "all");
              }}
            >
              <SegmentedControlItem value="all" label={text.effectAll} />
              <SegmentedControlItem value="pending" label={named(text.deliveryStatus, "pending")} />
              <SegmentedControlItem value="delivered" label={named(text.deliveryStatus, "delivered")} />
              <SegmentedControlItem value="set_aside" label={named(text.deliveryStatus, "set_aside")} />
            </SegmentedControl>
          </HStack>
          {deliveries.state === "loading" ? <Waiting text={text} /> : null}
          {deliveries.state === "failed" ? (
            <Failed failure={deliveries.failure} again={againDeliveries} text={text} />
          ) : null}
          {deliveries.state === "loaded" ? (
            <VStack gap={4}>
              <Table<{ id: string; delivery: WebhookDelivery }>
                data={deliveries.value.items.map((delivery) => ({ id: delivery.id, delivery }))}
                idKey="id"
                emptyState={<EmptyState title={text.noDeliveries} description={text.noDeliveriesHint} isCompact />}
                columns={[
                  {
                    key: "event",
                    header: text.columnEvent,
                    renderCell: ({ delivery }) => (
                      <VStack gap={0}>
                        <span className="console-mono">{delivery.eventType}</span>
                        <Identifier value={delivery.eventId} text={text} />
                      </VStack>
                    ),
                  },
                  {
                    key: "status",
                    header: text.columnStatus,
                    renderCell: ({ delivery }) => <DeliveryBadge status={delivery.status} text={text} />,
                  },
                  {
                    key: "attempts",
                    header: text.columnAttempts,
                    renderCell: ({ delivery }) => <Text>{delivery.attempts}</Text>,
                  },
                  {
                    key: "answer",
                    header: text.columnLastAnswer,
                    renderCell: ({ delivery }) => <Text color="secondary">{lastAnswer(delivery, text)}</Text>,
                  },
                  {
                    key: "when",
                    header: text.columnWhen,
                    renderCell: ({ delivery }) => (
                      <VStack gap={0}>
                        <Text color="secondary">{moment(delivery.createdAt, text)}</Text>
                        <Text type="supporting" color="secondary">
                          {delivery.nextAttemptAt !== null
                            ? text.nextAttempt(moment(delivery.nextAttemptAt, text))
                            : delivery.finishedAt !== null
                              ? text.finishedAt(moment(delivery.finishedAt, text))
                              : ""}
                        </Text>
                      </VStack>
                    ),
                  },
                  {
                    key: "redeliver",
                    header: "",
                    align: "end",
                    renderCell: ({ delivery }) =>
                      delivery.status === "set_aside" && may(me.permissions, "redeliver") ? (
                        <Button size="sm" label={text.redeliver} onClick={() => setOpen({ what: "redeliver", delivery })} />
                      ) : null,
                  },
                ]}
              />
              {more.failure !== null ? <Failed failure={more.failure} text={text} /> : null}
              {deliveries.value.nextCursor !== null ? (
                <HStack justify="center">
                  <Button label={text.loadMore} isLoading={more.busy} onClick={() => void loadMore(deliveries.value)} />
                </HStack>
              ) : null}
            </VStack>
          ) : null}
        </VStack>
      </Card>

      {open?.what === "subscriptions" ? (
        <SubscriptionsForm
          endpoint={shown}
          client={client}
          text={text}
          onClose={close}
          submit={async (eventTypes) => {
            replaceEndpoint(await client.replaceSubscriptions(shown.id, eventTypes));
            close();
            say(text.subscriptionsChanged);
          }}
        />
      ) : null}

      {open?.what === "rotate" ? (
        <Confirm
          action="rotateEndpointSecret"
          title={text.rotateEndpointSecretTitle}
          confirmLabel={text.rotateEndpointSecret}
          typed={shown.url}
          text={text}
          onClose={close}
          onConfirm={async () => {
            const made = await client.rotateEndpointSecret(shown.id);
            replaceEndpoint(made.endpoint);
            close();
            setSecret(made.secret);
          }}
        >
          <ul className="console-facts">
            <Consequence what={text.rotateEndpointNew} value={text.rotateEndpointNewValue} />
            <Consequence what={text.rotateEndpointPrevious} value={text.rotateEndpointPreviousValue} />
          </ul>
        </Confirm>
      ) : null}

      {open?.what === "remove" ? (
        <Confirm
          action="removeEndpoint"
          title={text.removeEndpointTitle}
          confirmLabel={text.removeEndpoint}
          typed={shown.url}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.removeEndpoint(shown.id);
            close();
            say(text.endpointRemoved);
            go({ name: "webhooks" });
          }}
        >
          <ul className="console-facts">
            <Consequence what={text.removeEndpointWhat} value={text.removeEndpointValue} />
          </ul>
        </Confirm>
      ) : null}

      {open?.what === "redeliver" ? (
        <Confirm
          action="redeliver"
          title={text.redeliverTitle(open.delivery.eventType)}
          confirmLabel={text.redeliver}
          isDestructive={false}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.redeliver(open.delivery.id);
            close();
            say(text.redelivered);
            againDeliveries();
          }}
        >
          <Text>{text.redeliverLead}</Text>
        </Confirm>
      ) : null}

      {secret !== null ? (
        <ShownOnce
          secret={secret}
          title={text.signingSecretShownOnceTitle}
          lead={text.signingSecretShownOnceLead}
          label={text.signingSecretLabel}
          text={text}
          onClose={() => {
            // Forgotten as the dialog closes.
            setSecret(null);
          }}
        />
      ) : null}
    </Page>
  );
}
