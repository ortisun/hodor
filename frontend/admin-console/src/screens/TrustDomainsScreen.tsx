import { Badge } from "@astryxdesign/core/Badge";
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
import type { Failure, Page as Paged, TrustDomain } from "../client";
import { moment, named, type Messages } from "../messages";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";
import { TrustDomainForm } from "./TrustDomainForm";
import { follow, Page, type ScreenProps } from "./shared";

type Row = { id: string; domain: TrustDomain };

/** Why fetching a bundle fails, in words; the code itself when it is one the console does not know. */
export function bundleFailure(code: string | null, text: Messages): string {
  return code === null ? text.bundleFailureUnknown : named(text.bundleFailures, code);
}

/** The state of the bundle a trust domain trusts: in force, failing to be fetched, or none for the mesh. */
export function BundleStatus({ domain, text }: { domain: TrustDomain; text: Messages }) {
  if (domain.bundle === null) {
    return <Badge variant="neutral" label={text.noBundle} />;
  }
  if (domain.refresh !== null && domain.refresh.failingSince !== null) {
    return <Badge variant="error" label={text.bundleFailing} />;
  }
  return <Badge variant="success" label={text.bundleInForce} />;
}

/** The last refresh of a trust domain's bundle, or why it has none. */
function LastRefresh({ domain, text }: { domain: TrustDomain; text: Messages }) {
  const refresh = domain.refresh;
  if (refresh === null) {
    return <Text color="secondary">{domain.source === "mesh" ? text.nothingToFetch : text.replacedByHand}</Text>;
  }
  return (
    <VStack gap={0}>
      <Text color="secondary">
        {refresh.fetchedAt === null ? text.neverFetched : text.fetchedAt(moment(refresh.fetchedAt, text))}
      </Text>
      {refresh.failingSince !== null ? (
        <Text type="supporting" color="secondary">
          {text.failingSince(moment(refresh.failingSince, text))} {bundleFailure(refresh.lastError, text)}
        </Text>
      ) : null}
      <Text type="supporting" color="secondary">
        {text.nextFetch(moment(refresh.nextAt, text))}
      </Text>
    </VStack>
  );
}

/** The tenant's trust domains, a page at a time, and the form that adds one. */
export function TrustDomainsScreen({ client, me, text, go, path, say }: ScreenProps) {
  const first = useCallback(() => client.listTrustDomains(), [client]);
  const [loading, again, replace] = useLoaded<Paged<TrustDomain>>(first);
  const [adding, setAdding] = useState(false);
  const [more, setMore] = useState<{ busy: boolean; failure: Failure | null }>({ busy: false, failure: null });

  async function loadMore(shown: Paged<TrustDomain>) {
    if (more.busy || shown.nextCursor === null) {
      return;
    }
    setMore({ busy: true, failure: null });
    try {
      const next = await client.listTrustDomains(shown.nextCursor);
      replace({ items: [...shown.items, ...next.items], nextCursor: next.nextCursor });
      setMore({ busy: false, failure: null });
    } catch (thrown) {
      setMore({ busy: false, failure: asFailure(thrown) });
    }
  }

  return (
    <Page
      title={text.trustDomains}
      lead={text.trustDomainsLead}
      actions={
        may(me.permissions, "addTrustDomain") ? (
          <Button variant="primary" label={text.addTrustDomain} icon={<Icon icon={Plus} />} onClick={() => setAdding(true)} />
        ) : null
      }
    >
      {loading.state === "loading" ? <Waiting text={text} /> : null}
      {loading.state === "failed" ? <Failed failure={loading.failure} again={again} text={text} /> : null}
      {loading.state === "loaded" ? (
        <VStack gap={4}>
          <Table<Row>
            data={loading.value.items.map((domain) => ({ id: domain.id, domain }))}
            idKey="id"
            hasHover
            emptyState={<EmptyState title={text.noTrustDomains} description={text.noTrustDomainsHint} isCompact />}
            columns={[
              {
                key: "name",
                header: text.columnName,
                renderCell: ({ domain }) => {
                  const screen = { name: "trustDomain", id: domain.id } as const;
                  return (
                    <Link href={path(screen)} onClick={(event) => follow(event, go, screen)}>
                      <span className="console-mono">{domain.name}</span>
                    </Link>
                  );
                },
              },
              {
                key: "source",
                header: text.columnSource,
                renderCell: ({ domain }) => <Text>{named(text.trustDomainSources, domain.source)}</Text>,
              },
              {
                key: "bundle",
                header: text.columnBundle,
                renderCell: ({ domain }) => (
                  <VStack gap={1} hAlign="start">
                    <BundleStatus domain={domain} text={text} />
                    {domain.bundle === null ? (
                      <Text type="supporting" color="secondary">
                        {text.meshHasNoBundle}
                      </Text>
                    ) : domain.bundleChangedAt !== null ? (
                      <Text type="supporting" color="secondary">
                        {text.bundleChangedAt(moment(domain.bundleChangedAt, text))}
                      </Text>
                    ) : null}
                  </VStack>
                ),
              },
              {
                key: "refresh",
                header: text.columnRefresh,
                renderCell: ({ domain }) => <LastRefresh domain={domain} text={text} />,
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

      {adding ? (
        <TrustDomainForm
          current={null}
          text={text}
          onClose={() => setAdding(false)}
          submit={async (name, settings) => {
            const added = await client.addTrustDomain(name, settings);
            setAdding(false);
            say(text.trustDomainAdded(added.name));
            go({ name: "trustDomain", id: added.id });
          }}
        />
      ) : null}
    </Page>
  );
}
