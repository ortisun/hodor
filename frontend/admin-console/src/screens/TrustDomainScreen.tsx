import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { useCallback, useState } from "react";
import { may } from "../actions";
import type { TrustDomain } from "../client";
import { lifetime, moment, named } from "../messages";
import { Confirm, Consequence } from "../parts/Confirm";
import { Identifier } from "../parts/Identifier";
import { Failed, useLoaded, Waiting } from "../parts/Loaded";
import { TrustDomainForm } from "./TrustDomainForm";
import { BundleStatus, bundleFailure } from "./TrustDomainsScreen";
import { follow, Page, type ScreenProps } from "./shared";

type Open = "replace" | "remove" | null;

/**
 * One trust domain: its source, the bundle in force summarized, and, for
 * a bundle endpoint, how its bundle is kept current. Its authorities are
 * counted, not shown: the administration interface gives them whole.
 */
export function TrustDomainScreen({ id, client, me, text, go, path, say }: ScreenProps & { id: string }) {
  const load = useCallback(() => client.getTrustDomain(id), [client, id]);
  const [loading, again, replace] = useLoaded<TrustDomain>(load);
  const [open, setOpen] = useState<Open>(null);
  const close = () => setOpen(null);

  const above = (
    <Breadcrumbs variant="supporting">
      <BreadcrumbItem
        href={path({ name: "trustDomains" })}
        onClick={(event) => follow(event, go, { name: "trustDomains" })}
      >
        {text.trustDomains}
      </BreadcrumbItem>
      <BreadcrumbItem>{text.trustDomainTitle}</BreadcrumbItem>
    </Breadcrumbs>
  );

  if (loading.state !== "loaded") {
    return (
      <Page title={text.trustDomainTitle} above={above}>
        {loading.state === "loading" ? (
          <Waiting text={text} />
        ) : (
          <Failed failure={loading.failure} again={again} text={text} />
        )}
      </Page>
    );
  }

  const shown = loading.value;
  const { bundle, refresh } = shown;

  return (
    <Page
      title={shown.name}
      above={above}
      lead={named(text.trustDomainSources, shown.source)}
      actions={
        may(me.permissions, "replaceTrustDomain") ? (
          <>
            <Button label={text.replaceTrustDomain} onClick={() => setOpen("replace")} />
            <Button variant="destructive" label={text.removeTrustDomain} onClick={() => setOpen("remove")} />
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
            <MetadataListItem label={text.nameLabel}>
              <span className="console-mono">{shown.name}</span>
            </MetadataListItem>
            <MetadataListItem label={text.sourceLabel}>
              <VStack gap={0}>
                <Text>{named(text.trustDomainSources, shown.source)}</Text>
                <Text type="supporting" color="secondary">
                  {named(text.trustDomainSourceHints, shown.source)}
                </Text>
              </VStack>
            </MetadataListItem>
            {shown.bundleEndpointUrl !== null ? (
              <MetadataListItem label={text.bundleEndpointLabel}>
                <span className="console-mono console-wrap">{shown.bundleEndpointUrl}</span>
              </MetadataListItem>
            ) : null}
            <MetadataListItem label={text.created}>{moment(shown.createdAt, text)}</MetadataListItem>
            <MetadataListItem label={text.changed}>{moment(shown.updatedAt, text)}</MetadataListItem>
          </MetadataList>
        </VStack>
      </Card>

      <Card>
        <VStack gap={3}>
          <HStack justify="between" vAlign="center" wrap="wrap" gap={2}>
            <Heading level={2}>{text.bundleTitle}</Heading>
            <BundleStatus domain={shown} text={text} />
          </HStack>
          {bundle === null ? (
            <Text color="secondary">{text.meshLead}</Text>
          ) : (
            <>
              <Text type="supporting" color="secondary">
                {text.bundleLead}
              </Text>
              <MetadataList>
                <MetadataListItem label={text.sequenceLabel}>
                  {bundle.sequence === null ? text.notGiven : String(bundle.sequence)}
                </MetadataListItem>
                <MetadataListItem label={text.refreshHintLabel}>
                  {bundle.refreshHint === null ? text.notGiven : lifetime(bundle.refreshHint, text)}
                </MetadataListItem>
                <MetadataListItem label={text.x509AuthoritiesLabel}>{String(bundle.x509Authorities)}</MetadataListItem>
                <MetadataListItem label={text.jwtAuthoritiesLabel}>{String(bundle.jwtAuthorities)}</MetadataListItem>
                {shown.bundleChangedAt !== null ? (
                  <MetadataListItem label={text.changed}>{moment(shown.bundleChangedAt, text)}</MetadataListItem>
                ) : null}
              </MetadataList>
            </>
          )}
        </VStack>
      </Card>

      {refresh !== null ? (
        <Card>
          <VStack gap={3}>
            <VStack gap={1}>
              <Heading level={2}>{text.refreshTitle}</Heading>
              <Text type="supporting" color="secondary">
                {text.refreshLead}
              </Text>
            </VStack>
            <MetadataList>
              <MetadataListItem label={text.lastFetchLabel}>
                {refresh.fetchedAt === null ? text.neverFetched : moment(refresh.fetchedAt, text)}
              </MetadataListItem>
              <MetadataListItem label={text.nextFetchLabel}>{moment(refresh.nextAt, text)}</MetadataListItem>
              {refresh.failingSince !== null ? (
                <>
                  <MetadataListItem label={text.failingSinceLabel}>{moment(refresh.failingSince, text)}</MetadataListItem>
                  <MetadataListItem label={text.lastErrorLabel}>{bundleFailure(refresh.lastError, text)}</MetadataListItem>
                </>
              ) : null}
            </MetadataList>
          </VStack>
        </Card>
      ) : null}

      {open === "replace" ? (
        <TrustDomainForm
          current={shown}
          text={text}
          onClose={close}
          submit={async (_name, settings) => {
            replace(await client.replaceTrustDomain(shown.id, settings));
            close();
            say(text.trustDomainReplaced(shown.name));
          }}
        />
      ) : null}

      {open === "remove" ? (
        <Confirm
          action="removeTrustDomain"
          title={text.removeTrustDomainTitle(shown.name)}
          confirmLabel={text.removeTrustDomain}
          typed={shown.name}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.removeTrustDomain(shown.id);
            close();
            say(text.trustDomainRemoved(shown.name));
            go({ name: "trustDomains" });
          }}
        >
          <ul className="console-facts">
            <Consequence what={text.removeTrustDomainWorkloads} value={text.removeTrustDomainWorkloadsValue} />
            <Consequence what={text.removeTrustDomainBundle} value={text.removeTrustDomainBundleValue} />
          </ul>
        </Confirm>
      ) : null}
    </Page>
  );
}
