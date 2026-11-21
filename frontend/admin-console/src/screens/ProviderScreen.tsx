import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Heading } from "@astryxdesign/core/Heading";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type MouseEvent, useCallback, useState } from "react";
import { may } from "../actions";
import type { Provider } from "../client";
import { moment, named } from "../messages";
import { Confirm, Consequence } from "../parts/Confirm";
import { Identifier } from "../parts/Identifier";
import { Failed, useLoaded, Waiting } from "../parts/Loaded";
import { ProviderForm } from "./ProviderForm";
import { ProviderStatus } from "./ProvidersScreen";
import { Page, type ScreenProps } from "./shared";

type Open = "change" | "secret" | "disable" | "enable" | null;

export function ProviderScreen({ id, client, me, text, go, path, say }: ScreenProps & { id: string }) {
  const load = useCallback(() => client.getProvider(id), [client, id]);
  const [loading, again, replace] = useLoaded<Provider>(load);
  const [open, setOpen] = useState<Open>(null);
  const [secret, setSecret] = useState("");

  function back(event: MouseEvent) {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    go({ name: "providers" });
  }

  function close() {
    setOpen(null);
    // A secret that was typed and not sent is forgotten.
    setSecret("");
  }

  const above = (
    <Breadcrumbs variant="supporting">
      <BreadcrumbItem href={path({ name: "providers" })} onClick={back}>
        {text.providers}
      </BreadcrumbItem>
      <BreadcrumbItem>{text.providerTitle}</BreadcrumbItem>
    </Breadcrumbs>
  );

  if (loading.state !== "loaded") {
    return (
      <Page title={text.providerTitle} above={above}>
        {loading.state === "loading" ? (
          <Waiting text={text} />
        ) : (
          <Failed failure={loading.failure} again={again} text={text} />
        )}
      </Page>
    );
  }

  const provider = loading.value;
  const mayChange = may(me.permissions, "changeProvider");
  const enabled = provider.status === "enabled";

  return (
    <Page
      title={provider.displayName}
      above={above}
      lead={<ProviderStatus status={provider.status} text={text} />}
      actions={
        mayChange ? (
          <>
            <Button label={text.changeSettings} onClick={() => setOpen("change")} />
            <Button label={text.replaceSecret} onClick={() => setOpen("secret")} />
            {enabled ? (
              <Button variant="destructive" label={text.disableProvider} onClick={() => setOpen("disable")} />
            ) : (
              <Button variant="primary" label={text.enableProvider} onClick={() => setOpen("enable")} />
            )}
          </>
        ) : null
      }
    >
      <Card>
        <VStack gap={2} hAlign="start">
          <Heading level={2}>{text.callbackAddress}</Heading>
          <Identifier value={provider.callbackAddress} whole text={text} />
          <Text type="supporting" color="secondary">
            {text.callbackAddressHint}
          </Text>
        </VStack>
      </Card>

      <Card>
        <VStack gap={3}>
          <Heading level={2}>{text.settings}</Heading>
          <MetadataList>
            <MetadataListItem label={text.aliasLabel}>
              <span className="console-mono">{provider.alias}</span>
            </MetadataListItem>
            <MetadataListItem label={text.kindLabel}>{named(text.providerKinds, provider.kind)}</MetadataListItem>
            <MetadataListItem label={text.issuerLabel}>
              <span className="console-wrap">{provider.issuer}</span>
            </MetadataListItem>
            <MetadataListItem label={text.clientIdLabel}>
              <span className="console-mono console-wrap">{provider.clientId}</span>
            </MetadataListItem>
            <MetadataListItem label={text.clientSecretLabel}>{text.clientSecretSet}</MetadataListItem>
            <MetadataListItem label={text.scopesLabel}>
              <span className="console-mono">{provider.scopes.join(" ")}</span>
            </MetadataListItem>
            <MetadataListItem label={text.columnCreatesUsers}>
              {provider.createsUsers ? text.createsUsersOn(provider.displayName) : text.createsUsersOff(provider.displayName)}
            </MetadataListItem>
            <MetadataListItem label={text.created}>{moment(provider.createdAt, text)}</MetadataListItem>
            <MetadataListItem label={text.changed}>{moment(provider.updatedAt, text)}</MetadataListItem>
          </MetadataList>
        </VStack>
      </Card>

      {open === "change" ? (
        <ProviderForm
          adding={false}
          current={provider}
          text={text}
          submit={(change) => client.changeProvider(provider.id, change)}
          onClose={close}
          onDone={(changed) => {
            replace(changed);
            close();
            say(text.providerChanged(changed.displayName));
          }}
        />
      ) : null}

      {open === "secret" ? (
        <Confirm
          action="replaceClientSecret"
          title={text.replaceSecretTitle(provider.displayName)}
          confirmLabel={text.replaceSecret}
          ready={secret !== ""}
          isDestructive={false}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.replaceClientSecret(provider.id, secret);
            close();
            say(text.secretReplaced);
            again();
          }}
        >
          <Text>{text.replaceSecretLead}</Text>
          <TextInput
            label={text.newClientSecretLabel}
            description={text.clientSecretHint}
            type="password"
            value={secret}
            onChange={setSecret}
            autoComplete="off"
            hasSpellCheck={false}
            hasAutoFocus
            width="100%"
          />
        </Confirm>
      ) : null}

      {open === "disable" ? (
        <Confirm
          action="disableProvider"
          title={text.disableProviderTitle(provider.displayName)}
          confirmLabel={text.disableProvider}
          typed={provider.alias}
          text={text}
          onClose={close}
          onConfirm={async () => {
            replace(await client.disableProvider(provider.id));
            close();
            say(text.providerDisabled(provider.displayName));
          }}
        >
          <ul className="console-facts">
            <Consequence what={text.disableConsequenceOffered} value={text.disableConsequenceOfferedValue} />
            <Consequence what={text.disableConsequenceSignIn} value={text.disableConsequenceSignInValue} />
            <Consequence what={text.disableConsequenceAccounts} value={text.disableConsequenceAccountsValue} />
          </ul>
        </Confirm>
      ) : null}

      {open === "enable" ? (
        <Confirm
          action="enableProvider"
          title={text.enableProviderTitle(provider.displayName)}
          confirmLabel={text.enableProvider}
          isDestructive={false}
          text={text}
          onClose={close}
          onConfirm={async () => {
            replace(await client.enableProvider(provider.id));
            close();
            say(text.providerEnabled(provider.displayName));
          }}
        >
          <Text>{text.enableProviderLead}</Text>
        </Confirm>
      ) : null}
    </Page>
  );
}
