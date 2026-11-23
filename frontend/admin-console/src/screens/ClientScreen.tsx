import { Banner } from "@astryxdesign/core/Banner";
import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { Text } from "@astryxdesign/core/Text";
import { TextArea } from "@astryxdesign/core/TextArea";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, type MouseEvent, useCallback, useState } from "react";
import { may } from "../actions";
import type { ApplicationClient } from "../client";
import { describe, lifetime, moment, named, type Messages } from "../messages";
import { Confirm, Ladder } from "../parts/Confirm";
import { Identifier } from "../parts/Identifier";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";
import { RoleAssignments } from "./RoleAssignments";
import { ShownOnce } from "../parts/ShownOnce";
import { ClientForm } from "./ClientForm";
import { ProviderStatus } from "./ProvidersScreen";
import { Page, type ScreenProps } from "./shared";

type Open =
  | { what: "change" | "rotate" | "disable" | "enable" | "key" }
  | { what: "revoke"; secretId: string }
  | { what: "remove"; kid: string }
  | null;

/** The form that adds a public key: the JSON Web Key as pasted. */
function KeyForm({
  submit,
  onClose,
  text,
}: {
  submit: (jwk: unknown) => Promise<void>;
  onClose: () => void;
  text: Messages;
}) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || typed.trim() === "") {
      return;
    }
    let jwk: unknown;
    try {
      jwk = JSON.parse(typed);
    } catch {
      setFailure(text.keyNotJson);
      return;
    }
    setBusy(true);
    setFailure(null);
    try {
      await submit(jwk);
    } catch (thrown) {
      setFailure(describe(asFailure(thrown), text));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={600} purpose="form">
      <DialogHeader title={text.addKey} subtitle={<Ladder action="addKey" text={text} />} />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {failure !== null ? <Banner status="error" title={failure} role="alert" /> : null}
          <TextArea
            label={text.keyLabel}
            description={text.keyHint}
            value={typed}
            onChange={setTyped}
            rows={8}
            width="100%"
          />
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button type="submit" variant="primary" label={text.addKey} isDisabled={typed.trim() === ""} isLoading={busy} />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}

export function ClientScreen({ id, client, me, text, go, path, say }: ScreenProps & { id: string }) {
  const load = useCallback(() => client.getClient(id), [client, id]);
  const [loading, again, replace] = useLoaded<ApplicationClient>(load);
  const [open, setOpen] = useState<Open>(null);
  // A new secret, until the person has kept it.
  const [secret, setSecret] = useState<string | null>(null);

  function follow(event: MouseEvent, screen: Parameters<typeof go>[0]) {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    go(screen);
  }

  const crumbs = (found: ApplicationClient | null) => (
    <Breadcrumbs variant="supporting">
      <BreadcrumbItem href={path({ name: "applications" })} onClick={(event) => follow(event, { name: "applications" })}>
        {text.applications}
      </BreadcrumbItem>
      {found !== null ? (
        <BreadcrumbItem
          href={path({ name: "application", id: found.applicationId })}
          onClick={(event) => follow(event, { name: "application", id: found.applicationId })}
        >
          {text.applicationTitle}
        </BreadcrumbItem>
      ) : null}
      <BreadcrumbItem>{text.clientTitle}</BreadcrumbItem>
    </Breadcrumbs>
  );

  if (loading.state !== "loaded") {
    return (
      <Page title={text.clientTitle} above={crumbs(null)}>
        {loading.state === "loading" ? (
          <Waiting text={text} />
        ) : (
          <Failed failure={loading.failure} again={again} text={text} />
        )}
      </Page>
    );
  }

  const found = loading.value;
  const mayChange = may(me.permissions, "changeClient");
  const enabled = found.status === "enabled";
  const usesSecret = found.authenticationMethod === "client_secret_basic" || found.authenticationMethod === "client_secret_post";
  const usesKeys = found.authenticationMethod === "private_key_jwt";
  const close = () => setOpen(null);
  const policy = found.tokenPolicy;

  return (
    <Page
      title={found.name}
      above={crumbs(found)}
      lead={<ProviderStatus status={found.status} text={text} />}
      actions={
        mayChange ? (
          <>
            <Button label={text.changeSettings} onClick={() => setOpen({ what: "change" })} />
            {enabled ? (
              <Button variant="destructive" label={text.disableClient} onClick={() => setOpen({ what: "disable" })} />
            ) : (
              <Button variant="primary" label={text.enableClient} onClick={() => setOpen({ what: "enable" })} />
            )}
          </>
        ) : null
      }
    >
      <Card>
        <VStack gap={2} hAlign="start">
          <Heading level={2}>{text.clientIdentifier}</Heading>
          <Identifier value={found.id} whole text={text} />
        </VStack>
      </Card>

      <Card>
        <VStack gap={3}>
          <Heading level={2}>{text.settings}</Heading>
          <MetadataList>
            <MetadataListItem label={text.clientTypeLabel}>{named(text.clientTypes, found.type)}</MetadataListItem>
            <MetadataListItem label={text.methodLabel}>{named(text.methods, found.authenticationMethod)}</MetadataListItem>
            <MetadataListItem label={text.grantsLabel}>
              <VStack gap={1}>
                {found.grantTypes.map((grant) => (
                  <span key={grant}>{named(text.grants, grant)}</span>
                ))}
              </VStack>
            </MetadataListItem>
            <MetadataListItem label={text.redirectUrisLabel}>
              <VStack gap={1}>
                {found.redirectUris.map((address) => (
                  <span key={address} className="console-mono console-wrap">
                    {address}
                  </span>
                ))}
              </VStack>
            </MetadataListItem>
            {found.postLogoutRedirectUris.length > 0 ? (
              <MetadataListItem label={text.postLogoutRedirectUrisLabel}>
                <VStack gap={1}>
                  {found.postLogoutRedirectUris.map((address) => (
                    <span key={address} className="console-mono console-wrap">
                      {address}
                    </span>
                  ))}
                </VStack>
              </MetadataListItem>
            ) : null}
            <MetadataListItem label={text.allowedScopesLabel}>
              <span className="console-mono">{found.allowedScopes.join(" ")}</span>
            </MetadataListItem>
            <MetadataListItem label={text.pkceLabel}>
              {found.requirePkce ? text.pkceRequired : text.pkceNotRequired}
            </MetadataListItem>
            <MetadataListItem label={text.created}>{moment(found.createdAt, text)}</MetadataListItem>
            <MetadataListItem label={text.changed}>{moment(found.updatedAt, text)}</MetadataListItem>
          </MetadataList>
        </VStack>
      </Card>

      <Card>
        <VStack gap={3}>
          <Heading level={2}>{text.tokenLifetimes}</Heading>
          <MetadataList>
            <MetadataListItem label={text.accessTokenLifetime}>{lifetime(policy.accessTokenSeconds, text)}</MetadataListItem>
            <MetadataListItem label={text.idTokenLifetime}>{lifetime(policy.idTokenSeconds, text)}</MetadataListItem>
            <MetadataListItem label={text.refreshTokenLifetime}>{lifetime(policy.refreshTokenSeconds, text)}</MetadataListItem>
            <MetadataListItem label={text.refreshIdleLifetime}>{lifetime(policy.refreshIdleSeconds, text)}</MetadataListItem>
          </MetadataList>
        </VStack>
      </Card>

      {usesSecret || found.secrets.length > 0 ? (
        <Card>
          <VStack gap={3}>
            <HStack justify="between" vAlign="center">
              <Heading level={2}>{text.secrets}</Heading>
              {usesSecret && may(me.permissions, "rotateSecret") ? (
                <Button label={text.rotateSecret} onClick={() => setOpen({ what: "rotate" })} />
              ) : null}
            </HStack>
            {found.secrets.map((kept) => (
              <HStack key={kept.id} justify="between" vAlign="center" wrap="wrap" gap={2}>
                <VStack gap={0}>
                  <Identifier value={kept.id} text={text} />
                  <Text type="supporting" color="secondary">
                    {text.secretCreated(moment(kept.createdAt, text))} · {text.secretExpires(moment(kept.expiresAt, text))}
                  </Text>
                </VStack>
                {may(me.permissions, "revokeSecret") ? (
                  <Button
                    variant="destructive"
                    size="sm"
                    label={text.revokeSecret}
                    onClick={() => setOpen({ what: "revoke", secretId: kept.id })}
                  />
                ) : null}
              </HStack>
            ))}
          </VStack>
        </Card>
      ) : (
        <Text color="secondary">{text.noSecrets}</Text>
      )}

      {usesKeys ? (
        <Card>
          <VStack gap={3}>
            <HStack justify="between" vAlign="center">
              <Heading level={2}>{text.keys}</Heading>
              {may(me.permissions, "addKey") ? <Button label={text.addKey} onClick={() => setOpen({ what: "key" })} /> : null}
            </HStack>
            {found.keys.length === 0 ? <Text color="secondary">{text.noKeys}</Text> : null}
            {found.keys.map((key) => (
              <HStack key={key.kid} justify="between" vAlign="center" wrap="wrap" gap={2}>
                <VStack gap={0}>
                  <span className="console-mono">{key.kid}</span>
                  <Text type="supporting" color="secondary">
                    {String(key.jwk["kty"] ?? "")} {String(key.jwk["crv"] ?? "")} · {moment(key.addedAt, text)}
                  </Text>
                </VStack>
                {may(me.permissions, "removeKey") ? (
                  <Button size="sm" label={text.removeKey} onClick={() => setOpen({ what: "remove", kid: key.kid })} />
                ) : null}
              </HStack>
            ))}
          </VStack>
        </Card>
      ) : null}

      {open?.what === "change" ? (
        <ClientForm
          current={found}
          text={text}
          onClose={close}
          submit={async (_type, settings) => {
            const changed = await client.changeClient(found.id, settings);
            replace(changed);
            close();
            say(text.clientChanged(changed.name));
          }}
        />
      ) : null}

      {open?.what === "rotate" ? (
        <Confirm
          action="rotateSecret"
          title={text.rotateSecretTitle(found.name)}
          confirmLabel={text.rotateSecret}
          typed={found.name}
          text={text}
          onClose={close}
          onConfirm={async () => {
            const made = await client.rotateSecret(found.id);
            close();
            setSecret(made.secret);
            again();
          }}
        >
          <Text>{text.rotateSecretLead}</Text>
        </Confirm>
      ) : null}

      {open?.what === "revoke" ? (
        <Confirm
          action="revokeSecret"
          title={text.revokeSecretTitle(found.name)}
          confirmLabel={text.revokeSecret}
          typed={found.name}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.revokeSecret(found.id, open.secretId);
            close();
            say(text.secretRevoked);
            again();
          }}
        >
          <Text>{text.revokeSecretLead}</Text>
        </Confirm>
      ) : null}

      {open?.what === "key" ? (
        <KeyForm
          text={text}
          onClose={close}
          submit={async (jwk) => {
            const changed = await client.addKey(found.id, jwk);
            replace(changed);
            close();
            const kid = (jwk as Record<string, unknown>)["kid"];
            say(text.keyAdded(typeof kid === "string" ? kid : ""));
          }}
        />
      ) : null}

      {open?.what === "remove" ? (
        <Confirm
          action="removeKey"
          title={text.removeKeyTitle(open.kid)}
          confirmLabel={text.removeKey}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.removeKey(found.id, open.kid);
            close();
            say(text.keyRemoved(open.kid));
            again();
          }}
        >
          <Text>{text.removeKeyLead}</Text>
        </Confirm>
      ) : null}

      {open?.what === "disable" ? (
        <Confirm
          action="disableClient"
          title={text.disableClientTitle(found.name)}
          confirmLabel={text.disableClient}
          typed={found.name}
          text={text}
          onClose={close}
          onConfirm={async () => {
            replace(await client.disableClient(found.id));
            close();
            say(text.clientDisabled(found.name));
          }}
        >
          <Text>{text.disableClientLead}</Text>
        </Confirm>
      ) : null}

      {open?.what === "enable" ? (
        <Confirm
          action="enableClient"
          title={text.enableClientTitle(found.name)}
          confirmLabel={text.enableClient}
          isDestructive={false}
          text={text}
          onClose={close}
          onConfirm={async () => {
            replace(await client.enableClient(found.id));
            close();
            say(text.clientEnabled(found.name));
          }}
        >
          <Text>{text.enableClientLead}</Text>
        </Confirm>
      ) : null}

      {me.permissions.includes("roles:read") ? (
        <Card padding={5}>
          <RoleAssignments kind="client" id={id} client={client} me={me} text={text} say={say} />
        </Card>
      ) : null}

      {secret !== null ? (
        <ShownOnce
          secret={secret}
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
