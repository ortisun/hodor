import { Badge } from "@astryxdesign/core/Badge";
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { TextArea } from "@astryxdesign/core/TextArea";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useCallback, useState } from "react";
import { may } from "../actions";
import { isIdentifier } from "../address";
import type { ApiKey, ApiKeySettings, Client, MadeApiKey, Me, Workload } from "../client";
import { describe, moment, named, type Messages } from "../messages";
import { Confirm, Consequence, Ladder } from "../parts/Confirm";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";
import { ShownOnce } from "../parts/ShownOnce";
import { linesOf } from "./WorkloadForm";

/** The lifetime of a key unless the person chooses another, as the server's own default. */
const DEFAULT_LIFETIME_DAYS = 90;

const tone = { active: "success", expired: "neutral", revoked: "error" } as const;

type Open = { what: "create" } | { what: "rotate"; key: ApiKey } | { what: "revoke"; key: ApiKey } | null;

/** A workload's API keys, newest first, each of which can be rotated or revoked; and making one. */
export function ApiKeys({
  workload,
  client,
  me,
  text,
  say,
}: {
  workload: Workload;
  client: Client;
  me: Me;
  text: Messages;
  say: (message: string) => void;
}) {
  const { kind, id } = workload;
  const load = useCallback(() => client.listApiKeys(kind, id), [client, kind, id]);
  const [keys, again] = useLoaded<ApiKey[]>(load);
  const [open, setOpen] = useState<Open>(null);
  // A new key, until the person has kept it.
  const [made, setMade] = useState<string | null>(null);
  const close = () => setOpen(null);

  function shown(key: MadeApiKey) {
    close();
    setMade(key.secret);
    again();
  }

  return (
    <VStack gap={3}>
      <HStack justify="between" vAlign="center">
        <VStack gap={1}>
          <Heading level={2}>{text.apiKeysTitle}</Heading>
          <Text type="supporting" color="secondary">
            {text.apiKeysLead}
          </Text>
        </VStack>
        {may(me.permissions, "createApiKey") && workload.status === "active" ? (
          <Button label={text.createApiKey} onClick={() => setOpen({ what: "create" })} />
        ) : null}
      </HStack>
      {keys.state === "loading" ? <Waiting text={text} /> : null}
      {keys.state === "failed" ? <Failed failure={keys.failure} again={again} text={text} /> : null}
      {keys.state === "loaded" ? (
        <Table<{ id: string; key: ApiKey }>
          data={keys.value.map((key) => ({ id: key.id, key }))}
          idKey="id"
          emptyState={<EmptyState title={text.noApiKeys} description={text.noApiKeysHint} isCompact />}
          columns={[
            {
              key: "name",
              header: text.columnName,
              renderCell: ({ key }) => (
                <VStack gap={0}>
                  <Text>{key.name}</Text>
                  <span className="console-mono">{text.apiKeyHint(key.hint)}</span>
                </VStack>
              ),
            },
            {
              key: "scopes",
              header: text.columnScopes,
              renderCell: ({ key }) => (
                <VStack gap={0}>
                  {key.scopes.map((scope) => (
                    <span key={scope} className="console-mono">
                      {scope}
                    </span>
                  ))}
                  {key.applicationId !== null ? (
                    <Text type="supporting" color="secondary">
                      {text.oneApplication(key.applicationId)}
                    </Text>
                  ) : null}
                </VStack>
              ),
            },
            {
              key: "status",
              header: text.columnStatus,
              renderCell: ({ key }) => (
                <VStack gap={0}>
                  <Badge
                    variant={tone[key.status as keyof typeof tone] ?? "neutral"}
                    label={named(text.apiKeyStatus, key.status)}
                  />
                  <Text type="supporting" color="secondary">
                    {key.status === "revoked" && key.revokedAt !== null
                      ? text.keyRevokedAt(moment(key.revokedAt, text))
                      : text.keyExpires(moment(key.expiresAt, text))}
                  </Text>
                  {key.replacedBy !== null ? (
                    <Text type="supporting" color="secondary">
                      {text.keyReplaced}
                    </Text>
                  ) : null}
                </VStack>
              ),
            },
            {
              key: "used",
              header: text.columnLastUsed,
              renderCell: ({ key }) => (
                <Text color="secondary">{key.lastUsedAt === null ? text.neverUsed : moment(key.lastUsedAt, text)}</Text>
              ),
            },
            {
              key: "actions",
              header: "",
              align: "end",
              renderCell: ({ key }) =>
                key.status === "active" ? (
                  <HStack gap={2} justify="end">
                    {may(me.permissions, "rotateApiKey") && key.replacedBy === null ? (
                      <Button size="sm" label={text.rotateApiKey} onClick={() => setOpen({ what: "rotate", key })} />
                    ) : null}
                    {may(me.permissions, "revokeApiKey") ? (
                      <Button
                        size="sm"
                        variant="destructive"
                        label={text.revokeApiKey}
                        onClick={() => setOpen({ what: "revoke", key })}
                      />
                    ) : null}
                  </HStack>
                ) : null,
            },
          ]}
        />
      ) : null}

      {open?.what === "create" ? (
        <ApiKeyForm
          workload={workload}
          text={text}
          onClose={close}
          submit={async (settings) => shown(await client.createApiKey(kind, id, settings))}
        />
      ) : null}

      {open?.what === "rotate" ? (
        <Confirm
          action="rotateApiKey"
          title={text.rotateApiKeyTitle(open.key.name)}
          confirmLabel={text.rotateApiKey}
          isDestructive={false}
          text={text}
          onClose={close}
          onConfirm={async () => shown(await client.rotateApiKey(kind, id, open.key.id))}
        >
          <ul className="console-facts">
            <Consequence what={text.rotateApiKeyNew} value={text.rotateApiKeyNewValue} />
            <Consequence what={text.rotateApiKeyOld} value={text.rotateApiKeyOldValue} />
          </ul>
        </Confirm>
      ) : null}

      {open?.what === "revoke" ? (
        <Confirm
          action="revokeApiKey"
          title={text.revokeApiKeyTitle(open.key.name)}
          confirmLabel={text.revokeApiKey}
          typed={open.key.name}
          text={text}
          onClose={close}
          onConfirm={async () => {
            await client.revokeApiKey(kind, id, open.key.id);
            close();
            say(text.apiKeyRevoked(open.key.name));
            again();
          }}
        >
          <Text>{text.revokeApiKeyLead}</Text>
        </Confirm>
      ) : null}

      {made !== null ? (
        <ShownOnce
          secret={made}
          title={text.apiKeyShownOnceTitle}
          lead={text.apiKeyShownOnceLead}
          label={text.apiKeyLabel}
          text={text}
          onClose={() => {
            // Forgotten as the dialog closes.
            setMade(null);
          }}
        />
      ) : null}
    </VStack>
  );
}

/**
 * Makes an API key: a name, its scopes one a line, the application it
 * asks the Authorization API about, and its lifetime. Level 1: before its
 * button the form says the key is shown once.
 */
function ApiKeyForm({
  workload,
  submit,
  onClose,
  text,
}: {
  workload: Workload;
  submit: (settings: ApiKeySettings) => Promise<void>;
  onClose: () => void;
  text: Messages;
}) {
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState("");
  const [application, setApplication] = useState("");
  const [days, setDays] = useState(String(DEFAULT_LIFETIME_DAYS));
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const listed = linesOf(scopes);
  const filled = name.trim() !== "" && listed.length > 0;

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || !filled) {
      return;
    }
    const wanted = application.trim().toLowerCase();
    if (wanted !== "" && !isIdentifier(wanted)) {
      setMessage(text.applicationNotAnIdentifier);
      return;
    }
    const lifetimeDays = Number(days.trim());
    if (!Number.isInteger(lifetimeDays) || lifetimeDays < 1 || lifetimeDays > 365) {
      setMessage(text.valueInvalid["credential.api_key_lifetime_invalid"] ?? text.somethingWrong);
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      await submit({ name, scopes: listed, applicationId: wanted === "" ? null : wanted, lifetimeDays });
    } catch (thrown) {
      setMessage(describe(asFailure(thrown), text));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={600} purpose="form">
      <DialogHeader title={text.createApiKeyTitle(workload.name)} subtitle={<Ladder action="createApiKey" text={text} />} />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {message !== null ? <Banner status="error" title={message} role="alert" /> : null}
          <TextInput label={text.nameLabel} value={name} onChange={setName} autoComplete="off" hasAutoFocus width="100%" />
          <TextArea
            label={text.apiKeyScopesLabel}
            description={text.apiKeyScopesHint}
            value={scopes}
            onChange={setScopes}
            rows={3}
            width="100%"
          />
          <TextInput
            label={`${text.apiKeyApplicationLabel} (${text.optional})`}
            description={text.apiKeyApplicationHint}
            value={application}
            onChange={setApplication}
            autoComplete="off"
            autoCapitalize="none"
            hasSpellCheck={false}
            width="100%"
          />
          <TextInput
            label={text.apiKeyLifetimeLabel}
            description={text.apiKeyLifetimeHint}
            value={days}
            onChange={setDays}
            inputMode="numeric"
            autoComplete="off"
            width="100%"
          />
          <Text color="secondary">{text.apiKeyShownOnceConsequence}</Text>
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button type="submit" variant="primary" label={text.createApiKey} isDisabled={!filled} isLoading={busy} />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
