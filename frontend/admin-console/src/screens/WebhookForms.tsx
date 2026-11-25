import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { CheckboxList, CheckboxListItem } from "@astryxdesign/core/CheckboxList";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { Text } from "@astryxdesign/core/Text";
import { TextArea } from "@astryxdesign/core/TextArea";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useCallback, useState } from "react";
import type { Client, EndpointSettings, WebhookEndpoint } from "../client";
import { describe, named, type Messages } from "../messages";
import { Ladder } from "../parts/Confirm";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";

/** The groups of the catalog, as the webhooks context groups them. */
const GROUPS = ["identity", "memberships", "session", "authentication", "credential", "federation", "oauth"] as const;
type Group = (typeof GROUPS)[number];

function groupOf(type: string): Group {
  if (/^identity\.(group_|organization_|invitation_)/.test(type)) {
    return "memberships";
  }
  const prefix = type.split(".")[0] ?? "";
  return (GROUPS as readonly string[]).includes(prefix) ? (prefix as Group) : "identity";
}

/** The event types of the catalog, a checkbox each, in their groups. */
function EventTypes({
  catalog,
  chosen,
  choose,
  text,
}: {
  catalog: string[];
  chosen: string[];
  choose: (types: string[]) => void;
  text: Messages;
}) {
  return (
    <VStack gap={3}>
      <Text>{text.eventTypesLabel}</Text>
      {GROUPS.map((group) => {
        const types = catalog.filter((type) => groupOf(type) === group);
        if (types.length === 0) {
          return null;
        }
        const others = chosen.filter((type) => groupOf(type) !== group);
        return (
          <CheckboxList
            key={group}
            label={named(text.eventGroups, group)}
            value={chosen.filter((type) => groupOf(type) === group)}
            onChange={(picked) => choose([...others, ...picked])}
          >
            {types.map((type) => (
              <CheckboxListItem key={type} value={type} label={<span className="console-mono">{type}</span>} />
            ))}
          </CheckboxList>
        );
      })}
    </VStack>
  );
}

/** The catalog, asked for when a form opens. */
function useCatalog(client: Client) {
  const load = useCallback(() => client.listEventTypes(), [client]);
  return useLoaded<string[]>(load);
}

/** The order of the catalog, for what is sent and compared. */
function inOrder(catalog: string[], chosen: string[]): string[] {
  return catalog.filter((type) => chosen.includes(type));
}

/**
 * Registers an endpoint: its address, an optional description and the
 * event types it receives. Level 1: before its button the form says that
 * every event of those types will be sent there, signed with a secret
 * shown once.
 */
export function EndpointForm({
  client,
  submit,
  onClose,
  text,
}: {
  client: Client;
  submit: (settings: EndpointSettings) => Promise<void>;
  onClose: () => void;
  text: Messages;
}) {
  const [catalog, again] = useCatalog(client);
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [chosen, setChosen] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const filled = url.trim() !== "" && chosen.length > 0;

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || !filled || catalog.state !== "loaded") {
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      await submit({ url, description, eventTypes: inOrder(catalog.value, chosen) });
    } catch (thrown) {
      setMessage(describe(asFailure(thrown), text));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={640} purpose="form">
      <DialogHeader title={text.registerEndpointTitle} subtitle={<Ladder action="registerEndpoint" text={text} />} />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {message !== null ? <Banner status="error" title={message} role="alert" /> : null}
          <TextInput
            label={text.endpointAddressLabel}
            description={text.endpointAddressHint}
            value={url}
            onChange={setUrl}
            autoComplete="off"
            autoCapitalize="none"
            hasSpellCheck={false}
            hasAutoFocus
            width="100%"
          />
          <TextArea
            label={`${text.descriptionLabel} (${text.optional})`}
            value={description}
            onChange={setDescription}
            rows={2}
            width="100%"
          />
          {catalog.state === "loading" ? <Waiting text={text} /> : null}
          {catalog.state === "failed" ? <Failed failure={catalog.failure} again={again} text={text} /> : null}
          {catalog.state === "loaded" ? (
            <EventTypes catalog={catalog.value} chosen={chosen} choose={setChosen} text={text} />
          ) : null}
          <Text color="secondary">{text.registerEndpointConsequence}</Text>
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button type="submit" variant="primary" label={text.registerEndpoint} isDisabled={!filled} isLoading={busy} />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}

/**
 * Replaces the event types of an endpoint. Level 1: the form says that
 * only events that happen from now on are sent with the new choice.
 */
export function SubscriptionsForm({
  endpoint,
  client,
  submit,
  onClose,
  text,
}: {
  endpoint: WebhookEndpoint;
  client: Client;
  submit: (eventTypes: string[]) => Promise<void>;
  onClose: () => void;
  text: Messages;
}) {
  const [catalog, again] = useCatalog(client);
  const [chosen, setChosen] = useState<string[]>(endpoint.eventTypes);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const ordered = catalog.state === "loaded" ? inOrder(catalog.value, chosen) : chosen;
  const changed =
    ordered.length !== endpoint.eventTypes.length || ordered.some((type) => !endpoint.eventTypes.includes(type));
  const filled = ordered.length > 0 && changed;

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || !filled) {
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      await submit(ordered);
    } catch (thrown) {
      setMessage(describe(asFailure(thrown), text));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={640} purpose="form">
      <DialogHeader
        title={text.changeSubscriptionsTitle(endpoint.url)}
        subtitle={<Ladder action="changeSubscriptions" text={text} />}
      />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {message !== null ? <Banner status="error" title={message} role="alert" /> : null}
          {catalog.state === "loading" ? <Waiting text={text} /> : null}
          {catalog.state === "failed" ? <Failed failure={catalog.failure} again={again} text={text} /> : null}
          {catalog.state === "loaded" ? (
            <EventTypes catalog={catalog.value} chosen={chosen} choose={setChosen} text={text} />
          ) : null}
          <Text color="secondary">{text.changeSubscriptionsConsequence}</Text>
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button
              type="submit"
              variant="primary"
              label={text.saveSubscriptions}
              isDisabled={!filled}
              isLoading={busy}
            />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
