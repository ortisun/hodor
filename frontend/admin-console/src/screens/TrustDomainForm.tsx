import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { RadioList, RadioListItem } from "@astryxdesign/core/RadioList";
import { Text } from "@astryxdesign/core/Text";
import { TextArea } from "@astryxdesign/core/TextArea";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useState } from "react";
import type { TrustDomain, TrustDomainSettings, TrustDomainSource } from "../client";
import { describe, named, type Messages } from "../messages";
import { Ladder } from "../parts/Confirm";
import { asFailure } from "../parts/Loaded";

const SOURCES: readonly TrustDomainSource[] = ["bundle_endpoint", "uploaded", "mesh"];

interface Props {
  /** The trust domain whose source is replaced; `null` to add one. */
  current: TrustDomain | null;
  /** Adds or replaces; a failure it throws is shown and the form stays open. */
  submit: (name: string, settings: TrustDomainSettings) => Promise<void>;
  onClose: () => void;
  text: Messages;
}

/**
 * Adds a trust domain, with its name and one source, or replaces the
 * source of one, whose name never changes. Level 1: before its button the
 * form says what the tenant trusts from the next request. A bundle that is
 * not JSON is said without asking the server; every other rule is the
 * server's.
 */
export function TrustDomainForm({ current, submit, onClose, text }: Props) {
  const [name, setName] = useState("");
  const [source, setSource] = useState<TrustDomainSource>(current?.source ?? "bundle_endpoint");
  const [address, setAddress] = useState(current?.bundleEndpointUrl ?? "");
  const [bundle, setBundle] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const filled =
    (current !== null || name.trim() !== "") &&
    (source !== "uploaded" || bundle.trim() !== "") &&
    (source !== "bundle_endpoint" || address.trim() !== "") &&
    // A mesh trust domain has nothing to replace with another mesh.
    !(current?.source === "mesh" && source === "mesh");

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || !filled) {
      return;
    }
    let settings: TrustDomainSettings;
    if (source === "uploaded") {
      let parsed: unknown;
      try {
        parsed = JSON.parse(bundle);
      } catch {
        setMessage(text.bundleNotJson);
        return;
      }
      settings = { source, bundle: parsed };
    } else if (source === "bundle_endpoint") {
      settings = { source, bundleEndpointUrl: address };
    } else {
      settings = { source };
    }
    setBusy(true);
    setMessage(null);
    try {
      await submit(current?.name ?? name, settings);
    } catch (thrown) {
      setMessage(describe(asFailure(thrown), text));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={640} purpose="form">
      <DialogHeader
        title={current === null ? text.addTrustDomainTitle : text.replaceTrustDomainTitle(current.name)}
        subtitle={<Ladder action={current === null ? "addTrustDomain" : "replaceTrustDomain"} text={text} />}
      />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {message !== null ? <Banner status="error" title={message} role="alert" /> : null}
          {current === null ? (
            <TextInput
              label={text.nameLabel}
              description={text.trustDomainNameHint}
              value={name}
              onChange={setName}
              autoComplete="off"
              autoCapitalize="none"
              hasSpellCheck={false}
              hasAutoFocus
              width="100%"
            />
          ) : null}
          <RadioList
            label={text.sourceLabel}
            value={source}
            onChange={(chosen) => setSource(chosen === "uploaded" || chosen === "mesh" ? chosen : "bundle_endpoint")}
            size="sm"
          >
            {SOURCES.map((value) => (
              <RadioListItem
                key={value}
                value={value}
                label={named(text.trustDomainSources, value)}
                description={named(text.trustDomainSourceHints, value)}
              />
            ))}
          </RadioList>
          {source === "bundle_endpoint" ? (
            <TextInput
              label={text.bundleEndpointLabel}
              description={text.bundleEndpointHint}
              value={address}
              onChange={setAddress}
              autoComplete="off"
              autoCapitalize="none"
              hasSpellCheck={false}
              width="100%"
            />
          ) : null}
          {source === "uploaded" ? (
            <TextArea
              label={text.bundleLabel}
              description={text.bundleHint}
              value={bundle}
              onChange={setBundle}
              rows={8}
              width="100%"
            />
          ) : null}
          <Text color="secondary">
            {current === null ? text.addTrustDomainConsequence : text.replaceTrustDomainConsequence}
          </Text>
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button
              type="submit"
              variant="primary"
              label={current === null ? text.addTrustDomain : text.saveTrustDomain}
              isDisabled={!filled}
              isLoading={busy}
            />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
