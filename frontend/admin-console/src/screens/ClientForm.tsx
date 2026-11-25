import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { CheckboxList, CheckboxListItem } from "@astryxdesign/core/CheckboxList";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { HStack } from "@astryxdesign/core/HStack";
import { RadioList, RadioListItem } from "@astryxdesign/core/RadioList";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { Switch } from "@astryxdesign/core/Switch";
import { Text } from "@astryxdesign/core/Text";
import { TextArea } from "@astryxdesign/core/TextArea";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useState } from "react";
import { isIdentifier } from "../address";
import type { ApplicationClient, ClientSettings, Failure } from "../client";
import { describe, named, type Messages } from "../messages";
import { Ladder } from "../parts/Confirm";
import { asFailure } from "../parts/Loaded";
import { scopesOf } from "./ProviderForm";

const GRANTS = ["authorization_code", "refresh_token", "client_credentials"] as const;
const CONFIDENTIAL_METHODS = [
  "client_secret_basic",
  "client_secret_post",
  "private_key_jwt",
  "spiffe_jwt",
  "spiffe_x509",
  "tls_client_auth",
  "linkerd_identity",
] as const;

/**
 * The methods by which a client proves its workload's identity, given by
 * its mesh or SPIRE: such a client acts as a service account, asks only
 * for client credentials, and has no secret.
 */
const WORKLOAD_METHODS: readonly string[] = ["spiffe_jwt", "spiffe_x509", "tls_client_auth", "linkerd_identity"];

/** Which identity a method binds the client to; `tls_client_auth` takes either. */
type IdentityKind = "spiffe" | "linkerd";

function identityOf(method: string, chosen: IdentityKind): IdentityKind | null {
  switch (method) {
    case "spiffe_jwt":
    case "spiffe_x509":
      return "spiffe";
    case "linkerd_identity":
      return "linkerd";
    case "tls_client_auth":
      return chosen;
    default:
      return null;
  }
}

/** Redirect addresses as typed: one per line, kept exactly as written otherwise. */
export function linesOf(typed: string): string[] {
  return typed
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

interface Props {
  /** The client being changed; `null` to create one. */
  current: ApplicationClient | null;
  /** Creates or changes; a failure it throws is shown and the form stays open. */
  submit: (type: string, settings: ClientSettings) => Promise<void>;
  onClose: () => void;
  text: Messages;
}

/**
 * The form of a client. The server checks every rule of a client; the
 * form keeps to what can be chosen, so that a public client is never
 * offered a secret, and a client of a workload's identity is offered only
 * client credentials and the identity its method takes.
 */
export function ClientForm({ current, submit, onClose, text }: Props) {
  const [type, setType] = useState(current?.type ?? "confidential");
  const [name, setName] = useState(current?.name ?? "");
  const [method, setMethod] = useState(current?.authenticationMethod ?? "client_secret_basic");
  const [grants, setGrants] = useState<string[]>(current?.grantTypes ?? ["authorization_code"]);
  const [redirects, setRedirects] = useState((current?.redirectUris ?? []).join("\n"));
  const [afterLogout, setAfterLogout] = useState((current?.postLogoutRedirectUris ?? []).join("\n"));
  const [scopes, setScopes] = useState((current?.allowedScopes ?? ["openid"]).join(" "));
  const [principal, setPrincipal] = useState(current?.principal ?? "");
  const [chosenIdentity, setChosenIdentity] = useState<IdentityKind>(
    current !== null && current.spiffeId === null && current.linkerdIdentity !== null ? "linkerd" : "spiffe",
  );
  const [spiffeId, setSpiffeId] = useState(current?.spiffeId ?? "");
  const [linkerdIdentity, setLinkerdIdentity] = useState(current?.linkerdIdentity ?? "");
  const [bound, setBound] = useState(current?.certificateBoundAccessTokens ?? false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [notPrincipal, setNotPrincipal] = useState(false);
  const isPublic = type === "public";
  const chosenMethod = isPublic ? "none" : method;
  const ofWorkload = WORKLOAD_METHODS.includes(chosenMethod);
  const identity = identityOf(chosenMethod, chosenIdentity);
  // A client of a Linkerd identity has no certificate to bind its tokens to.
  const mayBind = chosenMethod !== "linkerd_identity";
  const offered = GRANTS.filter((grant) =>
    ofWorkload ? grant === "client_credentials" : !(isPublic && grant === "client_credentials"),
  );
  const chosenGrants = offered.filter((grant) => grants.includes(grant));
  const filled =
    name.trim() !== "" &&
    chosenGrants.length > 0 &&
    (!ofWorkload || principal.trim() !== "") &&
    (identity !== "spiffe" || spiffeId.trim() !== "") &&
    (identity !== "linkerd" || linkerdIdentity.trim() !== "");

  function chooseMethod(chosen: string) {
    setMethod(chosen);
    if (WORKLOAD_METHODS.includes(chosen)) {
      // A workload's client asks only for client credentials.
      setGrants(["client_credentials"]);
    }
  }

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy || !filled) {
      return;
    }
    if (ofWorkload && !isIdentifier(principal.trim())) {
      setNotPrincipal(true);
      return;
    }
    setNotPrincipal(false);
    setBusy(true);
    setFailure(null);
    try {
      await submit(type, {
        name,
        authenticationMethod: chosenMethod,
        // Kept in the order the server documents them.
        grantTypes: chosenGrants,
        redirectUris: ofWorkload ? [] : linesOf(redirects),
        postLogoutRedirectUris: ofWorkload ? [] : linesOf(afterLogout),
        allowedScopes: scopesOf(scopes),
        principal: ofWorkload ? principal : null,
        spiffeId: identity === "spiffe" ? spiffeId : null,
        linkerdIdentity: identity === "linkerd" ? linkerdIdentity : null,
        certificateBoundAccessTokens: mayBind && bound,
      });
    } catch (thrown) {
      setFailure(asFailure(thrown));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={640} purpose="form">
      <DialogHeader
        title={current === null ? text.addClient : text.changeSettingsTitle(current.name)}
        subtitle={<Ladder action={current === null ? "addClient" : "changeClient"} text={text} />}
      />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {failure !== null ? <Banner status="error" title={describe(failure, text)} role="alert" /> : null}
          <TextInput
            label={text.clientNameLabel}
            value={name}
            onChange={setName}
            autoComplete="off"
            hasAutoFocus
            width="100%"
          />
          <VStack gap={1}>
            <Text>{text.clientTypeLabel}</Text>
            {current === null ? (
              <SegmentedControl label={text.clientTypeLabel} value={type} onChange={setType}>
                <SegmentedControlItem value="confidential" label={named(text.clientTypes, "confidential")} />
                <SegmentedControlItem value="public" label={named(text.clientTypes, "public")} />
              </SegmentedControl>
            ) : (
              <Text>{named(text.clientTypes, type)}</Text>
            )}
            <Text type="supporting" color="secondary">
              {current === null ? named(text.clientTypeHints, type) : text.clientTypeFixed}
            </Text>
          </VStack>
          {isPublic ? null : (
            <RadioList label={text.methodLabel} value={method} onChange={chooseMethod} size="sm">
              {CONFIDENTIAL_METHODS.map((value) => (
                <RadioListItem
                  key={value}
                  value={value}
                  label={named(text.methods, value)}
                  description={named(text.methodHints, value)}
                />
              ))}
            </RadioList>
          )}
          {ofWorkload ? (
            <>
              <Text color="secondary">{text.workloadMethodLead}</Text>
              <TextInput
                label={text.principalServiceAccountLabel}
                description={text.principalServiceAccountHint}
                value={principal}
                onChange={(typed) => {
                  setPrincipal(typed);
                  setNotPrincipal(false);
                }}
                status={notPrincipal ? { type: "error", message: text.principalNotAnIdentifier } : undefined}
                autoComplete="off"
                autoCapitalize="none"
                hasSpellCheck={false}
                width="100%"
              />
            </>
          ) : null}
          {chosenMethod === "tls_client_auth" ? (
            <VStack gap={1}>
              <Text>{text.identityKindLabel}</Text>
              <SegmentedControl
                label={text.identityKindLabel}
                value={chosenIdentity}
                onChange={(value) => setChosenIdentity(value === "linkerd" ? "linkerd" : "spiffe")}
              >
                <SegmentedControlItem value="spiffe" label={text.spiffeIdLabel} />
                <SegmentedControlItem value="linkerd" label={text.linkerdIdentityLabel} />
              </SegmentedControl>
            </VStack>
          ) : null}
          {identity === "spiffe" ? (
            <TextInput
              label={text.spiffeIdLabel}
              description={text.spiffeIdHint}
              value={spiffeId}
              onChange={setSpiffeId}
              autoComplete="off"
              autoCapitalize="none"
              hasSpellCheck={false}
              width="100%"
            />
          ) : null}
          {identity === "linkerd" ? (
            <TextInput
              label={text.linkerdIdentityLabel}
              description={text.linkerdIdentityHint}
              value={linkerdIdentity}
              onChange={setLinkerdIdentity}
              autoComplete="off"
              autoCapitalize="none"
              hasSpellCheck={false}
              width="100%"
            />
          ) : null}
          <CheckboxList label={text.grantsLabel} value={chosenGrants} onChange={setGrants}>
            {offered.map((grant) => (
              <CheckboxListItem key={grant} value={grant} label={named(text.grants, grant)} />
            ))}
          </CheckboxList>
          {ofWorkload ? null : (
            <>
              <TextArea
                label={text.redirectUrisLabel}
                description={text.redirectUrisHint}
                value={redirects}
                onChange={setRedirects}
                rows={3}
                width="100%"
              />
              <TextArea
                label={text.postLogoutRedirectUrisLabel}
                description={text.postLogoutRedirectUrisHint}
                value={afterLogout}
                onChange={setAfterLogout}
                rows={2}
                width="100%"
              />
            </>
          )}
          <TextInput
            label={text.allowedScopesLabel}
            description={text.allowedScopesHint}
            value={scopes}
            onChange={setScopes}
            autoComplete="off"
            autoCapitalize="none"
            hasSpellCheck={false}
            width="100%"
          />
          {mayBind ? (
            <VStack gap={1}>
              <Switch label={text.certificateBoundLabel} value={bound} onChange={setBound} />
              <Text type="supporting" color="secondary">
                {text.certificateBoundHint}
              </Text>
            </VStack>
          ) : null}
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button
              type="submit"
              variant="primary"
              label={current === null ? text.addClient : text.saveClient}
              isDisabled={!filled}
              isLoading={busy}
            />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
