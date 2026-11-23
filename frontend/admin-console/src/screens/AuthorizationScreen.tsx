import { Badge } from "@astryxdesign/core/Badge";
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { TextArea } from "@astryxdesign/core/TextArea";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { type FormEvent, useCallback, useState } from "react";
import { may } from "../actions";
import type { Binding, DecisionRecord, Failure, PolicyStatus, ResourceServer, RoleDefinition } from "../client";
import { describe, type Messages, moment } from "../messages";
import { Confirm, Consequence, Ladder } from "../parts/Confirm";
import { asFailure, Failed, useLoaded, Waiting } from "../parts/Loaded";
import { Page, type ScreenProps } from "./shared";

/** A role's permissions as the editor writes them: one a line, `name` or `name if condition`. */
export function permissionLines(role: RoleDefinition): string {
  return role.permissions
    .map((held) => (held.condition === null ? held.name : `${held.name} if ${held.condition}`))
    .join("\n");
}

/** Reads the editor's lines back. The server checks every name and condition. */
export function readPermissionLines(lines: string): RoleDefinition["permissions"] {
  return lines
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "")
    .map((line) => {
      const at = line.indexOf(" if ");
      return at < 0
        ? { name: line, condition: null }
        : { name: line.slice(0, at).trim(), condition: line.slice(at + 4).trim() };
    });
}

function reference(role: { namespace: string; name: string }): string {
  return `${role.namespace}#${role.name}`;
}

/**
 * The tenant's authorization: its roles, the engine of each resource
 * server, what is published for Open Policy Agent, and recent decisions.
 * Publishing and rolling back are not here: only the command line holds
 * the key that signs bundles.
 */
export function AuthorizationScreen({ client, me, text, say }: ScreenProps) {
  const loadRoles = useCallback(
    () => Promise.all([client.listRoles(), client.listResourceServers()]),
    [client],
  );
  const [roles, againRoles] = useLoaded<[RoleDefinition[], ResourceServer[]]>(loadRoles);
  const mayBindings = me.permissions.includes("bindings:read");
  const loadBindings = useCallback(
    () => (mayBindings ? client.listBindings() : Promise.resolve<Binding[]>([])),
    [client, mayBindings],
  );
  const [bindings, againBindings] = useLoaded<Binding[]>(loadBindings);
  const mayPolicies = me.permissions.includes("policies:read");
  const loadStatus = useCallback(
    () => (mayPolicies ? client.policyStatus().catch(() => null) : Promise.resolve(null)),
    [client, mayPolicies],
  );
  const [status] = useLoaded<PolicyStatus | null>(loadStatus);
  const mayDecisions = me.permissions.includes("decisions:read");
  const [effect, setEffect] = useState<string>("all");
  const loadDecisions = useCallback(
    () => (mayDecisions ? client.listDecisions(effect === "all" ? null : effect) : Promise.resolve<DecisionRecord[]>([])),
    [client, mayDecisions, effect],
  );
  const [decisions, againDecisions] = useLoaded<DecisionRecord[]>(loadDecisions);
  const [editing, setEditing] = useState<{ role: RoleDefinition; server: ResourceServer } | null>(null);
  const [unbinding, setUnbinding] = useState<Binding | null>(null);

  const servers = roles.state === "loaded" ? roles.value[1] : [];
  const serverOf = (namespace: string) => servers.find((server) => server.audience === namespace) ?? null;

  return (
    <Page title={text.authorization} lead={text.authorizationLead}>
      <VStack gap={6}>
        <VStack gap={3}>
          <Heading level={2}>{text.rolesTitle}</Heading>
          {roles.state === "loading" ? <Waiting text={text} /> : null}
          {roles.state === "failed" ? <Failed failure={roles.failure} again={againRoles} text={text} /> : null}
          {roles.state === "loaded" ? (
            <Table<{ id: string; role: RoleDefinition }>
              data={roles.value[0].map((role) => ({ id: reference(role), role }))}
              idKey="id"
              emptyState={<EmptyState title={text.noRoles} description={text.noRolesHint} isCompact />}
              columns={[
                {
                  key: "role",
                  header: text.columnRole,
                  renderCell: ({ role }) => <span className="console-mono">{reference(role)}</span>,
                },
                {
                  key: "permissions",
                  header: text.columnPermissions,
                  renderCell: ({ role }) => (
                    <VStack gap={1}>
                      {role.permissions.map((held) => (
                        <Text key={held.name}>
                          <span className="console-mono">{held.name}</span>
                          {held.condition === null ? null : (
                            <Text type="supporting" color="secondary">
                              {" "}
                              {text.conditionShown(held.condition)}
                            </Text>
                          )}
                        </Text>
                      ))}
                    </VStack>
                  ),
                },
                {
                  key: "includes",
                  header: text.columnIncludes,
                  renderCell: ({ role }) => role.includes.map(reference).join(", ") || "—",
                },
                {
                  key: "edit",
                  header: "",
                  renderCell: ({ role }) => {
                    const server = serverOf(role.namespace);
                    return server !== null && may(me.permissions, "defineRole") ? (
                      <Button label={text.editRole} onClick={() => setEditing({ role, server })} />
                    ) : null;
                  },
                },
              ]}
            />
          ) : null}
        </VStack>

        {mayBindings ? (
          <VStack gap={3}>
            <Heading level={2}>{text.bindingsTitle}</Heading>
            {bindings.state === "loading" ? <Waiting text={text} /> : null}
            {bindings.state === "failed" ? <Failed failure={bindings.failure} again={againBindings} text={text} /> : null}
            {bindings.state === "loaded" ? (
              <Table<{ id: string; binding: Binding }>
                data={bindings.value.map((binding) => ({ id: binding.namespace, binding }))}
                idKey="id"
                emptyState={<EmptyState title={text.noBindings} description={text.noBindingsHint} isCompact />}
                columns={[
                  {
                    key: "namespace",
                    header: text.columnResourceServer,
                    renderCell: ({ binding }) => <span className="console-mono">{binding.namespace}</span>,
                  },
                  { key: "engine", header: text.columnEngine, renderCell: ({ binding }) => binding.engine },
                  {
                    key: "limit",
                    header: text.columnTimeLimit,
                    renderCell: ({ binding }) => text.milliseconds(binding.timeLimitMilliseconds),
                  },
                  {
                    key: "open",
                    header: text.columnFailOpen,
                    renderCell: ({ binding }) =>
                      binding.failOpenActions.length === 0 ? (
                        text.failsClosed
                      ) : (
                        <Badge variant="orange" label={binding.failOpenActions.join(", ")} />
                      ),
                  },
                  {
                    key: "remove",
                    header: "",
                    renderCell: ({ binding }) =>
                      may(me.permissions, "unbind") ? (
                        <Button label={text.unbind} onClick={() => setUnbinding(binding)} />
                      ) : null,
                  },
                ]}
              />
            ) : null}
          </VStack>
        ) : null}

        {mayPolicies && status.state === "loaded" && status.value !== null ? (
          <VStack gap={3}>
            <Heading level={2}>{text.policiesTitle}</Heading>
            <Text color="secondary">{text.policiesPublishedWithCli}</Text>
            {status.value.latest === null ? (
              <Text>{text.nothingPublished}</Text>
            ) : (
              <Text>
                {text.latestRevision(status.value.latest.revision, moment(status.value.latest.publishedAt, text))}
              </Text>
            )}
            {status.value.pendingActivation ? <Banner status="warning" title={text.activationPending} /> : null}
            <ul className="console-facts">
              {status.value.instances.map((instance) => (
                <Consequence
                  key={instance.instance}
                  what={instance.instance}
                  value={
                    instance.current
                      ? text.instanceCurrent
                      : text.instanceBehind(instance.activeRevision ?? "—")
                  }
                />
              ))}
            </ul>
          </VStack>
        ) : null}

        {mayDecisions ? (
          <VStack gap={3}>
            <HStack gap={3} vAlign="center" justify="between">
              <Heading level={2}>{text.decisionsTitle}</Heading>
              <SegmentedControl label={text.effectFilter} value={effect} onChange={setEffect}>
                <SegmentedControlItem value="all" label={text.effectAll} />
                <SegmentedControlItem value="allow" label={text.effectAllow} />
                <SegmentedControlItem value="deny" label={text.effectDeny} />
                <SegmentedControlItem value="indeterminate" label={text.effectIndeterminate} />
              </SegmentedControl>
            </HStack>
            {decisions.state === "loading" ? <Waiting text={text} /> : null}
            {decisions.state === "failed" ? (
              <Failed failure={decisions.failure} again={againDecisions} text={text} />
            ) : null}
            {decisions.state === "loaded" ? (
              <Table<{ id: string; record: DecisionRecord }>
                data={decisions.value.map((record) => ({ id: record.id, record }))}
                idKey="id"
                emptyState={<EmptyState title={text.noDecisions} isCompact />}
                columns={[
                  { key: "when", header: text.columnWhen, renderCell: ({ record }) => moment(record.decidedAt, text) },
                  {
                    key: "effect",
                    header: text.columnEffect,
                    renderCell: ({ record }) => (
                      <Badge
                        variant={record.effect === "allow" ? "green" : record.effect === "deny" ? "red" : "orange"}
                        label={record.effect}
                      />
                    ),
                  },
                  { key: "reason", header: text.columnReason, renderCell: ({ record }) => record.reason },
                  {
                    key: "asked",
                    header: text.columnAsked,
                    renderCell: ({ record }) => (
                      <span className="console-mono">{`${record.subject} ${record.action} · ${record.namespace}`}</span>
                    ),
                  },
                ]}
              />
            ) : null}
          </VStack>
        ) : null}
      </VStack>

      {editing !== null ? (
        <RoleEditor
          role={editing.role}
          text={text}
          onClose={() => setEditing(null)}
          submit={async (role) => {
            await client.defineRole(editing.server.id, role);
          }}
          onDone={(role) => {
            setEditing(null);
            say(text.roleSaved(reference(role)));
            againRoles();
          }}
        />
      ) : null}

      {unbinding !== null ? (
        <Confirm
          action="unbind"
          title={text.unbindTitle(unbinding.namespace)}
          confirmLabel={text.unbind}
          typed={unbinding.namespace}
          text={text}
          onClose={() => setUnbinding(null)}
          onConfirm={async () => {
            const server = serverOf(unbinding.namespace);
            if (server === null) {
              throw new Error("no resource server");
            }
            await client.unbind(server.id);
            setUnbinding(null);
            say(text.unbound(unbinding.namespace));
            againBindings();
          }}
        >
          <ul className="console-facts">
            <Consequence what={text.unbindConsequence} value={text.unbindConsequenceValue} />
          </ul>
        </Confirm>
      ) : null}
    </Page>
  );
}

/** The form of a role: its description and permissions, conditions included, as text. */
function RoleEditor({
  role,
  text,
  submit,
  onDone,
  onClose,
}: {
  role: RoleDefinition;
  text: Messages;
  submit: (role: RoleDefinition) => Promise<void>;
  onDone: (role: RoleDefinition) => void;
  onClose: () => void;
}) {
  const [description, setDescription] = useState(role.description);
  const [lines, setLines] = useState(permissionLines(role));
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<Failure | null>(null);

  async function send(event: FormEvent) {
    event.preventDefault();
    if (busy) {
      return;
    }
    setBusy(true);
    setFailure(null);
    const changed = { ...role, description, permissions: readPermissionLines(lines) };
    try {
      await submit(changed);
      onDone(changed);
    } catch (thrown) {
      setFailure(asFailure(thrown));
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onOpenChange={onClose} width={640} purpose="form">
      <DialogHeader title={text.editRoleTitle(reference(role))} subtitle={<Ladder action="defineRole" text={text} />} />
      <form noValidate onSubmit={(event) => void send(event)}>
        <VStack gap={4} padding={4}>
          {failure !== null ? <Banner status="error" title={describe(failure, text)} role="alert" /> : null}
          <TextInput label={text.roleDescriptionLabel} value={description} onChange={setDescription} width="100%" />
          <TextArea
            label={text.rolePermissionsLabel}
            description={text.rolePermissionsHint}
            value={lines}
            onChange={setLines}
            rows={6}
            width="100%"
          />
          <HStack gap={2} justify="end">
            <Button label={text.cancel} onClick={onClose} />
            <Button type="submit" variant="primary" label={text.saveRole} isLoading={busy} />
          </HStack>
        </VStack>
      </form>
    </Dialog>
  );
}
