// The foundations, the Astryx components the consoles use most, and
// Hodor's own security patterns, side by side.

import { Badge } from "@astryxdesign/core/Badge";
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { HStack } from "@astryxdesign/core/HStack";
import { Heading } from "@astryxdesign/core/Heading";
import { Icon } from "@astryxdesign/core/Icon";
import { IconButton } from "@astryxdesign/core/IconButton";
import { Kbd } from "@astryxdesign/core/Kbd";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { Switch } from "@astryxdesign/core/Switch";
import { Table } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { useToast } from "@astryxdesign/core/Toast";
import { VStack } from "@astryxdesign/core/VStack";
import { RefreshCw } from "lucide-react";
import { type ReactNode, useState } from "react";
import { HoldButton, Identifier, Ladder, Overline, Severity } from "./parts";

function Section({ title, lead, children }: { title: string; lead: string; children: ReactNode }) {
  return (
    <VStack as="section" gap={3}>
      <Heading level={2}>{title}</Heading>
      <Text color="secondary">{lead}</Text>
      {children}
    </VStack>
  );
}

const swatches = [
  ["body", "--color-background-body"],
  ["surface", "--color-background-surface"],
  ["card", "--color-background-card"],
  ["muted", "--color-background-muted"],
  ["border", "--color-border-emphasized"],
  ["text", "--color-text-primary"],
  ["text-secondary", "--color-text-secondary"],
  ["accent", "--color-accent"],
  ["success", "--color-success"],
  ["warning", "--color-warning"],
  ["error", "--color-error"],
  ["info", "--color-info"],
] as const;

type AuditRecord = {
  id: string;
  actor: string;
  action: string;
  target: string;
  result: ReactNode;
  address: string;
  request: string;
  time: string;
};

const records: AuditRecord[] = [
  { id: "1", actor: "Rafaela Lima", action: "policy.published", target: "orders-access v13", result: <Badge variant="success" label="Success" />, address: "192.0.2.14", request: "0193c4…91d7", time: "14:02:11" },
  { id: "2", actor: "Marina Costa", action: "role.assigned", target: "tenant-administrator → j.silva", result: <Badge variant="warning" label="Pending approval" />, address: "192.0.2.88", request: "0193c3…0a4e", time: "13:47:52" },
  { id: "3", actor: "hodor-worker", action: "key.rotation_due", target: "tenant-signing", result: <Badge variant="error" label="Overdue" />, address: "—", request: "0193c1…77c0", time: "09:00:00" },
];

const ladder = [
  [0, "0 · Routine", "None", "Rename an application, edit a description"],
  [1, "1 · Notable", "A confirmation that names the consequence", "Generate a client secret, disable a user"],
  [2, "2 · Disruptive", "Type the name of the object", "Revoke all sessions of a user, delete a client"],
  [3, "3 · Critical", "Type the name, then a recent authentication", "Rotate signing keys, publish a policy"],
  [4, "4 · Irreversible", "All of the above, and a second administrator approves", "Delete a tenant, remove the last administrator"],
] as const;

export function Gallery() {
  const [density, setDensity] = useState("comfortable");
  const [pkce, setPkce] = useState(true);
  const [name, setName] = useState("");
  const [lifetime, setLifetime] = useState("90 days");
  const showToast = useToast();

  return (
    <div className="hodor-page">
      <VStack gap={8}>
        <VStack gap={1}>
          <Heading level={1}>Hodor design system</Heading>
          <Text type="supporting" color="secondary">
            Astryx components under the Hodor theme · Specification: docs/design/design-system.md · Decisions 0016 and
            0018
          </Text>
        </VStack>

        <Section
          title="Color"
          lead='Astryx tokens with Hodor&apos;s values: a cool "ink" neutral and the "signal" accent. Signal marks where you are and what you can do; it is never a status. Switch the mode in the top bar to see every token change.'
        >
          <div className="hodor-swatches">
            {swatches.map(([key, token]) => (
              <VStack key={key} gap={1}>
                <div className={`hodor-swatch__color hodor-swatch--${key}`} />
                <span className="hodor-mono">{token}</span>
              </VStack>
            ))}
          </div>
        </Section>

        <Section
          title="Status and severity"
          lead="Status describes an operation or an object; severity describes a security finding or event. Severity always pairs color with a shape and a word, so it survives color blindness and forced colors."
        >
          <HStack gap={2} wrap="wrap">
            <Badge variant="success" label="Verified" />
            <Badge variant="warning" label="Weakened setting" />
            <Badge variant="error" label="Locked" />
            <Badge variant="info" label="Draft" />
            <Badge label="Accepted" />
            <Badge variant="cyan" label="Security administrator" />
          </HStack>
          <HStack gap={5} wrap="wrap">
            <Severity level="critical" />
            <Severity level="high" />
            <Severity level="medium" />
            <Severity level="low" />
            <Severity level="informational" />
          </HStack>
        </Section>

        <Section
          title="Typography"
          lead="IBM Plex Sans for the interface and IBM Plex Mono for identifiers, secrets and policies, served with the application. Text takes a role, not a size."
        >
          <Card>
            <VStack gap={3}>
              <span className="hodor-figure">98.2% · 48,213</span>
              <Heading level={1}>Security posture</Heading>
              <Heading level={2}>Signing keys</Heading>
              <Text type="large">Confirm it is you before rotating the key.</Text>
              <Text>Administrators who sign in with a one-time code can be phished.</Text>
              <Text type="supporting" color="secondary">
                Last changed by Rafaela Lima 4 minutes ago
              </Text>
              <Overline>Refresh token reuse</Overline>
              <span className="hodor-mono">0193b8e2-77a1-7d0c-9f3e-1b2c9a8e4c1a O0 l1I</span>
            </VStack>
          </Card>
        </Section>

        <Section
          title="Actions"
          lead="Buttons are verbs that name the result. The destructive button is never the default and never pre-focused."
        >
          <HStack gap={2} wrap="wrap" vAlign="center">
            <Button variant="primary" label="Create application" />
            <Button label="Export report" />
            <Button variant="ghost" label="Cancel" />
            <Button variant="destructive" label="Delete user" />
            <Button label="Disabled" isDisabled />
            <Button size="sm" label="Small" />
            <IconButton label="Refresh" icon={<Icon icon={RefreshCw} />} />
            <Kbd keys="mod+k" />
          </HStack>
        </Section>

        <Section title="Inputs" lead="A field carries its label, its hint and what is wrong with it.">
          <div className="hodor-split hodor-split--even">
            <TextInput
              label="Application name"
              description="Shown on the consent screen."
              placeholder="Billing portal"
              value={name}
              onChange={setName}
            />
            <TextInput
              label="Refresh token lifetime"
              value={lifetime}
              onChange={setLifetime}
              status={{ type: "warning", message: "Recommended: 30 days with rotation." }}
              statusVariant="detached"
            />
            <VStack gap={1} hAlign="start">
              <Text type="label">Density</Text>
              <SegmentedControl label="Density" value={density} onChange={setDensity}>
                <SegmentedControlItem value="comfortable" label="Comfortable" />
                <SegmentedControlItem value="compact" label="Compact" />
              </SegmentedControl>
            </VStack>
            <Switch
              label="Require PKCE"
              description="Cannot be turned off for new clients."
              value={pkce}
              onChange={setPkce}
            />
          </div>
        </Section>

        <Section title="Feedback" lead="Alerts name the problem and the way out.">
          <VStack gap={3}>
            <Banner
              status="error"
              title="Audit delivery to the security event management system is failing"
              description="Events are kept and retried for 72 hours. Check the stream's endpoint."
            />
            <Banner
              status="warning"
              title="You are working under a support grant"
              description="Granted by Rafaela Lima, read-only, until 18:00 today."
            />
            <Banner status="success" title="Domain acme.example verified" description="It can now be used to route sign-ins." />
            <HStack>
              <Button label="Show a toast" onClick={() => showToast({ body: "Policy published. Recorded as audit record 0193c4b2…91d7." })} />
            </HStack>
          </VStack>
        </Section>

        <Section
          title="Data"
          lead="Tables put decision-relevant columns first, use tabular figures, and truncate identifiers in the middle."
        >
          <Table
            data={records}
            idKey="id"
            density={density === "compact" ? "compact" : "balanced"}
            hasHover
            columns={[
              { key: "actor", header: "Actor" },
              { key: "action", header: "Action" },
              { key: "target", header: "Target" },
              { key: "result", header: "Result", renderCell: (record) => record.result },
              { key: "address", header: "IP address" },
              { key: "request", header: "Request", renderCell: (record) => <span className="hodor-mono">{record.request}</span> },
              { key: "time", header: "Time", align: "end" },
            ]}
          />
        </Section>

        <Section
          title="Dangerous action ladder"
          lead="Every state-changing action has one level, defined once in the action catalog. The control plane example shows levels 2 and 3 working."
        >
          <Table
            data={ladder.map(([level, name, friction, examples]) => ({ id: String(level), level, name, friction, examples }))}
            idKey="id"
            columns={[
              { key: "name", header: "Level", renderCell: (row) => <Ladder level={row.level}>{row.name}</Ladder> },
              { key: "friction", header: "Friction" },
              { key: "examples", header: "Examples" },
            ]}
          />
          <HStack gap={3} vAlign="center" wrap="wrap">
            <HoldButton label="Hold to confirm" onConfirm={() => showToast({ body: "Held for 1.5 seconds: confirmed." })} />
            <Text type="supporting" color="secondary">
              Pointer or Space held for 1.5 seconds. Reserved for the most destructive actions.
            </Text>
          </HStack>
        </Section>

        <Section
          title="Secrets and identifiers"
          lead="A secret is shown once, then only its prefix. Identifiers are mono, middle-truncated and copyable."
        >
          <div className="hodor-split hodor-split--even">
            <VStack gap={2}>
              <Overline>Shown once</Overline>
              <div className="hodor-secret">hds_live_K9vT2mXq7RbW4nLp8sYc3HdF6jZa1Ue5</div>
              <Text type="supporting" color="secondary">
                Hodor stores only a hash. Copy it now.
              </Text>
            </VStack>
            <Card>
              <VStack gap={2} hAlign="start">
                <Overline>Stored secret</Overline>
                <Identifier shown="hds_live_K9vT…a1Ue5" value="hds_live_K9vT" label="Copy secret prefix" />
                <Text type="supporting" color="secondary">
                  Created 2025-11-20 · last used 3 hours ago
                </Text>
              </VStack>
            </Card>
          </div>
        </Section>
      </VStack>
    </div>
  );
}
