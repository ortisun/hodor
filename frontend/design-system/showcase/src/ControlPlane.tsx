// The security posture screen of the control plane, with sample data
// (docs/design/control-plane.md).

import { Badge } from "@astryxdesign/core/Badge";
import { Banner } from "@astryxdesign/core/Banner";
import { BreadcrumbItem, Breadcrumbs } from "@astryxdesign/core/Breadcrumbs";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { HStack } from "@astryxdesign/core/HStack";
import { Heading } from "@astryxdesign/core/Heading";
import { Icon } from "@astryxdesign/core/Icon";
import { Link } from "@astryxdesign/core/Link";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { StatusDot } from "@astryxdesign/core/StatusDot";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { Download, LifeBuoy, RefreshCw } from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";
import type { DialogName } from "./dialogs";
import { Code, Decision, Diff, type DiffLine, Fact, Facts, Identifier, Overline, Score, Severity, type SeverityLevel, Spark } from "./parts";

interface Finding {
  severity: SeverityLevel;
  title: ReactNode;
  why: string;
  objects?: ReactNode;
  action?: { label: string; opens?: DialogName };
  accepted?: boolean;
}

const findings: Finding[] = [
  {
    severity: "high",
    title: "2 administrators have no phishing-resistant multi-factor authentication",
    why: "Administrators who sign in with a password and a one-time code can be phished. Passkeys are bound to Hodor's origin and cannot be replayed on a look-alike site.",
    objects: (
      <>
        <Badge label="joao.silva" />
        <Badge label="marina.costa" />
      </>
    ),
    action: { label: "Review administrators" },
  },
  {
    severity: "medium",
    title: (
      <>
        Signing key set <Code>tenant-signing</Code> is 12 days past its rotation date
      </>
    ),
    why: "Long-lived signing keys widen the window in which a leaked key can mint valid tokens. The current key was created on 2026-08-08.",
    objects: (
      <Identifier shown="kid 0193b8e2…4c1a" value="0193b8e2-77a1-7d0c-9f3e-1b2c9a8e4c1a" label="Copy key identifier" />
    ),
    action: { label: "Rotate key", opens: "rotate" },
  },
  {
    severity: "medium",
    title: (
      <>
        Client <Code>billing-portal</Code> issues refresh tokens valid for 90 days
      </>
    ),
    why: "The recommended baseline is 30 days with rotation. A weakened setting stays listed here until it is changed back or accepted with a reason and an expiry.",
    objects: (
      <>
        <Badge variant="warning" label="Weakened setting" />
        <Badge label="Billing portal" />
      </>
    ),
    action: { label: "Open setting" },
  },
  {
    severity: "medium",
    title: (
      <>
        3 holders of <Code>tenant-administrator</Code> have not used it in 30 days
      </>
    ),
    why: "Standing privilege that is not used is risk without benefit. Remove the role, or make it eligible on request when approvals arrive.",
    objects: <Badge label="3 role assignments" />,
    action: { label: "Review assignments" },
  },
  {
    severity: "low",
    title: (
      <>
        Client secret of <Code>reporting-batch</Code> expires in 9 days
      </>
    ),
    why: "When it expires, the nightly export stops. Generate a new secret now; the old one keeps working until its expiry so the change has no downtime.",
    objects: <Identifier shown="hds_live_r7Q2…" value="hds_live_r7Q2" label="Copy secret prefix" />,
    action: { label: "Generate secret", opens: "secret" },
  },
  {
    severity: "low",
    title: "Session absolute timeout is 24 hours, above the 12-hour baseline",
    why: 'Accepted by Rafaela Lima until 2026-12-31: "Field agents work 14-hour shifts; revisit after the passkey rollout."',
    accepted: true,
  },
];

type Tone = "error" | "warning" | "success" | "neutral";

interface Event {
  tone: Tone;
  text: ReactNode;
  meta: string;
  opens?: DialogName;
}

const first: Event[] = [
  {
    tone: "error",
    text: (
      <>
        Refresh token reuse detected for <strong>ana.mendes</strong>; token family revoked
      </>
    ),
    meta: "2 minutes ago · 203.0.113.42",
    opens: "revoke",
  },
  {
    tone: "warning",
    text: (
      <>
        Account <strong>p.rocha</strong> locked after 5 failed sign-ins
      </>
    ),
    meta: "6 minutes ago · 198.51.100.7",
  },
  {
    tone: "success",
    text: (
      <>
        Policy <strong>orders-access</strong> version 13 published by Rafaela Lima
      </>
    ),
    meta: "41 minutes ago · after step-up with a passkey",
  },
  {
    tone: "neutral",
    text: (
      <>
        Identity provider <strong>Microsoft Entra ID</strong> test sign-in succeeded
      </>
    ),
    meta: "1 hour ago",
  },
];

const arriving: Event[] = [
  {
    tone: "warning",
    text: (
      <>
        Unusual sign-in for <strong>lucas.prado</strong>: new country, step-up requested
      </>
    ),
    meta: "Just now · 198.51.100.23",
  },
  {
    tone: "success",
    text: (
      <>
        Client secret of <strong>reporting-batch</strong> rotated by Rafaela Lima
      </>
    ),
    meta: "Just now · after step-up with a passkey",
  },
  {
    tone: "neutral",
    text: (
      <>
        Organization <strong>Acme Brasil</strong> invited 4 members
      </>
    ),
    meta: "Just now · Marina Costa",
  },
];

const diff: DiffLine[] = [
  { number: 12, text: "allow if {" },
  { number: 13, text: '    input.action == "orders:refund"' },
  { number: 14, change: "removed", text: '    "support" in input.subject.roles' },
  { number: 14, change: "added", text: '    "refund-approver" in input.subject.roles' },
  { number: 15, change: "added", text: "    input.resource.amount <= 5000  # larger refunds need finance" },
  { number: 16, text: "    input.subject.tenant == input.resource.tenant" },
  { number: 17, text: "}" },
];

function Metric({ name, note, children }: { name: string; note: ReactNode; children: ReactNode }) {
  return (
    <Card>
      <VStack gap={2}>
        <HStack justify="between" vAlign="center">
          <Overline>{name}</Overline>
          {note}
        </HStack>
        {children}
      </VStack>
    </Card>
  );
}

const day = (
  <Text type="supporting" color="secondary">
    24 hours
  </Text>
);

export function ControlPlane({ open }: { open: (name: DialogName) => void }) {
  const [filter, setFilter] = useState("open");
  const [events, setEvents] = useState(first);

  // New events arrive while the screen is open, unless motion is unwelcome.
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }
    let next = 0;
    const timer = window.setInterval(() => {
      const event = arriving[next++];
      if (event === undefined) {
        window.clearInterval(timer);
        return;
      }
      setEvents((shown) => [event, ...shown].slice(0, 5));
    }, 9000);
    return () => window.clearInterval(timer);
  }, []);

  const shown = findings.filter((finding) => filter === "all" || (filter === "accepted") === (finding.accepted === true));

  return (
    <div className="hodor-page">
      <VStack gap={5}>
        <HStack justify="between" vAlign="end" wrap="wrap" gap={4}>
          <VStack gap={1}>
            <Breadcrumbs variant="supporting">
              <BreadcrumbItem>acme-payments</BreadcrumbItem>
              <BreadcrumbItem>Overview</BreadcrumbItem>
            </Breadcrumbs>
            <Heading level={1}>Security posture</Heading>
            <Text type="supporting" color="secondary">
              Evaluated by the server 3 minutes ago against 14 checks · Baseline{" "}
              <Link href="#" hasUnderline type="inherit">
                Hodor recommended, version 2026.11
              </Link>
            </Text>
          </VStack>
          <HStack gap={2}>
            <Button label="Export report" icon={<Icon icon={Download} />} />
            <Button variant="primary" label="Evaluate now" icon={<Icon icon={RefreshCw} />} />
          </HStack>
        </HStack>

        <section className="hodor-split hodor-split--even" aria-label="Summary">
          <Card>
            <HStack gap={5} vAlign="center">
              <Score value={82} />
              <VStack gap={2}>
                <Overline>Posture score</Overline>
                <Text color="accent">Up 6 points in 30 days</Text>
                <Text type="supporting" color="secondary">
                  The score summarizes the checks below. Fix the findings, not the number.
                </Text>
                <HStack gap={4} wrap="wrap">
                  <HStack gap={2} vAlign="center">
                    <Severity level="high" />
                    <strong>1</strong>
                  </HStack>
                  <HStack gap={2} vAlign="center">
                    <Severity level="medium" />
                    <strong>3</strong>
                  </HStack>
                  <HStack gap={2} vAlign="center">
                    <Severity level="low" />
                    <strong>1</strong>
                  </HStack>
                  <HStack gap={2} vAlign="center">
                    <Text type="supporting" color="secondary">
                      Accepted risks
                    </Text>
                    <strong>1</strong>
                  </HStack>
                </HStack>
              </VStack>
            </HStack>
          </Card>
          <div className="hodor-split hodor-split--even">
            <Metric name="Sign-in success" note={day}>
              <span className="hodor-figure">98.2%</span>
              <Spark tone="accent" points={[10, 9, 11, 8, 9, 7, 10, 8, 9, 6, 8, 7, 6]} />
            </Metric>
            <Metric name="Lockouts" note={day}>
              <span className="hodor-figure">37</span>
              <Spark tone="warning" points={[26, 27, 25, 26, 24, 25, 20, 14, 18, 22, 24, 23, 25]} />
            </Metric>
            <Metric name="Step-ups completed" note={day}>
              <span className="hodor-figure">214</span>
              <Spark tone="info" points={[22, 20, 21, 18, 19, 16, 17, 15, 16, 13, 14, 12, 13]} />
            </Metric>
            <Metric name="Refresh token reuse" note={<Severity level="critical" />}>
              <span className="hodor-figure">2</span>
              <Text type="supporting" color="secondary">
                2 token families revoked automatically
              </Text>
            </Metric>
          </div>
        </section>

        <section className="hodor-split">
          <Card>
            <HStack justify="between" vAlign="center">
              <Heading level={2}>Findings</Heading>
              <SegmentedControl label="Filter findings" size="sm" value={filter} onChange={setFilter}>
                <SegmentedControlItem value="open" label="Open 5" />
                <SegmentedControlItem value="accepted" label="Accepted 1" />
                <SegmentedControlItem value="all" label="All" />
              </SegmentedControl>
            </HStack>
            <ul className="hodor-list">
              {shown.map((finding, index) => (
                <li key={index} className={finding.accepted ? "hodor-finding hodor-finding--accepted" : "hodor-finding"}>
                  <Severity level={finding.severity} />
                  <VStack gap={2}>
                    <Text weight="semibold">{finding.title}</Text>
                    <Text type="supporting" color="secondary">
                      {finding.why}
                    </Text>
                    {finding.objects ? (
                      <HStack gap={2} wrap="wrap">
                        {finding.objects}
                      </HStack>
                    ) : null}
                  </VStack>
                  {finding.action ? (
                    <Button
                      size="sm"
                      label={finding.action.label}
                      onClick={() => finding.action?.opens && open(finding.action.opens)}
                    />
                  ) : (
                    <Badge label="Accepted" />
                  )}
                </li>
              ))}
            </ul>
          </Card>

          <VStack gap={4}>
            <Card>
              <HStack justify="between" vAlign="center">
                <Heading level={2}>Live activity</Heading>
                <HStack gap={2} vAlign="center">
                  <StatusDot variant="accent" label="Streaming" isPulsing />
                  <Text type="supporting" color="secondary">
                    Streaming
                  </Text>
                </HStack>
              </HStack>
              <ul className="hodor-list" aria-live="polite">
                {events.map((event, index) => (
                  <li key={events.length - index} className="hodor-activity">
                    <span className="hodor-activity__marker">
                      <StatusDot variant={event.tone} label={event.tone} />
                    </span>
                    <VStack gap={1} hAlign="start">
                      <Text>{event.text}</Text>
                      <Text type="supporting" color="secondary">
                        {event.meta}
                      </Text>
                      {event.opens ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          label="Revoke all her sessions"
                          onClick={() => event.opens && open(event.opens)}
                        />
                      ) : null}
                    </VStack>
                  </li>
                ))}
              </ul>
            </Card>

            <Card>
              <VStack gap={3}>
                <HStack justify="between" vAlign="center">
                  <Heading level={2}>Break-glass accounts</Heading>
                  <Badge variant="success" label="Ready" />
                </HStack>
                {["emergency-01", "emergency-02"].map((account) => (
                  <HStack key={account} justify="between" vAlign="center">
                    <HStack gap={2} vAlign="center">
                      <Icon icon={LifeBuoy} size="sm" />
                      <Text>{account}</Text>
                    </HStack>
                    <Text type="supporting" color="secondary">
                      Never used · tested 2026-10-02
                    </Text>
                  </HStack>
                ))}
                <Text type="supporting" color="secondary">
                  Any use raises a high-severity finding and alerts every security administrator.
                </Text>
              </VStack>
            </Card>
          </VStack>
        </section>

        <Card>
          <VStack gap={4}>
            <HStack justify="between" vAlign="center" wrap="wrap" gap={3}>
              <VStack gap={1}>
                <Heading level={2}>
                  Pending change: policy <Code>orders-access</Code>, draft version 14
                </Heading>
                <Text type="supporting" color="secondary">
                  Drafted by Marina Costa 18 minutes ago · validation passed with 1 warning
                </Text>
              </VStack>
              <HStack gap={2} vAlign="center">
                <Badge variant="info" label="Draft" />
                <Button label="Discard draft" />
                <Button variant="primary" label="Review and publish" onClick={() => open("publish")} />
              </HStack>
            </HStack>
            <div className="hodor-split">
              <VStack gap={2}>
                <Overline>Diff against version 13</Overline>
                <Diff label="Policy diff" lines={diff} />
              </VStack>
              <VStack gap={4}>
                <VStack gap={1}>
                  <Overline>Blast radius</Overline>
                  <Facts>
                    <Fact what="Applications that call this policy" value="3" />
                    <Fact what="Subjects whose decision changes" value="412" />
                    <Fact what="Decisions last 24 hours that would flip" value="1,887" />
                  </Facts>
                </VStack>
                <VStack gap={1}>
                  <Overline>Simulation on sample subjects</Overline>
                  <Facts>
                    <Fact what="support agent, refund 120" value={<><Decision allow /> → <Decision allow={false} /></>} />
                    <Fact what="refund approver, refund 900" value={<><Decision allow={false} /> → <Decision allow /></>} />
                    <Fact what="refund approver, refund 8,000" value={<><Decision allow={false} /> → <Decision allow={false} /></>} />
                  </Facts>
                </VStack>
                <Banner
                  status="warning"
                  title="412 support agents lose refunds"
                  description="Assign the new role before publishing, or they will be denied."
                />
              </VStack>
            </div>
          </VStack>
        </Card>
      </VStack>
    </div>
  );
}
