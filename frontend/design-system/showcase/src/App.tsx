import { AppShell } from "@astryxdesign/core/AppShell";
import { Avatar } from "@astryxdesign/core/Avatar";
import { Badge } from "@astryxdesign/core/Badge";
import { Button } from "@astryxdesign/core/Button";
import { CommandPalette } from "@astryxdesign/core/CommandPalette";
import { HStack } from "@astryxdesign/core/HStack";
import { Icon } from "@astryxdesign/core/Icon";
import { IconButton } from "@astryxdesign/core/IconButton";
import { Kbd } from "@astryxdesign/core/Kbd";
import { LayerProvider } from "@astryxdesign/core/Layer";
import { Link } from "@astryxdesign/core/Link";
import { SideNav, SideNavItem, SideNavSection } from "@astryxdesign/core/SideNav";
import { StatusDot } from "@astryxdesign/core/StatusDot";
import { Text } from "@astryxdesign/core/Text";
import { Theme } from "@astryxdesign/core/theme";
import { useToast } from "@astryxdesign/core/Toast";
import { TopNav, TopNavHeading } from "@astryxdesign/core/TopNav";
import { createStaticSource } from "@astryxdesign/core/Typeahead";
import { useHotkeys } from "@astryxdesign/core/hooks";
import { hodorTheme } from "@hodor-theme/hodor.js";
import {
  Activity,
  Building2,
  ClipboardCheck,
  Clock,
  Cpu,
  DoorOpen,
  FileText,
  KeyRound,
  LayoutGrid,
  Link2,
  List,
  Lock,
  type LucideIcon,
  Monitor,
  Moon,
  Play,
  Radar,
  Radio,
  Scale,
  Search,
  Settings,
  Shield,
  Sun,
  User,
  Users,
  Workflow,
} from "lucide-react";
import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { ControlPlane } from "./ControlPlane";
import { Confirmation, type DialogName } from "./dialogs";
import { Gallery } from "./Gallery";

type Screen = "posture" | "gallery";

interface Entry {
  label: string;
  icon: LucideIcon;
  count?: string;
  alert?: boolean;
  screen?: Screen;
}

/** The navigation of the control plane (docs/design/control-plane.md). */
const navigation: [string, Entry[]][] = [
  ["Overview", [{ label: "Security posture", icon: Shield, count: "6", alert: true, screen: "posture" }, { label: "Live activity", icon: Activity }]],
  ["Directory", [{ label: "Users", icon: User, count: "48,213" }, { label: "Groups", icon: Users }, { label: "Organizations", icon: Building2 }, { label: "Service accounts and agents", icon: Cpu }]],
  ["Access", [{ label: "Applications", icon: LayoutGrid, count: "27" }, { label: "Identity providers", icon: Link2 }, { label: "Authentication flows", icon: Workflow }]],
  ["Authorization", [{ label: "Roles and permissions", icon: KeyRound }, { label: "Policies", icon: Scale }, { label: "Simulator", icon: Play }, { label: "Decision logs", icon: List }]],
  ["Security", [{ label: "Sessions", icon: Monitor }, { label: "Signing keys", icon: Lock, count: "1", alert: true }, { label: "Detections and lockouts", icon: Radar }]],
  ["Governance", [{ label: "Administrators", icon: Shield }, { label: "Approvals", icon: ClipboardCheck, count: "2" }]],
  ["Audit", [{ label: "Audit records", icon: FileText }, { label: "Streams and webhooks", icon: Radio }]],
  ["Configuration", [{ label: "Tenant settings", icon: Settings }, { label: "Design system", icon: LayoutGrid, screen: "gallery" }]],
];

const commands: { id: string; label: string; opens?: DialogName }[] = [
  { id: "revoke", label: "Revoke sessions for a user… · level 2", opens: "revoke" },
  { id: "rotate", label: "Rotate signing keys… · level 3", opens: "rotate" },
  { id: "secret", label: "Generate a client secret… · level 1", opens: "secret" },
  { id: "users", label: "Go to Users" },
  { id: "applications", label: "Go to Applications" },
  { id: "audit", label: "Go to Audit records" },
  { id: "policies", label: "Go to Policies" },
];

const IDLE_SECONDS = 15 * 60;

/** Counts down the administrator's session; any activity starts it again. */
function useSessionClock(): string {
  const [seconds, setSeconds] = useState(IDLE_SECONDS - 8);
  useEffect(() => {
    const tick = window.setInterval(() => setSeconds((left) => Math.max(0, left - 1)), 1000);
    const reset = () => setSeconds(IDLE_SECONDS);
    window.addEventListener("pointerdown", reset);
    window.addEventListener("keydown", reset);
    return () => {
      window.clearInterval(tick);
      window.removeEventListener("pointerdown", reset);
      window.removeEventListener("keydown", reset);
    };
  }, []);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function Shell() {
  const [screen, setScreen] = useState<Screen>("posture");
  const [dialog, setDialog] = useState<DialogName | null>(null);
  const [palette, setPalette] = useState(false);
  const showToast = useToast();
  const remaining = useSessionClock();
  const source = useMemo(() => createStaticSource(commands), []);

  useHotkeys([{ keys: "mod+k", onPress: () => setPalette(true), allowInInputs: true }]);

  function run(id: string) {
    setPalette(false);
    const command = commands.find((candidate) => candidate.id === id);
    if (command?.opens) {
      setDialog(command.opens);
    }
  }

  function done(said?: string) {
    setDialog(null);
    if (said !== undefined) {
      // After the action, a toast links to the audit record it produced.
      showToast({ body: said, endContent: <Link href="#">View audit record</Link> });
    }
  }

  return (
    <>
      <AppShell
        variant="section"
        topNav={
          <TopNav
            label="Scope"
            heading={<TopNavHeading logo={<Icon icon={DoorOpen} color="accent" />} heading="Hodor" />}
            startContent={
              <HStack gap={3} vAlign="center">
                <Button variant="ghost" label="Acme Payments · acme-payments" tooltip="Switch tenant" />
                <Badge variant="error" label="Production" icon={<StatusDot variant="error" label="Production" />} />
              </HStack>
            }
            endContent={
              <HStack gap={3} vAlign="center">
                <Button
                  label="Search or run a command"
                  icon={<Icon icon={Search} />}
                  endContent={<Kbd keys="mod+k" />}
                  onClick={() => setPalette(true)}
                />
                <Badge variant="cyan" label="Security administrator" />
                <HStack gap={1} vAlign="center">
                  <Icon icon={Clock} size="sm" color="secondary" />
                  <Text type="supporting" color="secondary" hasTabularNumbers>
                    Session {remaining}
                  </Text>
                </HStack>
                <ModeToggle />
                <Avatar name="Rafaela Lima" size="sm" />
              </HStack>
            }
          />
        }
        sideNav={
          <SideNav>
            {navigation.map(([title, entries]) => (
              <SideNavSection key={title} title={title}>
                {entries.map((entry) => (
                  <SideNavItem
                    key={entry.label}
                    label={entry.label}
                    icon={entry.icon}
                    size="sm"
                    isSelected={entry.screen === screen}
                    onClick={() => entry.screen && setScreen(entry.screen)}
                    endContent={
                      entry.count ? <Badge variant={entry.alert ? "error" : "neutral"} label={entry.count} /> : undefined
                    }
                  />
                ))}
              </SideNavSection>
            ))}
          </SideNav>
        }
      >
        {screen === "posture" ? <ControlPlane open={setDialog} /> : <Gallery />}
      </AppShell>

      <CommandPalette
        isOpen={palette}
        onOpenChange={setPalette}
        searchSource={source}
        onValueChange={run}
        emptyBootstrapText="Search screens, users, clients, or paste an identifier"
      />
      {dialog !== null ? <Confirmation key={dialog} name={dialog} onDone={done} /> : null}
    </>
  );
}

type Mode = "dark" | "light";

const ModeContext = createContext<{ mode: Mode; change: (mode: Mode) => void }>({ mode: "dark", change: () => undefined });

function ModeToggle() {
  const { mode, change } = useContext(ModeContext);
  const next = mode === "dark" ? "light" : "dark";
  return (
    <IconButton
      variant="ghost"
      label={`Switch to ${next} mode`}
      icon={<Icon icon={mode === "dark" ? Sun : Moon} />}
      onClick={() => change(next)}
    />
  );
}

/** The showcase opens in the dark mode, the default of the admin console. */
export function App() {
  const [mode, change] = useState<Mode>("dark");
  const value = useMemo(() => ({ mode, change }), [mode]);
  return (
    <ModeContext value={value}>
      <Theme theme={hodorTheme} mode={mode}>
        <LayerProvider>
          <Shell />
        </LayerProvider>
      </Theme>
    </ModeContext>
  );
}
