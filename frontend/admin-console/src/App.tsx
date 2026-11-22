import { AppShell } from "@astryxdesign/core/AppShell";
import { Avatar } from "@astryxdesign/core/Avatar";
import { Badge } from "@astryxdesign/core/Badge";
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { CommandPalette } from "@astryxdesign/core/CommandPalette";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { Icon } from "@astryxdesign/core/Icon";
import { IconButton } from "@astryxdesign/core/IconButton";
import { Kbd } from "@astryxdesign/core/Kbd";
import { Link } from "@astryxdesign/core/Link";
import { SideNav, SideNavItem, SideNavSection } from "@astryxdesign/core/SideNav";
import { Text } from "@astryxdesign/core/Text";
import { useToast } from "@astryxdesign/core/Toast";
import { TopNav, TopNavHeading } from "@astryxdesign/core/TopNav";
import { VStack } from "@astryxdesign/core/VStack";
import { useHotkeys } from "@astryxdesign/core/hooks";
import { AppWindow, Clock, DoorOpen, FileText, Link2, LogOut, type LucideIcon, Moon, Search, Sun, Users } from "lucide-react";
import { type MouseEvent, type ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { accountPath, isIdentifier, pathOf, type Place, type Screen, signInPath } from "./address";
import type { Client, Me, Permission } from "./client";
import { moment, named, type Messages } from "./messages";
import { asFailure, Failed, type Loading, Waiting } from "./parts/Loaded";
import { ApplicationScreen } from "./screens/ApplicationScreen";
import { ApplicationsScreen } from "./screens/ApplicationsScreen";
import { AuditScreen } from "./screens/AuditScreen";
import { ClientScreen } from "./screens/ClientScreen";
import { ProviderScreen } from "./screens/ProviderScreen";
import { ProvidersScreen } from "./screens/ProvidersScreen";
import { nameOf } from "./screens/UsersScreen";
import { UserScreen } from "./screens/UserScreen";
import { UsersScreen } from "./screens/UsersScreen";

export type Mode = "dark" | "light";

export interface AppProps {
  place: Place;
  client: Client;
  text: Messages;
  mode: Mode;
  changeMode: (mode: Mode) => void;
  /** Opens another screen of the console, in this tab. */
  go: (screen: Screen) => void;
  /** Leaves the console for another page of the tenant. */
  leave: (path: string) => void;
}

interface Entry {
  screen: Screen;
  label: (text: Messages) => string;
  icon: LucideIcon;
  needs: Permission;
}

/** The screens of the console, each with what a person needs to open it. */
const SECTIONS: { title: (text: Messages) => string; entries: Entry[] }[] = [
  {
    title: (text) => text.directory,
    entries: [{ screen: { name: "users" }, label: (text) => text.users, icon: Users, needs: "users:read" }],
  },
  {
    title: (text) => text.access,
    entries: [
      {
        screen: { name: "providers" },
        label: (text) => text.providers,
        icon: Link2,
        needs: "identity-providers:read",
      },
      {
        screen: { name: "applications" },
        label: (text) => text.applications,
        icon: AppWindow,
        needs: "applications:read",
      },
    ],
  },
  {
    title: (text) => text.audit,
    entries: [{ screen: { name: "audit" }, label: (text) => text.auditRecords, icon: FileText, needs: "audit:read" }],
  },
];

function entriesFor(me: Me): Entry[] {
  return SECTIONS.flatMap((section) => section.entries).filter((entry) => me.permissions.includes(entry.needs));
}

/** A page that is all there is to show: nobody to show the console to. */
function Alone({ title, children }: { title: string; children: ReactNode }) {
  return (
    <main className="console-center">
      <div className="console-notice">
        <Card padding={6}>
          <VStack gap={4}>
            <Heading level={1}>{title}</Heading>
            {children}
          </VStack>
        </Card>
      </div>
    </main>
  );
}

/** Finds out who is using the console, and shows it to those who may use it. */
export function App(props: AppProps) {
  const { place, client, text, leave } = props;
  const [me, setMe] = useState<Loading<Me>>({ state: "loading" });
  const [turn, setTurn] = useState(0);

  useEffect(() => {
    let current = true;
    client.me().then(
      (found) => {
        if (!current) {
          return;
        }
        if (found === null) {
          // Nobody is signed in, or the sign-in is too old for the console.
          leave(signInPath(place.tenant));
        } else {
          setMe({ state: "loaded", value: found });
        }
      },
      (thrown: unknown) => {
        if (current) {
          setMe({ state: "failed", failure: asFailure(thrown) });
        }
      },
    );
    return () => {
      current = false;
    };
  }, [client, leave, place.tenant, turn]);

  useEffect(() => {
    document.title = `${text.console} · ${place.tenant}`;
  }, [text, place.tenant]);

  if (me.state === "loading") {
    return (
      <main className="console-center">
        <Waiting text={text} />
      </main>
    );
  }
  if (me.state === "failed") {
    return (
      <Alone title={text.console}>
        <Failed
          failure={me.failure}
          again={() => {
            setMe({ state: "loading" });
            setTurn((count) => count + 1);
          }}
          text={text}
        />
      </Alone>
    );
  }
  if (entriesFor(me.value).length === 0) {
    return (
      <Alone title={text.noAccessTitle}>
        <Text>{text.noAccess(place.tenant)}</Text>
        <Text type="supporting" color="secondary">
          {text.signedInAs(nameOf(me.value.user, text))}
        </Text>
        <Link href={accountPath(place.tenant)} hasUnderline>
          {text.goToAccount}
        </Link>
      </Alone>
    );
  }
  return <Frame {...props} me={me.value} />;
}

function Frame({ place, client, text, mode, changeMode, go, leave, me }: AppProps & { me: Me }) {
  const { tenant } = place;
  const [palette, setPalette] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const showToast = useToast();
  const entries = useMemo(() => entriesFor(me), [me]);
  const path = useCallback((screen: Screen) => pathOf(tenant, screen), [tenant]);
  const say = useCallback((message: string) => void showToast({ body: message }), [showToast]);

  useHotkeys([{ keys: "mod+k", onPress: () => setPalette(true), allowInInputs: true }]);

  // The start of the console is the first screen the person may open.
  const first = entries[0]?.screen;
  useEffect(() => {
    if (place.screen?.name === "home" && first !== undefined) {
      go(first);
    }
  }, [place.screen, first, go]);

  // A pasted user identifier opens that user; anything else finds a screen.
  const source = useMemo(
    () => ({
      bootstrap: () => entries.map((entry) => ({ id: pathOf(tenant, entry.screen), label: text.goTo(entry.label(text)) })),
      search: (query: string) => {
        const wanted = query.trim().toLowerCase();
        const screens = entries
          .map((entry) => ({ id: pathOf(tenant, entry.screen), label: text.goTo(entry.label(text)) }))
          .filter((item) => item.label.toLowerCase().includes(wanted));
        return isIdentifier(wanted) && me.permissions.includes("users:read")
          ? [{ id: pathOf(tenant, { name: "user", id: wanted }), label: text.openUser(wanted) }, ...screens]
          : screens;
      },
    }),
    [entries, tenant, text, me.permissions],
  );

  function run(chosen: string) {
    setPalette(false);
    const entry = entries.find((candidate) => pathOf(tenant, candidate.screen) === chosen);
    const user = chosen.split("/").pop() ?? "";
    if (entry) {
      go(entry.screen);
    } else if (isIdentifier(user)) {
      go({ name: "user", id: user });
    }
  }

  async function signOut() {
    if (leaving) {
      return;
    }
    setLeaving(true);
    try {
      await client.signOut();
    } finally {
      // Signed out or not, the console is left: the sign-in page says where the person stands.
      leave(signInPath(tenant));
    }
  }

  function open(event: MouseEvent, screen: Screen) {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    go(screen);
  }

  const screen = place.screen;
  const props = { client, me, text, go, path, say };
  const allowed = (needs: Permission) => me.permissions.includes(needs);
  const next: Mode = mode === "dark" ? "light" : "dark";

  return (
    <>
      <AppShell
        variant="section"
        topNav={
          <TopNav
            label={text.scope}
            heading={<TopNavHeading logo={<Icon icon={DoorOpen} color="accent" />} heading={text.product} />}
            startContent={
              <HStack gap={2} vAlign="center">
                <Text type="supporting" color="secondary">
                  {text.tenant}
                </Text>
                <Badge variant="cyan" label={<span className="console-mono">{tenant}</span>} />
              </HStack>
            }
            endContent={
              <HStack gap={3} vAlign="center">
                <Button
                  label={text.searchOrRun}
                  icon={<Icon icon={Search} />}
                  endContent={<Kbd keys="mod+k" />}
                  onClick={() => setPalette(true)}
                />
                {me.roles.map((role) => (
                  <Badge key={role} label={named(text.roles, role)} />
                ))}
                <HStack gap={1} vAlign="center">
                  <Icon icon={Clock} size="sm" color="secondary" />
                  <Text type="supporting" color="secondary">
                    <span title={text.sessionUntilHint}>{text.sessionUntil(moment(me.consoleUntil, text))}</span>
                  </Text>
                </HStack>
                <IconButton
                  variant="ghost"
                  label={mode === "dark" ? text.switchToLight : text.switchToDark}
                  icon={<Icon icon={mode === "dark" ? Sun : Moon} />}
                  onClick={() => changeMode(next)}
                />
                <Avatar name={nameOf(me.user, text)} size="sm" />
                <IconButton
                  variant="ghost"
                  label={text.signOut}
                  tooltip={text.signOut}
                  icon={<Icon icon={LogOut} />}
                  isLoading={leaving}
                  onClick={() => void signOut()}
                />
              </HStack>
            }
          />
        }
        sideNav={
          <SideNav>
            {SECTIONS.map((section) => {
              const shown = section.entries.filter((entry) => allowed(entry.needs));
              return shown.length === 0 ? null : (
                <SideNavSection key={section.title(text)} title={section.title(text)}>
                  {shown.map((entry) => (
                    <SideNavItem
                      key={entry.screen.name}
                      label={entry.label(text)}
                      icon={entry.icon}
                      href={path(entry.screen)}
                      isSelected={
                        screen?.name === entry.screen.name ||
                        (screen?.name === "user" && entry.screen.name === "users") ||
                        (screen?.name === "provider" && entry.screen.name === "providers") ||
                        ((screen?.name === "application" || screen?.name === "client") &&
                          entry.screen.name === "applications")
                      }
                      onClick={(event) => open(event, entry.screen)}
                    />
                  ))}
                </SideNavSection>
              );
            })}
          </SideNav>
        }
      >
        {screen?.name === "users" && allowed("users:read") ? <UsersScreen {...props} /> : null}
        {screen?.name === "user" && allowed("users:read") ? <UserScreen key={screen.id} id={screen.id} {...props} /> : null}
        {screen?.name === "audit" && allowed("audit:read") ? <AuditScreen {...props} /> : null}
        {screen?.name === "providers" && allowed("identity-providers:read") ? <ProvidersScreen {...props} /> : null}
        {screen?.name === "provider" && allowed("identity-providers:read") ? (
          <ProviderScreen key={screen.id} id={screen.id} {...props} />
        ) : null}
        {screen?.name === "applications" && allowed("applications:read") ? <ApplicationsScreen {...props} /> : null}
        {screen?.name === "application" && allowed("applications:read") ? (
          <ApplicationScreen key={screen.id} id={screen.id} {...props} />
        ) : null}
        {screen?.name === "client" && allowed("applications:read") ? (
          <ClientScreen key={screen.id} id={screen.id} {...props} />
        ) : null}
        {screen === null || (screen.name !== "home" && !allowed(needsOf(screen))) ? (
          <div className="console-page">
            <VStack gap={3} hAlign="start">
              <Heading level={1}>{text.notFoundTitle}</Heading>
              <Banner status="info" title={text.notFound} />
              <Link href={path({ name: "home" })} hasUnderline onClick={(event) => open(event, { name: "home" })}>
                {text.goToStart}
              </Link>
            </VStack>
          </div>
        ) : null}
      </AppShell>

      <CommandPalette
        isOpen={palette}
        onOpenChange={setPalette}
        searchSource={source}
        onValueChange={run}
        emptyBootstrapText={text.paletteHint}
        emptySearchText={text.paletteHint}
        label={text.searchOrRun}
      />
    </>
  );
}

/** What a person needs to open a screen. A screen they may not open is, to them, not there. */
function needsOf(screen: Screen): Permission {
  switch (screen.name) {
    case "audit":
      return "audit:read";
    case "providers":
    case "provider":
      return "identity-providers:read";
    case "applications":
    case "application":
    case "client":
      return "applications:read";
    default:
      return "users:read";
  }
}
