import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import type { MouseEvent, ReactNode } from "react";
import type { Screen } from "../address";
import type { Client, Me } from "../client";
import type { Messages } from "../messages";

/** What every screen is given. */
export interface ScreenProps {
  client: Client;
  me: Me;
  text: Messages;
  /** Opens another screen of the console. */
  go: (screen: Screen) => void;
  /** The address of another screen, for links. */
  path: (screen: Screen) => string;
  /** Says that something was done. */
  say: (message: string) => void;
}

interface PageProps {
  title: string;
  lead?: ReactNode;
  /** What stands above the title: where this screen is. */
  above?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}

/** The frame of a screen: where it is, its title, its actions, its content. */
export function Page({ title, lead, above, actions, children }: PageProps) {
  return (
    <div className="console-page">
      <VStack gap={5}>
        <HStack justify="between" vAlign="end" wrap="wrap" gap={4}>
          <VStack gap={1}>
            {above}
            <Heading level={1}>{title}</Heading>
            {lead ? (
              <Text type="supporting" color="secondary">
                {lead}
              </Text>
            ) : null}
          </VStack>
          {actions ? <HStack gap={2}>{actions}</HStack> : null}
        </HStack>
        {children}
      </VStack>
    </div>
  );
}

/**
 * Opens a screen of the console from a link. A plain click stays in the
 * console; a click that asks for a new tab gets one.
 */
export function follow(event: MouseEvent, go: (screen: Screen) => void, screen: Screen) {
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) {
    return;
  }
  event.preventDefault();
  go(screen);
}
