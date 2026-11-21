import { Card } from "@astryxdesign/core/Card";
import { Heading } from "@astryxdesign/core/Heading";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import { type ReactNode, useEffect, useId, useRef } from "react";
import type { Messages } from "../messages";

interface FrameProps {
  tenant: string;
  title: string;
  text: Messages;
  children: ReactNode;
}

/**
 * What every page has: the card, the tenant and the heading. When the
 * heading changes it takes focus, so that a screen reader announces what
 * is now shown.
 */
export function Frame({ tenant, title, text, children }: FrameProps) {
  const heading = useRef<HTMLHeadingElement>(null);
  const headingId = useId();

  useEffect(() => {
    document.title = `${title} · ${tenant}`;
    heading.current?.focus();
  }, [title, tenant]);

  return (
    <main className="auth-page">
      <section className="auth-card" aria-labelledby={headingId}>
        <Card padding={6}>
          <VStack gap={5}>
            <VStack gap={1}>
              <Text as="p" type="supporting" color="secondary">
                {text.organization}: {tenant}
              </Text>
              <Heading level={1} id={headingId} ref={heading} tabIndex={-1} className="auth-title">
                {title}
              </Heading>
            </VStack>
            {children}
          </VStack>
        </Card>
      </section>
    </main>
  );
}
