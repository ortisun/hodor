import { Link } from "@astryxdesign/core/Link";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import type { ReactNode } from "react";

interface WordsProps {
  /** Secondary text: it helps, and the page is understood without it. */
  quiet?: boolean;
  /** Text that changes without the person asking is announced politely. */
  announced?: boolean;
  children: ReactNode;
}

/** A paragraph of a page. */
export function Words({ quiet = false, announced = false, children }: WordsProps) {
  return (
    <Text as="p" color={quiet ? "secondary" : "primary"} role={announced ? "status" : undefined}>
      {children}
    </Text>
  );
}

/** A link to another page. Inside text, a link is told apart by more than its color. */
export function PageLink({ href, children }: { href: string; children: string }) {
  return (
    <Link href={href} hasUnderline>
      {children}
    </Link>
  );
}

/** The other places a person may go from a page, one to a line. */
export function Ways({ children }: { children: ReactNode }) {
  return (
    <VStack as="ul" gap={2} className="auth-ways">
      {children}
    </VStack>
  );
}
