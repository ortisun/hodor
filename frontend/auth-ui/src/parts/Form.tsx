import { VStack } from "@astryxdesign/core/VStack";
import type { FormEvent, ReactNode } from "react";

interface FormProps {
  onSubmit: (event: FormEvent) => void;
  children: ReactNode;
}

/**
 * A form of a page: its fields and its buttons, one under the other. What
 * was typed is checked by the server, which answers in the person's
 * language; the browser's own checking is turned off.
 */
export function Form({ onSubmit, children }: FormProps) {
  return (
    <form method="post" noValidate onSubmit={onSubmit}>
      <VStack gap={4}>{children}</VStack>
    </form>
  );
}
