import { CheckboxInput } from "@astryxdesign/core/CheckboxInput";
import { TextInput } from "@astryxdesign/core/TextInput";
import { useState } from "react";
import type { Messages } from "../messages";

interface FieldProps {
  label: string;
  hint?: string;
  /** What is wrong with what was typed, if anything. */
  error?: string | null;
  name: string;
  type?: "text" | "email" | "password";
  autoComplete: string;
  autoFocus?: boolean;
  /** Names and addresses are typed as they are: no capital letters or corrections are offered. */
  verbatim?: boolean;
  value: string;
  onChange: (value: string) => void;
}

/** A labelled input. Its hint and its error are tied to it. */
export function Field({ label, hint, error, name, type = "text", autoFocus, verbatim, ...input }: FieldProps) {
  return (
    <TextInput
      {...input}
      label={label}
      description={hint}
      status={error ? { type: "error", message: error } : undefined}
      statusVariant="detached"
      htmlName={name}
      type={type}
      size="lg"
      width="100%"
      hasAutoFocus={autoFocus}
      autoCapitalize={verbatim ? "none" : undefined}
      hasAutoCorrect={verbatim ? false : undefined}
      hasSpellCheck={verbatim ? false : undefined}
    />
  );
}

interface PasswordFieldProps extends Omit<FieldProps, "type" | "verbatim"> {
  text: Messages;
}

/** A password field the person may choose to read. */
export function PasswordField({ text, ...field }: PasswordFieldProps) {
  const [shown, setShown] = useState(false);
  return (
    <>
      <Field {...field} type={shown ? "text" : "password"} verbatim />
      <CheckboxInput label={text.showPassword} value={shown} onChange={setShown} size="sm" />
    </>
  );
}
