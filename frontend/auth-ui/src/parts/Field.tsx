import { type InputHTMLAttributes, useId, useState } from "react";
import type { Messages } from "../messages";

interface FieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "id" | "className"> {
  label: string;
  hint?: string;
  /** What is wrong with what was typed, if anything. */
  error?: string | null;
}

/** A labelled input. Its hint and its error are tied to it. */
export function Field({ label, hint, error, ...input }: FieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const described = [hint ? hintId : null, error ? errorId : null].filter(Boolean).join(" ");

  return (
    <div className="field">
      <label className="field__label" htmlFor={id}>
        {label}
      </label>
      <input
        {...input}
        id={id}
        className="input"
        aria-invalid={error ? true : undefined}
        aria-describedby={described === "" ? undefined : described}
      />
      {hint ? (
        <p id={hintId} className="field__hint auth-text">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={errorId} className="auth-field-error">
          {error}
        </p>
      ) : null}
    </div>
  );
}

interface PasswordFieldProps extends Omit<FieldProps, "type"> {
  text: Messages;
}

/** A password field the person may choose to read. */
export function PasswordField({ text, ...field }: PasswordFieldProps) {
  const [shown, setShown] = useState(false);
  return (
    <>
      <Field {...field} type={shown ? "text" : "password"} autoCapitalize="none" spellCheck={false} />
      <label className="auth-check">
        <input type="checkbox" checked={shown} onChange={(event) => setShown(event.target.checked)} />
        {text.showPassword}
      </label>
    </>
  );
}
