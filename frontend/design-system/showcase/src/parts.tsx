// Hodor's own components, sketched on Astryx components and tokens. The
// admin console builds them for real (docs/design/design-system.md, section 7).

import { IconButton } from "@astryxdesign/core/IconButton";
import { Icon } from "@astryxdesign/core/Icon";
import { useClipboard } from "@astryxdesign/core/hooks";
import { Check, Copy } from "lucide-react";
import { type KeyboardEvent, type ReactNode, useEffect, useRef, useState } from "react";

export function Overline({ children }: { children: ReactNode }) {
  return <div className="hodor-overline">{children}</div>;
}

export function Code({ children }: { children: ReactNode }) {
  return <code className="hodor-code">{children}</code>;
}

export type SeverityLevel = "critical" | "high" | "medium" | "low" | "informational";

const shapes: Record<SeverityLevel, ReactNode> = {
  critical: <path d="M6 0 12 6 6 12 0 6Z" />,
  high: <path d="M6 1 12 11H0Z" />,
  medium: <rect x="1" y="1" width="10" height="10" />,
  low: <circle cx="6" cy="6" r="5" />,
  informational: <circle cx="6" cy="6" r="4.5" stroke="currentColor" strokeWidth="1.5" />,
};

const words: Record<SeverityLevel, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
};

/** The severity of a finding or event: a shape and a word, and a color with them. */
export function Severity({ level }: { level: SeverityLevel }) {
  return (
    <span className={`hodor-severity hodor-severity--${level}`}>
      <svg viewBox="0 0 12 12" aria-hidden="true">
        {shapes[level]}
      </svg>
      {words[level]}
    </span>
  );
}

/** The level of an action on the dangerous action ladder, 0 to 4. */
export function Ladder({ level, children }: { level: 0 | 1 | 2 | 3 | 4; children: ReactNode }) {
  return (
    <span className="hodor-ladder">
      <span className="hodor-ladder__steps" aria-hidden="true">
        {[1, 2, 3, 4].map((step) => (
          <span
            key={step}
            className={step <= level ? "hodor-ladder__step hodor-ladder__step--on" : "hodor-ladder__step"}
          />
        ))}
      </span>
      {children}
    </span>
  );
}

const CIRCUMFERENCE = 2 * Math.PI * 54;

export function Score({ value }: { value: number }) {
  return (
    <div className="hodor-score" role="img" aria-label={`Posture score ${value} out of 100`}>
      <svg viewBox="0 0 120 120" aria-hidden="true">
        <circle className="hodor-score__track" cx="60" cy="60" r="54" strokeWidth="8" />
        <circle
          className="hodor-score__value"
          cx="60"
          cy="60"
          r="54"
          strokeWidth="8"
          strokeDasharray={`${(CIRCUMFERENCE * value) / 100} ${CIRCUMFERENCE}`}
        />
      </svg>
      <div className="hodor-score__label" aria-hidden="true">
        <span className="hodor-figure">{value}</span>
        <span className="hodor-overline">of 100</span>
      </div>
    </div>
  );
}

export function Spark({ tone, points }: { tone: "accent" | "warning" | "info"; points: number[] }) {
  const path = points.map((y, index) => `${index === 0 ? "M" : "L"}${index * 10} ${y}`).join(" ");
  return (
    <svg className={`hodor-spark hodor-spark--${tone}`} viewBox="0 0 120 32" preserveAspectRatio="none" aria-hidden="true">
      <path d={path} />
    </svg>
  );
}

/** One line of a list of facts: what, and how much. */
export function Fact({ what, value }: { what: ReactNode; value: ReactNode }) {
  return (
    <li className="hodor-fact">
      <span>{what}</span>
      <strong>{value}</strong>
    </li>
  );
}

export function Facts({ children }: { children: ReactNode }) {
  return <ul className="hodor-list">{children}</ul>;
}

export interface DiffLine {
  number: number;
  change?: "added" | "removed";
  text: string;
}

export function Diff({ label, lines }: { label: string; lines: DiffLine[] }) {
  return (
    <pre className="hodor-diff" aria-label={label}>
      {lines.map((line, index) => (
        <span
          key={index}
          className={line.change ? `hodor-diff__line hodor-diff__line--${line.change}` : "hodor-diff__line"}
        >
          <span className="hodor-diff__number">{line.number}</span>
          <span>{line.change === "added" ? "+" : line.change === "removed" ? "−" : " "}</span>
          <span>{line.text}</span>
        </span>
      ))}
    </pre>
  );
}

export function Decision({ allow }: { allow: boolean }) {
  return (
    <span className={allow ? "hodor-decision hodor-decision--allow" : "hodor-decision hodor-decision--deny"}>
      {allow ? "ALLOW" : "DENY"}
    </span>
  );
}

/** An identifier: mono, truncated in the middle, with the whole value one click away. */
export function Identifier({ shown, value, label }: { shown: string; value: string; label: string }) {
  const { copy, isCopied } = useClipboard();
  return (
    <span className="hodor-identifier">
      <span>{shown}</span>
      <IconButton
        variant="ghost"
        size="sm"
        label={isCopied ? "Copied" : label}
        icon={<Icon icon={isCopied ? Check : Copy} />}
        onClick={() => void copy(value)}
      />
    </span>
  );
}

const HOLD_MILLISECONDS = 1500;

interface HoldButtonProps {
  label: string;
  isDisabled?: boolean;
  onConfirm: () => void;
}

/**
 * The button of the most destructive actions: it acts only after being
 * held, with the pointer or with Space, for a second and a half.
 */
export function HoldButton({ label, isDisabled = false, onConfirm }: HoldButtonProps) {
  const [holding, setHolding] = useState(false);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  function start() {
    if (isDisabled || holding) {
      return;
    }
    setHolding(true);
    timer.current = window.setTimeout(() => {
      setHolding(false);
      onConfirm();
    }, HOLD_MILLISECONDS);
  }

  function stop() {
    window.clearTimeout(timer.current);
    setHolding(false);
  }

  function onKey(event: KeyboardEvent, begin: boolean) {
    if (event.key !== " " && event.key !== "Enter") {
      return;
    }
    event.preventDefault();
    if (begin && !event.repeat) {
      start();
    } else if (!begin) {
      stop();
    }
  }

  return (
    <button
      type="button"
      className={holding ? "hodor-hold hodor-hold--holding" : "hodor-hold"}
      aria-disabled={isDisabled}
      onPointerDown={start}
      onPointerUp={stop}
      onPointerLeave={stop}
      onBlur={stop}
      onKeyDown={(event) => onKey(event, true)}
      onKeyUp={(event) => onKey(event, false)}
    >
      <span>{label}</span>
    </button>
  );
}
