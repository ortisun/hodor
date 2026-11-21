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
      <section className="card auth-card" aria-labelledby={headingId}>
        <div className="card__body auth-card__body">
          <div className="auth-card__heading">
            <p className="overline auth-text">
              {text.organization}: {tenant}
            </p>
            <h1 id={headingId} ref={heading} tabIndex={-1} className="auth-card__title">
              {title}
            </h1>
          </div>
          {children}
        </div>
      </section>
    </main>
  );
}
