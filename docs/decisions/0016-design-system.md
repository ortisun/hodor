# Decision 0016: One token-based design system for the three frontends, with security patterns built in

Status: Proposed

## Context

Hodor has three frontends — the admin console, the account console and the hosted login user interface ([Decision 0011](0011-frontends-bff.md)). The admin console is a privileged tool: a mistake in it can lock users out of every application or open a tenant to attack. Comparable products leave the safety of dangerous actions to each screen, so the same kind of action is guarded differently in different places, and tenant branding often reaches screens where it helps phishing.

The frontends run under a strict Content Security Policy: no inline script, no third-party origins, Trusted Types.

## Decision

- **One design system** in `frontend/design-system/`, shared by the three frontends, specified in [docs/design/design-system.md](../design/design-system.md).
- **Design tokens as CSS custom properties**, in two layers (reference and semantic), defined in OKLCH. Themes and tenant branding are token overrides and nothing else.
- **Static CSS only**: no runtime CSS-in-JavaScript and no inline `style` attributes, so that the Content Security Policy needs no `unsafe-inline` for styles. React components, when built, apply class names from the design system.
- **Self-hosted IBM Plex** (Sans, Sans Condensed, Mono) under the open font license, served by `hodor-server`.
- **Dark theme by default for the admin console**, light for the account console and login; all three support both, plus forced colors.
- **Security interaction patterns are part of the design system**: the scope bar, the dangerous action ladder (five levels, assigned once per action in an action catalog), change preview, secret reveal, provenance and weakened-setting labeling.
- **The admin console is never tenant-branded.** Tenant branding is limited to the account console and login, and is validated for contrast before it is stored.

## Consequences

- The same action is guarded the same way everywhere, and a reviewer can check the ladder level of every action in one catalog.
- A new screen gets the safety patterns by using the components; skipping them takes deliberate work that shows up in review.
- Static CSS gives up some conveniences of component-scoped styling libraries; class naming discipline replaces them.
- Self-hosting fonts adds a few hundred kilobytes to the image.

## Alternatives considered

- **An off-the-shelf component library with its own theme** (Material, Ant Design, Chakra): fast to start, but most inject styles at runtime, which conflicts with the Content Security Policy, and none carries the security patterns, which are the point.
- **Separate design systems per frontend**: lets the login screens move faster, but splits accessibility and security fixes across two codebases.
- **Tenant branding in the admin console**: requested by some products' customers, rejected because a control plane that changes appearance per tenant is easier to imitate and easier to confuse between tenants.
