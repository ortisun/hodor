# Design system

The design system is the shared visual language of Hodor's three frontends: the admin console (the *control plane*), the account console and the hosted login user interface (`auth-ui`). It defines the foundations (color, type, space, motion), the components, and — most important for an identity product — the interaction patterns that keep privileged work safe.

The design system is built on [Astryx](https://github.com/facebook/astryx), the open source design system published by Meta: Astryx gives the foundations and the components, and Hodor adds its own theme and its security interaction patterns ([Decision 0018](../decisions/0018-astryx-component-foundation.md)). [Section 10](#10-how-it-is-built) says where each part lives.

This page is the specification, and the implementation follows it. How the control plane is organized, screen by screen, is in [control-plane.md](control-plane.md). Why the design system has the principles and patterns it has is recorded in [Decision 0016](../decisions/0016-design-system.md).

## 1. Who it is for

| Frontend | Audience | Character |
|---|---|---|
| Admin console | Tenant administrators, security engineers, platform operators | Dense, fast, keyboard-driven; dark theme by default; never tenant-branded |
| Account console | End users managing their own profile, multi-factor authentication, sessions and consents | Calm and plain; light theme by default; tenant-branded within limits |
| Hosted login user interface | Anyone signing in | Minimal, trustworthy, tenant-branded within limits |

The three share foundations and components. They differ in default theme, density and how much of the brand a tenant may change ([section 5](#5-tenant-branding)).

## 2. Principles

These come first because every later choice follows from them. They are drawn from what security practitioners ask of privileged tools (see the [competitive analysis](../product/competitive-analysis.md#4-what-security-practitioners-ask-of-a-privileged-console)).

1. **Context is never ambiguous.** The tenant, the environment and the administrator's own privilege are visible on every screen of the admin console. A person should not be able to change the wrong tenant because two tabs look alike.
2. **Consequences before commitment.** Any change that affects sign-in, tokens or authorization shows what will change (a diff), whom it will affect (the blast radius) and, where Hodor can compute it, a simulated outcome — before the button that applies it.
3. **The secure path is the easy path.** Secure defaults are pre-selected. Weakening an option is possible only where the product allows it at all, takes an extra step, and stays labeled as a weakened setting afterwards.
4. **Calm by default, loud when it matters.** Color is reserved for meaning. A screen with nothing wrong is mostly neutral; a critical finding or a destructive action is unmistakable. Decoration never uses the status colors.
5. **Evidence over assertion.** Every state the console shows can be traced to its source: who changed it, when, and the audit record that proves it.
6. **Dense, but legible.** Operators scan long tables of users, sessions and events. The default density favors scanning; text never drops below the minimum sizes in [section 3.2](#32-typography).
7. **Keyboard first.** Every action is reachable from the keyboard; the command palette reaches every screen and frequent action.
8. **One language, written in full.** Copy follows the [writing conventions](../development/conventions.md#3-words-not-abbreviations): words are written in full, buttons are verbs, nothing relies on an abbreviation the reader must decode.

## 3. Foundations

All foundations are **design tokens**: named values exposed as CSS custom properties. Components use tokens only, never raw values, so that a theme is a change of token values and nothing else.

The token names are Astryx's (`--color-background-surface`, `--color-text-secondary`, `--spacing-4`); the full list is printed by `npx astryx docs tokens`. The values are Hodor's, set by the **Hodor theme**, which starts from Astryx's neutral theme and changes what this section describes:

- the **palette** is generated from six seed colors (the accent, the neutral and the four status colors) in the OKLCH color space, which keeps perceived lightness even across hues, so that the status colors read as equally strong. The generation recipe is pinned, so that an upgrade of Astryx does not move a shade;
- the **typeface** is IBM Plex;
- the **radius** scale is Hodor's.

Hodor's own code (the layout of a page, a security pattern) uses the same tokens and no raw value.

### 3.1 Color

#### Neutrals — "ink"

A cool, slightly blue-tinted neutral ramp from near white to near black, generated from the seed `#737b84`. The dark theme builds its surfaces from the dark end, the light theme from the light end.

| Semantic token | Use |
|---|---|
| `--color-background-body` | The page background |
| `--color-background-surface` / `--color-background-card` | Panels; cards |
| `--color-background-popover` | Menus, popovers, dialogs |
| `--color-background-muted` | Wells, code blocks, table headers |
| `--color-border` / `--color-border-emphasized` | Dividers; input and control outlines |
| `--color-text-primary` / `--color-text-secondary` / `--color-text-disabled` | Body text; secondary text; disabled text |

#### Accent — "signal"

Hodor's brand accent is **signal**, a clear cyan (seed `#007b92`; token `--color-accent`). It marks the current location, focus, primary actions and links. It is deliberately not a status color: a signal-colored element is "where you are" or "what you can do", never "good" or "bad".

#### Status

Four status families, each with a solid fill (`--color-success`), a tinted fill (`--color-success-muted`), a text color (`--color-text-success`) and a border color (`--color-border-success`).

| Status | Seed | Meaning | Examples |
|---|---|---|---|
| `success` | `#137d41` | Something finished as intended or is in a healthy state | Domain verified, policy published, check passed |
| `warning` | `#a06604` | Needs attention soon; nothing is broken yet | Key rotation due, secret expires in 7 days, weakened setting |
| `error` | `#c22826` | Broken, blocked or destructive | Failed verification, account locked, delete |
| `info` | `#3a65b8` | Neutral information | Draft, scheduled, in progress |

#### Severity

Security findings and events use a five-step severity scale, separate from status because a "high" finding is not the same as a "failed" operation. Severity is always shown with a text label and a shape, never by color alone.

| Severity | Shape | Use |
|---|---|---|
| `critical` | Filled diamond | Active compromise indicators, refresh token reuse detected, cross-tenant access attempt |
| `high` | Filled triangle | Brute-force lockouts across many accounts, administrator role granted outside approval |
| `medium` | Filled square | Repeated failed sign-ins on one account, insecure client configuration |
| `low` | Filled circle | Unverified identifier used to sign in, deprecated algorithm still accepted |
| `informational` | Hollow circle | Routine administrative changes |

#### Data visualization

Charts use an eight-step categorical palette derived from the same lightness band, chosen to stay distinguishable for the common forms of color blindness. Severity charts use the severity tokens. Charts follow the same rule as everything else: meaning is never carried by color alone (labels, direct annotation or patterns accompany it).

### 3.2 Typography

| Role | Family | Why |
|---|---|---|
| Interface text | IBM Plex Sans | Open font license, wide Latin coverage (including Portuguese), excellent legibility at small sizes, a technical character that suits infrastructure software |
| Headings and section labels | IBM Plex Sans Condensed | Same family, narrower: headings and table column labels fit dense layouts |
| Identifiers, secrets, code, policies | IBM Plex Mono | Unambiguous glyphs (`0`/`O`, `1`/`l`/`I`), which matters for client identifiers, key identifiers and Rego |

Fonts are self-hosted and served by `hodor-server` with the rest of the static assets: the Content Security Policy allows no third-party origin ([Decision 0011](../decisions/0011-frontends-bff.md)). The theme names the families (`--font-family-body`, `--font-family-heading`, `--font-family-code`); each frontend bundles the font files it uses. The hosted pages use IBM Plex Sans only; the condensed and the mono families arrive with the admin console.

The type scale is Astryx's geometric scale with a 1.2 ratio anchored at 14 pixels. Text is written with Astryx's `Text` and `Heading` components, which take a role and not a size:

| Role | Use |
|---|---|
| `Text` `supporting` | Captions, badges, metadata, hints under a field |
| `Text` `body` | Default body text |
| `Text` `large` | Body text where a page has little of it, such as a lead paragraph |
| `Heading` levels 2 to 6 | Section headings, each one step of the scale smaller than the one above |
| `Heading` level 1 | Page titles |
| `Heading` `display` types | Key figures on the overview |

Rules:

- Numbers in tables and metrics use tabular figures, so that columns align.
- Identifiers longer than their cell are truncated in the middle (`0193…7f2a`), never at the end, because the end of a UUIDv7 is the part that differs; the full value is one click or one key away.
- No body text below 12 pixels.

### 3.3 Space, size and layout

- **Spacing** is Astryx's 4-pixel grid: `--spacing-1` (4 pixels) to `--spacing-12`. Layout components (`VStack`, `HStack`, `Grid`) take a step of the grid, not a length.
- **Control sizes**: Astryx's `sm`, `md` and `lg`. The admin console uses `md` (`sm` in compact density); the account console and login use `lg`. Every interactive target is at least 24 by 24 pixels (Web Content Accessibility Guidelines 2.2, success criterion 2.5.8).
- **Radius**: `--radius-inner` (4 pixels) for badges and for what sits inside a control, `--radius-element` (6) for buttons, inputs and cards, `--radius-container` (10) for dialogs. Tenants may adjust radius on the login and account surfaces only.
- **Layout of the admin console**: a fixed left navigation (240 pixels, collapsible to 56), a top *scope bar* ([section 6.1](#61-the-scope-bar)), and a content area with a maximum readable width of 1440 pixels. Detail views open as a side panel over lists, so that the list keeps its position.
- **Density**: `comfortable` and `compact` modes change control height and table row height (40 and 32 pixels); text size does not change.

### 3.4 Elevation

Elevation separates layers without heavy shadows. In the dark theme, higher layers are lighter surfaces with a hairline border; in the light theme, they add a soft shadow.

| Level | Use |
|---|---|
| 0 | Canvas |
| 1 | Panels, cards, tables |
| 2 | Sticky headers, side panels |
| 3 | Menus, popovers, toasts |
| 4 | Dialogs and the command palette, over a dimmed backdrop |

### 3.5 Motion

Motion explains a change; it never decorates. Durations come from Astryx's motion tokens (`--duration-fast`, `--duration-medium`, `--duration-slow`) with its standard easing. When the operating system asks for reduced motion, transitions become instant fades and nothing moves.

Two motions carry meaning and are reserved: the **pulse** on a live indicator (a stream receiving events) and the **hold-to-confirm** fill on the most destructive actions ([section 6.2](#62-the-dangerous-action-ladder)).

### 3.6 Icons

One outlined icon set: the icons of Astryx's neutral theme (Lucide), used by semantic name through Astryx's `Icon` component and bundled with the frontend, so that nothing is loaded from another origin. Icons accompany text labels; an icon alone is allowed only for universally understood actions (close, copy, search, more) and always carries an accessible name.

## 4. Themes

| Theme | Default for | Notes |
|---|---|---|
| Dark | Admin console | Low glare for long sessions and operations rooms |
| Light | Account console, login | Familiar for end users |
| System | — | Follows the operating system's preference when the user chooses it |
| Forced colors | — | When the operating system's high contrast mode is on, components fall back to system colors and keep visible borders and focus rings |

Light and dark are the two modes of the one Hodor theme: every color token holds a value for each, and Astryx's `Theme` component at the root of a frontend chooses the mode (`light`, `dark` or `system`). Forced colors are handled by the Astryx components themselves.

The theme is a preference stored in the user's account (not in browser storage alone), so it follows the administrator across devices.

## 5. Tenant branding

Tenant branding is declarative and narrow ([Decision 0011](../decisions/0011-frontends-bff.md), Requirement-Tenancy-05). A tenant may set:

- a logo (SVG sanitized by the server, or PNG) and a favicon;
- one brand color, from which Hodor derives the accent for the account console and login, with the same palette generation the Hodor theme uses;
- the radius scale (sharp, default, round);
- copy and default locale.

Hodor validates a brand color before accepting it: the derived accent must reach a contrast of 4.5 to 1 against the surfaces it is used on in both themes, or it is rejected with the reason.

**The admin console is never tenant-branded.** Administrators must always recognize Hodor's own control plane; a control plane that changes appearance per tenant is easier to imitate in a phishing page and easier to confuse between tenants. The tenant's identity in the admin console is carried by the scope bar instead.

## 6. Security interaction patterns

These patterns are part of the design system, not left to each screen. A screen that performs one of these actions uses the pattern; it does not invent its own.

### 6.1 The scope bar

A bar across the top of every admin console screen that states, left to right:

- **Tenant**: name, slug and a stable color chip derived from the tenant identifier (the same tenant always has the same chip, different tenants rarely share one). Switching tenant opens a searchable list; it never happens by changing a dropdown accidentally.
- **Environment label**: an optional label set by the platform operator (for example `production`, `staging`). A `production` label adds a thin colored rule along the top edge of the window.
- **Your access**: the administrator's active roles in this tenant and, when the administrator is working under a time-boxed support grant or an elevated role (Threat-Tenancy-05), a countdown to its expiry.
- **Session**: time left before the administrator's session idles out; a warning appears two minutes before, with a button to stay signed in.

When an administrator acts under a support grant, the whole bar turns to the warning treatment and states whose grant it is and why. It cannot be dismissed.

### 6.2 The dangerous action ladder

Every state-changing action in the admin console is assigned one of five levels. The level decides the friction; the friction grows with the damage the action can do and how hard it is to undo.

| Level | Friction | Applies to (examples) |
|---|---|---|
| 0 — Reversible | Apply immediately; a toast offers **Undo** for 10 seconds | Rename a group, edit a description, add a member |
| 1 — Confirm | A dialog names the object and the effect; the confirming button repeats the verb ("Suspend user") | Suspend a user, revoke one session, disable an application |
| 2 — Type to confirm | Level 1, plus typing the object's name or slug | Delete a user, delete an application, revoke all sessions of a tenant, deactivate an identity provider |
| 3 — Recent authentication | Level 2, plus fresh authentication: Hodor's API answers `step_up_required` ([API conventions](../api/api-spec.md)) and the console runs the step-up inline, with a passkey where possible | Rotate or revoke signing keys, change the tenant's multi-factor authentication policy, grant an administrator role, publish a policy or flow to production, export audit records, delete a tenant |
| 4 — Second approver | Level 3, plus approval by a different administrator before it takes effect (Phase 7, Epic 27) | Grant a platform role, disable audit delivery, weaken a tenant-wide security policy |

Rules shared by every level:

- The destructive button is never the default button and is never pre-focused; pressing Enter in the dialog does not trigger it.
- The dialog says what will happen in words a reader can check ("Revokes 1,204 sessions across 3 applications; users must sign in again"), using numbers from the API, not estimates.
- After the action, a toast links to the audit record it produced.
- The level of an action is defined once, in the design system's action catalog, so that the same action behaves the same everywhere.

### 6.3 Change preview: diff, blast radius, simulation

Changes to authentication flows, authorization policies, client configuration, identity provider mappings and tenant security settings are made as a **draft** and applied through a review step that shows:

1. **Diff**: before and after, side by side or inline, for structured settings and for Rego or flow definitions.
2. **Blast radius**: the applications, users or clients affected, as counts with links.
3. **Simulation**, where Hodor offers it (`:simulate` on flows and policies): the outcome for sample subjects, highlighting decisions that change from `ALLOW` to `DENY` or the reverse.
4. **Validation**: blocking errors and non-blocking warnings, each linked to the line or field it concerns.

Publishing is a separate, explicit action at the right level of the ladder; rollback to any earlier version is one action from the version history.

### 6.4 Secrets and credentials

- A generated secret (client secret, API key, recovery codes) is **shown once**, in a dedicated panel with a copy button and a download option, and a checkbox "I have stored this secret" that must be ticked before the panel closes. It is never retrievable afterwards; the console says so.
- Stored secrets are shown only as their identifiable prefix and last characters, with creation date, last use and expiry.
- Copying a secret to the clipboard shows a notice; the console does not keep the value in its state after the panel closes.
- Secrets are never placed in URLs, page titles or notifications.

### 6.5 Identifiers

Identifiers (`UserId`, client identifiers, key identifiers, request identifiers) are shown in the mono family, middle-truncated, with a copy button and a tooltip holding the full value. Every request identifier links to the matching audit record and trace.

### 6.6 Weakened settings

Where Hodor allows a weaker option (for example, a longer session lifetime than recommended, or automatic account linking by email), the control shows the recommended value, marks the weakened choice with a `warning` badge that names the risk, and the setting appears on the security posture page ([control-plane.md](control-plane.md#security-posture)) until it is changed back or explicitly accepted with a reason and an expiry.

### 6.7 Provenance

Every configuration object shows "Last changed by *name* *time ago*" linking to the audit record. Hovering the time shows the exact UTC timestamp.

### 6.8 Errors and empty states

- Errors come from the API's problem documents. The console shows the title and the safe detail, the request identifier, and a link to the audit record when one exists. It never shows stack traces or internal messages.
- An empty state explains what the object is, why it matters for security, and offers the first action ("No identity providers yet. Users sign in with a password only. Add an identity provider").

## 7. Components

Components come from Astryx. A frontend imports them from `@astryxdesign/core` and does not write one Astryx has; `npx astryx component --list` prints all of them, and `npx astryx component Button` the documentation of one. The table says which Astryx components serve each need of the frontends.

| Group | Need | Astryx components |
|---|---|---|
| Actions | Buttons (primary, secondary, ghost, destructive; with icon; loading), icon button, grouped buttons | `Button`, `IconButton`, `ButtonGroup`, `ToggleButton` |
| Inputs | Text field, textarea, select, combobox, checkbox, radio, switch, segmented control, date and time range, tag input, file drop | `TextInput`, `TextArea`, `Selector`, `Typeahead`, `CheckboxInput`, `RadioList`, `Switch`, `SegmentedControl`, `DateRangeInput`, `DateTimeInput`, `Tokenizer`, `FileInput`, laid out with `FormLayout` |
| Feedback | Badge, status dot, toast, inline alert, banner, progress, skeleton | `Badge`, `StatusDot`, `Toast`, `Banner`, `ProgressBar`, `Spinner`, `Skeleton` |
| Navigation | Side navigation, breadcrumbs, tabs, command palette, pagination | `AppShell`, `SideNav`, `TopNav`, `Breadcrumbs`, `TabList`, `CommandPalette`, `Pagination` |
| Data | Data table, key-value list, timeline, code block, timestamps | `Table` with its selection toolbar, `MetadataList`, `Stepper`, `CodeBlock`, `Timestamp` |
| Overlays | Dialog, confirmation dialog, side panel, popover, tooltip, menu | `Dialog`, `AlertDialog`, `Drawer`, `Popover`, `Tooltip`, `DropdownMenu`, `ContextMenu` |
| Layout and text | Stacks, grids, cards, headings, text, links | `VStack`, `HStack`, `Grid`, `Layout`, `Card`, `Heading`, `Text`, `Link` |

What Astryx does not have is Hodor's to build, composed from Astryx components and its tokens, once, in the design system:

| Hodor component | Built from | Status |
|---|---|---|
| Scope bar and tenant switcher ([section 6.1](#61-the-scope-bar)) | `TopNav`, `Selector` | Specified |
| Confirmation dialogs of the dangerous action ladder, with the hold-to-confirm button ([section 6.2](#62-the-dangerous-action-ladder)) | `AlertDialog`, `Button`, `TextInput` | Specified |
| Change preview and diff viewer ([section 6.3](#63-change-preview-diff-blast-radius-simulation)) | `Dialog`, `CodeBlock`, `Table` | Specified |
| Secret field and secret reveal panel ([section 6.4](#64-secrets-and-credentials)) | `TextInput`, `Dialog`, `CheckboxInput` | Specified |
| Identifier ([section 6.5](#65-identifiers)) | `Text`, `Tooltip`, `IconButton` | Specified |
| Weakened-setting badge, provenance line, support-grant banner ([sections 6.6](#66-weakened-settings) and [6.7](#67-provenance)) | `Badge`, `Timestamp`, `Banner` | Specified |
| Severity badge with its shape ([section 3.1](#31-color)) | `Badge`, `Icon` | Specified |
| Step-up prompt, approval request card, posture score, metric tile, sparkline, live indicator | `Dialog`, `Card`, `StatusDot` | Specified |

Status: **Specified** means defined on this page; **Built** means implemented as a React component. Hodor's components are built with the admin console (Epic 12). Until then the showcase ([section 10](#10-how-it-is-built)) draws most of them on Astryx components, with sample data and no server behind them. The hosted pages are built today, on nine Astryx components: `Card`, `Heading`, `Text`, `VStack`, `TextInput`, `CheckboxInput`, `Banner`, `Button` and `Link` ([hosted pages](../architecture/hosted-pages.md#appearance)).

## 8. Accessibility

The frontends conform to Web Content Accessibility Guidelines 2.2 level AA (Requirement-Usability-01). The design system makes the common cases correct by construction:

- Text contrast at least 4.5 to 1, large text and interface component outlines at least 3 to 1, checked for every semantic token pair in both themes as part of the token build.
- A visible focus ring (2 pixels, signal color, 2-pixel offset) on every focusable element; focus is never removed, only restyled.
- Status and severity always pair color with a text label and a shape.
- Targets at least 24 by 24 pixels.
- Dialogs trap focus and return it on close; side panels do not trap focus.
- Live regions announce toasts and the session-expiry warning.
- Reduced motion and forced colors are respected ([section 3.5](#35-motion), [section 4](#4-themes)).

## 9. Content and localization

- English and Brazilian Portuguese at launch (`en`, `pt-BR`); all copy is externalized (Requirement-Usability-02). Layouts allow 30% text expansion.
- Sentence case for titles, buttons and labels.
- Buttons are verbs that name the result: "Revoke sessions", not "OK".
- Times are relative in lists ("4 minutes ago") with the absolute UTC time on hover; absolute in audit and exports.
- Words are written in full, following the [conventions](../development/conventions.md#3-words-not-abbreviations); a protocol name such as OAuth or SAML stays as it is.

## 10. How it is built

| Part | Where | What it is |
|---|---|---|
| Foundations and components | The packages `@astryxdesign/core` and `@astryxdesign/cli`, at one exact version | Astryx: the compiled style sheets `reset.css` and `astryx.css`, and the React components |
| The Hodor theme | `frontend/auth-ui/src/themes/hodor/` | `hodorTheme.ts` is the source, written by hand. `npm run theme` compiles it into `hodor.css` and `hodor.js` beside it, which are committed and are what a frontend loads |
| Hodor's own components | `frontend/admin-console/src/parts/` | The security interaction patterns of [section 6](#6-security-interaction-patterns), built as the [admin console](../architecture/admin-console.md) needs them: so far the confirmations of the dangerous action ladder and the identifier |
| The showcase | `frontend/design-system/showcase/` | A small application, never shipped, built on Astryx with the Hodor theme: the security posture screen of the control plane with working confirmations of the dangerous action ladder, step-up, secret reveal and command palette, and a gallery of the foundations and components. It is where Hodor's own components are first drawn, before the admin console builds them for real |

The theme lives with the hosted pages, where it was first built; the admin console and the showcase read the compiled theme from there. Moving it to a place of its own, shared by the frontends, is not done yet.

The showcase is run from its folder with `npm ci` and `npm run dev`. It opens in the dark mode, the default of the admin console, and switches to the light one from its top bar.

A frontend wires the design system once, at its root:

```tsx
import "@astryxdesign/core/reset.css";
import "@astryxdesign/core/astryx.css";

import { Theme } from "@astryxdesign/core/theme";
import { defaultThemeSlug, themes } from "./astryx-themes";

<Theme theme={themes[defaultThemeSlug]} mode="light">
  <App />
</Theme>;
```

`astryx-themes.ts` is written by `npx astryx theme add hodor`; it imports the compiled theme and its style sheet.

These rules follow from the Content Security Policy and the backend-for-frontend design ([Decision 0011](../decisions/0011-frontends-bff.md)):

- **Every style is a compiled file.** A frontend loads Astryx's style sheets and the compiled theme. It never defines a theme in the browser (`defineTheme` is for the source file only), because that makes a `<style>` element, which the policy refuses. Hodor's own code writes no inline `style` attribute.
- **The compiled theme is never stale.** Continuous integration runs `npm run theme-check`, which fails when `hodor.css` no longer matches `hodorTheme.ts`.
- **No third-party origin**: fonts, icons and images are served by `hodor-server`. Astryx's instructions for loading from a content delivery network are not used.
- **The versions of Astryx are exact** in `package.json`, the same for every `@astryxdesign` package, and are raised together with `npx astryx upgrade --apply`, followed by the browser tests.
- Tenant branding is applied by the server as a generated style sheet of token overrides, validated before it is stored ([section 5](#5-tenant-branding)).
- The design system carries no data fetching and no authentication logic; it is presentation only.
