# Decision 0018: Astryx is the foundation of the design system

Status: Accepted (requested by the project owner)

## Context

[Decision 0016](0016-design-system.md) gave Hodor one design system for its three frontends and chose to write it by hand: tokens and component styles as static CSS, with React components to follow. It rejected the component libraries of the time because most of them make their styles in the browser, which the Content Security Policy of the frontends forbids, and because none carries the security interaction patterns.

Since then two things changed:

- The hosted pages were built on the hand-written styles, and every component they needed (field, button, alert, card) had to be written, made accessible and tested here. The admin console needs several dozen more, among them a data table, a command palette, dialogs and date pickers.
- [Astryx](https://github.com/facebook/astryx) was published under the MIT license: the design system Meta uses internally, with more than 150 accessible React components. It ships **compiled style sheets**, a theme is **a set of CSS custom property overrides compiled ahead of time into a static style sheet**, and its fonts are files in the package. That is the same model Decision 0016 chose, already built.

The project owner asked for Astryx to be Hodor's design system.

## Decision

- **Astryx is the foundation of the design system.** Foundations (the token names, the spacing, type and motion scales) and components come from `@astryxdesign/core`. Hodor does not write a component Astryx already has.
- **Hodor keeps its own look as an Astryx theme**, the *Hodor theme*: the ink neutrals, the signal accent, the four status colors and IBM Plex. The theme is compiled ahead of time; the frontends load the compiled style sheet and never define a theme in the browser.
- **What Decision 0016 decided about safety stands unchanged**: one design system for the three frontends; the security interaction patterns (scope bar, dangerous action ladder, change preview, secret reveal, provenance, weakened-setting labeling) are part of it; the admin console is never tenant-branded; tenant branding is token overrides, validated before they are stored. The patterns are now Hodor components composed from Astryx components.
- **The Content Security Policy does not change.** No `unsafe-inline`, no third-party origin, Trusted Types as before. Only the compiled style sheets of Astryx and of the theme are loaded, and the fonts are served by `hodor-server`. The browser tests fail on any violation of the policy.
- **The versions of the Astryx packages are pinned exactly** and moved together, on purpose, with Astryx's own upgrade command. Astryx is in beta: a minor version may change a component.
- **The hand-written component styles are removed.** `tokens.css`, `components.css` and `shell.css` are deleted, and the showcase that was written on them is rebuilt on Astryx components.

The specification is [docs/design/design-system.md](../design/design-system.md), revised with this decision.

## Consequences

- The admin console starts from a library of accessible components, page templates and documentation, where it would have started from style sheets.
- Hodor's own work on the design system narrows to what is Hodor's: the theme and the security patterns.
- Hodor depends on a library in beta, maintained by one company. Pinned versions and the browser tests contain a bad release; Astryx's `swizzle` command copies the source of a component into the repository if one ever has to be owned here.
- The pages are heavier: Astryx ships one style sheet for all of its components, and the hosted pages use nine of them. The sizes are recorded in [the hosted pages](../architecture/hosted-pages.md#appearance), with what can be done about them.
- Astryx components set a few values (a width, a position) through the style interface of the document, which the policy allows; the rule that Hodor's own code writes no inline style stays.
- Token names change from Hodor's (`--color-surface`, `--space-4`) to Astryx's (`--color-background-surface`, `--spacing-4`). A tenant's branding is stored as a brand color and a radius choice, not as token names, so nothing stored changes.

## Alternatives considered

- **Keep writing the design system by hand** (Decision 0016 as it was): full control and the smallest pages, at the cost of building and maintaining every component and its accessibility here, before any of the admin console exists.
- **Astryx with one of its ready-made themes**: the least work, but the three frontends would look like any other Astryx application, and an administrator should recognize Hodor's control plane at a glance.
- **Another component library**: the ones considered in Decision 0016 still make their styles in the browser. Astryx is the one whose model matches the policy without exception.
