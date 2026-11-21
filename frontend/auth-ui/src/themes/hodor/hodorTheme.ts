import { themePalette } from "@astryxdesign/core/palette";
import { defineTheme } from "@astryxdesign/core/theme";
import { neutralTheme } from "@astryxdesign/theme-neutral";

/**
 * The Hodor theme: Astryx's neutral theme with Hodor's own colors and type.
 * It is specified in docs/design/design-system.md, section 3.
 *
 * This file is the source. `npm run theme` compiles it into the static
 * stylesheet and module beside it, which are what the pages load: the
 * Content Security Policy allows no style to be made in the browser.
 */

const plex = "IBM Plex Sans";
const systemFonts = "system-ui, -apple-system, 'Segoe UI', sans-serif";

export const hodorTheme = defineTheme({
  name: "hodor",
  extends: neutralTheme,
  palette: themePalette({
    // "Signal", the accent: where you are and what you can do.
    accent: "#007b92",
    // "Ink", the cool neutral of every surface and text.
    neutral: "#737b84",
    success: "#137d41",
    warning: "#a06604",
    danger: "#c22826",
    info: "#3a65b8",
    // Pinned, so that an upgrade of Astryx does not move the shades.
    recipe: "astryx-oklch-v2",
  }),
  typography: {
    scale: { base: 14, ratio: 1.2 },
    body: { family: plex, fallbacks: systemFonts },
    heading: { family: plex, fallbacks: systemFonts },
  },
  tokens: {
    // Badges and inputs inside a control; buttons, inputs and cards; dialogs.
    "--radius-inner": "4px",
    "--radius-element": "6px",
    "--radius-container": "10px",
  },
});
