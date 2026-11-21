import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "dist",
      "node_modules",
      "test-results",
      "playwright-report",
      // Written by `npm run theme` from src/themes/hodor/hodorTheme.ts.
      "src/astryx-themes.ts",
      "src/themes/hodor/hodor.*",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.strict,
  reactHooks.configs.flat.recommended,
  {
    languageOptions: { globals: { ...globals.browser } },
    rules: {
      // Markup is only ever built by React from text. Turning text into
      // markup is what the Content Security Policy forbids as well.
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "Text is never turned into markup.",
        },
        {
          selector: "JSXAttribute[name.name='style']",
          message: "No inline styles: the Content Security Policy allows none.",
        },
      ],
    },
  },
  {
    files: ["browser-tests/**", "*.config.ts", "*.config.js"],
    languageOptions: { globals: { ...globals.node } },
  },
);
