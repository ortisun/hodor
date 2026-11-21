import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

// The Hodor theme lives with the hosted pages; the console reads the
// compiled theme from there (docs/design/design-system.md, section 10).
const theme = fileURLToPath(new URL("../auth-ui/src/themes/hodor", import.meta.url));

// The server under development, for `npm run dev`.
const server = process.env["HODOR_URL"] ?? "http://localhost:8080";

/**
 * In development, answers the console's addresses with the application,
 * as `hodor-server` does (docs/architecture/admin-console.md).
 */
function consoleAddresses(): Plugin {
  return {
    name: "hodor-console-addresses",
    configureServer(development) {
      development.middlewares.use((request, _response, next) => {
        const path = (request.url ?? "").split("?")[0] ?? "";
        if (/^\/t\/[^/]+\/console(\/(?!api(\/|$)).*)?$/.test(path)) {
          request.url = "/admin-console/index.html";
        }
        next();
      });
    },
  };
}

/**
 * Fills `src/layer-rules.css` with the rules Astryx would otherwise write
 * into the page as a style element, which the policy of the page refuses.
 */
function layerRules(): Plugin {
  return {
    name: "hodor-layer-rules",
    enforce: "pre",
    async transform(code, id) {
      if (!id.split("?")[0]?.endsWith("/src/layer-rules.css")) {
        return null;
      }
      const rules = fileURLToPath(
        new URL("./node_modules/@astryxdesign/core/dist/Layer/layerSlideRules.js", import.meta.url),
      );
      const { slideRulesCss } = (await import(rules)) as { slideRulesCss: () => string };
      return `${code}\n${slideRulesCss()}\n`;
    },
  };
}

// The server serves `dist/index.html` for every screen and `dist/assets`
// under `/admin-console/assets`.
export default defineConfig({
  base: "/admin-console/",
  plugins: [react(), consoleAddresses(), layerRules()],
  resolve: {
    alias: { "@hodor-theme": theme },
    // The compiled theme imports Astryx; it must find this project's copy.
    dedupe: ["react", "react-dom", "@astryxdesign/core", "@astryxdesign/theme-neutral", "@stylexjs/stylex"],
  },
  server: {
    port: 4175,
    fs: { allow: [".", theme] },
    proxy: {
      "^/t/[^/]+/(console/api|interaction|account)": { target: server, changeOrigin: false },
      "^/auth-ui/": { target: server, changeOrigin: false },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Every file referenced by the page is a file of its own: the Content
    // Security Policy allows no inline script, style or data address.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/setup.ts"],
    restoreMocks: true,
  },
});
