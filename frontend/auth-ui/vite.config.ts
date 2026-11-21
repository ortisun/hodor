import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The server serves `dist/index.html` for every page and `dist/assets`
// under `/auth-ui/assets`. See docs/architecture/hosted-pages.md.
export default defineConfig({
  base: "/auth-ui/",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Every file referenced by the page is a file of its own: the Content
    // Security Policy allows no inline script, style or data address.
    assetsInlineLimit: 0,
    // The policy also forbids the inline script a preload helper would need.
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true,
  },
});
