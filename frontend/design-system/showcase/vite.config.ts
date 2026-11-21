import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The Hodor theme lives with the hosted pages until a second frontend is
// started (docs/design/design-system.md, section 10). The showcase reads
// the compiled theme from there.
const theme = fileURLToPath(new URL("../../auth-ui/src/themes/hodor", import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@hodor-theme": theme },
    // The compiled theme imports Astryx; it must find this project's copy.
    dedupe: ["react", "react-dom", "@astryxdesign/core", "@astryxdesign/theme-neutral", "@stylexjs/stylex"],
  },
  server: { port: 4174, fs: { allow: [".", theme] } },
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
});
