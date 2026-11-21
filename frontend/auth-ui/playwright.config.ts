import { defineConfig, devices } from "@playwright/test";

// The browser tests drive a running stack: the server with the pages, the
// worker and the development mail server. See docs/architecture/hosted-pages.md.
export default defineConfig({
  testDir: "browser-tests",
  globalSetup: "./browser-tests/stack.ts",
  // One at a time: attempts are limited by the address requests come
  // from, and every test comes from the same one.
  workers: 1,
  fullyParallel: false,
  forbidOnly: process.env["CI"] !== undefined,
  retries: 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: process.env["HODOR_URL"] ?? "http://localhost:8080",
    locale: "en-US",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
