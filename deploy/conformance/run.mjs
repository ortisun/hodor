// Runs the Basic OpenID Provider, Config OpenID Provider and Back-Channel
// OpenID Provider plans of the OpenID conformance suite against Hodor, then
// the Basic and Back-Channel plans again with pairwise clients, in the stack
// of compose.yaml, and fails unless every test ends as
// docs/operations/conformance.md expects. The Form Post plan of the code
// flow runs when asked for with CONFORMANCE_PLANS.
//
// NOT FOR ANYTHING REAL: the person, the clients and their secrets are made
// here for the run and written to the console.
//
//   HODOR_IMAGE=hodor:conformance docker compose -f deploy/conformance/compose.yaml up --wait
//   (cd deploy/conformance && npm ci && node run.mjs)
//
// The suite's own browser cannot run Hodor's pages, which are a React
// application, so this script is the browser: whenever a test waits for one,
// it opens the addresses the test names in Chromium, signs in on Hodor's
// pages, and takes the screenshot a test asks for when it expects a page of
// Hodor's to show an error.
//
// Environment: CONFORMANCE_ONLY (comma-separated test names, to run only
// those), CONFORMANCE_REPORT (a file to write the results to as JSON),
// CONFORMANCE_PLANS (comma-separated names of PLANS below, to run only
// those; the plans of continuous integration unless given).

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const HERE = dirname(fileURLToPath(import.meta.url));
const COMPOSE_FILE = join(HERE, "compose.yaml");
const EXPECTED = JSON.parse(readFileSync(join(HERE, "expected.json"), "utf8"));

const SUITE = "https://localhost.emobix.co.uk:8443/";
const HODOR = "https://hodor.localhost:8453";
const MAIL = `http://127.0.0.1:${process.env.HODOR_CONFORMANCE_MAIL_PORT ?? "28025"}`;
const TENANT = "conformance";
const ALIAS = "hodor";
const PERSON = "conformance@example.com";
const OPERATOR = "operator@example.com";
const PASSWORD = "conformance-suite-password";
const ISSUER = `${HODOR}/t/${TENANT}`;
const CALLBACK = `${SUITE}test/a/${ALIAS}/callback`;
const POST_LOGOUT = `${SUITE}test/a/${ALIAS}/post_logout_redirect`;
// The suite's back-channel logout address, `test/a/{alias}/backchannel_logout`,
// as the worker reaches it: through the relay of compose.yaml.
const RELAY = "suite-relay:8080";
const BACKCHANNEL_LOGOUT = `http://${RELAY}/test/a/${ALIAS}/backchannel_logout`;
// The sector identifier address of the second pairwise client, answered by
// `sector-document` of compose.yaml with the suite's redirect address. Its
// host is that client's sector.
const SECTOR_DOCUMENT_HOST = "sector-document:8080";
const SECTOR_IDENTIFIER_URI = `http://${SECTOR_DOCUMENT_HOST}/redirect_uris.json`;
const ONLY = (process.env.CONFORMANCE_ONLY ?? "").split(",").filter((name) => name !== "");
// The plans this script can run, by a short name. Continuous integration
// runs the first five; the Form Post plan of the code flow runs when named.
const PLANS = ["basic", "config", "backchannel", "basic-pairwise", "backchannel-pairwise", "formpost-basic"];
const CONTINUOUS_INTEGRATION_PLANS = PLANS.slice(0, 5);
const CHOSEN = (process.env.CONFORMANCE_PLANS ?? CONTINUOUS_INTEGRATION_PLANS.join(","))
  .split(",")
  .filter((name) => name !== "");
for (const name of CHOSEN) {
  if (!PLANS.includes(name)) {
    throw new Error(`no plan is named ${name}; the plans are ${PLANS.join(", ")}`);
  }
}

// Both servers show certificates of their own making.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

function step(message) {
  console.log(`\n== ${message}`);
}

/** Runs `hodor-cli` in the stack, as an operator would. */
function cli(...args) {
  return execFileSync(
    "docker",
    [
      "compose", "-f", COMPOSE_FILE, "run", "--rm", "--no-deps", "-T",
      "--entrypoint", "/usr/local/bin/hodor-cli",
      "-e", "HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor",
      // The back-channel logout address is checked, and the sector
      // identifier address fetched, when the client is made, as the server
      // does it: the relay and the sector document are the exceptions.
      "-e", `HODOR_OUTBOUND_DEVELOPMENT_HOSTS=${RELAY},${SECTOR_DOCUMENT_HOST}`,
      "hodor", ...args,
    ],
    { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] },
  );
}

/** The value after `label` on the line that starts with it, in what `hodor-cli` printed. */
function printed(output, label) {
  const line = output.split("\n").find((candidate) => candidate.startsWith(`${label} `));
  if (line === undefined) {
    throw new Error(`hodor-cli printed no ${label}:\n${output}`);
  }
  return line.split(" ")[1];
}

async function suite(method, path, { query, body } = {}) {
  const url = new URL(path, SUITE);
  for (const [name, value] of Object.entries(query ?? {})) {
    if (value === undefined) {
      continue;
    }
    url.searchParams.set(name, typeof value === "string" ? value : JSON.stringify(value));
  }
  const response = await fetch(url, {
    method,
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(`${method} ${url}: ${response.status} ${await response.text()}`);
  }
  const text = await response.text();
  return text === "" ? null : JSON.parse(text);
}

async function waitForState(module, states, seconds) {
  const until = Date.now() + seconds * 1000;
  for (;;) {
    const answer = await suite("GET", `api/runner/${module}/wait-state`, {
      query: { states: [...states, "INTERRUPTED"].join(","), timeoutMs: "10000" },
    });
    if (answer?.state !== undefined && [...states, "INTERRUPTED"].includes(answer.state)) {
      return answer.state;
    }
    if (Date.now() > until) {
      throw new Error(`test ${module} never reached ${states.join(" or ")}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Hodor: the tenant, the application, its clients and the person.
// ---------------------------------------------------------------------------

function seedHodor() {
  step("A tenant, an application and eight clients in Hodor");
  if (!cli("tenant", "list").split("\n").some((line) => line.includes(` ${TENANT} `) || line.startsWith(`${TENANT} `))) {
    cli("tenant", "create", "--slug", TENANT, "--name", "Conformance", "--open-registration");
  }
  // Until consent exists, only a first-party application gets codes.
  const application = printed(
    cli("application", "add", "--tenant", TENANT, "--name", "OpenID conformance suite", "--first-party"),
    "application",
  );
  const client = (name, method, more = []) => {
    const output = cli(
      "client", "add", "--tenant", TENANT, "--application", application, "--name", name,
      "--type", "confidential", "--method", method, "--without-pkce",
      "--grant", "authorization_code", "--grant", "refresh_token",
      "--redirect-uri", CALLBACK, "--post-logout-redirect-uri", POST_LOGOUT,
      "--scope", "openid", "--scope", "profile", "--scope", "email", "--scope", "offline_access",
      // The suite's request object tests send unsigned objects, which Hodor
      // reads only from a client that chose `none`.
      "--request-object-signing-alg", "none",
      ...more,
    );
    return { client_id: printed(output, "client"), client_secret: printed(output, "secret") };
  };
  // A static client of the suite cannot choose how its ID tokens are
  // signed, so each client is made with one of the four algorithms Hodor
  // offers, and every one of them signs the ID tokens of some client: the
  // suite checks each against the tenant's key set.
  const signedWith = (algorithm) => ["--id-token-algorithm", algorithm];
  return {
    first: client("First client", "client_secret_basic", signedWith("ES256")),
    second: client("Second client", "client_secret_basic", signedWith("RS256")),
    post: client("Client that sends its secret in the form", "client_secret_post", signedWith("PS256")),
    // The back-channel plan's alone: a test of another plan that signs out
    // never gets a logout token it does not wait for.
    backchannel: client("Client told when the session ends", "client_secret_basic", [
      "--backchannel-logout-uri", BACKCHANNEL_LOGOUT, "--backchannel-logout-session-required",
      ...signedWith("PS256"),
    ]),
    // The same four, pairwise, for the plans' second run: each knows the
    // person by an identifier of its sector. The second names a sector
    // identifier address, so its sector is another host than the others'.
    pairwise: {
      first: client("Pairwise first client", "client_secret_basic", [
        "--subject-type", "pairwise", ...signedWith("EdDSA"),
      ]),
      second: client("Pairwise second client", "client_secret_basic", [
        "--subject-type", "pairwise", "--sector-identifier-uri", SECTOR_IDENTIFIER_URI,
        ...signedWith("PS256"),
      ]),
      post: client("Pairwise client that sends its secret in the form", "client_secret_post", [
        "--subject-type", "pairwise", ...signedWith("RS256"),
      ]),
      backchannel: client("Pairwise client told when the session ends", "client_secret_basic", [
        "--subject-type", "pairwise",
        "--backchannel-logout-uri", BACKCHANNEL_LOGOUT, "--backchannel-logout-session-required",
        ...signedWith("EdDSA"),
      ]),
    },
  };
}

async function messageLink(address) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const found = await (await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent(`to:"${address}"`)}`)).json();
    if (found.messages.length > 0) {
      const message = await (await fetch(`${MAIL}/api/v1/message/${found.messages[0].ID}`)).json();
      const link = /https?:\/\/\S+#token=[0-9a-f]+/.exec(message.Text);
      if (link === null) {
        throw new Error(`the message to ${address} carries no link`);
      }
      return link[0];
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`no message reached ${address}`);
}

async function makePerson(browser) {
  step(`The person the suite signs in as: ${PERSON}`);
  const earlier = await (await fetch(`${MAIL}/api/v1/search?query=${encodeURIComponent(`to:"${PERSON}"`)}`)).json();
  if (earlier.messages.length > 0) {
    console.log("made by an earlier run on this stack");
    return;
  }
  // Made by an administrator with a name, so that UserInfo has a profile
  // claim to give; the person then chooses a password through the link
  // that recovering it sends, as any person made this way would.
  const token = printed(cli("admin", "bootstrap", "--tenant", TENANT, "--email", OPERATOR), "token");
  const made = await fetch(`${ISSUER}/api/v1/admin/users`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ email: PERSON, display_name: "Ada Conformance", locale: "en" }),
  });
  if (made.status !== 201) {
    throw new Error(`the administration interface did not make ${PERSON}: ${made.status} ${await made.text()}`);
  }
  const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" });
  const page = await context.newPage();
  await page.goto(`${ISSUER}/account/recover`);
  const email = page.locator('input[type="email"], input[name="email"]').first();
  await email.fill(PERSON);
  await email.press("Enter");
  await page.goto(await messageLink(PERSON));
  const password = page.locator('input[name="password"], input[autocomplete="new-password"]').first();
  await password.fill(PASSWORD);
  await password.press("Enter");
  await page.waitForURL((url) => !url.hash.includes("token="), { timeout: 15_000 });
  await context.close();
}

// ---------------------------------------------------------------------------
// The browser the suite waits for.
// ---------------------------------------------------------------------------

/** Signs in on Hodor's pages until the browser leaves them, or they stop asking. */
async function throughHodor(page) {
  const identifier = page.locator('input[name="identifier"]').first();
  const password = page.locator('input[name="password"]').first();
  let acted = "";
  for (let tick = 0; tick < 60; tick += 1) {
    const url = page.url();
    if (url.startsWith(SUITE)) {
      return "left";
    }
    if (url.startsWith(HODOR)) {
      if (await password.isVisible().catch(() => false)) {
        if (acted !== `password ${url}`) {
          await password.fill(PASSWORD);
          await password.press("Enter");
          acted = `password ${url}`;
        }
      } else if (await identifier.isVisible().catch(() => false)) {
        if (acted !== `identifier ${url}`) {
          await identifier.fill(PERSON);
          await identifier.press("Enter");
          acted = `identifier ${url}`;
        }
      } else if (tick > 10) {
        // A page of Hodor's that asks nothing: an error, or a question the
        // test did not expect to be answered.
        return "stayed";
      }
    }
    await page.waitForTimeout(250);
  }
  return "stayed";
}

/** Uploads a screenshot for every image a test is waiting for. */
async function answerPlaceholders(module, page) {
  const images = (await suite("GET", `api/log/${module}/images`)) ?? [];
  for (const entry of images) {
    if (entry.upload !== undefined && entry.img === undefined) {
      const shot = await page.screenshot({ fullPage: true });
      await suite("POST", `api/log/${module}/images/${entry.upload}`, {
        body: `data:image/png;base64,${shot.toString("base64")}`,
      });
    }
  }
}

async function runModule(plan, entry, browser) {
  const created = await suite("POST", "api/runner", {
    query: { test: entry.testModule, plan, variant: entry.variant ?? {} },
  });
  const module = created.id;
  const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: "en-US" });
  const page = await context.newPage();
  const visited = new Set();
  try {
    let state = await waitForState(module, ["CONFIGURED", "WAITING", "FINISHED"], 120);
    if (state === "CONFIGURED") {
      state = await waitForState(module, ["WAITING", "FINISHED"], 120);
    }
    const until = Date.now() + 300_000;
    while (state !== "FINISHED" && state !== "INTERRUPTED" && Date.now() < until) {
      const browserState = (await suite("GET", `api/runner/browser/${module}`)) ?? {};
      const pending = (browserState.urls ?? []).filter((url) => !visited.has(url));
      for (const url of pending) {
        visited.add(url);
        await page.goto(url, { waitUntil: "domcontentloaded" }).catch(() => {});
        const where = await throughHodor(page);
        if (where === "left") {
          // The suite's page that takes the answer back to the suite.
          await page.locator("#submission_complete").waitFor({ timeout: 20_000 }).catch(() => {});
        }
        await answerPlaceholders(module, page);
      }
      await answerPlaceholders(module, page);
      const info = await suite("GET", `api/info/${module}`);
      state = info.status;
      if (state !== "FINISHED" && state !== "INTERRUPTED") {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
  } finally {
    await context.close();
  }
  const info = await suite("GET", `api/info/${module}`);
  return { name: entry.testModule, module, status: info.status, result: info.result };
}

async function runPlan(name, config, variant, browser, label = name) {
  step(`Plan ${label}`);
  const plan = await suite("POST", "api/plan", { query: { planName: name, variant }, body: config });
  const results = [];
  for (const entry of plan.modules) {
    if (ONLY.length > 0 && !ONLY.includes(entry.testModule)) {
      continue;
    }
    const result = await runModule(plan.id, entry, browser);
    console.log(`${result.result ?? result.status}\t${result.name}\t${SUITE}log-detail.html?log=${result.module}`);
    results.push({ plan: label, ...result });
  }
  return results;
}

// ---------------------------------------------------------------------------

/** The suite takes a minute or two to start; `up --wait` cannot tell. */
async function suiteReady() {
  step("Waiting for the suite to answer");
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const ready = await fetch(new URL("api/runner/available", SUITE)).then((r) => r.ok, () => false);
    if (ready) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 2500));
  }
  throw new Error("the suite never answered");
}

async function main() {
  await suiteReady();
  const clients = seedHodor();
  const browser = await chromium.launch();
  try {
    await makePerson(browser);
    const config = {
      alias: ALIAS,
      description: "Hodor",
      server: { discoveryUrl: `${ISSUER}/.well-known/openid-configuration` },
      client: clients.first,
      client2: clients.second,
      // A Hodor client proves who it is in the one way it was registered
      // with; the suite takes the client of the test that sends the secret
      // in the form from here.
      client_secret_post: clients.post,
    };
    const plans = {
      basic: () => runPlan("oidcc-basic-certification-test-plan", config,
        { server_metadata: "discovery", client_registration: "static_client" }, browser),
      // This plan sets its own variants.
      config: () => runPlan("oidcc-config-certification-test-plan", config, undefined, browser),
      // The client of this plan is the one with a back-channel logout
      // address; the plan sets the rest of its variants.
      backchannel: () => runPlan("oidcc-backchannel-rp-initiated-logout-certification-test-plan",
        { ...config, client: clients.backchannel, client2: undefined, client_secret_post: undefined },
        { client_registration: "static_client", response_type: "code" }, browser),
      // The pairwise configuration, the acceptance of Issue-98: the same
      // plans with clients that know the person by an identifier of their
      // sector. The suite checks that UserInfo, a second sign-in and the
      // logout token give the `sub` and `sid` of the ID token.
      "basic-pairwise": () => runPlan("oidcc-basic-certification-test-plan",
        { ...config, client: clients.pairwise.first, client2: clients.pairwise.second,
          client_secret_post: clients.pairwise.post },
        { server_metadata: "discovery", client_registration: "static_client" }, browser,
        "oidcc-basic-certification-test-plan (pairwise)"),
      "backchannel-pairwise": () => runPlan(
        "oidcc-backchannel-rp-initiated-logout-certification-test-plan",
        { ...config, client: clients.pairwise.backchannel, client2: undefined,
          client_secret_post: undefined },
        { client_registration: "static_client", response_type: "code" }, browser,
        "oidcc-backchannel-rp-initiated-logout-certification-test-plan (pairwise)"),
      // Issue-129: the code flow of the Basic plan, every answer posted by
      // Hodor's page of `form_post`. The Implicit and Hybrid flows follow
      // their response types (Issues 127 and 128).
      "formpost-basic": () => runPlan("oidcc-formpost-basic-certification-test-plan", config,
        { server_metadata: "discovery", client_registration: "static_client" }, browser),
    };
    const results = [];
    for (const name of PLANS.filter((plan) => CHOSEN.includes(plan))) {
      results.push(...(await plans[name]()));
    }
    if (process.env.CONFORMANCE_REPORT) {
      writeFileSync(process.env.CONFORMANCE_REPORT, JSON.stringify(results, null, 2));
    }

    step("Results");
    const unexpected = [];
    for (const result of results) {
      const outcome = result.status === "FINISHED" ? result.result : result.status;
      const allowed = ["PASSED", ...Object.keys(EXPECTED[result.name] ?? {})];
      const mark = allowed.includes(outcome) ? "ok" : "UNEXPECTED";
      console.log(`${mark}\t${outcome}\t${result.plan}\t${result.name}`);
      if (mark !== "ok") {
        unexpected.push(result);
      }
    }
    if (unexpected.length > 0) {
      console.log(`\n${unexpected.length} tests did not end as docs/operations/conformance.md expects.`);
      process.exitCode = 1;
    }
  } finally {
    await browser.close();
  }
}

await main();
