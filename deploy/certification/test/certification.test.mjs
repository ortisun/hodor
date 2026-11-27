// The test of certification.mjs: `make` then `retire`, against a stand-in
// for `hodor-cli` (fake-hodor-cli.mjs) and a stand-in for Hodor and its
// mail server, served here, which share what was made through one file.
// docs/operations/certification-deployment.md, "How it is tested".
//
//   node --test deploy/certification/test/certification.test.mjs

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { readPlans } from "../certification.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, "..", "certification.mjs");
const PLANS = JSON.parse(readFileSync(join(HERE, "..", "plans.json"), "utf8"));
const SUITE = "https://www.certification.openid.net";

/** Hodor as the script sees it, over what the stand-in for `hodor-cli` made. */
function standIn(statePath) {
  const read = () => JSON.parse(readFileSync(statePath, "utf8"));
  const write = (state) => writeFileSync(statePath, JSON.stringify(state, null, 2));
  const answer = (response, status, body) => {
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify(body));
  };
  const body = (request) => new Promise((done) => {
    let text = "";
    request.on("data", (chunk) => { text += chunk; });
    request.on("end", () => done(text));
  });
  return createServer(async (request, response) => {
    const base = `http://${request.headers.host}`;
    const url = new URL(request.url, base);
    const state = read();
    if (url.pathname === "/mail/api/v1/search") {
      const to = /to:"([^"]+)"/.exec(url.searchParams.get("query"))[1];
      const messages = state.mail.filter((message) => message.to === to).reverse();
      return answer(response, 200, { messages: messages.map((message) => ({ ID: message.id })) });
    }
    const message = /^\/mail\/api\/v1\/message\/(.+)$/.exec(url.pathname);
    if (message !== null) {
      return answer(response, 200, { Text: state.mail.find((candidate) => candidate.id === message[1]).text });
    }
    const route = /^\/t\/([^/]+)(\/.*)$/.exec(url.pathname);
    if (route === null) {
      return answer(response, 404, { code: "route.not_found" });
    }
    const [, slug, path] = route;
    if (slug === "system" && path === "/.well-known/openid-configuration") {
      return answer(response, 200, { issuer: `${base}/t/system` });
    }
    const tenant = state.tenants[slug];
    if (tenant === undefined) {
      return answer(response, 404, { code: "tenant.not_found" });
    }
    if (tenant.status === "suspended") {
      return answer(response, 403, { code: "tenant.suspended" });
    }
    const issuer = `${base}/t/${slug}`;
    if (path === "/.well-known/openid-configuration") {
      return answer(response, 200, {
        issuer, token_endpoint: `${issuer}/oauth2/token`, jwks_uri: `${issuer}/oauth2/jwks`,
      });
    }
    if (path === "/oauth2/jwks") {
      return answer(response, 200, {
        keys: tenant.keys.filter((key) => key.status !== "revoked").map((key) => ({ kid: key.id, alg: key.algorithm })),
      });
    }
    if (path === "/api/v1/admin/users" && request.method === "POST") {
      const token = (request.headers.authorization ?? "").replace(/^Bearer /, "");
      if (tenant.admins[token] === undefined) {
        return answer(response, 401, { code: "auth.unauthorized" });
      }
      const user = JSON.parse(await body(request));
      tenant.users[user.email] = { ...user };
      write(state);
      return answer(response, 201, { id: user.email });
    }
    if (path === "/interaction/recovery" && request.method === "POST") {
      const { email } = JSON.parse(await body(request));
      const token = randomBytes(16).toString("hex");
      if (tenant.users[email] !== undefined) {
        tenant.users[email].recovery = token;
        state.mail.push({
          id: randomBytes(8).toString("hex"), to: email,
          text: `Choose a new password: ${issuer}/account/recover#token=${token}\n`,
        });
      }
      write(state);
      return answer(response, 202, { status: "accepted" });
    }
    if (path === "/interaction/recovery/complete" && request.method === "POST") {
      const { token, password } = JSON.parse(await body(request));
      const user = Object.values(tenant.users).find((candidate) => candidate.recovery === token);
      if (user === undefined) {
        return answer(response, 400, { code: "account.token_invalid" });
      }
      user.password = password;
      delete user.recovery;
      write(state);
      return answer(response, 200, { status: "done" });
    }
    if (path === "/oauth2/token" && request.method === "POST") {
      const form = new URLSearchParams(await body(request));
      let id = form.get("client_id");
      let secret = form.get("client_secret");
      const basic = /^Basic (.+)$/.exec(request.headers.authorization ?? "");
      if (basic !== null) {
        [id, secret] = Buffer.from(basic[1], "base64").toString().split(":").map(decodeURIComponent);
      }
      const client = tenant.clients[id];
      if (client === undefined || client.secret !== secret || !client.enabled
        || !tenant.applications[client.application].enabled) {
        return answer(response, 401, { error: "invalid_client" });
      }
      return answer(response, 400, { error: "invalid_grant" });
    }
    return answer(response, 404, { code: "route.not_found" });
  });
}

/** Runs the script and gives back what it printed and how it ended. */
function run(command, environment) {
  return new Promise((done) => {
    const child = spawn(process.execPath, [SCRIPT, command], {
      env: { ...process.env, ...environment }, stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("close", (status) => done({ status, stdout, stderr }));
  });
}

/** A stand-in deployment: its folder, the shared state, the server, and the script's settings. */
async function deployment(plans = PLANS) {
  const folder = mkdtempSync(join(tmpdir(), "hodor-certification-"));
  const statePath = join(folder, "hodor.json");
  writeFileSync(statePath, JSON.stringify({ calls: [], tenants: {}, mail: [] }));
  const plansFile = join(folder, "plans.json");
  writeFileSync(plansFile, JSON.stringify(plans));
  const server = standIn(statePath);
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  const base = `http://127.0.0.1:${server.address().port}`;
  const environment = {
    HODOR_PUBLIC_URL: base,
    CERTIFICATION_MAIL_URL: `${base}/mail`,
    CERTIFICATION_OUTPUT: join(folder, "output"),
    CERTIFICATION_PLANS_FILE: plansFile,
    CERTIFICATION_ENV_FILE: join(folder, "no.env"),
    CERTIFICATION_CLI: JSON.stringify([process.execPath, join(HERE, "fake-hodor-cli.mjs")]),
    FAKE_HODOR_STATE: statePath,
  };
  return {
    folder, base, environment,
    hodor: () => JSON.parse(readFileSync(statePath, "utf8")),
    close: () => new Promise((done) => server.close(done)),
  };
}

/** Every run of every plan of plans.json, by the name the script gives it. */
function everyRun(plans) {
  return plans.plans.flatMap((plan) => (plan.eachResponseType
    ? plans.allResponseTypes.map((type) => `${plan.plan} ${type}`)
    : [plan.plan]));
}
/** The name `everyRun` gives a run the script printed. */
function runName(entry) {
  const plan = PLANS.plans.find((candidate) => candidate.plan === entry.plan);
  return plan.eachResponseType ? `${entry.plan} ${entry.variant.response_type}` : entry.plan;
}

describe("the certification script, as plans.json stands", () => {
  let stand;
  let made;
  let printed;

  before(async () => {
    stand = await deployment();
    made = await run("make", stand.environment);
    assert.equal(made.status, 0, made.stderr);
    printed = JSON.parse(made.stdout);
  });
  after(async () => {
    await stand.close();
    rmSync(stand.folder, { recursive: true, force: true });
  });

  it("prints one JSON document and nothing else", () => {
    assert.equal(made.stdout.trim().startsWith("{"), true);
    assert.deepEqual(Object.keys(printed).sort(), ["alias", "person", "plans", "suite", "version", "waiting"]);
    assert.equal(printed.suite, SUITE);
    assert.match(printed.alias, /^hodor-[0-9a-f]{8}$/);
    assert.equal(printed.version, "0.5.0-test");
  });

  it("names every run of every plan, ready or waiting", () => {
    const named = [...printed.plans, ...printed.waiting].map(runName).sort();
    assert.deepEqual(named, everyRun(PLANS).sort());
  });

  it("has the plans built on develop ready, and nothing else", () => {
    assert.deepEqual(printed.plans.map(runName).sort(), [
      "oidcc-backchannel-rp-initiated-logout-certification-test-plan code",
      "oidcc-basic-certification-test-plan",
      "oidcc-config-certification-test-plan",
      "oidcc-formpost-basic-certification-test-plan",
      "oidcc-rp-initiated-logout-certification-test-plan code",
    ]);
  });

  it("says what each waiting plan waits for", () => {
    for (const entry of printed.waiting) {
      assert.ok(entry.waitingFor.length > 0, entry.plan);
      for (const reason of entry.waitingFor) {
        assert.match(reason, /^Issue-\d+(, pull request \d+)?: .+/);
      }
    }
    const implicit = printed.waiting.find((entry) => entry.plan === "oidcc-implicit-certification-test-plan");
    assert.deepEqual(implicit.waitingFor, [
      "Issue-127, pull request 178: an ID token through the browser",
      "Issue-128: an access token through the browser",
    ]);
  });

  it("gives every ready plan a complete configuration, written to its file", async () => {
    const hodor = stand.hodor();
    for (const entry of printed.plans) {
      const plan = PLANS.plans.find((candidate) => candidate.plan === entry.plan);
      const configuration = entry.configuration;
      assert.equal(configuration.alias, printed.alias);
      assert.match(configuration.description, new RegExp(`^Hodor 0\\.5\\.0-test, ${entry.profile}`));
      const discovery = await fetch(configuration.server.discoveryUrl);
      assert.equal(discovery.status, 200, configuration.server.discoveryUrl);
      assert.equal(configuration.server.discoveryUrl, `${stand.base}/t/${plan.tenant}/.well-known/openid-configuration`);
      assert.deepEqual(
        Object.keys(configuration).sort(),
        ["alias", "description", "server", ...Object.keys(plan.clients)].sort(),
      );
      for (const field of Object.keys(plan.clients)) {
        const client = hodor.tenants[plan.tenant].clients[configuration[field].client_id];
        assert.ok(client, `${entry.plan} ${field}`);
        assert.equal(configuration[field].client_secret, client.secret);
        assert.ok(client.redirectUris.includes(`${SUITE}/test/a/${printed.alias}/callback`));
        assert.ok(client.postLogoutRedirectUris.includes(`${SUITE}/test/a/${printed.alias}/post_logout_redirect`));
        assert.equal(client.withoutPkce, true);
      }
      for (const [name, value] of Object.entries(plan.variant)) {
        assert.equal(entry.variant[name], value);
      }
      const file = JSON.parse(readFileSync(join(stand.environment.CERTIFICATION_OUTPUT, entry.file), "utf8"));
      assert.deepEqual(file, configuration);
    }
  });

  it("makes the person with a password the owner signs in with", () => {
    const person = stand.hodor().tenants.certification.users[printed.person.email];
    assert.equal(printed.person.email, "certification@example.com");
    assert.equal(person.password, printed.person.password);
    assert.ok(printed.person.password.length >= 24);
    assert.equal(person.claims.given_name, "Ada");
  });

  it("makes no tenant, client or option for a feature not built", () => {
    const hodor = stand.hodor();
    assert.deepEqual(Object.keys(hodor.tenants), ["certification"]);
    const names = Object.values(hodor.tenants.certification.clients).map((client) => client.name).sort();
    assert.deepEqual(names, [
      "Client that sends its secret in the form", "Client that signs out", "Client told through the back channel",
      "First client", "Second client",
    ]);
    const flags = hodor.calls.flat();
    assert.equal(flags.includes("--response-type"), false);
    assert.equal(flags.includes("--frontchannel-logout-uri"), false);
    const backchannel = Object.values(hodor.tenants.certification.clients)
      .find((client) => client.backchannelLogoutUri !== undefined);
    assert.equal(backchannel.backchannelLogoutUri, `${SUITE}/test/a/${printed.alias}/backchannel_logout`);
  });

  it("refuses to make the deployment twice", async () => {
    const again = await run("make", stand.environment);
    assert.equal(again.status, 1);
    assert.match(again.stderr, /made already/);
  });

  it("retires everything it made, after which nothing of it works", async () => {
    const retired = await run("retire", stand.environment);
    assert.equal(retired.status, 0, retired.stderr);
    const report = JSON.parse(retired.stdout);
    assert.deepEqual(report.retired, ["certification"]);
    assert.ok(report.checks.length > 0);
    assert.ok(report.checks.every((check) => check.held), JSON.stringify(report.checks));

    const hodor = stand.hodor();
    const tenant = hodor.tenants.certification;
    assert.equal(tenant.status, "suspended");
    assert.ok(Object.values(tenant.clients).every((client) => !client.enabled));
    assert.ok(Object.values(tenant.applications).every((application) => !application.enabled));
    assert.ok(tenant.keys.every((key) => key.status === "revoked"));
    for (const entry of printed.plans) {
      const discovery = await fetch(entry.configuration.server.discoveryUrl);
      assert.equal(discovery.status, 403);
    }
  });
});

describe("the certification script, once more features are built", () => {
  it("turns a plan on with one line of plans.json", async () => {
    const plans = structuredClone(PLANS);
    plans.features["id-token-through-the-browser"].built = true;
    plans.features["front-channel-logout"].built = true;
    const stand = await deployment(plans);
    try {
      const made = await run("make", stand.environment);
      assert.equal(made.status, 0, made.stderr);
      const printed = JSON.parse(made.stdout);
      const ready = printed.plans.map(runName);
      for (const type of ["code", "id_token", "code id_token"]) {
        assert.ok(ready.includes(`oidcc-rp-initiated-logout-certification-test-plan ${type}`), type);
        assert.ok(ready.includes(`oidcc-backchannel-rp-initiated-logout-certification-test-plan ${type}`), type);
        assert.ok(ready.includes(`oidcc-frontchannel-rp-initiated-logout-certification-test-plan ${type}`), type);
      }
      // The Implicit and Hybrid plans also need an access token through the browser.
      assert.ok(!ready.includes("oidcc-implicit-certification-test-plan"));
      assert.ok(!ready.includes(`oidcc-rp-initiated-logout-certification-test-plan id_token token`));

      const clients = Object.values(stand.hodor().tenants.certification.clients);
      assert.ok(clients.every((client) => client.responseTypes.join(",") === "code,id_token,code id_token"));
      const frontchannel = clients.find((client) => client.frontchannelLogoutUri !== undefined);
      assert.equal(frontchannel.frontchannelLogoutUri, `${SUITE}/test/a/${printed.alias}/frontchannel_logout`);
      const entry = printed.plans.find((candidate) => runName(candidate)
        === "oidcc-frontchannel-rp-initiated-logout-certification-test-plan id_token");
      assert.equal(entry.variant.response_type, "id_token");
      assert.equal(entry.configuration.client.client_id, Object.entries(stand.hodor().tenants.certification.clients)
        .find(([, client]) => client.frontchannelLogoutUri !== undefined)[0]);
    } finally {
      await stand.close();
      rmSync(stand.folder, { recursive: true, force: true });
    }
  });

  it("makes the tenant of registration, and turns registration off when retiring", async () => {
    const plans = structuredClone(PLANS);
    plans.features["registration-endpoint"].built = true;
    plans.features["registration-management"].built = true;
    const stand = await deployment(plans);
    try {
      const made = await run("make", stand.environment);
      assert.equal(made.status, 0, made.stderr);
      const printed = JSON.parse(made.stdout);
      const third = printed.plans.find((entry) => entry.plan === "oidcc-3rdparty-init-login-certification-test-plan");
      assert.deepEqual(Object.keys(third.configuration).sort(), ["alias", "description", "server"]);
      const registration = stand.hodor().calls.find((call) => call[0] === "client-registration");
      assert.ok(registration.includes("www.certification.openid.net"));
      assert.equal(stand.hodor().tenants["certification-dynamic"].registration, "on");
      assert.equal(stand.hodor().tenants["certification-dynamic"].applications[
        registration[registration.indexOf("--application") + 1]].firstParty, false);

      const retired = await run("retire", stand.environment);
      assert.equal(retired.status, 0, retired.stderr);
      assert.equal(stand.hodor().tenants["certification-dynamic"].registration, "off");
      assert.equal(stand.hodor().tenants["certification-dynamic"].status, "suspended");
    } finally {
      await stand.close();
      rmSync(stand.folder, { recursive: true, force: true });
    }
  });

  it("fails the retirement when something still works", async () => {
    const stand = await deployment();
    try {
      assert.equal((await run("make", stand.environment)).status, 0);
      // A `hodor-cli` that changes nothing: every check must catch it.
      const nothing = JSON.stringify([process.execPath, "-e", "process.stdout.write('')"]);
      const retired = await run("retire", { ...stand.environment, CERTIFICATION_CLI: nothing });
      assert.equal(retired.status, 1);
      const report = JSON.parse(retired.stdout);
      assert.ok(report.checks.every((check) => !check.held), JSON.stringify(report.checks));
    } finally {
      await stand.close();
      rmSync(stand.folder, { recursive: true, force: true });
    }
  });
});

describe("reading plans.json", () => {
  it("refuses a feature it does not name", () => {
    const plans = structuredClone(PLANS);
    plans.plans[0].needs = ["teleportation"];
    assert.throws(() => readPlans(plans), /needs teleportation/);
  });
});
