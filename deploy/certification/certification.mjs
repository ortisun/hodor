// The certification deployment: makes, through `hodor-cli`, the tenants,
// clients and person every plan of the OpenID Foundation's hosted suite
// needs, prints the configuration to paste into the suite, and afterwards
// retires all of it. docs/operations/certification-deployment.md is the
// runbook.
//
//   node deploy/certification/certification.mjs make
//   node deploy/certification/certification.mjs retire
//
// `make` prints one JSON document on the standard output and nothing else:
// the configuration of every plan whose features are built, and the plans
// that wait, with what they wait for. What it is doing goes to the standard
// error. It writes a file per plan, and what it made, secrets included, to
// the output folder, which `retire` reads.
//
// `retire` disables every client and application it made, runs each
// tenant's retire commands, revokes every signing key, suspends the
// tenants, and checks that nothing it made still works. It ends in failure
// when a check does not hold.
//
// Which plans are ready is read from plans.json alone: a plan, a client or
// a tenant that needs a feature not built is left out and listed as
// waiting. Needs Node.js 24 and no package.
//
// Settings, from the environment or from deploy/certification/.env:
// HODOR_PUBLIC_URL (required), CERTIFICATION_SUITE_URL, CERTIFICATION_ALIAS,
// CERTIFICATION_PERSON_EMAIL, CERTIFICATION_MAIL_URL, CERTIFICATION_OUTPUT,
// CERTIFICATION_CLI (a JSON array), CERTIFICATION_ACCEPT_ANY_CERTIFICATE,
// CERTIFICATION_PLANS_FILE and CERTIFICATION_ENV_FILE.

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..");
const OPERATOR = "certification-operator@example.com";
const SCOPES = ["openid", "profile", "email", "address", "phone", "offline_access"];

function log(message) {
  process.stderr.write(`${message}\n`);
}

/** `KEY=value` lines of an environment file; comments and blank lines skipped. */
function readEnvironmentFile(path) {
  const values = {};
  if (!existsSync(path)) {
    return values;
  }
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const match = /^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (match !== null && !line.trimStart().startsWith("#")) {
      values[match[1]] = match[2].replace(/^(["'])(.*)\1$/, "$2");
    }
  }
  return values;
}

function readSettings() {
  const envFile = process.env.CERTIFICATION_ENV_FILE ?? join(HERE, ".env");
  const fromFile = readEnvironmentFile(envFile);
  const get = (name, fallback) => process.env[name] ?? fromFile[name] ?? fallback;
  const publicUrl = get("HODOR_PUBLIC_URL");
  if (publicUrl === undefined || publicUrl === "") {
    throw new Error(`HODOR_PUBLIC_URL is not set, in the environment or in ${envFile}`);
  }
  const defaultCli = [
    "docker", "compose", "--env-file", envFile,
    "-f", join(ROOT, "deploy/install/docker/compose.yaml"), "-f", join(HERE, "compose.yaml"),
    "run", "--rm", "-T", "cli",
  ];
  const cli = process.env.CERTIFICATION_CLI === undefined ? defaultCli : JSON.parse(process.env.CERTIFICATION_CLI);
  if (!Array.isArray(cli) || cli.length === 0 || !cli.every((part) => typeof part === "string")) {
    throw new Error("CERTIFICATION_CLI must be a JSON array of strings");
  }
  return {
    publicUrl: publicUrl.replace(/\/+$/, ""),
    suite: get("CERTIFICATION_SUITE_URL", "https://www.certification.openid.net").replace(/\/+$/, ""),
    alias: get("CERTIFICATION_ALIAS"),
    personEmail: get("CERTIFICATION_PERSON_EMAIL", "certification@example.com"),
    mail: get("CERTIFICATION_MAIL_URL", "http://127.0.0.1:8025").replace(/\/+$/, ""),
    output: resolve(get("CERTIFICATION_OUTPUT", join(HERE, "output"))),
    plansFile: get("CERTIFICATION_PLANS_FILE", join(HERE, "plans.json")),
    cli,
  };
}

// ---------------------------------------------------------------------------
// What plans.json says is ready, and what waits.
// ---------------------------------------------------------------------------

/** Reads plans.json and answers which runs, clients and tenants are ready. */
export function readPlans(document) {
  const features = document.features;
  const check = (names, where) => {
    for (const name of names) {
      if (features[name] === undefined) {
        throw new Error(`${where} needs ${name}, which plans.json does not name among its features`);
      }
    }
    return names;
  };
  const built = (name) => features[name].built === true;
  const describe = (name) => {
    const feature = features[name];
    const pull = feature.pullRequest === undefined ? "" : `, pull request ${feature.pullRequest}`;
    return `${feature.issue}${pull}: ${feature.what}`;
  };
  for (const [type, needs] of Object.entries(document.responseTypes)) {
    check(needs, `the response type ${type}`);
  }
  const tenantNeeds = (slug) => {
    const tenant = document.tenants[slug];
    if (tenant === undefined) {
      throw new Error(`plans.json names no tenant ${slug}`);
    }
    return check(tenant.needs ?? [], `the tenant ${slug}`);
  };
  const clientNeeds = (key) => {
    const client = document.clients[key];
    if (client === undefined) {
      throw new Error(`plans.json names no client ${key}`);
    }
    return [...tenantNeeds(client.tenant), ...check(client.needs ?? [], `the client ${key}`)];
  };
  // A client registers every response type whose features are built.
  const responseTypes = document.allResponseTypes.filter((type) => document.responseTypes[type].every(built));

  const ready = [];
  const waiting = [];
  for (const plan of document.plans) {
    const needs = [
      ...check(plan.needs ?? [], `the plan ${plan.name}`),
      ...tenantNeeds(plan.tenant),
      ...Object.values(plan.clients).flatMap(clientNeeds),
    ];
    const runs = plan.eachResponseType
      ? document.allResponseTypes.map((type) => ({
        type, needs: [...needs, ...document.responseTypes[type]],
        variant: { ...plan.variant, response_type: type },
      }))
      : [{ type: undefined, needs, variant: plan.variant }];
    for (const run of runs) {
      const entry = {
        name: run.type === undefined ? plan.name : `${plan.name}-${run.type.replaceAll(" ", "-")}`,
        profile: plan.profile,
        plan: plan.plan,
        tenant: plan.tenant,
        variant: run.variant,
        clients: plan.clients,
      };
      const missing = [...new Set(run.needs)].filter((name) => !built(name));
      if (missing.length === 0) {
        ready.push(entry);
      } else {
        waiting.push({ ...entry, waitingFor: missing.map(describe) });
      }
    }
  }
  const tenants = [...new Set(ready.map((entry) => entry.tenant))];
  const clients = [...new Set(ready.flatMap((entry) => Object.values(entry.clients)))];
  // The arguments a client needs for the response types it registers, such
  // as the mark of Issue-128.
  const typeArguments = [...new Set(responseTypes.flatMap((type) => document.responseTypes[type]))]
    .flatMap((name) => features[name].clientArguments ?? []);
  const tenantCommands = (slug) => [
    ...(document.tenants[slug].commands ?? []),
    ...tenantNeeds(slug).flatMap((name) => features[name].tenantCommands ?? []),
  ];
  return { ready, waiting, tenants, clients, responseTypes, typeArguments, tenantCommands };
}

/**
 * Replaces an argument that is exactly `{responseTypes}` with
 * `--response-type <type>` for each response type that is built; with
 * nothing when `code` alone is, which is every command's default.
 */
export function withResponseTypes(argumentsList, responseTypes) {
  const named = responseTypes.length > 1 ? responseTypes.flatMap((type) => ["--response-type", type]) : [];
  return argumentsList.flatMap((argument) => (argument === "{responseTypes}" ? named : [argument]));
}

/** Replaces `{name}` in each argument with its value. */
function fill(argumentsList, values) {
  return argumentsList.map((argument) =>
    argument.replace(/\{([a-zA-Z]+)\}/g, (whole, name) => {
      if (values[name] === undefined) {
        throw new Error(`no value for ${whole} in ${argument}`);
      }
      return values[name];
    }));
}

// ---------------------------------------------------------------------------
// Hodor.
// ---------------------------------------------------------------------------

function makeCli(settings) {
  return (...args) => {
    log(`  hodor-cli ${args.join(" ")}`);
    return execFileSync(settings.cli[0], [...settings.cli.slice(1), ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
    });
  };
}

/** The first word after `label` on the line that starts with it, in what `hodor-cli` printed. */
function printed(output, label) {
  const line = output.split("\n").find((candidate) => candidate.startsWith(`${label} `));
  if (line === undefined) {
    throw new Error(`hodor-cli printed no ${label}:\n${output}`);
  }
  return line.slice(label.length + 1).trim().split(" ")[0];
}

async function getJson(url) {
  const response = await fetch(url);
  if (response.status !== 200) {
    throw new Error(`GET ${url}: ${response.status} ${await response.text()}`);
  }
  return response.json();
}

async function postJson(url, body, headers = {}) {
  return fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

/** The link of the newest message to `address` that leads into `slug`. */
async function messageLink(settings, address, slug) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const query = encodeURIComponent(`to:"${address}"`);
    const found = await getJson(`${settings.mail}/api/v1/search?query=${query}`);
    for (const summary of found.messages ?? []) {
      const message = await getJson(`${settings.mail}/api/v1/message/${summary.ID}`);
      const link = /https?:\/\/\S+#token=([0-9A-Za-z_-]+)/.exec(message.Text ?? "");
      if (link !== null && link[0].includes(`/t/${slug}/`)) {
        return link[1];
      }
    }
    await new Promise((done) => setTimeout(done, 500));
  }
  throw new Error(`no message with a link into ${slug} reached ${address}`);
}

/** The person the owner signs in as, made by an administrator, with every standard claim and a password. */
async function makePerson(settings, cli, slug, issuer, person) {
  log(`The person ${person.email} in ${slug}`);
  const token = printed(cli("admin", "bootstrap", "--tenant", slug, "--email", OPERATOR), "token");
  const made = await postJson(
    `${issuer}/api/v1/admin/users`,
    { email: person.email, username: "ada", display_name: "Ada Certification", locale: "en" },
    { authorization: `Bearer ${token}` },
  );
  if (made.status !== 201) {
    throw new Error(`the administration interface did not make ${person.email}: ${made.status} ${await made.text()}`);
  }
  cli(
    "user", "claims", "--tenant", slug, "--user", person.email,
    "--given-name", "Ada", "--middle-name", "Augusta", "--family-name", "Certification",
    "--nickname", "Ada", "--gender", "female", "--birthdate", "1990-12-10",
    "--zoneinfo", "Europe/London", "--profile", "https://ada.example.com/profile",
    "--picture", "https://ada.example.com/picture.png", "--website", "https://ada.example.com",
    "--phone-number", "+44 20 7946 0000", "--phone-number-verified", "true",
    "--street-address", "12 St James's Square", "--locality", "London", "--region", "England",
    "--postal-code", "SW1Y 4JH", "--country", "GB",
    "--formatted-address", "12 St James's Square, London SW1Y 4JH, United Kingdom",
  );
  // The password is set as any person made this way sets it: through the
  // link recovery sends, read from the mail server that delivers nothing.
  const asked = await postJson(`${issuer}/interaction/recovery`, { email: person.email, locale: "en" });
  if (!asked.ok) {
    throw new Error(`recovery was not asked for ${person.email}: ${asked.status} ${await asked.text()}`);
  }
  const link = await messageLink(settings, person.email, slug);
  const set = await postJson(`${issuer}/interaction/recovery/complete`, { token: link, password: person.password });
  if (!set.ok) {
    throw new Error(`the password of ${person.email} was not set: ${set.status} ${await set.text()}`);
  }
}

// ---------------------------------------------------------------------------
// make
// ---------------------------------------------------------------------------

function saveState(settings, state) {
  mkdirSync(settings.output, { recursive: true, mode: 0o700 });
  const path = join(settings.output, "state.json");
  writeFileSync(path, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
}

async function make(settings) {
  const statePath = join(settings.output, "state.json");
  if (existsSync(statePath)) {
    throw new Error(`${statePath} exists: this deployment was made already. Retire it, reset it and remove the folder to start again`);
  }
  const document = JSON.parse(readFileSync(settings.plansFile, "utf8"));
  const plans = readPlans(document);
  const cli = makeCli(settings);

  log(`Hodor at ${settings.publicUrl}`);
  // Hodor answers whatever the tenant: the discovery document, or its own
  // problem in JSON. Anything else is another server, or none.
  const probe = await fetch(`${settings.publicUrl}/t/system/.well-known/openid-configuration`);
  const answered = await probe.json().catch(() => ({}));
  if (probe.status !== 200 && typeof answered.code !== "string") {
    throw new Error(`Hodor does not answer at ${settings.publicUrl}: ${probe.status}`);
  }
  const version = printed(cli("--version"), "hodor-cli");
  const alias = settings.alias ?? `hodor-${randomBytes(4).toString("hex")}`;
  const values = { suite: settings.suite, suiteHost: new URL(settings.suite).host, alias };
  const state = {
    publicUrl: settings.publicUrl,
    suite: settings.suite,
    alias,
    version,
    person: { email: settings.personEmail, password: randomBytes(24).toString("base64url") },
    tenants: {},
  };

  const existing = cli("tenant", "list").split("\n").map((line) => line.split(" ")[0]);
  for (const slug of plans.tenants) {
    if (existing.includes(slug)) {
      throw new Error(`the tenant ${slug} exists already: reset the deployment before making it again`);
    }
  }

  for (const slug of plans.tenants) {
    const tenant = document.tenants[slug];
    log(`The tenant ${slug}`);
    cli("tenant", "create", "--slug", slug, "--name", tenant.name);
    const issuer = `${settings.publicUrl}/t/${slug}`;
    const made = { issuer, clients: {}, retireCommands: [] };
    state.tenants[slug] = made;
    saveState(settings, state);

    made.application = printed(
      cli("application", "add", "--tenant", slug, "--name", tenant.application.name,
        ...(tenant.application.firstParty ? ["--first-party"] : [])),
      "application",
    );
    const tenantValues = { ...values, tenant: slug, application: made.application };
    made.retireCommands = (tenant.retireCommands ?? []).map((command) => fill(command, tenantValues));
    saveState(settings, state);
    for (const command of plans.tenantCommands(slug)) {
      cli(...fill(withResponseTypes(command, plans.responseTypes), tenantValues));
    }

    for (const key of plans.clients.filter((name) => document.clients[name].tenant === slug)) {
      const client = document.clients[key];
      const output = cli(
        "client", "add", "--tenant", slug, "--application", made.application, "--name", client.name,
        "--type", "confidential", "--method", client.method, "--without-pkce",
        "--grant", "authorization_code", "--grant", "refresh_token",
        "--redirect-uri", `${settings.suite}/test/a/${alias}/callback`,
        "--post-logout-redirect-uri", `${settings.suite}/test/a/${alias}/post_logout_redirect`,
        ...SCOPES.flatMap((scope) => ["--scope", scope]),
        // The suite's request object tests send unsigned objects, which
        // Hodor reads only from a client that chose `none`.
        "--request-object-signing-alg", "none",
        // `code` alone is the default, and the option exists only once
        // another response type is built.
        ...withResponseTypes(["{responseTypes}"], plans.responseTypes),
        ...plans.typeArguments,
        ...fill(client.arguments ?? [], tenantValues),
      );
      made.clients[key] = {
        client_id: printed(output, "client"),
        client_secret: printed(output, "secret"),
        method: client.method,
      };
      saveState(settings, state);
    }

    await makePerson(settings, cli, slug, issuer, state.person);
    const discovery = await getJson(`${issuer}/.well-known/openid-configuration`);
    made.tokenEndpoint = discovery.token_endpoint;
    made.jwksUri = discovery.jwks_uri;
    saveState(settings, state);
  }

  const printedPlans = plans.ready.map((entry, index) => {
    const made = state.tenants[entry.tenant];
    const clients = Object.fromEntries(Object.entries(entry.clients).map(([field, key]) => [
      field, { client_id: made.clients[key].client_id, client_secret: made.clients[key].client_secret },
    ]));
    const type = entry.variant.response_type;
    const configuration = {
      alias,
      description: `Hodor ${version}, ${entry.profile}${type === undefined ? "" : `, ${type}`}`,
      server: { discoveryUrl: `${made.issuer}/.well-known/openid-configuration` },
      ...clients,
    };
    const file = `${String(index + 1).padStart(2, "0")}-${entry.name}.json`;
    writeFileSync(join(settings.output, file), `${JSON.stringify(configuration, null, 2)}\n`, { mode: 0o600 });
    return { profile: entry.profile, plan: entry.plan, variant: entry.variant, file, configuration };
  });
  const result = {
    suite: settings.suite,
    alias,
    version,
    person: state.person,
    plans: printedPlans,
    waiting: plans.waiting.map((entry) => ({
      profile: entry.profile, plan: entry.plan, variant: entry.variant, waitingFor: entry.waitingFor,
    })),
  };
  writeFileSync(join(settings.output, "configuration.json"), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
  log(`${printedPlans.length} plan runs ready, ${result.waiting.length} waiting; the files are in ${settings.output}`);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

// ---------------------------------------------------------------------------
// retire
// ---------------------------------------------------------------------------

/** The `kid` of every key a key set publishes; none when it cannot be read. */
async function publishedKeys(url) {
  try {
    const set = await getJson(url);
    return (set.keys ?? []).map((key) => key.kid).filter((kid) => kid !== undefined);
  } catch {
    return [];
  }
}

/** What the token endpoint answers a client asking with its own secret. */
async function tokenAnswer(endpoint, client) {
  const form = new URLSearchParams({ grant_type: "refresh_token", refresh_token: "certification-check" });
  const headers = { "content-type": "application/x-www-form-urlencoded" };
  if (client.method === "client_secret_post") {
    form.set("client_id", client.client_id);
    form.set("client_secret", client.client_secret);
  } else {
    const pair = `${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.client_secret)}`;
    headers.authorization = `Basic ${Buffer.from(pair).toString("base64")}`;
  }
  const response = await fetch(endpoint, { method: "POST", headers, body: form });
  const body = await response.json().catch(() => ({}));
  return { status: response.status, error: body.error };
}

async function retire(settings) {
  const statePath = join(settings.output, "state.json");
  if (!existsSync(statePath)) {
    throw new Error(`${statePath} does not exist: nothing was made, or the output folder is elsewhere`);
  }
  const state = JSON.parse(readFileSync(statePath, "utf8"));
  const cli = makeCli(settings);
  // Each step is tried even when one before it failed: the checks decide.
  const attempt = (...args) => {
    try {
      return cli(...args);
    } catch (error) {
      log(`  failed: ${error.message.split("\n")[0]}`);
      return "";
    }
  };
  const checks = [];
  const record = (what, held, detail) => {
    checks.push({ what, held, detail });
    log(`  ${held ? "holds" : "DOES NOT HOLD"}: ${what} (${detail})`);
  };

  for (const [slug, made] of Object.entries(state.tenants)) {
    log(`Retiring the tenant ${slug}`);
    for (const client of Object.values(made.clients)) {
      attempt("client", "disable", "--tenant", slug, "--id", client.client_id);
    }
    if (made.application !== undefined) {
      attempt("application", "disable", "--tenant", slug, "--id", made.application);
    }
    for (const command of made.retireCommands ?? []) {
      attempt(...command);
    }
    const before = made.jwksUri === undefined ? [] : await publishedKeys(made.jwksUri);
    for (const line of attempt("keys", "list", "--tenant", slug).split("\n")) {
      const [version, , status] = line.split(" ");
      if (version && status !== "revoked") {
        attempt("keys", "revoke", "--tenant", slug, "--version", version, "--reason", "The certification run is over");
      }
    }

    if (made.tokenEndpoint !== undefined) {
      for (const [key, client] of Object.entries(made.clients)) {
        const answer = await tokenAnswer(made.tokenEndpoint, client);
        record(`the client ${key} of ${slug} is refused`, answer.error === "invalid_client",
          `${answer.status} ${answer.error}`);
      }
    }
    if (made.jwksUri !== undefined) {
      const after = await publishedKeys(made.jwksUri);
      const still = before.filter((kid) => after.includes(kid));
      record(`no key ${slug} published before is published still`, still.length === 0,
        still.length === 0 ? `${before.length} keys withdrawn` : `still published: ${still.join(", ")}`);
    }

    attempt("tenant", "suspend", "--slug", slug, "--reason", "The certification run is over");
    const discovery = await fetch(`${made.issuer}/.well-known/openid-configuration`);
    const body = await discovery.text();
    record(`${slug} is suspended`, discovery.status === 403 && body.includes("tenant.suspended"),
      `${discovery.status}`);
  }

  const result = { retired: Object.keys(state.tenants), checks };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (checks.some((check) => !check.held)) {
    log("Something made for the certification still works.");
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------

async function main() {
  const command = process.argv[2];
  if (command !== "make" && command !== "retire") {
    log("Usage: node deploy/certification/certification.mjs make | retire");
    process.exitCode = 2;
    return;
  }
  const settings = readSettings();
  if (process.env.CERTIFICATION_ACCEPT_ANY_CERTIFICATE === "1") {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }
  await (command === "make" ? make(settings) : retire(settings));
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    log(error.stack ?? String(error));
    process.exitCode = 1;
  });
}
