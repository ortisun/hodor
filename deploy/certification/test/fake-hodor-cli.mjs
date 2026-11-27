// A stand-in for `hodor-cli`, for the test of certification.mjs. It answers
// the commands the script runs as `hodor-cli` prints them, and keeps what
// they made in the JSON file named by FAKE_HODOR_STATE, which the test's
// stand-in for Hodor reads: a client disabled here is refused there, a key
// revoked here leaves the key set there, a tenant suspended here is
// suspended there. Every call is recorded under `calls`.

import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const path = process.env.FAKE_HODOR_STATE;
const state = JSON.parse(readFileSync(path, "utf8"));
const args = process.argv.slice(2);
state.calls.push(args);

/** The values of `--name`, each time it is given. */
function all(name) {
  const values = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === `--${name}`) {
      values.push(args[index + 1]);
    }
  }
  return values;
}
const one = (name) => all(name)[0];
const flag = (name) => args.includes(`--${name}`);

function fail(message) {
  writeFileSync(path, JSON.stringify(state, null, 2));
  process.stderr.write(`error: ${message}\n`);
  process.exit(1);
}

function tenant(slug) {
  const found = state.tenants[slug];
  if (found === undefined) {
    fail(`tenant.not_found: no tenant ${slug}`);
  }
  return found;
}

let output = "";
const [group, command] = args;
if (group === "--version") {
  output = "hodor-cli 0.5.0-test";
} else if (group === "tenant" && command === "list") {
  output = Object.entries(state.tenants)
    .map(([slug, entry]) => `${slug} ${entry.id} ${entry.status}`)
    .join("\n");
} else if (group === "tenant" && command === "create") {
  const slug = one("slug");
  if (state.tenants[slug] !== undefined) {
    fail("tenant.slug_taken");
  }
  const key = (algorithm) => ({ id: randomUUID(), algorithm, status: "active" });
  state.tenants[slug] = {
    id: randomUUID(), name: one("name"), status: "active",
    applications: {}, clients: {}, keys: [key("ES256"), key("RS256")], users: {}, admins: {},
    registration: "off",
  };
  output = `tenant ${state.tenants[slug].id}`;
} else if (group === "tenant" && command === "suspend") {
  tenant(one("slug")).status = "suspended";
  output = `${one("slug")} suspended`;
} else if (group === "application" && command === "add") {
  const id = randomUUID();
  tenant(one("tenant")).applications[id] = { name: one("name"), firstParty: flag("first-party"), enabled: true };
  output = `application ${id} ${one("name")}`;
} else if (group === "application" && command === "disable") {
  const application = tenant(one("tenant")).applications[one("id")];
  if (application === undefined) {
    fail("oauth.application_not_found");
  }
  application.enabled = false;
  output = "disabled";
} else if (group === "client" && command === "add") {
  const made = tenant(one("tenant"));
  if (made.applications[one("application")] === undefined) {
    fail("oauth.application_not_found");
  }
  const id = randomUUID();
  const secret = randomBytes(16).toString("hex");
  made.clients[id] = {
    application: one("application"), name: one("name"), method: one("method"), secret, enabled: true,
    redirectUris: all("redirect-uri"), postLogoutRedirectUris: all("post-logout-redirect-uri"),
    responseTypes: all("response-type"), backchannelLogoutUri: one("backchannel-logout-uri"),
    frontchannelLogoutUri: one("frontchannel-logout-uri"), withoutPkce: flag("without-pkce"),
  };
  output = `client ${id}\nsecret ${secret}\nexpires 2027-11-27T00:00:00Z`;
} else if (group === "client" && command === "disable") {
  const client = tenant(one("tenant")).clients[one("id")];
  if (client === undefined) {
    fail("oauth.client_not_found");
  }
  client.enabled = false;
  output = "disabled";
} else if (group === "client-registration") {
  tenant(one("tenant")).registration = command;
  output = `registration ${command}`;
} else if (group === "admin" && command === "bootstrap") {
  const token = randomBytes(16).toString("hex");
  tenant(one("tenant")).admins[token] = one("email");
  output = `user ${randomUUID()}\ntoken ${token}`;
} else if (group === "user" && command === "claims") {
  const made = tenant(one("tenant"));
  const user = made.users[one("user")];
  if (user === undefined) {
    fail("identity.user_not_found");
  }
  user.claims = { given_name: one("given-name"), family_name: one("family-name"), phone_number: one("phone-number") };
  output = `given_name ${one("given-name")}`;
} else if (group === "keys" && command === "list") {
  output = tenant(one("tenant")).keys
    .map((key) => `${key.id} ${key.algorithm} ${key.status} created 2026-11-27T00:00:00Z`)
    .join("\n");
} else if (group === "keys" && command === "revoke") {
  const key = tenant(one("tenant")).keys.find((candidate) => candidate.id === one("version"));
  if (key === undefined) {
    fail("keys.version_not_found");
  }
  key.status = "revoked";
  output = `${key.id} ${key.algorithm} revoked`;
} else {
  fail(`the stand-in does not know ${args.join(" ")}`);
}

writeFileSync(path, JSON.stringify(state, null, 2));
process.stdout.write(`${output}\n`);
