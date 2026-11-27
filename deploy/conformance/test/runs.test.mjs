// The tests of runs.mjs: the checks of plans.json and expected.json, the
// results allowed for a test in a plan, the set of plans each event calls
// for, and the issue of a failed night.
//
//   node --test deploy/conformance/test/

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  EVERY_PLAN_LABEL,
  allowedResults,
  checkExpected,
  checkPlans,
  choose,
  readExpected,
  readPlans,
  readResults,
  report,
} from "../runs.mjs";

const RUNS = join(dirname(fileURLToPath(import.meta.url)), "..", "runs.mjs");

const PLANS = [
  { name: "basic", core: true },
  { name: "config", core: true },
  { name: "formpost-basic", core: false },
  { name: "3rdparty-init", core: false },
];

const EXPECTED = {
  "oidcc-prompt-login": {
    REVIEW: { why: "A screenshot for a person to look at.", plans: ["basic", "formpost-basic"] },
  },
  "oidcc-claims-essential": {
    WARNING: { why: "A claim the person does not have.", plans: ["basic"] },
  },
};

function pullRequest({ base = "develop", labels = [], action = "synchronize", label } = {}) {
  return {
    action,
    ...(label === undefined ? {} : { label: { name: label } }),
    pull_request: { base: { ref: base }, labels: labels.map((name) => ({ name })) },
  };
}

// ---------------------------------------------------------------------------

test("the repository's plans.json and expected.json are read without a problem", () => {
  const plans = readPlans();
  assert.ok(plans.some((plan) => plan.core));
  readExpected(plans.map((plan) => plan.name));
});

test("plans.json with distinct short names and a core set passes", () => {
  assert.deepEqual(checkPlans({ plans: PLANS }), []);
});

test("plans.json is refused for a name given twice, a name that is not a short name, or `core` missing", () => {
  assert.deepEqual(
    checkPlans({
      plans: [
        { name: "basic", core: true },
        { name: "basic", core: false },
        { name: "Basic Plan", core: false },
        { name: "config" },
      ],
    }),
    [
      "basic is named twice",
      "Basic Plan is not lowercase words joined by hyphens",
      "config does not say with `core`, true or false, whether it is of the core set",
    ],
  );
});

test("plans.json is refused without a list of plans, or without a plan of the core set", () => {
  assert.deepEqual(checkPlans({}), ["it holds no list `plans`"]);
  assert.deepEqual(checkPlans({ plans: [{ name: "basic", core: false }] }), ["no plan is of the core set"]);
});

test("readPlans names the file and every problem", () => {
  const directory = mkdtempSync(join(tmpdir(), "conformance-plans-"));
  const file = join(directory, "plans.json");
  writeFileSync(file, JSON.stringify({ plans: [{ name: "basic" }] }));
  assert.throws(() => readPlans(file), (error) => {
    assert.match(error.message, /plans\.json/);
    assert.match(error.message, /basic does not say/);
    assert.match(error.message, /no plan is of the core set/);
    return true;
  });
});

// ---------------------------------------------------------------------------

test("expected.json naming known plans, with a reason for each result, passes", () => {
  assert.deepEqual(checkExpected(EXPECTED, PLANS.map((plan) => plan.name)), []);
});

test("expected.json is refused for an unknown plan, a failure allowed, a missing reason or no plans", () => {
  const problems = checkExpected(
    {
      "oidcc-server": {
        FAILED: { why: "Never allowed.", plans: ["basic"] },
        REVIEW: { why: "", plans: ["basic", "basic"] },
        WARNING: { why: "A reason.", plans: ["nowhere"] },
        SKIPPED: { why: "A reason.", plans: [] },
      },
      "oidcc-empty": {},
    },
    PLANS.map((plan) => plan.name),
  );
  assert.deepEqual(problems, [
    "oidcc-server FAILED: only REVIEW, WARNING, SKIPPED may be allowed",
    "oidcc-server REVIEW says no reason in `why`",
    "oidcc-server REVIEW names a plan twice",
    "oidcc-server WARNING names nowhere, which plans.json does not",
    "oidcc-server SKIPPED names no plan in `plans`",
    "oidcc-empty names no result",
  ]);
});

test("a result is allowed only in the plans named for it", () => {
  assert.deepEqual(allowedResults(EXPECTED, "oidcc-prompt-login", "basic"), ["PASSED", "REVIEW"]);
  assert.deepEqual(allowedResults(EXPECTED, "oidcc-prompt-login", "formpost-basic"), ["PASSED", "REVIEW"]);
  assert.deepEqual(allowedResults(EXPECTED, "oidcc-prompt-login", "config"), ["PASSED"]);
  assert.deepEqual(allowedResults(EXPECTED, "oidcc-claims-essential", "formpost-basic"), ["PASSED"]);
  assert.deepEqual(allowedResults(EXPECTED, "oidcc-server", "basic"), ["PASSED"]);
});

// ---------------------------------------------------------------------------

const CORE = ["basic", "config"];
const EVERY = ["basic", "config", "formpost-basic", "3rdparty-init"];

test("a pull request into develop runs the core set", () => {
  const chosen = choose("pull_request", pullRequest(), PLANS);
  assert.equal(chosen.set, "core");
  assert.deepEqual(chosen.plans, CORE);
  assert.equal(choose("pull_request", pullRequest({ action: "opened" }), PLANS).set, "core");
});

test("a pull request into develop with the label runs every plan, on each push", () => {
  const chosen = choose("pull_request", pullRequest({ labels: ["documentation", EVERY_PLAN_LABEL] }), PLANS);
  assert.equal(chosen.set, "every");
  assert.deepEqual(chosen.plans, EVERY);
});

test("adding the label runs every plan; adding another label runs nothing", () => {
  const added = pullRequest({ action: "labeled", label: EVERY_PLAN_LABEL, labels: [EVERY_PLAN_LABEL] });
  assert.deepEqual(choose("pull_request", added, PLANS).plans, EVERY);
  const other = pullRequest({ action: "labeled", label: "documentation", labels: [EVERY_PLAN_LABEL, "documentation"] });
  const chosen = choose("pull_request", other, PLANS);
  assert.equal(chosen.set, "none");
  assert.deepEqual(chosen.plans, []);
});

test("a pull request into main runs every plan, and adding the label to it runs nothing more", () => {
  assert.deepEqual(choose("pull_request", pullRequest({ base: "main" }), PLANS).plans, EVERY);
  const added = pullRequest({ base: "main", action: "labeled", label: EVERY_PLAN_LABEL });
  assert.equal(choose("pull_request", added, PLANS).set, "none");
});

test("the night runs every plan, and a push the core set", () => {
  assert.deepEqual(choose("schedule", {}, PLANS).plans, EVERY);
  assert.deepEqual(choose("push", { ref: "refs/heads/develop" }, PLANS).plans, CORE);
});

test("an event nobody chose a set for is refused", () => {
  assert.throws(() => choose("workflow_dispatch", {}, PLANS), /no set of plans is chosen for the event workflow_dispatch/);
});

test("choose prints the set and the plans for GITHUB_OUTPUT", () => {
  const directory = mkdtempSync(join(tmpdir(), "conformance-event-"));
  const event = join(directory, "event.json");
  writeFileSync(event, JSON.stringify(pullRequest({ base: "main" })));
  const printed = execFileSync(process.execPath, [RUNS, "choose"], {
    encoding: "utf8",
    env: { ...process.env, GITHUB_EVENT_NAME: "pull_request", GITHUB_EVENT_PATH: event },
    stdio: ["ignore", "pipe", "ignore"],
  });
  const lines = printed.trim().split("\n");
  assert.equal(lines[0], "set=every");
  assert.match(lines[1], /^plans=\[.*\]$/);
  assert.deepEqual(JSON.parse(lines[1].slice("plans=".length)), readPlans().map((plan) => plan.name));
});

// ---------------------------------------------------------------------------

const RUN_URL = "https://github.com/ortisun/hodor/actions/runs/1";

test("the issue names each failed plan and each test that did not end as expected", () => {
  const results = new Map([
    ["basic", [
      { run: "basic", name: "oidcc-server", outcome: "PASSED", allowed: true },
      { run: "basic", name: "oidcc-prompt-login", outcome: "FAILED", allowed: false },
      { run: "basic", name: "oidcc-max-age-1", status: "INTERRUPTED", outcome: "INTERRUPTED", allowed: false },
    ]],
    ["config", [{ run: "config", name: "oidcc-discovery", outcome: "PASSED", allowed: true }]],
    ["formpost-basic", undefined],
  ]);
  const { failed, body } = report({ chosen: ["basic", "config", "formpost-basic"], results, runUrl: RUN_URL });
  assert.deepEqual(failed, ["basic", "formpost-basic"]);
  assert.ok(body.startsWith(`The night's run of the OpenID conformance plans on \`develop\` failed: ${RUN_URL}\n`));
  assert.match(body, /2 of the 3 plans failed/);
  assert.match(body, /### `basic`\n\n- `oidcc-prompt-login` ended `FAILED`\n- `oidcc-max-age-1` ended `INTERRUPTED`\n/);
  assert.match(body, /### `formpost-basic`\n\nIt ended before it wrote its results/);
  assert.doesNotMatch(body, /`config`/);
  assert.doesNotMatch(body, /oidcc-server/);
});

test("the issue says so when no plan failed, or when no plan was chosen", () => {
  const passed = new Map([["basic", [{ name: "oidcc-server", outcome: "PASSED", allowed: true }]]]);
  const other = report({ chosen: ["basic"], results: passed, runUrl: RUN_URL });
  assert.deepEqual(other.failed, []);
  assert.match(other.body, /Every plan that ran ended as/);
  const never = report({ chosen: null, results: new Map(), runUrl: RUN_URL });
  assert.match(never.body, /It failed before it chose its plans/);
});

test("report reads the artifacts as download-artifact leaves them", () => {
  const directory = mkdtempSync(join(tmpdir(), "conformance-results-"));
  mkdirSync(join(directory, "conformance-results-basic"));
  writeFileSync(
    join(directory, "conformance-results-basic", "conformance-results.json"),
    JSON.stringify([{ run: "basic", name: "oidcc-server", outcome: "FAILED", allowed: false }]),
  );
  const results = readResults(directory, ["basic", "config"]);
  assert.equal(results.get("basic")[0].outcome, "FAILED");
  assert.equal(results.get("config"), undefined);
  const printed = execFileSync(process.execPath, [RUNS, "report", directory], {
    encoding: "utf8",
    env: { ...process.env, CONFORMANCE_CHOSEN: '["basic","config"]', CONFORMANCE_RUN_URL: RUN_URL },
  });
  assert.match(printed, /### `basic`\n\n- `oidcc-server` ended `FAILED`/);
  assert.match(printed, /### `config`\n\nIt ended before/);
});
