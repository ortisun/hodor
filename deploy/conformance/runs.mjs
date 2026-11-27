// Which plans of the OpenID conformance suite a run of continuous
// integration runs, the results each test may end with in each plan, and
// what the issue of a failed night says. docs/operations/conformance.md,
// "When each plan runs" and "Expected results", is the human-maintained
// page; `run.mjs` and the tests in `test/` import what is exported here.
//
//   node runs.mjs choose
//     Prints `set=` and `plans=` for $GITHUB_OUTPUT: the set of plans the
//     event of GITHUB_EVENT_NAME and GITHUB_EVENT_PATH calls for, `core`,
//     `every` or `none`, and the short names of its plans as a JSON array.
//   node runs.mjs report DIRECTORY
//     Prints the body of the issue of a failed night, from the results of
//     each plan of CONFORMANCE_CHOSEN (a JSON array of short names), found
//     in DIRECTORY/conformance-results-{plan}/conformance-results.json, and
//     the address of the run in CONFORMANCE_RUN_URL.
//
// Node's standard library only, so that it runs before `npm ci`.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** The label that makes a pull request into `develop` run every plan. */
export const EVERY_PLAN_LABEL = "conformance: full";

/** The results other than `PASSED` the Foundation counts toward a certification. */
export const ALLOWED_RESULTS = ["REVIEW", "WARNING", "SKIPPED"];

/** A short name: lowercase words and numbers joined by hyphens. */
const SHORT_NAME = /^[a-z0-9]+(-[a-z0-9]+)*$/;

// ---------------------------------------------------------------------------
// plans.json and expected.json
// ---------------------------------------------------------------------------

/** What is wrong with the contents of `plans.json`, one sentence each. */
export function checkPlans(data) {
  if (data === null || typeof data !== "object" || !Array.isArray(data.plans)) {
    return ["it holds no list `plans`"];
  }
  const problems = [];
  const seen = new Set();
  for (const [index, plan] of data.plans.entries()) {
    if (plan === null || typeof plan !== "object" || typeof plan.name !== "string") {
      problems.push(`plan ${index} has no name`);
      continue;
    }
    if (!SHORT_NAME.test(plan.name)) {
      problems.push(`${plan.name} is not lowercase words joined by hyphens`);
    }
    if (seen.has(plan.name)) {
      problems.push(`${plan.name} is named twice`);
    }
    seen.add(plan.name);
    if (typeof plan.core !== "boolean") {
      problems.push(`${plan.name} does not say with \`core\`, true or false, whether it is of the core set`);
    }
  }
  if (!data.plans.some((plan) => plan?.core === true)) {
    problems.push("no plan is of the core set");
  }
  return problems;
}

/** The plans of `plans.json`, `{ name, core }` each, or an error naming every problem. */
export function readPlans(file = join(HERE, "plans.json")) {
  const data = JSON.parse(readFileSync(file, "utf8"));
  const problems = checkPlans(data);
  if (problems.length > 0) {
    throw new Error(`${file}:\n  ${problems.join("\n  ")}`);
  }
  return data.plans.map(({ name, core }) => ({ name, core }));
}

/** What is wrong with the contents of `expected.json`, given the short names of the plans. */
export function checkExpected(expected, names) {
  if (expected === null || typeof expected !== "object" || Array.isArray(expected)) {
    return ["it is not an object of tests"];
  }
  const problems = [];
  for (const [test, results] of Object.entries(expected)) {
    if (results === null || typeof results !== "object" || Object.keys(results).length === 0) {
      problems.push(`${test} names no result`);
      continue;
    }
    for (const [result, entry] of Object.entries(results)) {
      const where = `${test} ${result}`;
      if (!ALLOWED_RESULTS.includes(result)) {
        problems.push(`${where}: only ${ALLOWED_RESULTS.join(", ")} may be allowed`);
      }
      if (typeof entry?.why !== "string" || entry.why.trim() === "") {
        problems.push(`${where} says no reason in \`why\``);
      }
      if (!Array.isArray(entry?.plans) || entry.plans.length === 0) {
        problems.push(`${where} names no plan in \`plans\``);
        continue;
      }
      for (const plan of entry.plans) {
        if (!names.includes(plan)) {
          problems.push(`${where} names ${plan}, which plans.json does not`);
        }
      }
      if (new Set(entry.plans).size !== entry.plans.length) {
        problems.push(`${where} names a plan twice`);
      }
    }
  }
  return problems;
}

/** The contents of `expected.json`, or an error naming every problem. */
export function readExpected(names, file = join(HERE, "expected.json")) {
  const expected = JSON.parse(readFileSync(file, "utf8"));
  const problems = checkExpected(expected, names);
  if (problems.length > 0) {
    throw new Error(`${file}:\n  ${problems.join("\n  ")}`);
  }
  return expected;
}

/** The results `test` may end with in the plan of short name `plan`. */
export function allowedResults(expected, test, plan) {
  const named = Object.entries(expected[test] ?? {})
    .filter(([, entry]) => entry.plans.includes(plan))
    .map(([result]) => result);
  return ["PASSED", ...named];
}

// ---------------------------------------------------------------------------
// Which plans run
// ---------------------------------------------------------------------------

/**
 * The set of plans the event calls for, as Decision 0051 says: `core`,
 * `every` or `none`, with the short names of its plans and why.
 */
export function choose(eventName, event, plans) {
  const core = { set: "core", plans: plans.filter((plan) => plan.core).map((plan) => plan.name) };
  const every = { set: "every", plans: plans.map((plan) => plan.name) };
  const none = { set: "none", plans: [] };
  switch (eventName) {
    case "schedule":
      return { ...every, why: "the night's run" };
    case "push":
      return { ...core, why: `a push to ${event?.ref ?? "a branch"}` };
    case "pull_request": {
      const pull = event?.pull_request ?? {};
      const base = pull.base?.ref;
      const labels = (pull.labels ?? []).map((label) => label.name);
      if (event?.action === "labeled") {
        // The concurrency group of conformance.yml keeps these two apart
        // from the run in progress, so that they stop nothing.
        if (event.label?.name !== EVERY_PLAN_LABEL) {
          return { ...none, why: `the label ${event.label?.name} asks for no plan` };
        }
        if (base === "main") {
          return { ...none, why: "a pull request into main already runs every plan" };
        }
        return { ...every, why: `the label ${EVERY_PLAN_LABEL} was added` };
      }
      if (base === "main") {
        return { ...every, why: "a pull request into main" };
      }
      if (labels.includes(EVERY_PLAN_LABEL)) {
        return { ...every, why: `the pull request is labelled ${EVERY_PLAN_LABEL}` };
      }
      return { ...core, why: `a pull request into ${base}` };
    }
    default:
      throw new Error(`no set of plans is chosen for the event ${eventName}`);
  }
}

// ---------------------------------------------------------------------------
// The issue of a failed night
// ---------------------------------------------------------------------------

/**
 * The plans that failed and the body of the issue. `chosen` is the short
 * names of the plans that were to run, or null when the run never chose
 * them; `results` maps each to what `run.mjs` wrote, or to undefined when
 * it wrote nothing.
 */
export function report({ chosen, results, runUrl }) {
  const lines = [`The night's run of the OpenID conformance plans on \`develop\` failed: ${runUrl}`, ""];
  if (chosen === null) {
    lines.push(
      "It failed before it chose its plans, so none of them ran. The job `Choose the plans` says why.",
    );
    return { failed: [], body: `${lines.join("\n")}\n` };
  }
  const failed = [];
  const sections = [];
  for (const plan of chosen) {
    const ended = results.get(plan);
    if (ended === undefined) {
      failed.push(plan);
      sections.push(
        `### \`${plan}\``,
        "",
        "It ended before it wrote its results: the image, its stack, the suite or the script stopped it. Its job's log says which.",
        "",
      );
      continue;
    }
    const unexpected = ended.filter((result) => result.allowed !== true);
    if (unexpected.length === 0) {
      continue;
    }
    failed.push(plan);
    sections.push(`### \`${plan}\``, "");
    for (const result of unexpected) {
      sections.push(`- \`${result.name}\` ended \`${result.outcome ?? result.status}\``);
    }
    sections.push("");
  }
  if (failed.length === 0) {
    lines.push(
      "Every plan that ran ended as `deploy/conformance/expected.json` expects; another job of the run failed, such as the image or the certification deployment. The run's jobs say which.",
    );
  } else {
    lines.push(
      `${failed.length} of the ${chosen.length} plans failed. Each test below did not end as \`deploy/conformance/expected.json\` expects for its plan; the run keeps each plan's results as the artifact \`conformance-results-{plan}\`, with the address of each test's log in the suite.`,
      "",
      ...sections,
    );
  }
  lines.push(
    "While this issue is open, a later night that fails comments here. docs/operations/conformance.md, \"When each plan runs\", says how the run works.",
  );
  return { failed, body: `${lines.join("\n")}\n` };
}

/** What `run.mjs` wrote for each plan of `chosen` in `directory`, as `report` takes it. */
export function readResults(directory, chosen) {
  const results = new Map();
  for (const plan of chosen) {
    const file = join(directory, `conformance-results-${plan}`, "conformance-results.json");
    results.set(plan, existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : undefined);
  }
  return results;
}

// ---------------------------------------------------------------------------

function main(args) {
  const [command, directory] = args;
  if (command === "choose") {
    const eventName = process.env.GITHUB_EVENT_NAME ?? "";
    const event = process.env.GITHUB_EVENT_PATH
      ? JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"))
      : {};
    const chosen = choose(eventName, event, readPlans());
    console.error(`${chosen.set}: ${chosen.why}; ${chosen.plans.join(", ") || "no plan"}`);
    console.log(`set=${chosen.set}`);
    console.log(`plans=${JSON.stringify(chosen.plans)}`);
    return 0;
  }
  if (command === "report" && directory !== undefined) {
    const named = process.env.CONFORMANCE_CHOSEN ?? "";
    const chosen = named === "" ? null : JSON.parse(named);
    const results = chosen === null ? new Map() : readResults(resolve(directory), chosen);
    const { body } = report({ chosen, results, runUrl: process.env.CONFORMANCE_RUN_URL ?? "" });
    process.stdout.write(body);
    return 0;
  }
  console.error("usage: node runs.mjs choose | node runs.mjs report DIRECTORY");
  return 2;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
