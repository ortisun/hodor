#!/usr/bin/env python3
"""A GitHub Projects board that mirrors the issue labels, and adapts to a board that already exists (ADR 0018).

One file, three uses:

  * CI and developers:   check, render   (read policies/project-board.yaml, need PyYAML)
  * the installer:       map, validate, titles   (read the rendered JSON, standard library only)
  * the GitHub Action:   sync            (reads the rendered JSON, standard library only; the installer copies this
                                          file into the target repository)

The labels are the truth and the board is a view. `sync` works out the stage of one issue from its labels and its
state, and puts the issue in the matching option of the board's field.

Safety rules, each with a test in scripts/tests/test_project_board.py:
  * Adapting is additive. This code never creates, renames, reorders or deletes an option of a field that exists.
    It maps the stages onto the options that are there. The one field it may create is a new one, on a project that
    has no board of its own, and the installer does that with `gh project field-create`.
  * Issue text is data. The stage comes from label names and the issue state, compared with fixed strings. Every
    value that goes to GitHub goes as a GraphQL variable, never into the text of a query.
  * The board credential (BOARD_TOKEN) is used for the board calls only. The issue is read with GH_TOKEN, the
    repository token. The credential is never printed.
  * A board that is not set up is not an error: with no config file or no credential `sync` says why and exits 0.
    A board that is set up and wrong (an option that no longer exists) is an error and exits 1.
  * Only an issue on a track is added to the board. A track is a label of the issue workflow: a closed issue with none
    of them is left alone, so closing an issue does not put it on the board.
  * Only a person with triage rights on the repository, or the factory's App, can make a card move. The author of an
    issue in a public repository is neither, so opening or closing an issue does not write to the board.
  * The board must belong to the repository's owner, or to an owner that the repository lists in FACTORY_BOARD_OWNERS.
    A change to the config file cannot aim the credential at somebody else's project.

Usage:
  project_board.py check  [--policy P] [--workflow-config W] [--rendered R]
  project_board.py render [--policy P] --out FILE
  project_board.py titles --policy-json FILE
  project_board.py map    --policy-json FILE --owner O --owner-type organization|user --number N
                          (--fields FILE --status-field NAME | --created)
  project_board.py validate --policy-json FILE --board-config FILE [--fields FILE]
  project_board.py sync   --event FILE --policy-json FILE --board-config FILE --repo OWNER/NAME
                          (environment: GH_TOKEN, BOARD_TOKEN, FACTORY_BOT_LOGIN, FACTORY_BOARD_OWNERS)

Exit codes: 0 done, 1 a check failed or a GitHub call failed, 2 wrong arguments, 3 BLOCKED (PyYAML missing).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse

SCHEMA_POLICY = "factory-project-board-policy/1"
SCHEMA_CONFIG = "factory-project-board/1"
EXIT_FAILED, EXIT_USAGE, EXIT_BLOCKED = 1, 2, 3

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
DEFAULT_POLICY = os.path.join(ROOT, "policies", "project-board.yaml")
DEFAULT_WORKFLOW_CONFIG = os.path.join(ROOT, "onboarding", "github", "issue-workflow.json")
DEFAULT_RENDERED = os.path.join(ROOT, "onboarding", "github", "project-board-policy.json")

NODE_ID = re.compile(r"^[A-Za-z0-9_=-]{1,200}$")
OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

_TOP_KEYS = {"schema_version", "policy", "created_field", "stages", "rules"}
_STAGE_KEYS = {"key", "title", "meaning", "matches", "fallback"}
_RULE_KEYS = {"stage", "labels_any", "issue_closed"}


def normalize(name):
    """A board option name, compared loosely: lower case, ASCII letters, digits and apostrophes, single spaces."""
    text = str(name).lower().replace("’", "'")
    return " ".join(re.sub(r"[^a-z0-9' ]+", " ", text).split())


# ---------------------------------------------------------------------------------------------------------------
# Policy: load, check, render
# ---------------------------------------------------------------------------------------------------------------

def load_policy(path):
    """Parse the policy file. Needs PyYAML, which only the CI and developer subcommands use."""
    try:
        import yaml  # noqa: PLC0415  (imported here on purpose: `sync` must run without it)
    except ImportError:
        print("BLOCKED: PyYAML is not installed. Run through: uv run --no-project --with pyyaml==6.0.3 python -I ...",
              file=sys.stderr)
        sys.exit(EXIT_BLOCKED)
    with open(path, "rb") as handle:
        raw = handle.read()
    return yaml.safe_load(raw), raw


def check_policy(policy, workflow_config):
    """Return a list of problems. An empty list means the policy is sound."""
    errors = []
    if not isinstance(policy, dict):
        return ["shape: the policy must be a mapping"]
    extra = sorted(set(policy) - _TOP_KEYS)
    if extra:
        errors.append("unknown-key: top level has unknown key(s) %s" % ", ".join(map(str, extra)))
    if policy.get("schema_version") != 1:
        errors.append("schema-version: schema_version must be 1")
    created = policy.get("created_field")
    if not isinstance(created, str) or not (1 <= len(created) <= 50):
        errors.append("created-field: created_field must be 1 to 50 characters")

    stages = policy.get("stages", [])
    keys = []
    titles = []
    for index, stage in enumerate(stages if isinstance(stages, list) else []):
        if not isinstance(stage, dict) or set(stage) - _STAGE_KEYS:
            errors.append("unknown-key: stage[%d] must be a mapping with only %s" % (index, ", ".join(sorted(_STAGE_KEYS))))
            continue
        key = stage.get("key")
        if not isinstance(key, str) or not re.match(r"^[a-z][a-z_]{0,30}$", key):
            errors.append("stage-key: stage[%d] key %r must be lower-case words joined by underscores" % (index, key))
        keys.append(key)
        title = stage.get("title")
        if not isinstance(title, str) or not (1 <= len(title) <= 50):
            errors.append("title: stage %r needs a title of 1 to 50 characters" % (key,))
        titles.append(normalize(title))
        if not isinstance(stage.get("meaning"), str) or not stage.get("meaning"):
            errors.append("meaning: stage %r needs a meaning" % (key,))
        matches = stage.get("matches")
        if not isinstance(matches, list) or not matches or any(not isinstance(m, str) or normalize(m) != m for m in matches):
            errors.append("matches: stage %r needs a list of names already in normal form (lower case, no punctuation)" % (key,))
    if len(set(keys)) != len(keys):
        errors.append("duplicate-stage: stage keys must be unique")
    if len(set(titles)) != len(titles):
        errors.append("duplicate-title: stage titles must be unique once normalized")

    # Fallbacks name real stages and never loop.
    fallback = {}
    for stage in stages if isinstance(stages, list) else []:
        if isinstance(stage, dict):
            fallback[stage.get("key")] = stage.get("fallback", [])
    for key, chain in fallback.items():
        if not isinstance(chain, list) or any(item not in keys for item in chain):
            errors.append("fallback: stage %r names a stage that does not exist" % (key,))
            continue
        seen, frontier = set(), list(chain)
        while frontier:
            item = frontier.pop()
            if item == key:
                errors.append("fallback-loop: stage %r falls back to itself" % (key,))
                break
            if item not in seen:
                seen.add(item)
                frontier.extend(fallback.get(item, []))

    # Rules.
    trigger = (workflow_config or {}).get("trigger")
    known = {label["name"] for label in (workflow_config or {}).get("labels", [])}
    used, reached = set(), set()
    for index, rule in enumerate(policy.get("rules", []) if isinstance(policy.get("rules"), list) else []):
        if not isinstance(rule, dict) or set(rule) - _RULE_KEYS:
            errors.append("unknown-key: rule[%d] must be a mapping with only %s" % (index, ", ".join(sorted(_RULE_KEYS))))
            continue
        if rule.get("stage") not in keys:
            errors.append("rule-stage: rule[%d] names the stage %r, which does not exist" % (index, rule.get("stage")))
        else:
            reached.add(rule["stage"])
        has_labels, has_closed = "labels_any" in rule, "issue_closed" in rule
        if has_labels == has_closed:
            errors.append("rule-condition: rule[%d] needs exactly one of labels_any and issue_closed" % index)
        if has_closed and rule["issue_closed"] is not True:
            errors.append("rule-condition: rule[%d] issue_closed can only be true" % index)
        for label in rule.get("labels_any", []) if has_labels else []:
            if label == trigger:
                errors.append("trigger-label: rule[%d] uses the trigger label, and the board never reacts to the request itself" % index)
            elif label not in known:
                errors.append("unknown-label: rule[%d] uses %r, which the issue workflow does not define" % (index, label))
            used.add(label)
    for key in keys:
        if key not in reached:
            errors.append("unreached-stage: no rule leads to the stage %r" % (key,))
    for label in sorted(known - used - {trigger}):
        errors.append("uncovered-label: the label %r appears in no rule, so an issue with it has no place on the board" % (label,))
    return errors


def render(policy, raw):
    """The JSON that the installer and the Action read. Deterministic: the same policy gives the same bytes."""
    out = {
        "schema": SCHEMA_POLICY,
        "source": "policies/project-board.yaml",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "created_field": policy["created_field"],
        "stages": [{"key": s["key"], "title": s["title"], "matches": list(s["matches"]), "fallback": list(s.get("fallback", []))}
                   for s in policy["stages"]],
        "rules": [dict(rule) for rule in policy["rules"]],
    }
    return json.dumps(out, indent=2, sort_keys=True) + "\n"


def load_config(path):
    with open(path, encoding="utf-8") as handle:
        config = json.load(handle)
    if config.get("schema") != SCHEMA_POLICY:
        raise ValueError("the policy rendering is not %s" % SCHEMA_POLICY)
    return config


# ---------------------------------------------------------------------------------------------------------------
# Pure decisions
# ---------------------------------------------------------------------------------------------------------------

def stage_for(config, labels, closed):
    """The stage of an issue, or None when it is on no track. The first rule that fits decides.

    A track is a label of the issue workflow. `issue_closed` applies only to an issue that carries one: a closed issue
    with none of them is on no track, so closing an issue never puts it on the board by itself.
    """
    labels = set(labels)
    tracked = {label for rule in config["rules"] for label in rule.get("labels_any", [])}
    for rule in config["rules"]:
        if rule.get("issue_closed"):
            if closed and labels & tracked:
                return rule["stage"]
            continue
        if labels & set(rule.get("labels_any", [])):
            return rule["stage"]
    return None


def field_options(fields, field_name):
    """The option names of a single-select field of `gh project field-list --format json`, or None."""
    items = fields.get("fields", []) if isinstance(fields, dict) else fields
    for field in items:
        if field.get("name") == field_name and isinstance(field.get("options"), list):
            return [option["name"] for option in field["options"]]
    return None


def propose_mapping(config, option_names):
    """Map each stage to an existing option, or to None. Returns (mapping, notes). Never asks for a new option."""
    by_name = {}
    for name in option_names:
        by_name.setdefault(normalize(name), name)
    stages = {s["key"]: s for s in config["stages"]}

    def direct(stage):
        for candidate in [normalize(stage["title"])] + list(stage["matches"]):
            if candidate in by_name:
                return by_name[candidate]
        return None

    mapping, notes = {}, []
    for key, stage in stages.items():
        option, via = direct(stage), None
        frontier = list(stage.get("fallback", []))
        seen = set()
        while option is None and frontier:
            other = frontier.pop(0)
            if other in seen:
                continue
            seen.add(other)
            option = direct(stages[other])
            if option is not None:
                via = other
            else:
                frontier.extend(stages[other].get("fallback", []))
        mapping[key] = option
        if option is None:
            notes.append("%s: no option fits, so the board will not move for this stage" % stage["title"])
        elif via is not None:
            notes.append("%s: no option of its own, shown as '%s'" % (stage["title"], option))
    return mapping, notes


def board_config(project, status_field, options):
    return {"schema": SCHEMA_CONFIG, "project": project, "status_field": status_field, "options": options}


def validate_board_config(config, board):
    """Problems with a project's own config file. Standard library only."""
    errors = []
    if not isinstance(board, dict) or set(board) != {"schema", "project", "status_field", "options"}:
        return ["shape: the board config needs exactly schema, project, status_field and options"]
    if board["schema"] != SCHEMA_CONFIG:
        errors.append("schema: must be %s" % SCHEMA_CONFIG)
    project = board["project"]
    if not isinstance(project, dict) or set(project) != {"owner", "owner_type", "number"}:
        errors.append("project: needs exactly owner, owner_type and number")
    else:
        if not isinstance(project["owner"], str) or not OWNER.match(project["owner"]):
            errors.append("project.owner: must be a GitHub login")
        if project["owner_type"] not in ("organization", "user"):
            errors.append("project.owner_type: must be organization or user")
        if not isinstance(project["number"], int) or isinstance(project["number"], bool) or project["number"] < 1:
            errors.append("project.number: must be a whole number from 1")
    if not isinstance(board["status_field"], str) or not (1 <= len(board["status_field"]) <= 100):
        errors.append("status_field: must be 1 to 100 characters")
    options = board["options"]
    keys = {s["key"] for s in config["stages"]}
    if not isinstance(options, dict) or set(options) != keys:
        errors.append("options: must name every stage and no other: %s" % ", ".join(sorted(keys)))
    else:
        for key, value in options.items():
            if value is not None and (not isinstance(value, str) or not (1 <= len(value) <= 100)):
                errors.append("options.%s: must be an option name or null" % key)
    return errors


def live_problems(board, fields):
    """Problems between a valid board config and the board as it is now."""
    names = field_options(fields, board["status_field"])
    if names is None:
        return ["field: the board has no single-select field named %r" % board["status_field"]]
    return ["option: the board has no option %r (for the stage %s)" % (value, key)
            for key, value in sorted(board["options"].items()) if value is not None and value not in names]


# ---------------------------------------------------------------------------------------------------------------
# GitHub: the only part that talks to the network
# ---------------------------------------------------------------------------------------------------------------

def run_gh(args, token=None):
    """Run `gh` with a list of arguments, never a shell string. `token` replaces GH_TOKEN for this one call."""
    environment = dict(os.environ)
    if token:
        environment["GH_TOKEN"] = token
    done = subprocess.run(["gh", *args], capture_output=True, text=True, check=False, env=environment)
    if done.returncode != 0:
        raise RuntimeError("gh %s failed with exit code %d" % (" ".join(args[:2]), done.returncode))
    return done.stdout


_PROJECT_QUERY = """query($login: String!, $number: Int!) {
  %s(login: $login) { projectV2(number: $number) { id fields(first: 50) { nodes {
    ... on ProjectV2SingleSelectField { id name options { id name } } } } } } }"""
_ADD_ITEM = """mutation($project: ID!, $content: ID!) {
  addProjectV2ItemById(input: {projectId: $project, contentId: $content}) { item { id } } }"""
_SET_OPTION = """mutation($project: ID!, $item: ID!, $field: ID!, $option: String!) {
  updateProjectV2ItemFieldValue(input: {projectId: $project, itemId: $item, fieldId: $field,
    value: {singleSelectOptionId: $option}}) { projectV2Item { id } } }"""


def _graphql(run, token, query, **variables):
    args = ["api", "graphql", "-f", "query=" + query]
    for key, value in variables.items():
        args += ["-F" if isinstance(value, int) else "-f", "%s=%s" % (key, value)]
    reply = json.loads(run(args, token))
    if reply.get("errors"):
        raise RuntimeError("GitHub refused the board call: %s" % "; ".join(str(e.get("message", "?"))[:120] for e in reply["errors"]))
    return reply["data"]


LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?$")
TRIAGE_ROLES = {"admin", "maintain", "write", "triage"}


def sender_may_move_cards(sender, repo, bot_login, run=run_gh):
    """True for the factory's App, or for a person whose role on the repository is triage or higher.

    The author of an issue is not that person in a public repository, so a card never moves because of what an outside
    account opened, closed or labelled. A failed lookup is a no: the answer fails closed.
    """
    sender = sender if isinstance(sender, dict) else {}
    login, kind = sender.get("login"), sender.get("type")
    if not isinstance(login, str) or not isinstance(kind, str) or not LOGIN.match(login):
        return False
    if bot_login and kind == "Bot" and login.lower() == bot_login.lower():
        return True
    if kind != "User":
        return False
    try:
        reply = json.loads(run(["api", "repos/%s/collaborators/%s/permission" % (repo, urllib.parse.quote(login, safe=""))]))
    except (RuntimeError, ValueError):
        return False
    return reply.get("role_name") in TRIAGE_ROLES or reply.get("permission") in ("admin", "write")


def board_owner_allowed(board, repo, extra_owners=""):
    """The board's owner must be the repository's owner or one the repository lists. Case does not matter."""
    allowed = {repo.split("/")[0].lower()}
    allowed |= {item.strip().lower() for item in str(extra_owners or "").split(",") if OWNER.match(item.strip())}
    return board["project"]["owner"].lower() in allowed


def sync(config, board, event, repo, token, run=run_gh, bot_login="", extra_owners=""):
    """Put one issue in the board option that its labels and state call for. Returns a sentence that says what was done."""
    if not REPO.match(repo) or {".", ".."} & set(repo.split("/")):
        raise ValueError("the repository must look like OWNER/NAME")
    if not board_owner_allowed(board, repo, extra_owners):
        raise RuntimeError("the board belongs to %s, who is not the owner of %s and is not listed in FACTORY_BOARD_OWNERS"
                           % (board["project"]["owner"], repo))
    if not sender_may_move_cards(event.get("sender"), repo, bot_login, run):
        return "left alone: whoever caused this event has no triage rights on the repository"
    number = int(event["issue"]["number"])
    issue = json.loads(run(["api", "repos/%s/issues/%d" % (repo, number)]))
    node_id = issue.get("node_id", "")
    if not isinstance(node_id, str) or not NODE_ID.match(node_id):
        raise ValueError("GitHub gave the issue no usable node id")
    stage = stage_for(config, {item["name"] for item in issue.get("labels", [])}, issue.get("state") == "closed")
    if stage is None:
        return "left alone: the issue is on no track"
    wanted = board["options"][stage]
    if wanted is None:
        return "left alone: the board has no option for the stage %s" % stage
    project = board["project"]
    kind = "organization" if project["owner_type"] == "organization" else "user"
    data = _graphql(run, token, _PROJECT_QUERY % kind, login=project["owner"], number=project["number"])
    node = (data.get(kind) or {}).get("projectV2")
    if not node:
        raise RuntimeError("the project %s/%d was not found, or the credential cannot see it" % (project["owner"], project["number"]))
    field = next((f for f in node["fields"]["nodes"] if f.get("name") == board["status_field"]), None)
    option = next((o for o in (field or {}).get("options", []) if o["name"] == wanted), None)
    if field is None or option is None:
        raise RuntimeError("the board has no option %r in the field %r. Run the installer again to map the stages."
                           % (wanted, board["status_field"]))
    item = _graphql(run, token, _ADD_ITEM, project=node["id"], content=node_id)["addProjectV2ItemById"]["item"]["id"]
    _graphql(run, token, _SET_OPTION, project=node["id"], item=item, field=field["id"], option=option["id"])
    return "moved to '%s' (stage %s)" % (wanted, stage)


# ---------------------------------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------------------------------

def _read_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _cmd_check(args):
    policy, raw = load_policy(args.policy)
    errors = check_policy(policy, _read_json(args.workflow_config))
    if not errors and args.rendered:
        try:
            with open(args.rendered, encoding="utf-8") as handle:
                on_disk = handle.read()
        except OSError:
            on_disk = None
        if on_disk != render(policy, raw):
            errors.append("stale-rendering: %s is not the current rendering. Run: project_board.py render --out %s"
                          % (args.rendered, args.rendered))
    for error in errors:
        print("FAIL %s" % error)
    if errors:
        return EXIT_FAILED
    print("OK the project board policy is sound: %d stages, %d rules" % (len(policy["stages"]), len(policy["rules"])))
    return 0


def _cmd_render(args):
    policy, raw = load_policy(args.policy)
    errors = check_policy(policy, _read_json(DEFAULT_WORKFLOW_CONFIG))
    if errors:
        for error in errors:
            print("FAIL %s" % error)
        return EXIT_FAILED
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(render(policy, raw))
    print("wrote %s" % args.out)
    return 0


def _cmd_titles(args):
    print(",".join(stage["title"] for stage in load_config(args.policy_json)["stages"]))
    return 0


def _cmd_map(args):
    config = load_config(args.policy_json)
    if args.created:
        field = config["created_field"]
        options = {s["key"]: s["title"] for s in config["stages"]}
        notes = []
    else:
        if not args.fields or not args.status_field:
            print("map needs --fields and --status-field, or --created", file=sys.stderr)
            return EXIT_USAGE
        names = field_options(_read_json(args.fields), args.status_field)
        if names is None:
            print("FAIL the board has no single-select field named %r" % args.status_field, file=sys.stderr)
            return EXIT_FAILED
        field = args.status_field
        options, notes = propose_mapping(config, names)
    board = board_config({"owner": args.owner, "owner_type": args.owner_type, "number": args.number}, field, options)
    problems = validate_board_config(config, board)
    if problems:
        for problem in problems:
            print("FAIL %s" % problem, file=sys.stderr)
        return EXIT_FAILED
    for note in notes:
        print("NOTE %s" % note, file=sys.stderr)
    print(json.dumps(board, indent=2, sort_keys=True))
    return 0


def _cmd_validate(args):
    config = load_config(args.policy_json)
    board = _read_json(args.board_config)
    problems = validate_board_config(config, board)
    if not problems and args.fields:
        problems = live_problems(board, _read_json(args.fields))
    for problem in problems:
        print("FAIL %s" % problem)
    return EXIT_FAILED if problems else 0


def _cmd_sync(args):
    if not os.path.exists(args.board_config):
        print("board sync skipped: this project has no %s" % args.board_config)
        return 0
    config = load_config(args.policy_json)
    board = _read_json(args.board_config)
    problems = validate_board_config(config, board)
    if problems:
        for problem in problems:
            print("FAIL %s" % problem, file=sys.stderr)
        return EXIT_FAILED
    token = os.environ.get("BOARD_TOKEN", "")
    if not token:
        print("::warning::board sync skipped: the board is set up but no credential is configured (BOARD_TOKEN)")
        return 0
    event = _read_json(args.event)
    print("board sync: %s" % sync(config, board, event, args.repo, token, bot_login=os.environ.get("FACTORY_BOT_LOGIN", ""),
                                  extra_owners=os.environ.get("FACTORY_BOARD_OWNERS", "")))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("--policy", default=DEFAULT_POLICY)
    check.add_argument("--workflow-config", default=DEFAULT_WORKFLOW_CONFIG)
    check.add_argument("--rendered", default=DEFAULT_RENDERED)
    rendering = sub.add_parser("render")
    rendering.add_argument("--policy", default=DEFAULT_POLICY)
    rendering.add_argument("--out", required=True)
    titles = sub.add_parser("titles")
    titles.add_argument("--policy-json", required=True)
    mapping = sub.add_parser("map")
    mapping.add_argument("--policy-json", required=True)
    mapping.add_argument("--owner", required=True)
    mapping.add_argument("--owner-type", required=True, choices=["organization", "user"])
    mapping.add_argument("--number", required=True, type=int)
    mapping.add_argument("--fields")
    mapping.add_argument("--status-field")
    mapping.add_argument("--created", action="store_true")
    validate = sub.add_parser("validate")
    validate.add_argument("--policy-json", required=True)
    validate.add_argument("--board-config", required=True)
    validate.add_argument("--fields")
    syncing = sub.add_parser("sync")
    syncing.add_argument("--event", required=True)
    syncing.add_argument("--policy-json", required=True)
    syncing.add_argument("--board-config", required=True)
    syncing.add_argument("--repo", required=True)
    args = parser.parse_args(argv)
    commands = {"check": _cmd_check, "render": _cmd_render, "titles": _cmd_titles, "map": _cmd_map,
                "validate": _cmd_validate, "sync": _cmd_sync}
    try:
        return commands[args.command](args)
    except (OSError, ValueError, KeyError, RuntimeError, json.JSONDecodeError) as error:
        print("FAIL %s" % error, file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
