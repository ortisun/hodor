#!/usr/bin/env python3
"""The GitHub issue workflow: check the policy, render it, and enforce it on an issue.

One file, three uses (ADR 0016):

  * CI and developers:   check, render   (read policies/issue-workflow.yaml, need PyYAML)
  * the installer:       labels          (read the rendered JSON, standard library only)
  * the GitHub Action:   apply           (read the rendered JSON, standard library only; the
                                          installer copies this file into the target repository)

The standard library is all that `labels` and `apply` import. PyYAML is imported inside `load_policy`
only, so the copy that runs in a target repository needs nothing installed.

Safety rules, each with a test in scripts/tests/test_issue_workflow.py:
  * The trigger label is never added or removed by this code. A label alone must not authorize work.
  * The `factory: ` namespace is written by the factory's GitHub App only. Any other writer is reverted.
  * Text from an issue (title, body, comments, label names it did not define) is data. It is matched
    against fixed patterns and is never put into a command line, a shell or a comment.
  * `apply` reads the labels and the body again from GitHub and does not trust the event payload for them.
  * A failed GitHub call fails the run. Nothing is skipped silently.

Usage:
  issue_workflow.py check  [--policy P] [--approval A] [--state-machine S] [--rendered R]
  issue_workflow.py render [--policy P] --out FILE
  issue_workflow.py labels --config FILE
  issue_workflow.py apply  --event FILE --config FILE --repo OWNER/NAME [--docs-root DIR]
                           (environment: GH_TOKEN, FACTORY_BOT_LOGIN)

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

SCHEMA = "factory-issue-workflow/1"
EXIT_FAILED, EXIT_USAGE, EXIT_BLOCKED = 1, 2, 3

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
DEFAULT_POLICY = os.path.join(ROOT, "policies", "issue-workflow.yaml")
DEFAULT_APPROVAL = os.path.join(ROOT, "policies", "approval.yaml")
DEFAULT_STATE_MACHINE = os.path.join(ROOT, "docs", "architecture", "state-machine.json")
DEFAULT_RENDERED = os.path.join(ROOT, "onboarding", "github", "issue-workflow.json")

COLOR = re.compile(r"^[0-9a-f]{6}$")
PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]+$")
GATE_MARKER = "<!-- issue-workflow:design-gate -->"

# ---------------------------------------------------------------------------------------------
# Policy: load, check, render
# ---------------------------------------------------------------------------------------------

_TOP_KEYS = {"schema_version", "policy", "trigger", "namespaces", "design_track", "factory_track", "intake_requirements"}
_ALLOWED = {
    "policy": {"id", "status"},
    "trigger": {"label", "color", "description"},
    "namespace": {"prefix", "written_by"},
    "design_track": {"start_states", "states", "transitions", "approval_requires"},
    "design_state": {"name", "color", "description"},
    "transition": {"from", "to"},
    "approval_requires": {"design_document"},
    "design_document": {"issue_body_field", "path_glob"},
    "factory_track": {"states"},
    "factory_state": {"job_state", "name", "color", "description"},
    "intake_requirements": {"design_track_requires", "design_approved_by", "design_refusal_cap_per_issue",
                            "design_withdrawal_cap_per_issue", "design_environment_cap_per_issue",
                            "design_reply_window_hours"},
}

# The caps on the replies the factory posts on one issue about its design (DG-9, DR-4), one for each kind of
# reply, and the window they share: how many, and over how many hours. Whole numbers, never zero, and no larger
# than what the engine's adapter can count in the pages it looks at.
_REPLY_CAP_RANGE = (1, 100)
_REPLY_WINDOW_HOURS_RANGE = (1, 168)

# The designations that may be named as the approver of a design (`intake_requirements.design_approved_by`).
# `requester` and `operator` are left out on purpose: the person who asks for work must not also be the
# person whose label says the design is approved, and an operator does not decide designs.
_DESIGN_APPROVER_DESIGNATIONS = {"approver", "security_approver", "repo_admin", "org_admin"}


def load_policy(path):
    """Parse the policy file. Needs PyYAML, which only the CI and developer subcommands use."""
    try:
        import yaml  # noqa: PLC0415  (imported here on purpose: `apply` must run without it)
    except ImportError:
        print("BLOCKED: PyYAML is not installed. Run through: uv run --no-project --with pyyaml==6.0.3 python -I ...",
              file=sys.stderr)
        sys.exit(EXIT_BLOCKED)
    with open(path, "rb") as handle:
        raw = handle.read()
    return yaml.safe_load(raw), raw


def _unknown(section, mapping, errors):
    if not isinstance(mapping, dict):
        errors.append("shape: %s must be a mapping" % section)
        return False
    extra = sorted(set(mapping) - _ALLOWED[section.split("[")[0]])
    if extra:
        errors.append("unknown-key: %s has unknown key(s) %s" % (section, ", ".join(map(str, extra))))
    return True


def _label_problems(name, color, description):
    problems = []
    if not isinstance(name, str) or not (1 <= len(name) <= 50) or not PRINTABLE_ASCII.match(name) or name != name.strip():
        problems.append("name %r must be 1 to 50 printable ASCII characters with no edge spaces" % (name,))
    if not isinstance(color, str) or not COLOR.match(color):
        problems.append("color %r must be six lower-case hex digits" % (color,))
    if not isinstance(description, str) or not (1 <= len(description) <= 100) or any(ord(c) < 32 for c in description):
        problems.append("description of %r must be 1 to 100 characters with no control characters" % (name,))
    return problems


def check_policy(policy, approval, state_machine):
    """Return a list of problems. An empty list means the policy is sound."""
    errors = []
    if not isinstance(policy, dict):
        return ["shape: the policy must be a mapping"]
    extra = sorted(set(policy) - _TOP_KEYS)
    if extra:
        errors.append("unknown-key: top level has unknown key(s) %s" % ", ".join(map(str, extra)))
    if policy.get("schema_version") != 1:
        errors.append("schema-version: schema_version must be 1")
    _unknown("policy", policy.get("policy", {}), errors)

    # Namespaces: exactly two, one writer each.
    namespaces = policy.get("namespaces", {})
    expected = {"design": ("design: ", "people"), "factory": ("factory: ", "factory")}
    if not isinstance(namespaces, dict) or set(namespaces) != set(expected):
        errors.append("namespaces: must be exactly design and factory")
        namespaces = {}
    for key, (prefix, writer) in expected.items():
        entry = namespaces.get(key)
        if entry is None:
            continue
        _unknown("namespace[%s]" % key, entry, errors)
        if entry.get("prefix") != prefix or entry.get("written_by") != writer:
            errors.append("namespaces: %s must have prefix %r and be written by %s" % (key, prefix, writer))

    # Trigger.
    trigger = policy.get("trigger", {})
    _unknown("trigger", trigger, errors)
    trigger_label = trigger.get("label") if isinstance(trigger, dict) else None
    errors += ["label: trigger " + p for p in _label_problems(trigger_label, trigger.get("color"), trigger.get("description"))]
    if isinstance(trigger_label, str):
        if trigger_label.startswith(("design: ", "factory: ")):
            errors.append("trigger-namespace: the trigger label must be outside both namespaces")
        approved_trigger = ((approval or {}).get("intake") or {}).get("trigger_label")
        if trigger_label != approved_trigger:
            errors.append("trigger-mismatch: trigger.label %r differs from intake.trigger_label %r in approval.yaml"
                          % (trigger_label, approved_trigger))

    seen = {}

    def remember(name, where):
        if isinstance(name, str):
            if name.lower() in seen:
                errors.append("duplicate-label: %r is used by %s and %s" % (name, seen[name.lower()], where))
            seen[name.lower()] = where

    remember(trigger_label, "trigger")

    # Design track.
    design = policy.get("design_track", {})
    _unknown("design_track", design, errors)
    states = design.get("states", []) if isinstance(design, dict) else []
    design_names = []
    for index, state in enumerate(states):
        if not _unknown("design_state[%d]" % index, state, errors):
            continue
        full = "design: " + str(state.get("name"))
        errors += ["label: " + p for p in _label_problems(full, state.get("color"), state.get("description"))]
        remember(full, "design state %s" % state.get("name"))
        design_names.append(state.get("name"))
    if len(set(design_names)) != len(design_names):
        errors.append("duplicate-state: design states must have unique names")
    start = design.get("start_states", []) if isinstance(design, dict) else []
    for name in start:
        if name not in design_names:
            errors.append("start-state: %r is not a design state" % (name,))
    if not start:
        errors.append("start-state: at least one start state is needed")
    edges = []
    for index, edge in enumerate(design.get("transitions", []) if isinstance(design, dict) else []):
        if not _unknown("transition[%d]" % index, edge, errors):
            continue
        source, target = edge.get("from"), edge.get("to")
        if source not in design_names or target not in design_names:
            errors.append("transition: %r -> %r names a state that does not exist" % (source, target))
        elif source == target:
            errors.append("transition: %r -> %r goes nowhere" % (source, target))
        elif (source, target) in edges:
            errors.append("transition: %r -> %r is listed twice" % (source, target))
        edges.append((source, target))
    reachable = {s for s in start if s in design_names}
    grew = True
    while grew:
        grew = False
        for source, target in edges:
            if source in reachable and target not in reachable:
                reachable.add(target)
                grew = True
    for name in design_names:
        if name not in reachable:
            errors.append("unreachable-state: design state %r cannot be reached from a start state" % (name,))
    required = (policy.get("intake_requirements") or {}).get("design_track_requires")
    _unknown("intake_requirements", policy.get("intake_requirements", {}), errors)
    if required not in design_names:
        errors.append("intake-requirement: design_track_requires %r is not a design state" % (required,))
    approver = (policy.get("intake_requirements") or {}).get("design_approved_by")
    if approver not in _DESIGN_APPROVER_DESIGNATIONS:
        errors.append("design-approver: design_approved_by %r must be one of %s"
                      % (approver, ", ".join(sorted(_DESIGN_APPROVER_DESIGNATIONS))))
    for key, label, (low, high) in (
            ("design_refusal_cap_per_issue", "design-reply-cap", _REPLY_CAP_RANGE),
            ("design_withdrawal_cap_per_issue", "design-reply-cap", _REPLY_CAP_RANGE),
            ("design_environment_cap_per_issue", "design-reply-cap", _REPLY_CAP_RANGE),
            ("design_reply_window_hours", "design-reply-window", _REPLY_WINDOW_HOURS_RANGE)):
        value = (policy.get("intake_requirements") or {}).get(key)
        # A bool is an int in Python and is not a number of replies.
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            errors.append("%s: %s %r must be a whole number from %d to %d" % (label, key, value, low, high))
    _unknown("approval_requires", (design or {}).get("approval_requires", {}), errors)
    document = ((design or {}).get("approval_requires") or {}).get("design_document") or {}
    _unknown("design_document", document, errors)
    glob = document.get("path_glob", "")
    if not re.match(r"^docs/designs/(\*|[A-Za-z0-9._-]+)\.md$", str(glob)) or ".." in str(glob):
        errors.append("path-glob: design_document.path_glob must look like docs/designs/*.md")
    if not re.match(r"^[A-Za-z ]{1,40}$", str(document.get("issue_body_field", ""))):
        errors.append("body-field: design_document.issue_body_field must be 1 to 40 letters and spaces")

    # Factory track: one label per job state, no job state left out, none invented.
    factory = policy.get("factory_track", {})
    _unknown("factory_track", factory, errors)
    job_states = []
    for index, state in enumerate(factory.get("states", []) if isinstance(factory, dict) else []):
        if not _unknown("factory_state[%d]" % index, state, errors):
            continue
        full = "factory: " + str(state.get("name"))
        errors += ["label: " + p for p in _label_problems(full, state.get("color"), state.get("description"))]
        remember(full, "factory state %s" % state.get("name"))
        job_states.append(state.get("job_state"))
    machine_states = list(((state_machine or {}).get("machines") or {}).get("job", {}).get("states", []))
    if len(set(job_states)) != len(job_states):
        errors.append("job-state: a job state is mapped twice")
    for name in machine_states:
        if name not in job_states:
            errors.append("job-state: the engine job state %s has no factory label" % name)
    for name in job_states:
        if name not in machine_states:
            errors.append("job-state: %s is not a job state of the engine" % name)
    return errors


def render(policy, raw):
    """The JSON that the installer and the Action read. Deterministic: the same policy gives the same bytes."""
    design = policy["design_track"]
    labels = [{"name": policy["trigger"]["label"], "color": policy["trigger"]["color"],
               "description": policy["trigger"]["description"], "kind": "trigger"}]
    for state in design["states"]:
        labels.append({"name": "design: " + state["name"], "color": state["color"],
                       "description": state["description"], "kind": "design"})
    for state in policy["factory_track"]["states"]:
        labels.append({"name": "factory: " + state["name"], "color": state["color"],
                       "description": state["description"], "kind": "factory"})
    document = design["approval_requires"]["design_document"]
    out = {
        "schema": SCHEMA,
        "source": "policies/issue-workflow.yaml",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "trigger": policy["trigger"]["label"],
        "labels": labels,
        "design": {
            "prefix": policy["namespaces"]["design"]["prefix"],
            "start_states": design["start_states"],
            "transitions": [[e["from"], e["to"]] for e in design["transitions"]],
            "approved": policy["intake_requirements"]["design_track_requires"],
            "reply_caps_per_issue": {
                "refusal": policy["intake_requirements"]["design_refusal_cap_per_issue"],
                "withdrawal": policy["intake_requirements"]["design_withdrawal_cap_per_issue"],
                "environment": policy["intake_requirements"]["design_environment_cap_per_issue"],
            },
            "reply_window_hours": policy["intake_requirements"]["design_reply_window_hours"],
            "document_field": document["issue_body_field"],
            "document_glob": document["path_glob"],
        },
        "factory": {
            "prefix": policy["namespaces"]["factory"]["prefix"],
            "job_states": {s["job_state"]: "factory: " + s["name"] for s in policy["factory_track"]["states"]},
        },
    }
    return json.dumps(out, indent=2, sort_keys=True) + "\n"


def load_config(path):
    with open(path, encoding="utf-8") as handle:
        config = json.load(handle)
    if config.get("schema") != SCHEMA:
        raise ValueError("the config is not %s" % SCHEMA)
    return config


# ---------------------------------------------------------------------------------------------
# The decision: pure, no network, no files
# ---------------------------------------------------------------------------------------------

def _names(config, kind):
    return {label["name"] for label in config["labels"] if label["kind"] == kind}


def _state(config, label):
    return label[len(config["design"]["prefix"]):]


def design_document_path(config, body):
    """The design document the issue body names, or None. The body is untrusted: only a fixed pattern is accepted."""
    field = re.escape(config["design"]["document_field"])
    # Issue forms in a browser send "\r\n". The body is read line by line, so unify the line endings first.
    text = (body or "").replace("\r\n", "\n").replace("\r", "\n")
    found = re.search(r"(?m)^%s:[ \t]*(\S+)[ \t]*$" % field, text)
    if not found:
        return None
    glob = config["design"]["document_glob"]
    pattern = "^" + re.escape(glob).replace(r"\*", "[A-Za-z0-9._-]+") + "$"
    path = found.group(1)
    return path if re.match(pattern, path) and ".." not in path else None


def decide(config, *, action, label, sender_login, sender_type, current, factory_bot_login, design_doc_exists):
    """Return the operations that keep an issue consistent after a label event.

    `current` is the set of label names the issue carries now, and `design_doc_exists` says whether the issue names a
    design document that is on the default branch (the caller works that out from the body, which is untrusted). The result is a list of
    ("remove_label", name), ("add_label", name) and ("comment", text) tuples. This function adds or
    removes the trigger label never, whatever the input.
    """
    ops = []
    trigger = config["trigger"]
    design_names, factory_names = _names(config, "design"), _names(config, "factory")
    design_prefix, factory_prefix = config["design"]["prefix"], config["factory"]["prefix"]
    approved = design_prefix + config["design"]["approved"]
    current = set(current)

    if label == trigger:
        # Applying the trigger is a decision of an authorized person, taken by the engine. The Action only
        # warns, because the engine does not yet refuse a design-track issue that is not approved (ADR 0016).
        if action == "labeled" and (current & design_names) and approved not in current:
            ops.append(("comment", GATE_MARKER + "\nThis issue is on the design track and its design is not approved yet "
                        "(it has no `%s` label). Work should start from an approved design. Until the factory "
                        "itself checks this, a person has to watch for it." % approved))
        return ops

    in_design = label.startswith(design_prefix)
    in_factory = label.startswith(factory_prefix)
    if not (in_design or in_factory):
        return ops

    if in_factory:
        is_bot = bool(factory_bot_login) and sender_type == "Bot" and sender_login.lower() == factory_bot_login.lower()
        if action == "labeled":
            if is_bot and label in factory_names:
                ops += [("remove_label", other) for other in sorted(current & factory_names) if other != label]
            else:
                ops.append(("remove_label", label))
                ops.append(("comment", "Labels that start with `%s` show the state of the factory's work, and only the "
                            "factory sets them. That label was removed." % factory_prefix.strip()))
        elif action == "unlabeled" and not is_bot and label in factory_names:
            ops.append(("add_label", label))
            ops.append(("comment", "The `%s` label shows the state of the factory's work, and only the factory changes "
                        "it. It was put back." % label))
        return ops

    # The design namespace.
    if action != "labeled":
        return ops  # allowed here; the engine keeps the issue on the track
    if label not in design_names:
        return [("remove_label", label),
                ("comment", "That label is not a design state. The states are: %s." %
                 ", ".join("`%s`" % n for n in sorted(design_names)))]
    others = sorted((current & design_names) - {label})
    target = _state(config, label)
    transitions = {tuple(edge) for edge in config["design"]["transitions"]}
    if not others:
        legal = target in config["design"]["start_states"]
        why = "A design starts as `proposed` or `in progress`."
    else:
        legal = any((_state(config, o), target) in transitions for o in others)
        why = "That move is not allowed from %s." % ", ".join("`%s`" % o for o in others)
    if legal and label == approved and not design_doc_exists:
        legal = False
        why = ("A design is approved only when the issue names a design document on the default branch. Add a line "
               "`%s: docs/designs/<name>.md` to the issue and merge the design pull request first." %
               config["design"]["document_field"])
    if not legal:
        return [("remove_label", label), ("comment", "The label `%s` was removed. %s" % (label, why))]
    return [("remove_label", o) for o in others]


# ---------------------------------------------------------------------------------------------
# GitHub: the only part that talks to the network
# ---------------------------------------------------------------------------------------------

class NotFound(RuntimeError):
    """GitHub answered 404. Taking away a label that is already gone is not a failure."""


def gh_api(method, path, fields=None, paginate=False):
    """Run one `gh api` call. The arguments are a list, never a shell string, and the path is built by the caller."""
    command = ["gh", "api", "-X", method, path]
    if paginate:
        command.append("--paginate")
    for key, value in (fields or {}).items():
        command += ["-f", "%s=%s" % (key, value)]
    done = subprocess.run(command, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        error = NotFound if "HTTP 404" in (done.stderr or "") else RuntimeError
        raise error("gh api %s %s failed with exit code %d" % (method, path, done.returncode))
    return done.stdout


def parse_pages(text):
    """The JSON arrays that `gh api --paginate` prints one after the other, as one list. Tolerant of both layouts."""
    decoder, index, items = json.JSONDecoder(), 0, []
    text = text or ""
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        value, index = decoder.raw_decode(text, index)
        for item in value if isinstance(value, list) else [value]:
            items.extend(item if isinstance(item, list) else [item])
    return items


def last_labelers(events):
    """For each label now on the issue: who applied it last, and when (the position in the list). From the issue events."""
    latest = {}
    for position, event in enumerate(events):
        label = event.get("label") if isinstance(event.get("label"), dict) else None
        if not label or not isinstance(label.get("name"), str):
            continue
        if event.get("event") == "labeled":
            actor = event.get("actor") if isinstance(event.get("actor"), dict) else {}
            latest[label["name"]] = (str(actor.get("login", "")), str(actor.get("type", "")), position)
        elif event.get("event") == "unlabeled":
            latest.pop(label["name"], None)
    return latest


def reconcile(config, *, current, labelers, factory_bot_login, design_doc_exists, restored=()):
    """Operations that make the WHOLE issue consistent, whatever events were seen or dropped.

    A run of the Action judges the label of its own event. GitHub keeps one waiting run per issue and drops the older
    waiting ones, so a run can be skipped, and a skipped label would stay. Every run therefore also checks the state:
      * a `factory: ` label stays only if the factory's App was the last to apply it, and only one stays;
      * one `design: ` label stays (the most recently applied), and `approved` stays only with a design document;
      * a label of either namespace that the policy does not define goes.
    `restored` names the labels that this same run has just put back for the factory; they are not judged by who applied
    them, because the events were read before. The trigger label is never touched.
    Returns ("remove_label", name) operations, and one ("comment", text) when it removed anything.
    """
    design_names, factory_names = _names(config, "design"), _names(config, "factory")
    design_prefix, factory_prefix = config["design"]["prefix"], config["factory"]["prefix"]
    approved = design_prefix + config["design"]["approved"]
    bot = (factory_bot_login or "").lower()
    current = set(current) - {config["trigger"]}
    restored = set(restored)

    def position(name):
        return labelers.get(name, ("", "", -1))[2]

    removed = set()
    for name in sorted(current):
        if name.startswith(factory_prefix):
            login, kind, _ = labelers.get(name, ("", "", -1))
            by_the_factory = bool(bot) and kind == "Bot" and login.lower() == bot
            if name not in factory_names or not (by_the_factory or name in restored):
                removed.add(name)
        elif name.startswith(design_prefix) and name not in design_names:
            removed.add(name)
    for names in (factory_names, design_names):
        kept = sorted((current & names) - removed, key=lambda n: (position(n), n))
        removed.update(kept[:-1])
    if approved in current and approved not in removed and not design_doc_exists:
        removed.add(approved)
    if not removed:
        return []
    named = sorted(removed & (design_names | factory_names))
    text = ("Some labels did not follow the issue workflow and were put right: %s." % ", ".join("`%s`" % n for n in named)
            if named else "A label of the `design:` or `factory:` group that the workflow does not define was removed.")
    return [("remove_label", name) for name in sorted(removed)] + [("comment", text)]


def _is_the_gate_comment(comment):
    """True for a comment that the Action itself posted: the bot account of GitHub Actions, and the marker first."""
    if not isinstance(comment, dict) or not isinstance(comment.get("user"), dict):
        return False
    user = comment["user"]
    return (user.get("login") == "github-actions[bot]" and user.get("type") == "Bot"
            and str(comment.get("body", "")).startswith(GATE_MARKER))


def _remove(api, base, name):
    try:
        api("DELETE", "%s/labels/%s" % (base, urllib.parse.quote(name, safe="")))
    except NotFound:
        pass  # already gone, for example because the factory moved the status in the same moment


def plain_file(root, relative):
    """True when root/relative is a regular file and no part of the path below root is a symbolic link."""
    current = root
    for part in relative.split("/"):
        current = os.path.join(current, part)
        if os.path.islink(current):
            return False
    return os.path.isfile(current)


def apply_event(config, event, repo, docs_root, bot_login, api=gh_api):
    """Read the issue again, decide, reconcile the whole issue, and carry the operations out. `api` is replaceable."""
    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repo) or {".", ".."} & set(repo.split("/")):
        raise ValueError("the repository must look like OWNER/NAME")
    # The copied configuration is trusted at run time, so refuse one that makes a namespace swallow the trigger.
    if not config["trigger"] or config["trigger"].startswith((config["design"]["prefix"], config["factory"]["prefix"])):
        raise ValueError("the trigger label must be outside both namespaces")
    number = int(event["issue"]["number"])
    base = "repos/%s/issues/%d" % (repo, number)
    issue = json.loads(api("GET", base))
    current = {item["name"] for item in issue.get("labels", [])}
    body = issue.get("body") or ""
    path = design_document_path(config, body)
    exists = bool(path) and plain_file(docs_root, path)
    ops = decide(
        config,
        action=event["action"],
        label=event["label"]["name"],
        sender_login=event["sender"]["login"],
        sender_type=event["sender"]["type"],
        current=current,
        factory_bot_login=bot_login or "",
        design_doc_exists=exists,
    )
    # What the event-driven rules already took away or put back, so that the state check judges the result.
    after = set(current)
    for op in ops:
        if op[0] == "remove_label":
            after.discard(op[1])
        elif op[0] == "add_label":
            after.add(op[1])
    labelers = last_labelers(parse_pages(api("GET", base + "/events?per_page=100", paginate=True)))
    already = {op[1] for op in ops if op[0] == "remove_label"}
    ops = ops + [op for op in reconcile(config, current=after, labelers=labelers, factory_bot_login=bot_login or "",
                                        design_doc_exists=exists,
                                        restored={o[1] for o in ops if o[0] == "add_label"})
                 if op[0] == "comment" or op[1] not in already]
    for op in ops:
        if op[0] == "remove_label":
            _remove(api, base, op[1])
        elif op[0] == "add_label":
            api("POST", base + "/labels", {"labels[]": op[1]})
        elif op[0] == "comment":
            text = op[1]
            if GATE_MARKER in text:
                # Only the Action's own comments count (PL-12). Anyone can paste the marker into a comment, so the
                # comment must be by the Actions bot account and must BEGIN with the marker, as the Action writes it.
                if any(_is_the_gate_comment(c) for c in parse_pages(api("GET", base + "/comments", paginate=True))):
                    continue
            api("POST", base + "/comments", {"body": text})
    return ops


# ---------------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------------

def _cmd_check(args):
    policy, raw = load_policy(args.policy)
    approval, _ = load_policy(args.approval)
    with open(args.state_machine, encoding="utf-8") as handle:
        machine = json.load(handle)
    errors = check_policy(policy, approval, machine)
    if not errors and args.rendered:
        try:
            with open(args.rendered, encoding="utf-8") as handle:
                on_disk = handle.read()
        except OSError:
            on_disk = None
        if on_disk != render(policy, raw):
            errors.append("stale-rendering: %s is not the current rendering. Run: issue_workflow.py render --out %s"
                          % (args.rendered, args.rendered))
    for error in errors:
        print("FAIL %s" % error)
    if errors:
        return EXIT_FAILED
    print("OK the issue workflow policy is sound: %d labels" % (len(policy["design_track"]["states"]) +
                                                               len(policy["factory_track"]["states"]) + 1))
    return 0


def _cmd_render(args):
    policy, raw = load_policy(args.policy)
    with open(args.state_machine, encoding="utf-8") as handle:
        machine = json.load(handle)
    approval, _ = load_policy(args.approval)
    errors = check_policy(policy, approval, machine)
    if errors:
        for error in errors:
            print("FAIL %s" % error)
        return EXIT_FAILED
    text = render(policy, raw)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(text)
    print("wrote %s" % args.out)
    return 0


def _cmd_labels(args):
    for label in load_config(args.config)["labels"]:
        print("%s\t%s\t%s" % (label["name"], label["color"], label["description"]))
    return 0


def _clean(text):
    """A string for the log: printable ASCII only, so a label name cannot write a workflow command or a control code."""
    return re.sub(r"[^\x20-\x7e]", "?", str(text))


def _cmd_apply(args):
    with open(args.event, encoding="utf-8") as handle:
        event = json.load(handle)
    if event.get("action") not in ("labeled", "unlabeled") or "label" not in event:
        print("nothing to do: not a label event")
        return 0
    bot_login = os.environ.get("FACTORY_BOT_LOGIN", "").strip()
    if not bot_login:
        # PL-21. Without the App's login every `factory:` label looks like a person's, so the Action would take the
        # factory's own status labels away and comment on each state change. It does nothing instead: no read, no
        # label, no comment. The text is fixed, and the annotation shows in the run's summary.
        print("nothing done: the repository variable FACTORY_BOT_LOGIN is not set, so this Action cannot tell the "
              "factory's own labels from a person's. It read nothing, changed no label and wrote no comment. Set the "
              "variable to the login of the factory's GitHub App, for example my-factory[bot].")
        print("::warning title=FACTORY_BOT_LOGIN is not set::The issue workflow did nothing. Set the repository "
              "variable FACTORY_BOT_LOGIN to the login of the factory's GitHub App.")
        return 0
    ops = apply_event(load_config(args.config), event, args.repo, args.docs_root, bot_login)
    for op in ops:
        print("%s %s" % (op[0], _clean(op[1].splitlines()[0] if op[0] == "comment" else op[1])))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "render"):
        p = sub.add_parser(name)
        p.add_argument("--policy", default=DEFAULT_POLICY)
        p.add_argument("--approval", default=DEFAULT_APPROVAL)
        p.add_argument("--state-machine", default=DEFAULT_STATE_MACHINE)
        if name == "check":
            p.add_argument("--rendered", default=DEFAULT_RENDERED)
        else:
            p.add_argument("--out", required=True)
    labels = sub.add_parser("labels")
    labels.add_argument("--config", required=True)
    apply_ = sub.add_parser("apply")
    apply_.add_argument("--event", required=True)
    apply_.add_argument("--config", required=True)
    apply_.add_argument("--repo", required=True)
    apply_.add_argument("--docs-root", default=".")
    args = parser.parse_args(argv)
    try:
        return {"check": _cmd_check, "render": _cmd_render, "labels": _cmd_labels, "apply": _cmd_apply}[args.command](args)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print("FAIL %s" % error, file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
