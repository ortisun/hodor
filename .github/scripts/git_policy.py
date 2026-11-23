#!/usr/bin/env python3
"""The git policy of a project that works with the factory: Conventional Commits and gitflow.

One file, three uses. The installer (scripts/install.sh) copies it into the project as `.github/scripts/git_policy.py`.

  * the installer:      resolve, write        find the repository, the board and the gitflow closing mode, and record them
  * a person and hooks: configure, hook ...   the git hooks in `.github/githooks/` call `hook commit-msg|pre-commit|pre-push`
  * the GitHub Action:  check-pr              `.github/workflows/git-policy.yml` checks every pull request

The settings live in `.factory/repository.json`, in the project. They say which GitHub repository the project is, which
GitHub Projects board tracks it (or none), which commit types are allowed, and how the gitflow branches close:

  closing_mode "develop"   classic gitflow. feature/ and bugfix/ branches close into develop. A release/ branch is cut
                           from develop and closes into main and back into develop.
  closing_mode "release"   feature/ and bugfix/ branches close straight into the open release/ branch. The release branch
                           closes into main and back into develop.

In both modes hotfix/ branches close into main, develop or the open release branch, and nobody commits on main or
develop directly: work reaches them by merging a branch. The factory's own branches (factory/...) are feature branches.

Where a value comes from, in order: a flag, the settings file, then what can be inferred. The repository is inferred
from the git remote (origin, or the only GitHub remote) and, failing that, from `gh repo view`. The board is inferred
from `.github/project-board.json` or from the one open board linked to the repository. The closing mode is inferred from
history: the merged pull requests of feature and bugfix branches (through `gh`) and the merge commits that git wrote.
Three or more such merges, of which at least four in five went the same way, make an inference; anything less is a
guess that a person confirms. Two remotes that disagree, or two boards, are never guessed between.

When a value is missing and a terminal is there, the person is asked (on /dev/tty, so it works inside a git hook).
Without a terminal nothing is asked: the command says what is missing and how to give it.

Usage:
  git_policy.py resolve   [--checkout DIR] [--repo O/N] [--board O/N|none|new:OWNER] [--closing-mode develop|release]
                          [--interactive] [--allow-new-board] [--no-gh]
  git_policy.py write     [--checkout DIR] --repo O/N --board O/N|none --closing-mode develop|release [--check]
  git_policy.py configure [--checkout DIR] [--repo O/N] [--board O/N|none] [--closing-mode M] [--non-interactive]
  git_policy.py check-settings [--checkout DIR]
  git_policy.py check-message  [--file FILE] [--settings FILE]      (the message on standard input without --file)
  git_policy.py hook commit-msg FILE | hook pre-commit | hook pre-push REMOTE URL
  git_policy.py check-pr  --settings FILE --checkout DIR --base-ref B --head-ref H --base-sha S --head-sha S
                          [--title T]   (the title is read from PR_TITLE when --title is not given)

Exit codes: 0 fine, 1 a rule is broken or a command failed, 2 wrong arguments, 3 NEEDS a person (a value is missing).

Standard library only, Python 3.9 or later: it runs in the project, on a developer's machine and on a GitHub runner.
"""
from __future__ import annotations

import argparse
import dataclasses
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import IO, Any

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_NEEDS = 0, 1, 2, 3

SETTINGS_REL = os.path.join(".factory", "repository.json")
BOARD_CONFIG_REL = os.path.join(".github", "project-board.json")
SCHEMA = "factory-repository-settings/1"
CLOSING_MODES = ("develop", "release")
BRANCH_KINDS = ("feature", "bugfix", "release", "hotfix", "support")
DEFAULT_TYPES = ["build", "chore", "ci", "docs", "feat", "fix", "perf", "refactor", "revert", "style", "test"]
DEFAULT_PREFIXES: dict[str, list[str]] = {
    "feature": ["feature/", "factory/"],
    "bugfix": ["bugfix/"],
    "release": ["release/"],
    "hotfix": ["hotfix/"],
    "support": ["support/"],
}
DEFAULT_HEADER_MAX = 100
AUTOSQUASH = ("fixup! ", "squash! ", "amend! ")

# How sure history must be before it decides the closing mode without asking: at least MIN_EVIDENCE merges of feature or
# bugfix branches, of which at least AGREEMENT_NUM / AGREEMENT_DEN went the same way. Integer arithmetic, no rounding.
MIN_EVIDENCE = 3
AGREEMENT_NUM, AGREEMENT_DEN = 4, 5
HISTORY_LIMIT = 1000
PUSH_CHECK_LIMIT = 500
GH_TIMEOUT_SECONDS = 20

OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$")
PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/$")
TYPE_RE = re.compile(r"^[a-z][a-z0-9-]*$")
SCOPE_LIST_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
HEADER_RE = re.compile(r"^(?P<type>[A-Za-z][A-Za-z0-9-]*)(?:\((?P<scope>[^()]*)\))?(?P<bang>!)?:(?P<space> *)(?P<subject>.*)$")
GITHUB_REMOTE_RE = re.compile(
    r"^(?:https?://(?:[^/@]+@)?github\.com/|ssh://(?:[^/@]+@)?github\.com(?::\d+)?/|(?:[^/:@]+@)?github\.com:)"
    r"(?P<owner>[A-Za-z0-9-]+)/(?P<name>[A-Za-z0-9._-]+?)(?:\.git)?/?$"
)
GIT_MERGE_HEADER_RE = re.compile(r"^Merge (?:(?:remote-tracking )?branch|branches|tag|commit) '")
MERGE_SUBJECT_RE = re.compile(r"^Merge (?:remote-tracking )?branch '(?P<head>[^']+)' into (?P<base>\S+)$")
ZERO_SHA = re.compile(r"^0+$")


class UsageError(Exception):
    pass


# ---------------------------------------------------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------------------------------------------------
@dataclass
class Flow:
    head_prefix: str
    into: list[str]


@dataclass
class Settings:
    owner: str
    name: str
    board: tuple[str, int] | None
    closing_mode: str
    main_branch: str = "main"
    develop_branch: str = "develop"
    types: list[str] = field(default_factory=lambda: list(DEFAULT_TYPES))
    scopes: list[str] = field(default_factory=list)
    require_scope: bool = False
    header_max_length: int = DEFAULT_HEADER_MAX
    prefixes: dict[str, list[str]] = field(default_factory=lambda: {k: list(v) for k, v in DEFAULT_PREFIXES.items()})
    additional_flows: list[Flow] = field(default_factory=list)

    @property
    def repository(self) -> str:
        return "%s/%s" % (self.owner, self.name)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "repository": {"owner": self.owner, "name": self.name},
            "project_board": None if self.board is None else {"owner": self.board[0], "number": self.board[1]},
            "commits": {
                "convention": "conventional-commits",
                "types": list(self.types),
                "scopes": list(self.scopes),
                "require_scope": self.require_scope,
                "header_max_length": self.header_max_length,
            },
            "gitflow": {
                "closing_mode": self.closing_mode,
                "main_branch": self.main_branch,
                "develop_branch": self.develop_branch,
                "prefixes": {kind: list(self.prefixes[kind]) for kind in BRANCH_KINDS},
                "additional_flows": [{"head_prefix": f.head_prefix, "into": list(f.into)} for f in self.additional_flows],
            },
        }


class SettingsError(Exception):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def _keys(where: str, value: Any, required: set[str], problems: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        problems.append("%s must be an object" % where)
        return {}
    for key in sorted(set(value) - required):
        problems.append("%s has an unknown key '%s'" % (where, key))
    for key in sorted(required - set(value)):
        problems.append("%s is missing the key '%s'" % (where, key))
    return value


def _string_list(where: str, value: Any, pattern: re.Pattern[str], problems: list[str], allow_empty: bool) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        problems.append("%s must be a list of strings" % where)
        return []
    items: list[str] = list(value)
    if not items and not allow_empty:
        problems.append("%s must not be empty" % where)
    for item in items:
        if not pattern.match(item):
            problems.append("%s has a value that is not allowed: %r" % (where, item))
    if len(set(items)) != len(items):
        problems.append("%s lists a value twice" % where)
    return items


def _as_int(value: Any) -> int | None:
    """The value when it is a whole number (JSON true and false are not), else None."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def parse_settings(document: Any) -> Settings:
    """Validate a settings document. Unknown keys are errors at every level, like the project manifest."""
    problems: list[str] = []
    top = _keys("the settings", document, {"schema", "repository", "project_board", "commits", "gitflow"}, problems)
    if problems and not top:
        raise SettingsError(problems)
    if top.get("schema") != SCHEMA:
        problems.append("schema must be %r" % SCHEMA)

    repo = _keys("repository", top.get("repository", {}), {"owner", "name"}, problems)
    owner, name = repo.get("owner"), repo.get("name")
    if not isinstance(owner, str) or not OWNER_RE.match(owner):
        problems.append("repository.owner must be a GitHub login")
        owner = ""
    if not isinstance(name, str) or not NAME_RE.match(name) or name in (".", ".."):
        problems.append("repository.name must be a GitHub repository name")
        name = ""

    board: tuple[str, int] | None = None
    raw_board = top.get("project_board")
    if raw_board is not None:
        b = _keys("project_board", raw_board, {"owner", "number"}, problems)
        b_owner, b_number = b.get("owner"), _as_int(b.get("number"))
        if not isinstance(b_owner, str) or not OWNER_RE.match(b_owner):
            problems.append("project_board.owner must be a GitHub login")
        elif b_number is None or b_number < 1:
            problems.append("project_board.number must be a whole number of 1 or more")
        else:
            board = (b_owner, b_number)

    commits = _keys("commits", top.get("commits", {}),
                    {"convention", "types", "scopes", "require_scope", "header_max_length"}, problems)
    if commits.get("convention") != "conventional-commits":
        problems.append("commits.convention must be 'conventional-commits'")
    types = _string_list("commits.types", commits.get("types"), TYPE_RE, problems, allow_empty=False)
    scopes = _string_list("commits.scopes", commits.get("scopes"), SCOPE_LIST_RE, problems, allow_empty=True)
    require_scope = commits.get("require_scope")
    if not isinstance(require_scope, bool):
        problems.append("commits.require_scope must be true or false")
        require_scope = False
    header_max = _as_int(commits.get("header_max_length"))
    if header_max is None or not 20 <= header_max <= 200:
        problems.append("commits.header_max_length must be a whole number from 20 to 200")
        header_max = DEFAULT_HEADER_MAX

    flow = _keys("gitflow", top.get("gitflow", {}),
                 {"closing_mode", "main_branch", "develop_branch", "prefixes", "additional_flows"}, problems)
    mode = flow.get("closing_mode")
    if mode not in CLOSING_MODES:
        problems.append("gitflow.closing_mode must be 'develop' or 'release'")
        mode = "develop"
    main_branch, develop_branch = flow.get("main_branch"), flow.get("develop_branch")
    for key, value in (("main_branch", main_branch), ("develop_branch", develop_branch)):
        if not isinstance(value, str) or not BRANCH_RE.match(value):
            problems.append("gitflow.%s must be a branch name" % key)
    if isinstance(main_branch, str) and main_branch == develop_branch:
        problems.append("gitflow.main_branch and gitflow.develop_branch must differ")
    raw_prefixes = _keys("gitflow.prefixes", flow.get("prefixes", {}), set(BRANCH_KINDS), problems)
    prefixes: dict[str, list[str]] = {}
    seen: dict[str, str] = {}
    for kind in BRANCH_KINDS:
        prefixes[kind] = _string_list("gitflow.prefixes.%s" % kind, raw_prefixes.get(kind), PREFIX_RE, problems,
                                      allow_empty=False)
        for prefix in prefixes[kind]:
            if prefix in seen and seen[prefix] != kind:
                problems.append("gitflow.prefixes: %r is listed for both %s and %s" % (prefix, seen[prefix], kind))
            seen[prefix] = kind
    flows: list[Flow] = []
    raw_flows = flow.get("additional_flows")
    if not isinstance(raw_flows, list):
        problems.append("gitflow.additional_flows must be a list")
        raw_flows = []
    for index, item in enumerate(raw_flows):
        where = "gitflow.additional_flows[%d]" % index
        entry = _keys(where, item, {"head_prefix", "into"}, problems)
        head = entry.get("head_prefix")
        if not isinstance(head, str) or not PREFIX_RE.match(head):
            problems.append("%s.head_prefix must look like 'name/'" % where)
            continue
        if head in seen:
            problems.append("%s.head_prefix %r is already a gitflow prefix" % (where, head))
        into = _string_list(where + ".into", entry.get("into"), re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$"), problems,
                            allow_empty=False)
        flows.append(Flow(head, into))

    if problems:
        raise SettingsError(problems)
    assert isinstance(owner, str) and isinstance(name, str) and isinstance(main_branch, str)
    assert isinstance(develop_branch, str) and isinstance(mode, str)
    return Settings(owner=owner, name=name, board=board, closing_mode=mode, main_branch=main_branch,
                    develop_branch=develop_branch, types=types, scopes=scopes, require_scope=require_scope,
                    header_max_length=header_max, prefixes=prefixes, additional_flows=flows)


def load_settings(path: str) -> Settings:
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as error:
        raise SettingsError(["%s is not readable JSON (%s)" % (path, error)]) from None
    return parse_settings(document)


def settings_text(settings: Settings) -> str:
    return json.dumps(settings.to_json(), indent=2) + "\n"


def atomic_write(path: str, text: str) -> None:
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=folder, prefix=".git_policy.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


# ---------------------------------------------------------------------------------------------------------------------
# git and gh
# ---------------------------------------------------------------------------------------------------------------------
def git(checkout: str, *args: str) -> tuple[int, str]:
    """Run git in the checkout without letting its configuration start a program (fsmonitor, hooks)."""
    environment = dict(os.environ, GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    try:
        done = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", checkout,
                               *args], capture_output=True, text=True, env=environment, check=False)
    except OSError:
        return 127, ""
    return done.returncode, done.stdout


def gh(checkout: str, *args: str) -> tuple[int, str]:
    try:
        done = subprocess.run(["gh", *args], capture_output=True, text=True, cwd=checkout, check=False,
                              timeout=GH_TIMEOUT_SECONDS, env=dict(os.environ, NO_COLOR="1", GH_PROMPT_DISABLED="1"))
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return done.returncode, done.stdout


def is_git_repository(checkout: str) -> bool:
    rc, out = git(checkout, "rev-parse", "--is-inside-work-tree")
    return rc == 0 and out.strip() == "true"


def local_branches(checkout: str) -> set[str]:
    rc, out = git(checkout, "for-each-ref", "--format=%(refname:short)", "refs/heads")
    return set(out.split()) if rc == 0 else set()


def remote_branches(checkout: str) -> set[str]:
    """Branch names as last fetched from any remote, without the remote's name."""
    rc, out = git(checkout, "for-each-ref", "--format=%(refname)", "refs/remotes")
    names: set[str] = set()
    if rc != 0:
        return names
    for ref in out.split():
        parts = ref.split("/", 3)
        if len(parts) == 4 and parts[3] != "HEAD":
            names.add(parts[3])
    return names


def remotes(checkout: str) -> list[tuple[str, str]]:
    rc, out = git(checkout, "remote")
    if rc != 0:
        return []
    found = []
    for name in out.split():
        rc, url = git(checkout, "remote", "get-url", name)
        if rc == 0:
            found.append((name, url.strip()))
    return found


def parse_github_remote(url: str) -> tuple[str, str] | None:
    match = GITHUB_REMOTE_RE.match(url.strip())
    if not match:
        return None
    owner, name = match.group("owner"), match.group("name")
    if not OWNER_RE.match(owner) or not NAME_RE.match(name) or name in (".", ".."):
        return None
    return owner, name


def parse_repo(text: str) -> tuple[str, str] | None:
    owner, slash, name = text.strip().partition("/")
    if not slash or "/" in name or not OWNER_RE.match(owner) or not NAME_RE.match(name) or name in (".", ".."):
        return None
    return owner, name


def parse_board(text: str) -> tuple[str, int] | None:
    owner, slash, number = text.strip().partition("/")
    if not slash or not OWNER_RE.match(owner) or not number.isdigit() or int(number) < 1:
        return None
    return owner, int(number)


# ---------------------------------------------------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------------------------------------------------
@dataclass
class Found:
    """A value with where it came from. `sure` is False for a guess that only serves as the default of a question."""
    value: str | None
    source: str
    sure: bool = True
    choices: list[str] = field(default_factory=list)


def infer_repository(checkout: str, use_gh: bool) -> Found:
    candidates: dict[str, str] = {}
    unparsed: list[str] = []
    for remote, url in remotes(checkout):
        parsed = parse_github_remote(url)
        if parsed:
            candidates[remote] = "%s/%s" % parsed
        else:
            unparsed.append(remote)
    if "origin" in candidates:
        others = sorted({value for key, value in candidates.items() if key != "origin" and value != candidates["origin"]})
        if others:
            return Found(candidates["origin"], "the remote origin; other remotes name %s" % ", ".join(others), sure=False,
                         choices=[candidates["origin"]] + others)
        return Found(candidates["origin"], "the remote origin")
    distinct = sorted(set(candidates.values()))
    if len(distinct) == 1:
        remote = sorted(k for k, v in candidates.items() if v == distinct[0])[0]
        return Found(distinct[0], "the remote %s" % remote)
    if len(distinct) > 1:
        return Found(None, "the remotes name different repositories: %s" % ", ".join(distinct), sure=False,
                     choices=distinct)
    if unparsed and use_gh:
        # A remote with an SSH host alias (git@work:owner/name.git): gh resolves the alias through ssh's configuration.
        rc, out = gh(checkout, "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner")
        if rc == 0 and parse_repo(out):
            return Found(out.strip(), "gh repo view (the remote %s)" % unparsed[0])
    if unparsed:
        return Found(None, "the remote %s does not point at github.com" % unparsed[0], sure=False)
    return Found(None, "the checkout has no git remote", sure=False)


def board_from_config(checkout: str) -> tuple[str, int] | None:
    try:
        with open(os.path.join(checkout, BOARD_CONFIG_REL), encoding="utf-8") as handle:
            project = json.load(handle).get("project", {})
        owner, number = project.get("owner"), _as_int(project.get("number"))
    except (OSError, ValueError, AttributeError):
        return None
    if isinstance(owner, str) and OWNER_RE.match(owner) and number is not None and number >= 1:
        return owner, number
    return None


LINKED_QUERY = ("query($o:String!,$n:String!){repository(owner:$o,name:$n){projectsV2(first:20){nodes{number title "
                "closed owner{__typename ... on Organization{login} ... on User{login}}}}}}")


def linked_boards(checkout: str, repository: str) -> list[tuple[str, int, str]] | None:
    owner, _, name = repository.partition("/")
    rc, out = gh(checkout, "api", "graphql", "-f", "query=" + LINKED_QUERY, "-f", "o=" + owner, "-f", "n=" + name)
    if rc != 0:
        return None
    try:
        data = json.loads(out)
        nodes = ((((data.get("data") or {}).get("repository") or {}).get("projectsV2") or {}).get("nodes")) or []
    except (ValueError, AttributeError):
        return None
    boards = []
    for node in nodes:
        if not isinstance(node, dict) or node.get("closed"):
            continue
        login = (node.get("owner") or {}).get("login", "")
        number = _as_int(node.get("number"))
        if isinstance(login, str) and OWNER_RE.match(login) and number is not None and number >= 1:
            boards.append((login, number, str(node.get("title", ""))))
    return boards


def infer_board(checkout: str, repository: str | None, use_gh: bool) -> Found:
    configured = board_from_config(checkout)
    if configured:
        return Found("%s/%d" % configured, BOARD_CONFIG_REL)
    if not repository:
        return Found(None, "the repository is not known yet", sure=False)
    if not use_gh:
        return Found(None, "gh is not available to list the boards linked to %s" % repository, sure=False)
    boards = linked_boards(checkout, repository)
    if boards is None:
        return Found(None, "could not list the boards linked to %s (gh auth refresh -s project)" % repository, sure=False)
    if len(boards) == 1:
        return Found("%s/%d" % boards[0][:2], "the one board linked to %s (%s)" % (repository, boards[0][2]))
    if not boards:
        return Found(None, "no board is linked to %s" % repository, sure=False)
    return Found(None, "%d boards are linked to %s" % (len(boards), repository), sure=False,
                 choices=["%s/%d  %s" % b for b in boards])


def kind_of(branch: str, prefixes: dict[str, list[str]]) -> str | None:
    for kind in BRANCH_KINDS:
        if any(branch.startswith(prefix) for prefix in prefixes[kind]):
            return kind
    return None


@dataclass
class Evidence:
    develop: int = 0
    release: int = 0

    def add(self, head: str, base: str, prefixes: dict[str, list[str]], develop_branch: str) -> None:
        if kind_of(head, prefixes) not in ("feature", "bugfix"):
            return
        if base == develop_branch:
            self.develop += 1
        elif kind_of(base, prefixes) == "release":
            self.release += 1


def closing_evidence(checkout: str, repository: str | None, use_gh: bool, prefixes: dict[str, list[str]],
                     develop_branch: str) -> tuple[Evidence, list[str]]:
    evidence = Evidence()
    sources: list[str] = []
    remote_names = {name for name, _ in remotes(checkout)}
    rc, out = git(checkout, "log", "--all", "--merges", "-n", str(HISTORY_LIMIT), "--format=%s")
    if rc == 0:
        before = evidence.develop + evidence.release
        for subject in out.splitlines():
            match = MERGE_SUBJECT_RE.match(subject.strip())
            if not match:
                continue
            head, base = match.group("head"), match.group("base")
            first, _, rest = head.partition("/")
            if first in remote_names and rest:
                head = rest
            evidence.add(head, base, prefixes, develop_branch)
        if evidence.develop + evidence.release > before:
            sources.append("merge commits")
    if repository and use_gh:
        rc, out = gh(checkout, "pr", "list", "--repo", repository, "--state", "merged", "--limit", "200",
                     "--json", "headRefName,baseRefName")
        if rc == 0:
            try:
                pulls = json.loads(out)
            except ValueError:
                pulls = []
            before = evidence.develop + evidence.release
            for pull in pulls if isinstance(pulls, list) else []:
                if isinstance(pull, dict):
                    head, base = pull.get("headRefName"), pull.get("baseRefName")
                    if isinstance(head, str) and isinstance(base, str):
                        evidence.add(head, base, prefixes, develop_branch)
            if evidence.develop + evidence.release > before:
                sources.append("merged pull requests")
    return evidence, sources


def decide_closing_mode(evidence: Evidence) -> str | None:
    """The mode that history shows, or None. Needs MIN_EVIDENCE merges and an agreement of AGREEMENT_NUM/AGREEMENT_DEN."""
    total = evidence.develop + evidence.release
    if total < MIN_EVIDENCE:
        return None
    for mode, count in (("develop", evidence.develop), ("release", evidence.release)):
        if count * AGREEMENT_DEN >= total * AGREEMENT_NUM:
            return mode
    return None


def infer_closing_mode(checkout: str, repository: str | None, use_gh: bool, develop_branch: str = "develop") -> Found:
    prefixes = DEFAULT_PREFIXES
    evidence, sources = closing_evidence(checkout, repository, use_gh, prefixes, develop_branch)
    total = evidence.develop + evidence.release
    counted = "%d of %d merged feature/bugfix branches went into %s (%s)"
    mode = decide_closing_mode(evidence)
    if mode == "develop":
        return Found("develop", counted % (evidence.develop, total, develop_branch, ", ".join(sources)))
    if mode == "release":
        return Found("release", counted % (evidence.release, total, "a release branch", ", ".join(sources)))
    branches = local_branches(checkout) | remote_branches(checkout)
    has_develop = develop_branch in branches
    has_release = any(kind_of(b, prefixes) == "release" for b in branches)
    if total:
        guess = "develop" if evidence.develop >= evidence.release else "release"
        return Found(guess, "history is not clear: %d into %s, %d into a release branch" % (
            evidence.develop, develop_branch, evidence.release), sure=False)
    if has_release and not has_develop:
        return Found("release", "there are release branches and no %s branch" % develop_branch, sure=False)
    if has_develop:
        return Found("develop", "there is a %s branch and no merge history to judge by" % develop_branch, sure=False)
    return Found("develop", "a new project: no history to judge by", sure=False)


def infer_main_branch(checkout: str) -> str:
    branches = local_branches(checkout) | remote_branches(checkout)
    for candidate in ("main", "master"):
        if candidate in branches:
            return candidate
    rc, out = git(checkout, "symbolic-ref", "--quiet", "--short", "HEAD")
    if rc == 0 and out.strip() in ("main", "master"):
        return out.strip()
    return "main"


# ---------------------------------------------------------------------------------------------------------------------
# Questions on the terminal
# ---------------------------------------------------------------------------------------------------------------------
class Terminal:
    """Questions go to /dev/tty, so they work inside a git hook, whose standard input is not the terminal.
    FACTORY_PROMPT_TTY names another file to read the answers from (tests and scripted answers); the questions then go
    to standard error."""

    def __init__(self, reader: IO[str], writer: IO[str]):
        self.reader, self.writer = reader, writer

    @classmethod
    def open(cls) -> Terminal | None:
        scripted = os.environ.get("FACTORY_PROMPT_TTY")
        try:
            if scripted:
                with open(scripted, encoding="utf-8") as handle:
                    return cls(io.StringIO(handle.read()), sys.stderr)
            reader = open("/dev/tty", encoding="utf-8")
            writer = open("/dev/tty", "w", encoding="utf-8")
            return cls(reader, writer)
        except OSError:
            return None

    def say(self, text: str) -> None:
        self.writer.write(text + "\n")
        self.writer.flush()

    def ask(self, question: str, default: str | None) -> str:
        suffix = " [%s]" % default if default else ""
        self.writer.write("%s%s: " % (question, suffix))
        self.writer.flush()
        line = self.reader.readline()
        if not line:
            raise EOFError("no answer")
        answer = line.strip()
        return answer or (default or "")


def ask_until(terminal: Terminal, question: str, default: str | None, accept: Any, explain: str) -> str:
    for _ in range(5):
        answer = terminal.ask(question, default)
        value = accept(answer)
        if value is not None:
            return value
        terminal.say("  " + explain)
    raise EOFError("no valid answer after five tries")


# ---------------------------------------------------------------------------------------------------------------------
# resolve and write
# ---------------------------------------------------------------------------------------------------------------------
@dataclass
class Resolution:
    settings_state: str = "absent"            # present | absent | invalid | not-git
    settings_detail: str = ""
    repository: Found = field(default_factory=lambda: Found(None, ""))
    board: Found = field(default_factory=lambda: Found(None, ""))
    closing_mode: Found = field(default_factory=lambda: Found(None, ""))
    main_branch: str = "main"
    develop_branch: str = "develop"
    needs: list[tuple[str, str]] = field(default_factory=list)
    conflicts: list[tuple[str, str]] = field(default_factory=list)
    created_repository: bool = False

    def lines(self) -> list[str]:
        """Tab-separated lines for the installer. No field is empty (a tab-separated read in bash would merge it)."""
        def clean(text: str) -> str:
            return re.sub(r"[\x00-\x1f\x7f]", " ", text).strip() or "-"
        out = ["settings\t%s\t%s" % (self.settings_state, clean(self.settings_detail))]
        if self.created_repository:
            out.append("created\tgit\tgit init -b main")
        for key, found in (("repository", self.repository), ("board", self.board), ("closing_mode", self.closing_mode)):
            out.append("%s\t%s\t%s\t%s" % (key, found.value or "-", "sure" if found.sure else "guess", clean(found.source)))
        out.append("main_branch\t%s" % self.main_branch)
        out.append("develop_branch\t%s" % self.develop_branch)
        out += ["need\t%s\t%s" % (k, clean(v)) for k, v in self.needs]
        out += ["conflict\t%s\t%s" % (k, clean(v)) for k, v in self.conflicts]
        return out


def _board_answer(text: str, allow_new: bool) -> str | None:
    text = text.strip()
    if text.lower() == "none":
        return "none"
    if allow_new and text.lower().startswith("new"):
        owner = text[3:].lstrip(": ").strip() or "@me"
        if owner == "@me" or OWNER_RE.match(owner):
            return "new:" + owner
        return None
    parsed = parse_board(text)
    return "%s/%d" % parsed if parsed else None


def _mode_answer(text: str) -> str | None:
    text = text.strip().lower()
    return {"1": "develop", "develop": "develop", "2": "release", "release": "release"}.get(text)


def resolve(checkout: str, repo_flag: str | None, board_flag: str | None, mode_flag: str | None, interactive: bool,
            allow_new_board: bool, use_gh: bool, terminal: Terminal | None = None) -> Resolution:
    result = Resolution()
    if not is_git_repository(checkout) and interactive:
        terminal = terminal or Terminal.open()
        if terminal is not None and terminal.ask("%s is not a git repository. Create one with 'git init -b main'? (yes/no)"
                                                 % checkout, "yes").lower() in ("y", "yes"):
            if git(checkout, "init", "-q", "-b", "main")[0] != 0:  # git older than 2.28 has no -b
                git(checkout, "init", "-q")
                git(checkout, "symbolic-ref", "HEAD", "refs/heads/main")
            result.created_repository = True
    if not is_git_repository(checkout):
        result.settings_state = "not-git"
        result.settings_detail = "%s is not a git repository" % checkout
        result.needs.append(("git", "run 'git init -b main' in %s (a new project), then run this again" % checkout))
        return result

    existing: Settings | None = None
    path = os.path.join(checkout, SETTINGS_REL)
    try:
        existing = load_settings(path)
        result.settings_state = "present"
        result.settings_detail = SETTINGS_REL
    except FileNotFoundError:
        result.settings_state = "absent"
        result.settings_detail = "%s does not exist" % SETTINGS_REL
    except SettingsError as error:
        result.settings_state = "invalid"
        result.settings_detail = "; ".join(error.problems[:4])
        result.needs.append(("settings", "fix %s or delete it: %s" % (SETTINGS_REL, "; ".join(error.problems[:4]))))
        return result

    # 1. Values given and values recorded. A flag that disagrees with the file is a conflict: never guess which wins.
    if existing:
        result.main_branch, result.develop_branch = existing.main_branch, existing.develop_branch
        recorded_board = "none" if existing.board is None else "%s/%d" % existing.board
        pairs = (("repository", repo_flag, existing.repository, "--repo"),
                 ("board", board_flag, recorded_board, "--project / --no-board"),
                 ("closing_mode", mode_flag, existing.closing_mode, "--gitflow-mode"))
        for key, given, recorded, flag_name in pairs:
            if given is not None and given.lower() != recorded.lower():
                result.conflicts.append((key, "%s says %s but %s records %s; edit the file or pass the same value" % (
                    flag_name, given, SETTINGS_REL, recorded)))
        result.repository = Found(existing.repository, SETTINGS_REL)
        result.board = Found(recorded_board, SETTINGS_REL)
        result.closing_mode = Found(existing.closing_mode, SETTINGS_REL)
        configured = board_from_config(checkout)
        if configured and existing.board is not None and configured != existing.board:
            result.conflicts.append(("board", "%s records the board %s/%d but %s maps the board %s/%d" % (
                SETTINGS_REL, existing.board[0], existing.board[1], BOARD_CONFIG_REL, configured[0], configured[1])))
        return result

    result.main_branch = infer_main_branch(checkout)
    result.repository = Found(repo_flag, "--repo") if repo_flag else infer_repository(checkout, use_gh)
    if terminal is None and interactive:
        terminal = Terminal.open()
        if terminal is None:
            interactive = False

    if interactive and terminal is not None:
        terminal.say("The factory needs a few settings for this project (%s). Press Enter to take the value in brackets."
                     % SETTINGS_REL)
        if not repo_flag:
            if result.repository.choices:
                terminal.say("  Remotes name: %s" % ", ".join(result.repository.choices))
            answer = ask_until(terminal, "GitHub repository (OWNER/NAME)", result.repository.value,
                               lambda t: ("%s/%s" % parse_repo(t)) if parse_repo(t) else None,
                               "Write it as OWNER/NAME, for example acme/widgets.")
            source = "your answer" if answer != result.repository.value else result.repository.source + ", confirmed"
            result.repository = Found(answer, source)

    repository = result.repository.value if result.repository.sure or interactive else None
    if board_flag:
        result.board = Found(board_flag, "--project" if "/" in board_flag else "--create-project" if
                             board_flag.startswith("new:") else "--no-board")
    else:
        result.board = infer_board(checkout, repository, use_gh)
    if mode_flag:
        result.closing_mode = Found(mode_flag, "--gitflow-mode")
    else:
        result.closing_mode = infer_closing_mode(checkout, repository, use_gh)

    if interactive and terminal is not None:
        if not board_flag:
            for choice in result.board.choices:
                terminal.say("  Linked board: %s" % choice)
            hint = "OWNER/NUMBER, 'none'" + (", or 'new' to create one" if allow_new_board else "")
            default = result.board.value
            answer = ask_until(terminal, "GitHub Projects board (%s)" % hint, default,
                               lambda t: _board_answer(t, allow_new_board),
                               "Write OWNER/NUMBER (the number is in the board's address), or none%s." % (
                                   ", or new" if allow_new_board else ""))
            source = "your answer" if answer != default else result.board.source + ", confirmed"
            result.board = Found(answer, source)
        if not mode_flag:
            terminal.say("Gitflow: where do feature/ and bugfix/ branches close?")
            terminal.say("  1) develop  - classic gitflow: they merge into %s; a release/ branch is cut from it"
                         % result.develop_branch)
            terminal.say("  2) release  - they merge straight into the open release/ branch")
            terminal.say("  (%s: %s)" % ("inferred" if result.closing_mode.sure else "a guess",
                                         result.closing_mode.source))
            default_choice = "1" if result.closing_mode.value != "release" else "2"
            answer = ask_until(terminal, "Choose 1 or 2", default_choice, _mode_answer, "Answer 1 or 2.")
            source = "your answer" if answer != result.closing_mode.value else result.closing_mode.source + ", confirmed"
            result.closing_mode = Found(answer, source)

    if not result.repository.sure or not result.repository.value:
        result.needs.append(("repository", "%s; pass --repo OWNER/NAME or answer the question in a terminal"
                             % result.repository.source))
        result.repository = Found(None, result.repository.source, sure=False, choices=result.repository.choices)
    if not result.board.sure or not result.board.value:
        result.needs.append(("board", "%s; pass --project OWNER/NUMBER, --create-project OWNER or --no-board, or answer "
                             "the question in a terminal" % result.board.source))
        result.board = Found(None, result.board.source, sure=False, choices=result.board.choices)
    if not result.closing_mode.sure:
        result.needs.append(("closing_mode", "%s; pass --gitflow-mode develop|release or answer the question in a "
                             "terminal" % result.closing_mode.source))
        result.closing_mode = Found(None, result.closing_mode.source, sure=False)
    return result


def build_settings(checkout: str, repository: str, board: str, mode: str, main_branch: str | None = None,
                   develop_branch: str | None = None) -> tuple[Settings, Settings | None]:
    """The settings to write, and the ones already there. Fields the person edited by hand are kept."""
    repo = parse_repo(repository)
    if not repo:
        raise UsageError("--repo must look like OWNER/NAME")
    parsed_board: tuple[str, int] | None = None
    if board != "none":
        parsed_board = parse_board(board)
        if not parsed_board:
            raise UsageError("--board must look like OWNER/NUMBER or be none")
    if mode not in CLOSING_MODES:
        raise UsageError("--closing-mode must be develop or release")
    path = os.path.join(checkout, SETTINGS_REL)
    try:
        existing: Settings | None = load_settings(path)
    except FileNotFoundError:
        existing = None
    if existing:
        updated = dataclasses.replace(existing, owner=repo[0], name=repo[1], board=parsed_board, closing_mode=mode)
        return updated, existing
    settings = Settings(owner=repo[0], name=repo[1], board=parsed_board, closing_mode=mode,
                        main_branch=main_branch or infer_main_branch(checkout), develop_branch=develop_branch or "develop")
    return settings, None


def write(checkout: str, repository: str, board: str, mode: str, check_only: bool) -> tuple[str, str]:
    try:
        settings, existing = build_settings(checkout, repository, board, mode)
    except SettingsError as error:
        return "NEEDS", "%s is not valid: %s" % (SETTINGS_REL, "; ".join(error.problems[:4]))
    path = os.path.join(checkout, SETTINGS_REL)
    if os.path.islink(path) or os.path.islink(os.path.dirname(path)):
        return "BLOCKED", "%s is, or goes through, a symbolic link; it was not written" % SETTINGS_REL
    summary = "repository %s, board %s, gitflow closes feature branches into %s" % (
        settings.repository, "none" if settings.board is None else "%s/%d" % settings.board,
        settings.develop_branch if settings.closing_mode == "develop" else "the release branch")
    if existing is not None and settings_text(existing) == settings_text(settings):
        return "PRESENT", "%s: %s" % (SETTINGS_REL, summary)
    if check_only:
        return "WOULD_ADD", "%s would be %s: %s" % (SETTINGS_REL, "updated" if existing else "written", summary)
    atomic_write(path, settings_text(settings))
    return ("UPDATED" if existing else "ADDED"), "%s: %s" % (SETTINGS_REL, summary)


# ---------------------------------------------------------------------------------------------------------------------
# Conventional Commits
# ---------------------------------------------------------------------------------------------------------------------
def message_lines(text: str, comment_char: str = "#") -> list[str]:
    """The message as git keeps it: comment lines and everything below the scissors line removed."""
    lines = []
    scissors = "%s ------------------------ >8 ------------------------" % comment_char
    for line in text.replace("\r\n", "\n").split("\n"):
        if line.rstrip() == scissors:
            break
        if comment_char and line.startswith(comment_char):
            continue
        lines.append(line.rstrip())
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def check_header(header: str, settings: Settings | None) -> list[str]:
    types = settings.types if settings else DEFAULT_TYPES
    max_length = settings.header_max_length if settings else DEFAULT_HEADER_MAX
    example = "feat(parser): accept dates without a year"
    match = HEADER_RE.match(header)
    if not match:
        return ["the first line must look like 'type(scope): description', for example '%s'; types: %s"
                % (example, ", ".join(types))]
    problems = []
    kind = match.group("type")
    if kind not in types:
        lowered = " (write it in lower case)" if kind.lower() in types else ""
        problems.append("'%s' is not an allowed type%s; use one of: %s" % (kind, lowered, ", ".join(types)))
    scope = match.group("scope")
    if scope is not None:
        if not scope.strip() or scope != scope.strip():
            problems.append("the scope in parentheses must be a word with no spaces around it, or be left out")
        elif settings and settings.scopes and scope not in settings.scopes:
            problems.append("'%s' is not an allowed scope; use one of: %s" % (scope, ", ".join(settings.scopes)))
    elif settings and settings.require_scope:
        problems.append("this project requires a scope: 'type(scope): description'")
    if match.group("space") != " ":
        problems.append("put exactly one space after the colon")
    if not match.group("subject").strip():
        problems.append("the description after the colon is empty")
    if len(header) > max_length:
        problems.append("the first line has %d characters; the limit is %d" % (len(header), max_length))
    return problems


def check_message(text: str, settings: Settings | None, allow_autosquash: bool, comment_char: str = "#") -> list[str]:
    lines = message_lines(text, comment_char)
    if not lines:
        return ["the commit message is empty"]
    header = lines[0]
    if header.startswith(AUTOSQUASH):
        return [] if allow_autosquash else ["'%s' commits must be squashed (git rebase -i --autosquash) before review"
                                            % header.split(" ", 1)[0]]
    if re.match(r'^Revert ".*"$', header):
        return []
    problems = check_header(header, settings)
    if len(lines) > 1 and lines[1].strip():
        problems.append("leave the second line blank: the body starts on the third line")
    for line in lines[1:]:
        if re.match(r"(?i)^breaking[ -]change:", line) and not re.match(r"^BREAKING[ -]CHANGE:", line):
            problems.append("write the footer as 'BREAKING CHANGE:' in capitals")
    return problems


# ---------------------------------------------------------------------------------------------------------------------
# gitflow
# ---------------------------------------------------------------------------------------------------------------------
def branch_problem(branch: str, settings: Settings) -> str | None:
    """Why a branch name is not a gitflow name, or None."""
    if branch in (settings.main_branch, settings.develop_branch):
        return None
    kind = kind_of(branch, settings.prefixes)
    extra = next((f for f in settings.additional_flows if branch.startswith(f.head_prefix)), None)
    prefix = None
    if kind:
        prefix = next(p for p in settings.prefixes[kind] if branch.startswith(p))
    elif extra:
        prefix = extra.head_prefix
    if prefix is None:
        allowed = [p for kind_ in BRANCH_KINDS for p in settings.prefixes[kind_]]
        allowed += [f.head_prefix for f in settings.additional_flows]
        return ("'%s' is not a gitflow branch name; start it with one of %s, or work on %s/%s"
                % (branch, ", ".join(allowed), settings.main_branch, settings.develop_branch))
    if not SLUG_RE.match(branch[len(prefix):]):
        return "'%s' needs a name after '%s', made of letters, digits, '.', '_' and '-'" % (branch, prefix)
    return None


def allowed_bases(head: str, settings: Settings) -> list[str]:
    """Where a branch may close. A value that ends in '/' is a prefix (any release/... branch)."""
    if head == settings.main_branch:
        return [settings.develop_branch]
    if head == settings.develop_branch:
        return []
    for extra in settings.additional_flows:
        if head.startswith(extra.head_prefix):
            return list(extra.into)
    kind = kind_of(head, settings.prefixes)
    releases = list(settings.prefixes["release"])
    if kind in ("feature", "bugfix"):
        return [settings.develop_branch] if settings.closing_mode == "develop" else releases
    if kind == "release":
        return [settings.main_branch, settings.develop_branch]
    if kind == "hotfix":
        return [settings.main_branch, settings.develop_branch] + releases
    return []


def base_allowed(base: str, allowed: list[str]) -> bool:
    for target in allowed:
        if target.endswith("/"):
            if base.startswith(target) and SLUG_RE.match(base[len(target):]):
                return True
        elif base == target:
            return True
    return False


def describe(allowed: list[str]) -> str:
    return " or ".join(("a %s... branch" % t) if t.endswith("/") else t for t in allowed) or "nothing"


def check_flow(head: str, base: str, settings: Settings) -> list[str]:
    problem = branch_problem(head, settings)
    if problem:
        return [problem]
    allowed = allowed_bases(head, settings)
    if not allowed:
        return ["'%s' does not close by pull request in this project's gitflow" % head]
    if not base_allowed(base, allowed):
        mode = ("this project closes feature and bugfix branches into %s" % settings.develop_branch
                if settings.closing_mode == "develop" else
                "this project closes feature and bugfix branches straight into the release branch")
        return ["'%s' may close into %s, not into '%s' (%s; see %s)" % (head, describe(allowed), base, mode,
                                                                       SETTINGS_REL)]
    return []


# ---------------------------------------------------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------------------------------------------------
def toplevel() -> str:
    rc, out = git(os.getcwd(), "rev-parse", "--show-toplevel")
    if rc != 0 or not out.strip():
        raise UsageError("not inside a git repository")
    return out.strip()


def comment_char(checkout: str) -> str:
    rc, out = git(checkout, "config", "--get", "core.commentChar")
    value = out.strip() if rc == 0 else ""
    return "#" if value in ("", "auto") else value[:1]


def ensure_settings(checkout: str, out: IO[str]) -> Settings | None:
    """The settings, asking for them on the terminal when they are missing. None (and a message) when they cannot be had."""
    path = os.path.join(checkout, SETTINGS_REL)
    try:
        return load_settings(path)
    except FileNotFoundError:
        pass
    except SettingsError as error:
        out.write("git policy: %s is not valid:\n%s\n" % (SETTINGS_REL, "\n".join("  - " + p for p in error.problems)))
        return None
    if os.environ.get("FACTORY_GIT_POLICY_NO_PROMPT") != "1":
        terminal = Terminal.open()
        if terminal is not None:
            code = configure(checkout, None, None, None, interactive=True, out=out, terminal=terminal)
            if code == EXIT_OK:
                try:
                    return load_settings(path)
                except (FileNotFoundError, SettingsError):
                    return None
            return None
    out.write("git policy: this project has no %s yet, and there is no terminal to ask for it.\n"
              "  Run this in a terminal, in %s:\n"
              "    python3 .github/scripts/git_policy.py configure\n"
              "  It asks for the GitHub repository, the Projects board and the gitflow closing mode, then commit the file.\n"
              % (SETTINGS_REL, checkout))
    return None


def hook_commit_msg(message_file: str, out: IO[str]) -> int:
    checkout = toplevel()
    settings = ensure_settings(checkout, out)
    if settings is None:
        return EXIT_FAILED
    rc, _ = git(checkout, "rev-parse", "-q", "--verify", "MERGE_HEAD")
    with open(message_file, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    lines = message_lines(text, comment_char(checkout))
    if lines and (rc == 0 and lines[0].startswith("Merge ") or GIT_MERGE_HEADER_RE.match(lines[0])):
        return EXIT_OK  # git's own words for a merge that closes a branch
    problems = check_message(text, settings, allow_autosquash=True, comment_char=comment_char(checkout))
    if problems:
        out.write("git policy: the commit message does not follow Conventional Commits:\n")
        out.write("".join("  - %s\n" % p for p in problems))
        out.write("  Your message is kept in .git/COMMIT_EDITMSG; reuse it with: git commit -e -F .git/COMMIT_EDITMSG\n")
        return EXIT_FAILED
    return EXIT_OK


def hook_pre_commit(out: IO[str]) -> int:
    checkout = toplevel()
    settings = ensure_settings(checkout, out)
    if settings is None:
        return EXIT_FAILED
    rc, branch = git(checkout, "symbolic-ref", "--quiet", "--short", "HEAD")
    if rc != 0:
        return EXIT_OK  # a detached HEAD: a rebase or a bisect, not a branch of the gitflow
    branch = branch.strip()
    if git(checkout, "rev-parse", "-q", "--verify", "HEAD")[0] != 0:
        return EXIT_OK  # the first commit of a new repository
    if git(checkout, "rev-parse", "-q", "--verify", "MERGE_HEAD")[0] == 0:
        return EXIT_OK  # closing a branch with a merge
    if branch in (settings.main_branch, settings.develop_branch):
        out.write("git policy: do not commit on %s directly. In gitflow, work reaches %s by merging a branch.\n"
                  "  Move this work to a branch and commit there:  git switch -c %sNAME\n"
                  % (branch, branch, settings.prefixes["hotfix" if branch == settings.main_branch else "feature"][0]))
        return EXIT_FAILED
    problem = branch_problem(branch, settings)
    if problem:
        out.write("git policy: %s.\n  Rename the branch:  git branch -m %sNAME\n"
                  % (problem, settings.prefixes["feature"][0]))
        return EXIT_FAILED
    return EXIT_OK


def commits_in(checkout: str, revisions: list[str]) -> list[tuple[str, int, str]]:
    """(sha, number of parents, message) for each commit, newest first."""
    rc, out = git(checkout, "log", "-n", str(PUSH_CHECK_LIMIT), "--format=%H%x00%P%x00%B%x1e", *revisions)
    if rc != 0:
        return []
    commits = []
    for record in out.split("\x1e"):
        record = record.lstrip("\n")
        if not record:
            continue
        sha, parents, body = (record.split("\x00", 2) + ["", ""])[:3]
        commits.append((sha, len(parents.split()), body))
    return commits


def report_commits(commits: list[tuple[str, int, str]], settings: Settings, allow_autosquash: bool,
                   char: str = "#") -> list[str]:
    problems = []
    for sha, parents, body in commits:
        if parents != 1:
            continue  # a merge commit closes a branch (its words are git's); a root commit comes before any policy
        for problem in check_message(body, settings, allow_autosquash, char):
            header = (message_lines(body, char) or [""])[0]
            problems.append("%s %s: %s" % (sha[:10], header[:60], problem))
    return problems


def hook_pre_push(_remote: str, stdin: IO[str], out: IO[str]) -> int:
    checkout = toplevel()
    settings = ensure_settings(checkout, out)
    if settings is None:
        return EXIT_FAILED
    problems = []
    for line in stdin.read().splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        _local_ref, local_sha, remote_ref, remote_sha = parts
        if ZERO_SHA.match(local_sha) or not remote_ref.startswith("refs/heads/"):
            continue  # a deletion, or a tag
        branch = remote_ref[len("refs/heads/"):]
        problem = branch_problem(branch, settings)
        if problem:
            problems.append(problem)
            continue
        if not ZERO_SHA.match(remote_sha) and git(checkout, "cat-file", "-e", remote_sha + "^{commit}")[0] == 0:
            revisions = ["%s..%s" % (remote_sha, local_sha)]
        else:
            revisions = [local_sha, "--not", "--remotes"]  # what no remote has yet (the remote may be a URL)
        problems += report_commits(commits_in(checkout, revisions), settings, allow_autosquash=True,
                                   char=comment_char(checkout))
    if problems:
        out.write("git policy: the push was stopped:\n" + "".join("  - %s\n" % p for p in problems))
        out.write("  Reword commits with: git rebase -i (choose 'reword'), then push again.\n")
        return EXIT_FAILED
    return EXIT_OK


# ---------------------------------------------------------------------------------------------------------------------
# Pull requests (the GitHub Action)
# ---------------------------------------------------------------------------------------------------------------------
def check_pr(settings_path: str, checkout: str, base_ref: str, head_ref: str, base_sha: str, head_sha: str, title: str,
             out: IO[str]) -> int:
    try:
        settings = load_settings(settings_path)
    except FileNotFoundError:
        out.write("FAIL settings: %s does not exist on the base branch. Run the factory's installer, or "
                  "'python3 .github/scripts/git_policy.py configure', and merge the file.\n" % SETTINGS_REL)
        return EXIT_FAILED
    except SettingsError as error:
        out.write("FAIL settings: %s\n" % "; ".join(error.problems))
        return EXIT_FAILED
    failures: list[tuple[str, str]] = []
    failures += [("gitflow", p) for p in check_flow(head_ref, base_ref, settings)]
    if title:
        failures += [("title", "the pull request title: %s" % p) for p in check_header(title, settings)]
        # A pull request into the development branch is squash-merged, and its title becomes the commit's first line
        # with " (#number)" added, which the commit checks never see: leave room for it.
        room = settings.header_max_length - len(" (#99999)")
        if base_ref == settings.develop_branch and HEADER_RE.match(title) and room < len(title) <= settings.header_max_length:
            failures.append(("title", "the pull request title has %d characters; a squash merge adds ' (#number)', so "
                                      "keep it to %d" % (len(title), room)))
    else:
        failures.append(("title", "the pull request has no title"))
    for sha in (base_sha, head_sha):
        if not re.match(r"^[0-9a-f]{40}$", sha):
            raise UsageError("--base-sha and --head-sha must be full commit hashes")
    revisions = ["%s..%s" % (base_sha, head_sha)]
    # Into the main branch, what is already on the development branch was checked when it reached it: a release or
    # a back-merge carries all of it, and one commit that slipped through there would stop every release.
    develop_ref = "refs/remotes/origin/%s" % settings.develop_branch
    if base_ref == settings.main_branch and git(checkout, "rev-parse", "--verify", "--quiet", develop_ref)[0] == 0:
        revisions += ["--not", develop_ref]
    commits = commits_in(checkout, revisions)
    failures += [("commits", p) for p in report_commits(commits, settings, allow_autosquash=False)]
    annotate = os.environ.get("GITHUB_ACTIONS") == "true"
    if not failures:
        out.write("PASS %s -> %s, the title and %d commit(s) follow Conventional Commits and the %s gitflow\n"
                  % (head_ref, base_ref, len(commits), settings.closing_mode))
        return EXIT_OK
    for group, problem in failures:
        clean = re.sub(r"[\x00-\x1f\x7f]", " ", problem)
        out.write(("::error title=git policy (%s)::%s\n" % (group, clean)) if annotate else "FAIL %s: %s\n" % (group, clean))
    return EXIT_FAILED


# ---------------------------------------------------------------------------------------------------------------------
# configure: the person's own command, also used by the hooks
# ---------------------------------------------------------------------------------------------------------------------
def configure(checkout: str, repo_flag: str | None, board_flag: str | None, mode_flag: str | None, interactive: bool,
              out: IO[str], terminal: Terminal | None = None) -> int:
    use_gh = _have("gh")
    result = resolve(checkout, repo_flag, board_flag, mode_flag, interactive, allow_new_board=False, use_gh=use_gh,
                     terminal=terminal)
    if result.settings_state == "present" and not result.conflicts:
        out.write("PRESENT %s\n" % SETTINGS_REL)
        return EXIT_OK
    problems = [text for _, text in result.conflicts + result.needs]
    if problems:
        out.write("git policy: the settings are not complete:\n" + "".join("  - %s\n" % p for p in problems))
        return EXIT_NEEDS if not result.conflicts else EXIT_FAILED
    assert result.repository.value and result.board.value and result.closing_mode.value
    state, detail = write(checkout, result.repository.value, result.board.value, result.closing_mode.value, False)
    out.write("%s %s\n" % (state, detail))
    if state in ("ADDED", "UPDATED"):
        out.write("Commit %s so that everybody, and the GitHub Action, use the same settings.\n" % SETTINGS_REL)
        return EXIT_OK
    return EXIT_OK if state == "PRESENT" else EXIT_FAILED


def _have(program: str) -> bool:
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if folder and os.access(os.path.join(folder, program), os.X_OK):
            return True
    return False


def _repo_arg(value: str) -> str:
    parsed = parse_repo(value)
    if not parsed:
        raise argparse.ArgumentTypeError("must look like OWNER/NAME")
    return "%s/%s" % parsed


def _board_arg(value: str) -> str:
    answer = _board_answer(value, allow_new=True)
    if answer is None:
        raise argparse.ArgumentTypeError("must look like OWNER/NUMBER, none or new:OWNER")
    return answer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("resolve", help="find the settings, ask when a terminal is there; prints tab-separated lines")
    p.add_argument("--checkout", default=".")
    p.add_argument("--repo", type=_repo_arg)
    p.add_argument("--board", type=_board_arg)
    p.add_argument("--closing-mode", choices=CLOSING_MODES)
    p.add_argument("--interactive", action="store_true")
    p.add_argument("--allow-new-board", action="store_true")
    p.add_argument("--no-gh", action="store_true")

    p = sub.add_parser("write", help="write .factory/repository.json, keeping the fields a person edited")
    p.add_argument("--checkout", default=".")
    p.add_argument("--repo", type=_repo_arg, required=True)
    p.add_argument("--board", type=_board_arg, required=True)
    p.add_argument("--closing-mode", choices=CLOSING_MODES, required=True)
    p.add_argument("--check", action="store_true")

    p = sub.add_parser("configure", help="record the settings of this project, asking for what cannot be inferred")
    p.add_argument("--checkout")
    p.add_argument("--repo", type=_repo_arg)
    p.add_argument("--board", type=_board_arg)
    p.add_argument("--closing-mode", choices=CLOSING_MODES)
    p.add_argument("--non-interactive", action="store_true")

    p = sub.add_parser("check-settings", help="validate .factory/repository.json")
    p.add_argument("--checkout", default=".")

    p = sub.add_parser("check-message", help="check one commit message")
    p.add_argument("--file")
    p.add_argument("--settings")
    p.add_argument("--allow-autosquash", action="store_true")

    p = sub.add_parser("hook", help="run as a git hook")
    p.add_argument("name", choices=("commit-msg", "pre-commit", "pre-push"))
    p.add_argument("args", nargs="*")

    p = sub.add_parser("check-pr", help="check a pull request (the GitHub Action)")
    p.add_argument("--settings", required=True)
    p.add_argument("--checkout", required=True)
    p.add_argument("--base-ref", required=True)
    p.add_argument("--head-ref", required=True)
    p.add_argument("--base-sha", required=True)
    p.add_argument("--head-sha", required=True)
    p.add_argument("--title")

    args = parser.parse_args(argv)
    try:
        if args.command == "resolve":
            if args.board and args.board.startswith("new:") and not args.allow_new_board:
                raise UsageError("--board new:OWNER needs --allow-new-board")
            result = resolve(os.path.abspath(args.checkout), args.repo, args.board, args.closing_mode, args.interactive,
                             args.allow_new_board, use_gh=not args.no_gh and _have("gh"))
            sys.stdout.write("".join(line + "\n" for line in result.lines()))
            return EXIT_OK
        if args.command == "write":
            if args.board.startswith("new:"):
                raise UsageError("write needs the board's number, not new:OWNER")
            state, detail = write(os.path.abspath(args.checkout), args.repo, args.board, args.closing_mode, args.check)
            sys.stdout.write("%s\t%s\n" % (state, detail))
            return EXIT_OK if state in ("PRESENT", "ADDED", "UPDATED", "WOULD_ADD") else EXIT_NEEDS
        if args.command == "configure":
            if args.board and args.board.startswith("new:"):
                raise UsageError("configure cannot create a board; run the factory's installer with --create-project")
            checkout = os.path.abspath(args.checkout) if args.checkout else toplevel()
            return configure(checkout, args.repo, args.board, args.closing_mode, not args.non_interactive, sys.stdout)
        if args.command == "check-settings":
            path = os.path.join(os.path.abspath(args.checkout), SETTINGS_REL)
            try:
                settings = load_settings(path)
            except FileNotFoundError:
                print("NEEDS %s does not exist" % SETTINGS_REL)
                return EXIT_NEEDS
            except SettingsError as error:
                print("FAIL " + "\nFAIL ".join(error.problems))
                return EXIT_FAILED
            print("PASS %s: %s, closing mode %s" % (SETTINGS_REL, settings.repository, settings.closing_mode))
            return EXIT_OK
        if args.command == "check-message":
            settings = load_settings(args.settings) if args.settings else None
            if args.file:
                with open(args.file, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            else:
                text = sys.stdin.read()
            problems = check_message(text, settings, args.allow_autosquash)
            for problem in problems:
                print("FAIL " + problem)
            return EXIT_FAILED if problems else EXIT_OK
        if args.command == "hook":
            if args.name == "commit-msg":
                if len(args.args) != 1:
                    raise UsageError("hook commit-msg needs the message file")
                return hook_commit_msg(args.args[0], sys.stderr)
            if args.name == "pre-commit":
                return hook_pre_commit(sys.stderr)
            return hook_pre_push(args.args[0] if args.args else "origin", sys.stdin, sys.stderr)
        if args.command == "check-pr":
            title = args.title if args.title is not None else os.environ.get("PR_TITLE", "")
            return check_pr(args.settings, os.path.abspath(args.checkout), args.base_ref, args.head_ref, args.base_sha,
                            args.head_sha, title, sys.stdout)
    except UsageError as error:
        print("git_policy.py: %s" % error, file=sys.stderr)
        return EXIT_USAGE
    except EOFError:
        print("git policy: no answer was given; nothing was written.", file=sys.stderr)
        return EXIT_NEEDS
    except SettingsError as error:
        print("git policy: " + "; ".join(error.problems), file=sys.stderr)
        return EXIT_FAILED
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
