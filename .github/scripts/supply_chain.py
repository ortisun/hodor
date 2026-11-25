#!/usr/bin/env python3
"""Checks of what Hodor is built from, beyond what cargo deny covers.

docs/security/supply-chain.md says what each check is for.

  supply_chain.py actions  [WORKFLOW_DIRECTORY]   every action named by a full commit
  supply_chain.py licenses LOCKFILE...            every npm package under an allowed license
  supply_chain.py test                            the checks' own tests

Uses the standard library only.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

# The licenses of packages that ship: the allowed list of deny.toml, and the
# license of the bundled fonts.
SHIPPED = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "0BSD",
    "Zlib",
    "Unicode-3.0",
    "OFL-1.1",
}

# Tools never leave the machine they run on, so licenses whose conditions
# apply to distribution are allowed for them too.
TOOLS = SHIPPED | {"MPL-2.0", "BlueOak-1.0.0", "MIT-0", "CC0-1.0", "CC-BY-4.0"}

USES = re.compile(r"^\s*(?:-\s+)?uses:\s*['\"]?([^'\"\s#]+)")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def unpinned_actions(workflow: str) -> list[str]:
    """The actions of a workflow named by something other than a full commit."""
    found = []
    for number, line in enumerate(workflow.splitlines(), start=1):
        match = USES.match(line)
        if not match:
            continue
        action = match.group(1)
        if action.startswith("./"):
            continue
        name, _, reference = action.partition("@")
        if not COMMIT.match(reference):
            found.append(f"line {number}: `{action}` is not named by a full commit")
        elif "#" not in line:
            found.append(f"line {number}: `{name}` says by no comment which release it is")
    return found


def allowed(expression: str, accepted: set[str]) -> bool:
    """Whether an SPDX expression is satisfied by accepted licenses.

    `A OR B` holds when either holds, `A AND B` when both do, and the
    parentheses group. Anything else, such as `WITH` or a custom license, is
    not read and so is not allowed.
    """
    tokens = re.findall(r"\(|\)|[^\s()]+", expression)
    position = 0

    def term() -> bool:
        nonlocal position
        if position >= len(tokens):
            raise ValueError("an expression that ends too soon")
        token = tokens[position]
        position += 1
        if token == "(":
            value = either()
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError("a parenthesis that is not closed")
            position += 1
            return value
        if token in {")", "AND", "OR", "WITH"}:
            raise ValueError(f"`{token}` where a license was expected")
        return token in accepted

    def both() -> bool:
        nonlocal position
        value = term()
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            value = term() and value
        return value

    def either() -> bool:
        nonlocal position
        value = both()
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            value = both() or value
        return value

    try:
        value = either()
    except ValueError:
        return False
    return position == len(tokens) and value


def refused_packages(lockfile: dict) -> list[str]:
    """The packages of a lockfile whose license is not allowed for their kind."""
    found = []
    for path, package in sorted(lockfile.get("packages", {}).items()):
        if not path or package.get("link"):
            continue
        name = path.split("node_modules/")[-1]
        license_expression = package.get("license")
        kind, accepted = ("tool", TOOLS) if package.get("dev") else ("shipped", SHIPPED)
        if not isinstance(license_expression, str) or not license_expression.strip():
            found.append(f"{name} ({kind}) declares no license")
        elif not allowed(license_expression, accepted):
            found.append(f"{name} ({kind}) is under `{license_expression}`, which is not allowed")
    return found


def check_actions(directory: Path) -> int:
    problems = []
    for workflow in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        problems += [f"{workflow}: {problem}" for problem in unpinned_actions(workflow.read_text())]
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print(f"every action in {directory} is named by a full commit")
    return 1 if problems else 0


def check_licenses(lockfiles: list[Path]) -> int:
    problems = []
    for lockfile in lockfiles:
        refused = refused_packages(json.loads(lockfile.read_text()))
        problems += [f"{lockfile}: {problem}" for problem in refused]
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print(f"every package of {len(lockfiles)} lockfiles is under an allowed license")
    return 1 if problems else 0


class Tests(unittest.TestCase):
    def test_an_action_named_by_a_commit_with_its_release_passes(self) -> None:
        workflow = (
            "steps:\n"
            "  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0\n"
            "  - uses: ./.github/actions/local\n"
            "  - run: echo uses: nothing@v1\n"
        )
        self.assertEqual(unpinned_actions(workflow), [])

    def test_an_action_named_by_a_tag_a_branch_or_a_short_commit_fails(self) -> None:
        workflow = (
            "  - uses: actions/checkout@v4\n"
            "    uses: 'actions/setup-node@main'\n"
            "  - uses: actions/cache@11d5960 # v4\n"
            "  - uses: docker://alpine:3\n"
        )
        self.assertEqual(len(unpinned_actions(workflow)), 4)

    def test_a_commit_without_its_release_fails(self) -> None:
        workflow = "  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
        self.assertEqual(len(unpinned_actions(workflow)), 1)

    def test_expressions_are_read(self) -> None:
        self.assertTrue(allowed("MIT", SHIPPED))
        self.assertTrue(allowed("(MIT OR GPL-3.0)", SHIPPED))
        self.assertTrue(allowed("MIT AND BSD-3-Clause", SHIPPED))
        self.assertFalse(allowed("MIT AND GPL-3.0", SHIPPED))
        self.assertFalse(allowed("MPL-2.0", SHIPPED))
        self.assertTrue(allowed("MPL-2.0", TOOLS))
        self.assertFalse(allowed("Apache-2.0 WITH LLVM-exception", SHIPPED))
        self.assertFalse(allowed("(MIT", SHIPPED))
        self.assertFalse(allowed("MIT OR", SHIPPED))
        self.assertFalse(allowed("SEE LICENSE IN LICENSE.md", TOOLS))

    def test_a_shipped_package_is_held_to_the_shorter_list(self) -> None:
        lockfile = {
            "packages": {
                "": {"name": "auth-ui"},
                "node_modules/react": {"license": "MIT"},
                "node_modules/lightningcss": {"license": "MPL-2.0", "dev": True},
                "node_modules/copyleft": {"license": "MPL-2.0"},
                "node_modules/nothing": {},
                "node_modules/a/node_modules/b": {"license": "GPL-3.0", "dev": True},
                "node_modules/linked": {"link": True},
            }
        }
        self.assertEqual(
            refused_packages(lockfile),
            [
                "b (tool) is under `GPL-3.0`, which is not allowed",
                "copyleft (shipped) is under `MPL-2.0`, which is not allowed",
                "nothing (shipped) declares no license",
            ],
        )

    def test_the_commands_read_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci.yml").write_text("  - uses: actions/checkout@v4\n")
            self.assertEqual(check_actions(root), 1)
            lockfile = root / "package-lock.json"
            lockfile.write_text(json.dumps({"packages": {"node_modules/x": {"license": "ISC"}}}))
            self.assertEqual(check_licenses([lockfile]), 0)


def main(arguments: list[str]) -> int:
    if not arguments:
        print(__doc__, file=sys.stderr)
        return 2
    command, rest = arguments[0], arguments[1:]
    if command == "actions":
        return check_actions(Path(rest[0] if rest else ".github/workflows"))
    if command == "licenses" and rest:
        return check_licenses([Path(path) for path in rest])
    if command == "test":
        result = unittest.main(argv=[sys.argv[0]], exit=False, verbosity=1).result
        return 0 if result.wasSuccessful() else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
