#!/usr/bin/env python3
"""Generate the requirements traceability matrix from the source tree.

BETA_BUILD_PLAN.md W-01 asks for a matrix mapping each beta requirement to code,
tests and evidence. Written by hand it would be stale within a week, so it is
generated: requirement IDs are read from the SRS, then located in the Rust and
Move sources and in the test suite.

Usage:  python3 docs/beta/traceability.py > docs/beta/TRACEABILITY.md
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRS = ROOT / "docs/src/SENA_SRS.md"
ID = re.compile(r"\b((?:REQ|NFR)-[A-Z]+-\d{3})\b")

# Directories searched, and how a hit in each is classified.
SOURCES = {
    "rust": ["crates"],
    "move": ["move"],
}


def requirement_ids() -> list[str]:
    """Every requirement defined in the SRS, in document order."""
    text = SRS.read_text(encoding="utf-8")
    seen: list[str] = []
    for match in ID.finditer(text):
        # A definition looks like "- **REQ-X-001:** ...", a reference does not.
        if match.group(1) not in seen:
            seen.append(match.group(1))
    return seen


def citations(req: str) -> dict[str, list[str]]:
    """Files citing a requirement, grouped by kind."""
    found: dict[str, list[str]] = {"rust": [], "move": [], "test": []}
    for kind, dirs in SOURCES.items():
        for directory in dirs:
            target = ROOT / directory
            if not target.exists():
                continue
            result = subprocess.run(
                ["grep", "-rl", req, str(target)],
                capture_output=True, text=True, check=False,
            )
            for line in result.stdout.splitlines():
                rel = pathlib.Path(line).relative_to(ROOT).as_posix()
                bucket = "test" if "/tests/" in rel or rel.endswith("_test.rs") else kind
                found[bucket].append(rel)
    return found


def link(path: str) -> str:
    return f"[`{pathlib.Path(path).name}`](../../{path})"


def main() -> None:
    ids = requirement_ids()
    if not ids:
        sys.exit("no requirement IDs found; is the SRS present?")

    covered = 0
    rows = []
    for req in ids:
        found = citations(req)
        has_impl = bool(found["rust"] or found["move"])
        if has_impl:
            covered += 1
        impl = ", ".join(sorted({link(p) for p in found["rust"] + found["move"]})) or "—"
        tests = ", ".join(sorted({link(p) for p in found["test"]})) or "—"
        status = "implemented" if has_impl else "not implemented"
        rows.append(f"| `{req}` | {status} | {impl} | {tests} |")

    print("# Requirements traceability")
    print()
    print("**Generated** by `docs/beta/traceability.py` — do not edit by hand.")
    print()
    print("Maps every requirement in the SRS to the code that cites it and the tests")
    print("that exercise it. A requirement showing `—` in both columns is not")
    print("implemented; that is information, not an error.")
    print()
    print("A citation means the source file names the requirement ID. It is evidence of")
    print("intent, not proof of correctness — read the cited code and its tests before")
    print("treating a row as satisfied.")
    print()
    print(f"**{covered} of {len(ids)} requirements are cited somewhere in the implementation.**")
    print()
    print("| Requirement | Status | Implementation | Tests |")
    print("|---|---|---|---|")
    print("\n".join(rows))


if __name__ == "__main__":
    main()
