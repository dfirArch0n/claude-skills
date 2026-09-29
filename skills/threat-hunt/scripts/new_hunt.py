#!/usr/bin/env python3
"""Scaffold a hunt package from the skill's templates.

new_hunt.py --slug rmm-persistence --hunts-root ~/git/hunts/hunts
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from huntkit.scaffold import ScaffoldError, create_hunt

SKILL_DIR = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, create the package, and report what was written."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", required=True, help="Short kebab-case hunt name.")
    parser.add_argument(
        "--hunts-root",
        default="hunts",
        help="Directory holding hunt packages (default: hunts). Keep this in "
        "your private hunt repository, not in the public skills repository.",
    )
    parser.add_argument("--hunter", default="", help="Name recorded in the charter.")
    parser.add_argument(
        "--allow-in-skills-repo",
        action="store_true",
        help="Permit creation inside the public skills repository. For testing "
        "the scaffolding only; real hunt output belongs elsewhere (ADR 0003).",
    )
    args = parser.parse_args(argv)

    try:
        result = create_hunt(
            slug=args.slug,
            hunts_root=Path(args.hunts_root).expanduser(),
            templates_dir=SKILL_DIR / "assets" / "templates",
            hunter=args.hunter or "<hunter>",
            allow_in_skills_repo=args.allow_in_skills_repo,
        )
    except ScaffoldError as exc:
        print(f"Could not create the hunt package: {exc}", file=sys.stderr)
        return 1

    for warning in result.warnings:
        print(f"WARNING: {warning}\n", file=sys.stderr)

    print(f"Created {result.package_dir}")
    for path in result.files:
        print(f"  {path.relative_to(result.package_dir)}")
    print("\nStart with 00-charter.md: the trigger, the climb, and the three gates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
