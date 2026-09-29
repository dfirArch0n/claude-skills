"""Create a hunt package from the bundled templates.

Templates are copied rather than generated, so the shape of a hunt package is
stable across runs and across models. A package whose sections drift between
hunts cannot be compared, and comparison across hunts is the whole point of
`metadata.yml`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date as date_type
from pathlib import Path

from huntkit.config import (
    PLACEHOLDER_DATE,
    PLACEHOLDER_HUNTER,
    PLACEHOLDER_SLUG,
    TEMPLATE_FILES,
)

SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class ScaffoldError(Exception):
    """Raised when a hunt package cannot be created.

    Unlike a conversion failure, this is not something to record and continue
    past: there is no package to continue into.
    """


@dataclass(frozen=True)
class ScaffoldResult:
    """Where the package landed and what it contains."""

    package_dir: Path
    files: tuple[Path, ...]
    warnings: tuple[str, ...]


def package_name(slug: str, on: date_type) -> str:
    """Build the dated directory name for a hunt."""
    return f"{on.isoformat()}-{slug}"


def validate_slug(slug: str) -> None:
    """Reject slugs that would produce awkward or unsafe directory names."""
    if not SLUG_PATTERN.match(slug):
        raise ScaffoldError(
            f"Slug '{slug}' must be lowercase words joined by hyphens, "
            "for example 'rmm-persistence'."
        )


def _render(text: str, slug: str, on: date_type, hunter: str) -> str:
    """Substitute template placeholders."""
    return (
        text.replace(PLACEHOLDER_SLUG, package_name(slug, on))
        .replace(PLACEHOLDER_DATE, on.isoformat())
        .replace(PLACEHOLDER_HUNTER, hunter)
    )


def _publication_warnings(hunts_root: Path) -> tuple[str, ...]:
    """Warn when a package is about to be created inside this public repository.

    A hunt package names hosts, accounts, indexes and the teams that own broken
    telemetry. ADR 0003 keeps that out of a public repository; `.gitignore` is
    the enforcement, and this warning is the part a human actually reads.
    """
    # scaffold.py -> huntkit -> scripts -> threat-hunt, which holds SKILL.md.
    marker = Path(__file__).resolve().parents[2] / "SKILL.md"
    if not marker.exists():
        return ()
    repo_root = marker.parents[2]
    try:
        hunts_root.resolve().relative_to(repo_root)
    except ValueError:
        return ()
    return (
        f"This package is being created inside {repo_root}, which is the public "
        "skills repository. Hunt output belongs in your private hunt repository "
        "(see docs/adr/0003). hunts/ is git-ignored here, so nothing will be "
        "committed, but the files are on disk in a checkout you may share.",
    )


def create_hunt(
    slug: str,
    hunts_root: Path,
    templates_dir: Path,
    hunter: str,
    on: date_type | None = None,
) -> ScaffoldResult:
    """Create a hunt package and return what was written.

    Args:
        slug: Short kebab-case name, e.g. `rmm-persistence`.
        hunts_root: Directory that holds hunt packages, normally `hunts/`.
        templates_dir: The skill's `assets/templates` directory.
        hunter: Name recorded in the charter and report.
        on: Date for the package name; today when omitted.

    Raises:
        ScaffoldError: If the slug is malformed, the templates are missing, or
            a package of that name already exists. Overwriting is refused
            because a hunt package accumulates irreplaceable analysis.
    """
    validate_slug(slug)
    on = on or date_type.today()

    if not templates_dir.is_dir():
        raise ScaffoldError(f"Templates directory not found: {templates_dir}")

    package_dir = hunts_root / package_name(slug, on)
    if package_dir.exists():
        raise ScaffoldError(
            f"{package_dir} already exists. Pick another slug, or continue the "
            "existing hunt rather than overwriting its analysis."
        )

    # Check every template before writing any of them. A package that is half
    # created is worse than one that was refused: the hunter starts filling it
    # in and discovers the missing section at the point they need it.
    missing = [rel for rel in TEMPLATE_FILES if not (templates_dir / rel).is_file()]
    if missing:
        raise ScaffoldError(
            "Templates missing from the skill: " + ", ".join(missing) + ". "
            "The skill directory is incomplete; reinstall it."
        )

    written: list[Path] = []
    for relative in TEMPLATE_FILES:
        source = templates_dir / relative
        destination = package_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            _render(source.read_text(encoding="utf-8"), slug, on, hunter),
            encoding="utf-8",
        )
        written.append(destination)

    return ScaffoldResult(
        package_dir=package_dir,
        files=tuple(written),
        warnings=_publication_warnings(hunts_root),
    )
