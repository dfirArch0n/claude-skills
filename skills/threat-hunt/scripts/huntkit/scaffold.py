"""Create a hunt package from the bundled templates.

Templates are copied rather than generated, so the shape of a hunt package is
stable across runs and across models. A package whose sections drift between
hunts cannot be compared, and comparison across hunts is the whole point of
`metadata.yml`.

Two properties are worth more than convenience here:

- **All or nothing.** A package is assembled in a temporary directory and moved
  into place once complete. A half-created package is worse than a refused one,
  because the refusal to overwrite then locks the hunter out of their own slug
  and the missing section is not discovered until it is needed.
- **Never into the public repository.** Hunt packages name hosts, accounts and
  the teams that own broken telemetry. ADR 0003 keeps that out of a public
  checkout, and a refusal enforces it where a warning would not.
"""

from __future__ import annotations

import re
import shutil
import tempfile
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


def skills_repo_root() -> Path | None:
    """Locate the skills repository this module is running from, if any."""
    # scaffold.py -> huntkit -> scripts -> threat-hunt, which holds SKILL.md.
    marker = Path(__file__).resolve().parents[2] / "SKILL.md"
    if not marker.exists():
        return None
    # threat-hunt -> skills -> repository root.
    return marker.parents[2]


def is_inside_skills_repo(path: Path) -> bool:
    """Would writing here put hunt output inside the public skills repository?"""
    root = skills_repo_root()
    if root is None:
        return False
    try:
        path.resolve().relative_to(root)
    except ValueError:
        return False
    return True


def _render(text: str, slug: str, on: date_type, hunter: str) -> str:
    """Substitute template placeholders."""
    return (
        text.replace(PLACEHOLDER_SLUG, package_name(slug, on))
        .replace(PLACEHOLDER_DATE, on.isoformat())
        .replace(PLACEHOLDER_HUNTER, hunter)
    )


def create_hunt(
    slug: str,
    hunts_root: Path,
    templates_dir: Path,
    hunter: str,
    on: date_type | None = None,
    allow_in_skills_repo: bool = False,
) -> ScaffoldResult:
    """Create a hunt package and return what was written.

    Args:
        slug: Short kebab-case name, e.g. `rmm-persistence`.
        hunts_root: Directory that holds hunt packages, normally `hunts/` inside
            a *private* hunt repository.
        templates_dir: The skill's `assets/templates` directory.
        hunter: Name recorded in the charter and report.
        on: Date for the package name; today when omitted.
        allow_in_skills_repo: Permit creation inside the public skills
            repository. Off by default; the caller must say so deliberately.

    Raises:
        ScaffoldError: If the slug is malformed, the destination is inside the
            public repository, the templates are missing, or a package of that
            name already exists. Overwriting is refused because a hunt package
            accumulates irreplaceable analysis.
    """
    validate_slug(slug)
    on = on or date_type.today()

    # Checked before anything is written, so a refusal leaves no trace.
    if is_inside_skills_repo(hunts_root) and not allow_in_skills_repo:
        raise ScaffoldError(
            f"{hunts_root} is inside the public skills repository "
            f"({skills_repo_root()}). A hunt package names hosts, accounts and "
            "the teams that own broken telemetry, so it belongs in your private "
            "hunt repository -- see docs/adr/0003. Pass --hunts-root to point "
            "somewhere else, or --allow-in-skills-repo if you are only testing."
        )

    if not templates_dir.is_dir():
        raise ScaffoldError(f"Templates directory not found: {templates_dir}")

    package_dir = hunts_root / package_name(slug, on)
    if package_dir.exists():
        raise ScaffoldError(
            f"{package_dir} already exists. Pick another slug, or continue the "
            "existing hunt rather than overwriting its analysis."
        )

    missing = [rel for rel in TEMPLATE_FILES if not (templates_dir / rel).is_file()]
    if missing:
        raise ScaffoldError(
            "Templates missing from the skill: " + ", ".join(missing) + ". "
            "The skill directory is incomplete; reinstall it."
        )

    written = _assemble(slug, package_dir, templates_dir, hunter, on)

    warnings: tuple[str, ...] = ()
    if is_inside_skills_repo(hunts_root):
        warnings = (
            f"This package is inside {skills_repo_root()}, the public skills "
            "repository. hunts/ is git-ignored so nothing will be committed, but "
            "the files are on disk in a checkout you may share.",
        )

    return ScaffoldResult(package_dir=package_dir, files=written, warnings=warnings)


def _assemble(
    slug: str,
    package_dir: Path,
    templates_dir: Path,
    hunter: str,
    on: date_type,
) -> tuple[Path, ...]:
    """Build the package in a staging directory, then move it into place.

    The move is the commit point. Anything that fails before it leaves the
    destination untouched, so a disk error cannot strand the hunter with a
    package that is missing its gap register.
    """
    package_dir.parent.mkdir(parents=True, exist_ok=True)
    # Staged as a sibling so the final move stays on one filesystem; a move
    # across devices is a copy, and a copy can fail halfway.
    staging = Path(tempfile.mkdtemp(prefix=f".{package_dir.name}.", dir=package_dir.parent))

    try:
        for relative in TEMPLATE_FILES:
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                _render((templates_dir / relative).read_text(encoding="utf-8"), slug, on, hunter),
                encoding="utf-8",
            )
        staging.rename(package_dir)
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise ScaffoldError(f"Could not create {package_dir}: {exc}") from exc

    return tuple(package_dir / relative for relative in TEMPLATE_FILES)
