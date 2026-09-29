"""Tests for hunt package scaffolding.

A hunt package accumulates analysis that exists nowhere else, so the behaviour
worth protecting here is mostly about *not destroying things*: never overwrite,
never half-create, and never let real hunt output land in a public repository
without saying so.
"""

from datetime import date
from pathlib import Path

import pytest

from huntkit.config import TEMPLATE_FILES
from huntkit.scaffold import ScaffoldError, create_hunt, package_name, validate_slug

SKILL_TEMPLATES = Path(__file__).resolve().parents[1] / "skills/threat-hunt/assets/templates"


@pytest.fixture
def templates(tmp_path):
    """A minimal template tree, so these tests do not depend on template wording."""
    root = tmp_path / "templates"
    for relative in TEMPLATE_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# {{SLUG}}\nDate: {{DATE}}\nBy: {{HUNTER}}\n", encoding="utf-8")
    return root


def test_every_template_file_is_created(tmp_path, templates):
    # Protects package completeness. A hunt whose gap register or metadata file
    # is missing loses outcomes 2 and the coverage metric entirely -- and the
    # loss is invisible until someone looks for the file months later.
    result = create_hunt(
        "rmm-persistence", tmp_path / "hunts", templates, "hunter", date(2026, 9, 29)
    )

    created = {p.relative_to(result.package_dir).as_posix() for p in result.files}
    assert created == set(TEMPLATE_FILES)


def test_placeholders_are_substituted(tmp_path, templates):
    # Protects against shipping a package still full of {{SLUG}}. A hunter
    # filling in a charter should not have to fix the header first, and a
    # literal placeholder in a report is the kind of thing that reaches a
    # stakeholder.
    result = create_hunt(
        "rmm-persistence", tmp_path / "hunts", templates, "B. Butz", date(2026, 9, 29)
    )

    charter = (result.package_dir / "00-charter.md").read_text()
    assert "2026-09-29-rmm-persistence" in charter
    assert "B. Butz" in charter
    assert "{{" not in charter


def test_existing_package_is_never_overwritten(tmp_path, templates):
    # The one genuinely destructive thing this code could do. Re-running the
    # same command on the same day -- easy to do after a crash or a lost
    # terminal -- must not wipe a day of analysis.
    hunts = tmp_path / "hunts"
    create_hunt("rmm-persistence", hunts, templates, "hunter", date(2026, 9, 29))
    (hunts / "2026-09-29-rmm-persistence" / "00-charter.md").write_text(
        "irreplaceable", encoding="utf-8"
    )

    with pytest.raises(ScaffoldError, match="already exists"):
        create_hunt("rmm-persistence", hunts, templates, "hunter", date(2026, 9, 29))

    assert (hunts / "2026-09-29-rmm-persistence" / "00-charter.md").read_text() == "irreplaceable"


def test_missing_templates_create_nothing_at_all(tmp_path, templates):
    # Protects against a half-created package, which is worse than a refused
    # one: the hunter starts filling it in and finds the missing section at the
    # moment they need it. All templates are checked before any are written.
    (templates / "metadata.yml").unlink()

    with pytest.raises(ScaffoldError, match=r"metadata\.yml"):
        create_hunt("rmm-persistence", tmp_path / "hunts", templates, "hunter", date(2026, 9, 29))

    assert not (tmp_path / "hunts" / "2026-09-29-rmm-persistence").exists()


def test_missing_templates_directory_is_reported_clearly(tmp_path):
    # Protects the symlinked-skill case: if the skill directory is incomplete or
    # the symlink is broken, say so rather than producing an empty package.
    with pytest.raises(ScaffoldError, match="Templates directory not found"):
        create_hunt("x-y", tmp_path / "hunts", tmp_path / "nope", "hunter", date(2026, 9, 29))


@pytest.mark.parametrize("bad", ["RMM Persistence", "rmm_persistence", "../escape", "rmm--x", ""])
def test_malformed_slugs_are_rejected(bad):
    # Slugs become directory names. Rejecting spaces, underscores and path
    # traversal keeps package names sortable and keeps `../` from writing
    # outside the hunts directory.
    with pytest.raises(ScaffoldError):
        validate_slug(bad)


@pytest.mark.parametrize("good", ["rmm-persistence", "aitm-m365", "t1543"])
def test_reasonable_slugs_are_accepted(good):
    # The companion check: the validator must not be so strict that ordinary
    # hunt names fail.
    validate_slug(good)


def test_package_name_sorts_chronologically(tmp_path):
    # Protects the ability to read a hunts directory as a timeline. An ISO date
    # prefix sorts correctly as a string, which no other date format does.
    assert package_name("aitm-m365", date(2026, 9, 29)) == "2026-09-29-aitm-m365"


def test_no_publication_warning_outside_the_skills_repository(tmp_path, templates):
    # Protects against warning fatigue. The public-repository warning must fire
    # only where it is true; a warning on every ordinary run teaches people to
    # ignore it, which is exactly when it matters.
    result = create_hunt(
        "rmm-persistence", tmp_path / "hunts", templates, "hunter", date(2026, 9, 29)
    )
    assert result.warnings == ()


def test_publication_warning_fires_inside_the_skills_repository(tmp_path, templates):
    # The other half: creating a package inside this public checkout must say so
    # out loud. .gitignore stops the commit, but the files are still on disk in
    # a directory the owner may share or screen-share. See ADR 0003.
    repo_root = Path(__file__).resolve().parents[1]
    result = create_hunt(
        "rmm-persistence", repo_root / "hunts", templates, "hunter", date(2026, 9, 29)
    )
    try:
        assert result.warnings
        assert "public" in result.warnings[0]
    finally:
        # These tests write into the real repository to exercise the real path
        # check, so clean up rather than leaving an ignored directory behind.
        for path in sorted(result.package_dir.rglob("*"), reverse=True):
            path.unlink() if path.is_file() else path.rmdir()
        result.package_dir.rmdir()
        (repo_root / "hunts").rmdir()


def test_the_shipped_templates_are_all_present():
    # Protects the skill itself rather than the code: config.TEMPLATE_FILES and
    # the files on disk must agree, or a fresh install scaffolds an incomplete
    # package. This is the test that catches a template renamed without
    # updating the list.
    missing = [rel for rel in TEMPLATE_FILES if not (SKILL_TEMPLATES / rel).is_file()]
    assert missing == []
