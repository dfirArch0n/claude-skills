"""Tests for hunt package scaffolding.

A hunt package accumulates analysis that exists nowhere else, so the behaviour
worth protecting here is mostly about *not destroying things*: never overwrite,
never half-create, and never let real hunt output land in a public repository
without saying so.
"""

import shutil
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


def test_creation_inside_the_skills_repository_is_refused(templates):
    # The public-repository control, upgraded from a warning to a refusal after
    # the second-AI review pointed out the obvious: new_hunt.py defaults to
    # ./hunts, so running the documented command from this checkout wrote hunt
    # output into the public repository and only mentioned it afterwards.
    repo_root = Path(__file__).resolve().parents[1]
    with pytest.raises(ScaffoldError, match="public skills repository"):
        create_hunt("rmm-persistence", repo_root / "hunts", templates, "hunter", date(2026, 9, 29))


def test_the_refusal_leaves_nothing_behind(templates):
    # A control that half-executes is not a control. The destination check runs
    # before any directory is created, so a refused run is indistinguishable
    # from one that never happened.
    repo_root = Path(__file__).resolve().parents[1]
    with pytest.raises(ScaffoldError):
        create_hunt("leftover-check", repo_root / "hunts", templates, "h", date(2026, 9, 29))
    assert not (repo_root / "hunts").exists()


def test_the_refusal_can_be_overridden_deliberately(templates):
    # Testing the scaffolding itself has to be possible. The override is
    # explicit and still warns, so it cannot be taken accidentally.
    repo_root = Path(__file__).resolve().parents[1]
    result = create_hunt(
        "rmm-persistence",
        repo_root / "hunts",
        templates,
        "hunter",
        date(2026, 9, 29),
        allow_in_skills_repo=True,
    )
    try:
        assert result.warnings
        assert "public" in result.warnings[0]
    finally:
        shutil.rmtree(repo_root / "hunts", ignore_errors=True)


def test_a_write_failure_leaves_no_package_behind(tmp_path, templates, monkeypatch):
    # The half-created package, reproduced. The package is assembled in a
    # staging directory and moved into place, so a disk error partway through
    # cannot strand the hunter with a package missing its gap register -- and
    # cannot lock them out of their own slug, since the refusal to overwrite
    # would then apply to the wreckage.
    real_write = Path.write_text
    calls = {"n": 0}

    def flaky(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError("No space left on device")
        return real_write(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", flaky)

    with pytest.raises(ScaffoldError, match="Could not create"):
        create_hunt("rmm-persistence", tmp_path / "hunts", templates, "h", date(2026, 9, 29))

    monkeypatch.undo()
    assert not (tmp_path / "hunts" / "2026-09-29-rmm-persistence").exists()
    # The staging directory is cleaned up too, rather than left as debris.
    assert list((tmp_path / "hunts").iterdir()) == []


def test_the_shipped_templates_are_all_present():
    # Protects the skill itself rather than the code: config.TEMPLATE_FILES and
    # the files on disk must agree, or a fresh install scaffolds an incomplete
    # package. This is the test that catches a template renamed without
    # updating the list.
    missing = [rel for rel in TEMPLATE_FILES if not (SKILL_TEMPLATES / rel).is_file()]
    assert missing == []
