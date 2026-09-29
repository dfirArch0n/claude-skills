"""Tests that the repository actually ships what it claims to ship.

These exist because of a real defect the second-AI review caught: `.gitignore`
carried an unanchored `hunts/` rule, which git matches at every level, so it
silently excluded `examples/hunts/` as well. The worked example was written,
committed as far as anyone could tell, and absent from the repository.

An over-matching ignore rule fails silently by construction -- nothing errors,
the file simply is not there -- so the only way to catch it is to assert.
"""

import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples/hunts/rmm-persistence-walkthrough.md"


def git(*args):
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=False)


def test_the_worked_example_exists_on_disk():
    # The cheap half of the check: ADR 0003 and the README both promise a
    # sanitised worked example built from public reporting.
    assert EXAMPLE.is_file()


def test_the_worked_example_is_not_git_ignored():
    # The half that actually caught the bug. `git check-ignore` exits 0 when a
    # path IS ignored, so success here means the file is excluded.
    result = git("check-ignore", "-v", str(EXAMPLE.relative_to(REPO)))
    assert result.returncode != 0, (
        f"examples/ is being ignored by: {result.stdout.strip()}. "
        "An unanchored rule in .gitignore matches at every level."
    )


def test_hunt_output_is_still_ignored():
    # The companion: fixing the over-match must not have disabled the rule that
    # keeps real hunt packages out of a public repository (ADR 0003).
    result = git("check-ignore", "-v", "hunts/2026-01-01-example/00-charter.md")
    assert result.returncode == 0, "hunts/ is no longer ignored -- ADR 0003 is unenforced."


@pytest.mark.parametrize(
    "promised",
    [
        "skills/threat-hunt/SKILL.md",
        "skills/threat-hunt/assets/canary.sigma.yml",
        "skills/threat-hunt/references/pyramid-and-hypothesis.md",
        "skills/threat-hunt/references/data-survey.md",
        "skills/threat-hunt/references/sigma-and-queries.md",
        "skills/threat-hunt/references/findings-and-detections.md",
        "skills/threat-hunt/references/frameworks.md",
        "skills/threat-hunt/scripts/setup_sigma.sh",
        "scripts/review-prompt.md",
    ],
)
def test_files_the_skill_points_at_are_tracked(promised):
    # SKILL.md sends the model to each of these by name. A reference that is on
    # disk locally but missing from the repository breaks the skill for everyone
    # who installs it, and breaks it silently -- the model simply cannot read
    # the file and carries on with less context than the author assumed.
    result = git("ls-files", "--error-unmatch", promised)
    assert result.returncode == 0, f"{promised} is not tracked by git."
