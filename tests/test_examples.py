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
    # sanitized worked example built from public reporting.
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


# --- the templates must carry the controls the references promise -----------

TEMPLATES = REPO / "skills/threat-hunt/assets/templates"


def test_the_gap_register_asks_why_the_gap_exists():
    # ADR 0005. A gap is an engineering problem or it is an adversary impairing
    # telemetry, and the register is where that question gets forced. If the
    # field goes missing from the template, the skill quietly reverts to
    # treating every absence as a procurement item.
    gaps = (TEMPLATES / "02-gaps.yml").read_text()
    assert "cause:" in gaps
    assert "cause_evidence:" in gaps
    assert "undetermined" in gaps


def test_metadata_records_the_attack_version():
    # Also ADR 0005. ATT&CK revokes and re-issues technique IDs between
    # releases, so counting techniques across hunts without knowing which
    # version each used counts two different taxonomies -- which would corrupt
    # the coverage metric ADR 0004 promises.
    assert "version:" in (TEMPLATES / "metadata.yml").read_text()


def test_the_survey_template_classifies_coverage_shape():
    # The input to the cause judgment: never-reported versus stopped-reporting
    # is what distinguishes an engineering gap from a hunt.
    survey = (TEMPLATES / "01-data-survey.md").read_text()
    assert "Why each gap exists" in survey
    assert "TA0112" in survey


# --- ADR 0006: the controls that stop the skill manufacturing confidence ----
#
# All three came from the evaluation, where the skill produced confident
# statements nothing had verified. The fix is instruction rather than code --
# no parser distinguishes a fluent sentence that overstates the register from
# one that does not -- so what is testable is that the instruction still ships.


def test_the_charter_records_a_source_check():
    # The worst eval finding: given a prompt claiming an advisory contained IP
    # addresses when it contained none, the skill accepted the premise and built
    # a sweep against a lookup that could never be populated. Everything
    # downstream inherits the trigger, so an unchecked premise aims the whole
    # hunt at the wrong thing.
    charter = (TEMPLATES / "00-charter.md").read_text()
    assert "Source check" in charter
    assert "Source read directly?" in charter
    assert "Where it contradicts the request" in charter
    # An unreachable source must record what it COSTS, not merely that it
    # happened. "Unverified" on its own is a label; the value is knowing which
    # conclusions fall over if the assumption is wrong.
    assert "what it costs" in charter


def test_the_skill_requires_sourcing_for_external_claims():
    # The skill arm asserted dated vendor specifics with no citations while the
    # baseline cited twelve primary sources. Recalled facts about telemetry age
    # badly and read identically to checked ones on the page.
    skill = (REPO / "skills/threat-hunt/SKILL.md").read_text()
    assert "Cite what you assert about the outside world" in skill
    assert "unverified" in skill


def test_the_report_may_not_outrun_the_gap_register():
    # One eval run's report said "Confirmed already: ..." for two items its own
    # gap register marked as placeholders. A report that asserts what the
    # register marks unverified manufactures the false confidence the whole
    # method exists to remove.
    report = (TEMPLATES / "05-report.md").read_text()
    assert "[FILL" in report
    assert "never as" in report and "confirmed" in report
    # Gap provenance: measured, reported, or assumed.
    assert "Established how" in report


def test_the_trigger_check_has_a_worked_example():
    # An instruction with no worked example gets read and not applied. This one
    # uses the real failure, from a public advisory, so the example carries its
    # own provenance.
    ref = (REPO / "skills/threat-hunt/references/pyramid-and-hypothesis.md").read_text()
    assert "Worked trigger check" in ref
    assert "AA24-109A" in ref
