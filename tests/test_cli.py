"""Tests for the two command-line entry points.

The logic lives in `huntkit` and is tested there. What these protect is the
wiring: argument names, exit codes, and which stream each message goes to. A
hunter's first contact with this skill is one of these commands, and a broken
`--hunts-root` flag is as blocking as a broken converter.

`/bin/echo` stands in for sigma-cli where a run needs to "succeed": it exits 0
and prints its arguments, which is all `convert_rule` requires to treat the
output as a query. No stub files, no network, no real converter.
"""

import sys
from datetime import date
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/threat-hunt/scripts"
sys.path.insert(0, str(SCRIPTS))

import convert as convert_cli  # noqa: E402
import new_hunt as new_hunt_cli  # noqa: E402


@pytest.fixture
def rule(tmp_path):
    path = tmp_path / "rmm-install.sigma.yml"
    path.write_text("title: test\n", encoding="utf-8")
    return path


def test_convert_reports_a_missing_rule_rather_than_crashing(tmp_path, capsys):
    # The likeliest user error: a typo in the rule path. It should cost one
    # clear line, not a traceback that looks like the tool is broken.
    code = convert_cli.main([str(tmp_path / "nope.yml")])
    assert code == 1
    assert "not found" in capsys.readouterr().err


def test_convert_writes_queries_and_exits_zero(rule, tmp_path, capsys):
    # The happy path through the CLI, including that --output-dir is honoured
    # and the manifest lands beside the queries.
    out = tmp_path / "generated"
    code = convert_cli.main(
        [str(rule), "--targets", "splunk", "--output-dir", str(out), "--sigma-binary", "/bin/echo"]
    )
    assert code == 0
    assert (out / "rmm-install.spl").exists()
    assert (out / "conversion-manifest.json").exists()
    assert "1/1 converted" in capsys.readouterr().out


def test_convert_exits_zero_on_a_partial_result(rule, tmp_path, capsys):
    # Deliberate: a partial result is the designed behavior, not an error. One
    # broken backend must not make a script treat three good queries as a failed
    # run. Only a run where nothing converted is an error.
    out = tmp_path / "generated"
    code = convert_cli.main(
        [
            str(rule),
            "--targets",
            "splunk",
            "crowdstrike",
            "--output-dir",
            str(out),
            "--sigma-binary",
            "/bin/echo",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "1/2 converted" in captured.out
    assert "Unknown target" in captured.err


def test_convert_exits_nonzero_when_nothing_converted(rule, tmp_path):
    # The inverse: if every target failed there is nothing to hunt with, and a
    # calling script should know.
    code = convert_cli.main(
        [str(rule), "--targets", "crowdstrike", "--output-dir", str(tmp_path / "g")]
    )
    assert code == 1


def test_convert_help_lists_the_real_target_names(capsys):
    # Targets are query languages, not plugin names -- `crowdstrike` and
    # `elasticsearch` both look right and both fail. --help is where a hunter
    # looks first, so the mapping has to be there.
    with pytest.raises(SystemExit):
        convert_cli.main(["--help"])
    out = capsys.readouterr().out
    assert "log_scale" in out
    assert "CrowdStrike NG-SIEM" in out


def test_new_hunt_creates_a_package_and_says_where(tmp_path, capsys):
    # The scaffolding path a hunter actually types, including that it prints the
    # location rather than leaving them to guess.
    code = new_hunt_cli.main(
        ["--slug", "rmm-persistence", "--hunts-root", str(tmp_path / "hunts"), "--hunter", "B"]
    )
    assert code == 0
    package = tmp_path / "hunts" / f"{date.today().isoformat()}-rmm-persistence"
    assert (package / "00-charter.md").exists()
    assert str(package) in capsys.readouterr().out


def test_new_hunt_rejects_a_bad_slug_with_a_usable_message(tmp_path, capsys):
    # Slugs become directory names, and the error has to say what a good one
    # looks like -- "invalid slug" alone sends the hunter to read the source.
    code = new_hunt_cli.main(["--slug", "RMM Persistence", "--hunts-root", str(tmp_path / "hunts")])
    assert code == 1
    assert "lowercase words joined by hyphens" in capsys.readouterr().err


def test_new_hunt_refuses_to_write_into_the_public_repository(capsys):
    # End-to-end proof of ADR 0003's control. The default --hunts-root is
    # `hunts`, so running this from inside the checkout is exactly the accident
    # the refusal exists to prevent.
    repo_root = Path(__file__).resolve().parents[1]
    code = new_hunt_cli.main(
        ["--slug", "should-not-exist", "--hunts-root", str(repo_root / "hunts")]
    )
    assert code == 1
    assert "public skills repository" in capsys.readouterr().err
    assert not (repo_root / "hunts").exists()
