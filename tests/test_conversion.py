"""Tests for Sigma rule conversion.

The behavior under test is mostly about *failure*: this skill's standing rule
is that one broken backend must not cost the hunter the other three, and that a
step which quietly did nothing must never read as a step that succeeded.

No real sigma-cli, no network, no temp shell scripts. The command runner is
injected, so each failure mode is produced by construction.
"""

import json
from pathlib import Path

import pytest

from huntkit.config import MANIFEST_NAME, TARGETS
from huntkit.conversion import (
    CommandResult,
    build_command,
    convert_rule,
    first_error_line,
    has_bare_or,
    output_warnings,
    parse_target_spec,
    resolve_sigma_binary,
)


def ok(stdout):
    """A runner that always succeeds with the given query text."""
    return lambda argv: CommandResult(0, stdout, "Parsing Sigma rules\n")


def per_target(outcomes):
    """A runner that answers differently depending on the -t argument.

    Lets one test exercise a mixed run: some backends working, some not.
    """

    def run(argv):
        target = argv[argv.index("-t") + 1]
        return outcomes[target]

    return run


@pytest.fixture
def rule(tmp_path):
    path = tmp_path / "rmm-persistence.sigma.yml"
    path.write_text("title: test\n", encoding="utf-8")
    return path


# --- the normal case -------------------------------------------------------


def test_every_target_converts_and_writes_a_file(rule, tmp_path):
    # Protects the basic promise: one rule in, one query file per platform out,
    # named after the rule so a hunt package stays navigable.
    out = tmp_path / "generated"
    results = convert_rule(
        rule, ["splunk", "kusto"], out, runner=ok("search foo"), sigma_binary="sigma"
    )

    assert [r.succeeded for r in results] == [True, True]
    assert (out / "rmm-persistence.spl").read_text().strip() == "search foo"
    assert (out / "rmm-persistence.kql").read_text().strip() == "search foo"


def test_manifest_records_every_attempt(rule, tmp_path):
    # Protects the audit trail. Query languages disagree about comment syntax,
    # so the record of which pipeline produced which file lives in a sidecar.
    # Without it, a hunter three weeks later cannot tell how a query was made.
    out = tmp_path / "generated"
    convert_rule(rule, ["splunk"], out, runner=ok("search foo"), sigma_binary="sigma")

    manifest = json.loads((out / MANIFEST_NAME).read_text())
    assert manifest["conversions"][0]["pipeline"] == "splunk_windows"
    assert "sigma convert -t splunk" in manifest["conversions"][0]["command"]


# --- failure never stops the rest ------------------------------------------


def test_one_failing_backend_does_not_stop_the_others(rule, tmp_path):
    # THE design rule. A hunter with four platforms and a broken Elastic plugin
    # must still get Splunk and Kusto queries. Before this behavior existed,
    # the natural implementation raised on the first failure and the hunt
    # stalled on a tooling problem.
    out = tmp_path / "generated"
    runner = per_target(
        {
            "splunk": CommandResult(0, "search foo", ""),
            "esql": CommandResult(2, "", "Error: pipeline not found"),
            "kusto": CommandResult(0, "DeviceProcessEvents", ""),
        }
    )
    results = convert_rule(
        rule, ["splunk", "esql", "kusto"], out, runner=runner, sigma_binary="sigma"
    )

    assert [r.succeeded for r in results] == [True, False, True]
    assert "pipeline not found" in results[1].error
    # The successes are on disk; the failure wrote nothing.
    assert (out / "rmm-persistence.spl").exists()
    assert (out / "rmm-persistence.kql").exists()
    assert not (out / "rmm-persistence.esql").exists()


def test_exit_zero_with_no_query_is_a_failure(rule, tmp_path):
    # The silent failure this whole module is shaped around. sigma-cli can exit
    # 0 and print nothing. Trusting the return code writes an empty file, and an
    # empty query file reads exactly like "the rule matched nothing" -- a false
    # all-clear, which is the worst outcome a hunt tool can produce.
    out = tmp_path / "generated"
    runner = ok("   \n  ")
    results = convert_rule(rule, ["splunk"], out, runner=runner, sigma_binary="sigma")

    assert results[0].succeeded is False
    assert "exited 0 but produced no query" in results[0].error
    assert not (out / "rmm-persistence.spl").exists()


def test_missing_sigma_binary_is_recorded_with_the_remedy(rule, tmp_path):
    # Protects the first-run experience. uv puts sigma in ~/.local/bin, which is
    # often not on PATH, so "not found" is the most likely first error. The
    # message names the fix instead of leaving the hunter to search for it.
    def explode(argv):
        raise OSError("No such file or directory: 'sigma'")

    results = convert_rule(rule, ["splunk"], tmp_path / "g", runner=explode, sigma_binary="sigma")

    assert results[0].succeeded is False
    assert "setup_sigma.sh" in results[0].error


def test_unknown_target_is_recorded_and_the_rest_continue(rule, tmp_path):
    # Protects against a typo costing the whole run. Naming the known targets in
    # the error matters because the identifiers are query languages, not plugin
    # names -- "crowdstrike" and "elasticsearch" both look right and both fail.
    out = tmp_path / "generated"
    results = convert_rule(
        rule, ["crowdstrike", "splunk"], out, runner=ok("search foo"), sigma_binary="sigma"
    )

    assert results[0].succeeded is False
    assert "log_scale" in results[0].error
    assert results[1].succeeded is True


def test_no_targets_produces_no_crash_and_still_writes_a_manifest(rule, tmp_path):
    # Boundary case. An empty target list is a caller mistake, not a reason to
    # raise; the manifest still records that a conversion was attempted with
    # nothing requested, which is easier to diagnose than silence.
    out = tmp_path / "generated"
    results = convert_rule(rule, [], out, runner=ok("x"), sigma_binary="sigma")

    assert results == []
    assert json.loads((out / MANIFEST_NAME).read_text())["conversions"] == []


# --- command construction --------------------------------------------------


def test_esql_gets_the_pipeline_check_override(rule):
    # Protects a fix for a real pySigma quirk: the ECS pipelines map ES|QL
    # fields correctly but are not registered against the esql target, so
    # sigma-cli rejects a combination that works. Losing this flag makes every
    # ES|QL conversion fail with a misleading "not intended to be used" error.
    argv = build_command("sigma", rule, TARGETS["esql"], "ecs_windows")
    assert "--disable-pipeline-check" in argv


def test_other_targets_do_not_get_the_override(rule):
    # The override suppresses a genuine safety check, so it must stay scoped to
    # the one target that needs it. Applying it everywhere would let a real
    # pipeline/target mismatch through silently.
    argv = build_command("sigma", rule, TARGETS["splunk"], "splunk_windows")
    assert "--disable-pipeline-check" not in argv


def test_pipeline_override_replaces_the_default(rule, tmp_path):
    # Protects the ability to hunt Sentinel instead of Defender, or CIM instead
    # of raw Windows. The default pipeline is a convenience; a hunter whose data
    # lives elsewhere must be able to say so.
    seen = []

    def spy(argv):
        seen.append(argv)
        return CommandResult(0, "imProcessCreate", "")

    convert_rule(rule, ["kusto:sentinel_asim"], tmp_path / "g", runner=spy, sigma_binary="sigma")
    assert "sentinel_asim" in seen[0]


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("splunk", ("splunk", None, None)),
        ("kusto:sentinel_asim", ("kusto", "sentinel_asim", None)),
        ("log_scale:", ("log_scale", None, None)),
        ("splunk:splunk_cim:data_model", ("splunk", "splunk_cim", "data_model")),
    ],
)
def test_target_spec_parsing(spec, expected):
    # Protects the target:pipeline argument shape, including the trailing-colon
    # typo, which should fall back to the default rather than ask for a
    # pipeline named "".
    assert parse_target_spec(spec) == expected


def test_resolve_sigma_binary_prefers_an_explicit_path():
    # Protects testability and the ability to point at a specific install.
    assert resolve_sigma_binary("/opt/sigma") == "/opt/sigma"


def test_resolve_sigma_binary_returns_something_when_nothing_is_installed(monkeypatch):
    # Protects against resolution raising. When sigma is genuinely absent the
    # caller should get a clean recorded failure from the runner, not an
    # exception thrown while working out the path.
    monkeypatch.setattr("huntkit.conversion.shutil.which", lambda _: None)
    monkeypatch.setattr(Path, "exists", lambda _: False)
    assert resolve_sigma_binary() == "sigma"


# --- error messages a human can act on -------------------------------------


def test_the_error_line_is_pulled_out_of_a_click_usage_block():
    # Protects message quality. sigma-cli wraps its real error in a click usage
    # block, so naive first-line or last-line extraction surfaces "Try --help"
    # or a hint about file names -- both true, neither the problem. A hunter
    # reading a failed conversion should see the cause on the first line.
    stderr = (
        "Usage: sigma convert [OPTIONS] INPUT...\n"
        "Try 'sigma convert --help' for help.\n"
        "\n"
        "Error: The pipeline 'does_not_exist' was not found.\n"
        "Pipelines not listed here are treated as file names.\n"
    )
    assert first_error_line(stderr) == "The pipeline 'does_not_exist' was not found."


def test_an_error_with_no_marker_falls_back_to_the_last_line():
    # Not every failure is a click error. A backend that crashes should still
    # produce something readable rather than an empty summary.
    assert first_error_line("Traceback...\nValueError: bad field mapping") == (
        "ValueError: bad field mapping"
    )


def test_an_empty_error_is_still_reportable():
    # Boundary case: a non-zero exit with nothing on stderr. The summary line
    # must not blow up building itself, because that would turn a reported
    # failure into a crash.
    assert first_error_line("   \n  ") == "(no error message)"


# --- a pipeline that needs a format ----------------------------------------


def test_splunk_cim_gets_the_data_model_format(rule, tmp_path):
    # The most dangerous defect the second-AI review found. splunk_cim maps
    # fields onto the CIM data model; without -f data_model sigma-cli emits a
    # bare filter over Processes.* attributes. That converts, reports success,
    # and returns zero rows in an ordinary search -- a false all-clear that
    # looks exactly like a clean hunt result.
    seen = []

    def spy(argv):
        seen.append(argv)
        return CommandResult(0, "| tstats count from datamodel=Endpoint.Processes", "")

    convert_rule(rule, ["splunk:splunk_cim"], tmp_path / "g", runner=spy, sigma_binary="sigma")
    assert "-f" in seen[0]
    assert "data_model" in seen[0]


def test_an_explicit_format_wins(rule, tmp_path):
    # The derived format is a safety net, not a straitjacket. A hunter who wants
    # savedsearches.conf must be able to say so.
    seen = []

    def spy(argv):
        seen.append(argv)
        return CommandResult(0, "[saved search]", "")

    convert_rule(
        rule, ["splunk:splunk_cim:savedsearches"], tmp_path / "g", runner=spy, sigma_binary="s"
    )
    assert seen[0][seen[0].index("-f") + 1] == "savedsearches"


def test_targets_without_a_format_requirement_pass_none(rule, tmp_path):
    # The inverse: passing -f where it is not wanted would change output shape
    # for every other platform.
    seen = []

    def spy(argv):
        seen.append(argv)
        return CommandResult(0, "DeviceProcessEvents", "")

    convert_rule(rule, ["kusto"], tmp_path / "g", runner=spy, sigma_binary="sigma")
    assert "-f" not in seen[0]


def test_elastalert_gets_the_pipeline_check_override(rule):
    # Same pySigma quirk as esql: the ECS pipelines map elastalert's fields
    # correctly but never registered against the target. Verified by converting
    # the canary rule both ways.
    argv = build_command("sigma", rule, TARGETS["elastalert"], "ecs_windows")
    assert "--disable-pipeline-check" in argv


# --- output files must not collide or go stale ------------------------------


def test_two_pipelines_for_one_target_get_separate_files(rule, tmp_path):
    # Reproduced by the reviewer: kusto:microsoft_xdr and kusto:sentinel_asim
    # both wrote <stem>.kql, so the second silently replaced the first while the
    # manifest claimed two outputs. Hunting Defender and Sentinel in one run is
    # an ordinary thing to want.
    out = tmp_path / "generated"
    results = convert_rule(
        rule,
        ["kusto:microsoft_xdr", "kusto:sentinel_asim"],
        out,
        runner=ok("DeviceProcessEvents"),
        sigma_binary="sigma",
    )

    paths = {r.output_path for r in results}
    assert len(paths) == 2
    assert (out / "rmm-persistence.microsoft_xdr.kql").exists()
    assert (out / "rmm-persistence.sentinel_asim.kql").exists()


def test_a_single_target_keeps_the_simple_filename(rule, tmp_path):
    # Disambiguation only where it is needed. Putting the pipeline into every
    # filename would make the common case ugly for no benefit.
    out = tmp_path / "generated"
    convert_rule(rule, ["kusto"], out, runner=ok("DeviceProcessEvents"), sigma_binary="sigma")
    assert (out / "rmm-persistence.kql").exists()


def test_a_failed_conversion_sets_stale_output_aside_without_destroying_it(rule, tmp_path):
    # Two failures in tension, and the second is worse. A conversion that worked
    # yesterday and fails today leaves its old query on disk: the manifest says
    # FAILED, the directory says otherwise, and the hunter runs logic that no
    # longer matches the rule. But deleting it destroys work -- this skill tells
    # LogScale users to repair generated CQL BY HAND, so that file may be the
    # only copy of someone's edits. It gets renamed, not removed.
    out = tmp_path / "generated"
    convert_rule(rule, ["splunk"], out, runner=ok("old query"), sigma_binary="sigma")
    (out / "rmm-persistence.spl").write_text("HAND-TUNED, hours of work\n")

    results = convert_rule(
        rule,
        ["splunk"],
        out,
        runner=lambda argv: CommandResult(2, "", "Error: pipeline not found"),
        sigma_binary="sigma",
    )

    # The misleading current-looking file is gone from the expected path...
    assert not (out / "rmm-persistence.spl").exists()
    # ...but the human's work still exists, and the error says where.
    assert (out / "rmm-persistence.spl.stale").read_text() == "HAND-TUNED, hours of work\n"
    assert "moved to rmm-persistence.spl.stale" in results[0].error


def test_a_warned_conversion_is_not_reported_as_clean(rule, tmp_path):
    # "4/4 converted" beside a query the backend is known to emit wrongly is a
    # number that gets believed. A known-defective output converts, but it is
    # not a clean success and must not be counted as one.
    out = tmp_path / "generated"
    results = convert_rule(
        rule,
        ["log_scale"],
        out,
        runner=ok("event_platform=/Win/i a=/x/i or b=/y/i"),
        sigma_binary="sigma",
    )
    assert results[0].succeeded is True
    assert results[0].clean is False
    assert results[0].summary.startswith("[WARN]")


def test_an_undefective_conversion_is_clean(rule, tmp_path):
    # The companion: output with no known defect must still read as a plain
    # success, or the WARN label stops meaning anything.
    results = convert_rule(
        rule, ["splunk"], tmp_path / "g", runner=ok("search foo"), sigma_binary="sigma"
    )
    assert results[0].clean is True
    assert results[0].summary.startswith("[ok]")


def test_a_lost_manifest_is_attached_to_every_conversion(rule, tmp_path):
    # Queries on disk with no record of the pipeline and format that produced
    # them are not reproducible. Previously the run still printed a Details path
    # that did not exist and reported complete success.
    out = tmp_path / "generated"
    out.mkdir(parents=True)
    (out / MANIFEST_NAME).mkdir()  # a directory where the file should go

    results = convert_rule(rule, ["splunk"], out, runner=ok("search foo"), sigma_binary="sigma")

    assert results[0].succeeded is True
    assert results[0].clean is False
    assert any("not reproducible" in w or "untraceable" in w for w in results[0].warnings)


def test_same_pipeline_different_formats_get_separate_files(rule, tmp_path):
    # splunk_cim as a data_model query and as savedsearches.conf are different
    # artifacts. Disambiguating on pipeline alone collided them, and the second
    # silently replaced the first while the manifest claimed two outputs.
    out = tmp_path / "generated"
    results = convert_rule(
        rule,
        ["splunk:splunk_cim:data_model", "splunk:splunk_cim:savedsearches"],
        out,
        runner=ok("| tstats count"),
        sigma_binary="sigma",
    )
    paths = {r.output_path for r in results}
    assert len(paths) == 2, f"outputs collided: {paths}"
    assert all(p is not None for p in paths)


# --- disk failures are recorded, never raised -------------------------------


def test_a_write_failure_is_recorded_and_the_others_continue(rule, tmp_path, monkeypatch):
    # Reproduced by the reviewer as a Critical: an unguarded write meant a disk
    # error on the first platform took the remaining platforms AND the manifest
    # with it. Converting is the expensive part; losing three good queries to a
    # full disk on the fourth is the opposite of the design rule.
    out = tmp_path / "generated"
    real_write = Path.write_text

    def flaky(self, *args, **kwargs):
        if self.name.endswith(".spl"):
            raise OSError("No space left on device")
        return real_write(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", flaky)
    results = convert_rule(rule, ["splunk", "kusto"], out, runner=ok("query"), sigma_binary="sigma")
    monkeypatch.undo()

    assert results[0].succeeded is False
    assert "could not write" in results[0].error
    assert results[1].succeeded is True
    # The audit trail survives the disk error that destroyed one query.
    assert (out / MANIFEST_NAME).exists()


def test_an_unwritable_output_directory_still_returns_results(rule, tmp_path, monkeypatch):
    # Boundary case: if the directory itself cannot be made, the caller still
    # gets one recorded failure per target rather than a traceback, so the CLI
    # can explain what happened for every platform asked for.
    def no_mkdir(self, *args, **kwargs):
        raise OSError("Read-only file system")

    monkeypatch.setattr(Path, "mkdir", no_mkdir)
    results = convert_rule(
        rule, ["splunk", "kusto"], tmp_path / "g", runner=ok("q"), sigma_binary="sigma"
    )
    monkeypatch.undo()

    assert len(results) == 2
    assert all(not r.succeeded for r in results)
    assert "Read-only file system" in results[0].error


def test_an_error_marker_with_the_message_on_the_next_line():
    # Caught by the reviewer: an "Error:" line whose message wraps produced a
    # blank failure reason, so the CLI printed FAILED with nothing after it.
    assert first_error_line("Usage: sigma\nError:\nThe pipeline was not found.") == (
        "The pipeline was not found."
    )


# --- known-bad backend output ----------------------------------------------
#
# Found by three independent eval runs and confirmed upstream:
# pySigma-backend-crowdstrike declares precedence (NOT, OR, AND) but emits AND
# as juxtaposition, which LogScale binds tighter than an explicit `or`. The
# parentheses around a nested OR group are dropped, so the AND-ed conjuncts
# apply only to the first disjunct and every later one matches unscoped. The
# query converts, runs, and matches far more than the rule states -- the exact
# silent-wrong-answer failure this toolchain exists to prevent.
#
# Fix merged upstream 2026-09-20; unreleased as of 3.0.0 (2025-11-30).


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("a=1 b=2 or c=3", True),
        ("a=1 not (b=2 or c=3)", False),
        ("a=1 b=2", False),
        ("(a=1 or b=2) c=3", False),
        ("(a=1 or b=2) c=3 or d=4", True),
        ("a=1 (b=2 or c=3) not (d=4 or e=5)", False),
    ],
)
def test_bare_or_detection(query, expected):
    # Distinguishes an `or` the backend left unscoped from one safely inside
    # parentheses. The converter does parenthesize negated groups, so warning on
    # every `or` would cry wolf on correct output and get ignored.
    assert has_bare_or(query) is expected


def test_log_scale_output_with_a_bare_or_is_flagged():
    # The warning that matters. Without it a hunter runs an over-matching query
    # and reads the extra hits as a noisy detection rather than a broken one.
    warnings = output_warnings("log_scale", "event_platform=/Win/i a=/x/i or b=/y/i")
    assert warnings
    assert "matches MORE than the rule states" in warnings[0]


def test_log_scale_output_without_a_bare_or_is_not_flagged():
    # The defect only manifests where an OR group is nested in an AND. A rule
    # with no disjunction converts correctly and should pass quietly.
    assert output_warnings("log_scale", "event_platform=/Win/i ImageFileName=/x/i") == ()


def test_other_backends_are_not_flagged():
    # Splunk, Kusto and Elastic parenthesize correctly. Warning on them would
    # train the hunter to skip the warning that is real.
    assert output_warnings("splunk", 'a="1" OR b="2"') == ()
    assert output_warnings("kusto", "a == 1 or b == 2") == ()


def test_the_warning_reaches_the_conversion_and_the_manifest(rule, tmp_path):
    # End to end: the warning has to survive into the Conversion object and the
    # manifest, because that sidecar is what a hunter reads weeks later when
    # deciding whether a saved query is trustworthy.
    out = tmp_path / "generated"
    results = convert_rule(
        rule,
        ["log_scale"],
        out,
        runner=ok("event_platform=/Win/i a=/x/i or b=/y/i"),
        sigma_binary="sigma",
    )
    assert results[0].warnings
    manifest = json.loads((out / MANIFEST_NAME).read_text())
    assert manifest["conversions"][0]["warnings"]
