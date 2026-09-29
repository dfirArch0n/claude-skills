"""Convert one Sigma rule to every requested platform.

The design rule this module exists to honour: **a failure on one backend never
stops the others.** A hunter with four platforms and a broken Elastic plugin
should still get Splunk, Kusto and NG-SIEM queries, plus a precise statement of
what went wrong on the fourth — not a traceback and nothing.

The matching rule: a step that quietly did nothing must never read as a step
that succeeded. Three ways that can happen here, all handled explicitly:

- sigma-cli exits 0 having produced no query at all.
- The query converts but cannot be written to disk, and the run stops there,
  taking the other platforms and the audit trail with it.
- A conversion fails while an output file from a previous run is still sitting
  at the destination, so the hunter runs a stale query believing it is current.

The subprocess call is injected as a `CommandRunner` rather than imported, so
tests can drive every failure mode without a real sigma-cli, a network, or a
temporary shell script. Same pattern as `ContextProvider` in security-tooling-dev.
"""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from huntkit.config import (
    MANIFEST_NAME,
    PIPELINE_FORMATS,
    SIGMA_BINARY,
    TARGETS,
    UV_TOOL_BIN,
    Target,
)


@dataclass(frozen=True)
class CommandResult:
    """What running a command produced."""

    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    """Runs a command and returns its result.

    A Protocol is a shape, not a base class: anything with a matching call
    signature satisfies it, so a test can pass a plain function.
    """

    def __call__(self, argv: Sequence[str]) -> CommandResult:
        """Run `argv` and return its outcome."""
        ...


def subprocess_runner(argv: Sequence[str]) -> CommandResult:
    """Run a command for real.

    A missing binary raises `OSError`, which the caller turns into a recorded
    failure rather than a crash.
    """
    completed = subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        check=False,
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def first_error_line(error: str) -> str:
    """Pull the line a human needs out of a multi-line error.

    sigma-cli errors are click usage blocks: a usage banner, a hint, then the
    actual `Error:` line, then more hints. Taking the first or last line gets
    you "Try 'sigma convert --help'" or a note about file names -- both true,
    neither the problem.

    The `Error:` marker sometimes ends the line, with the message wrapping onto
    the next one, so a bare `removeprefix` yields an empty string. Fall through
    to the following line when that happens.
    """
    lines = [line.strip() for line in error.strip().splitlines() if line.strip()]
    if not lines:
        return "(no error message)"
    for index, line in enumerate(lines):
        if line.startswith("Error:"):
            message = line.removeprefix("Error:").strip()
            if message:
                return message
            if index + 1 < len(lines):
                return lines[index + 1]
    return lines[-1]


@dataclass(frozen=True)
class Conversion:
    """The outcome of converting one rule for one target."""

    target: str
    language: str
    pipeline: str | None
    output_format: str | None
    command: str
    succeeded: bool
    query: str
    error: str
    output_path: str | None

    @property
    def summary(self) -> str:
        """One line suitable for a terminal or a hunt report."""
        state = "ok" if self.succeeded else "FAILED"
        detail = self.output_path if self.succeeded else first_error_line(self.error)
        return f"[{state}] {self.language} ({self.target}): {detail}"


def _failure(
    target: str, language: str, pipeline: str | None, fmt: str | None, command: str, error: str
) -> Conversion:
    """Build a failed outcome. Failures are values here, never exceptions."""
    return Conversion(
        target=target,
        language=language,
        pipeline=pipeline,
        output_format=fmt,
        command=command,
        succeeded=False,
        query="",
        error=error,
        output_path=None,
    )


def resolve_sigma_binary(explicit: str | None = None) -> str:
    """Find the `sigma` executable.

    `uv tool install` puts it in `~/.local/bin`, which is often not on PATH —
    a first run otherwise fails with a bare "not found" that tells the hunter
    nothing about the actual cause.
    """
    if explicit:
        return explicit
    found = shutil.which(SIGMA_BINARY)
    if found:
        return found
    fallback = Path(UV_TOOL_BIN).expanduser() / SIGMA_BINARY
    return str(fallback) if fallback.exists() else SIGMA_BINARY


def parse_target_spec(spec: str) -> tuple[str, str | None, str | None]:
    """Split a `target[:pipeline[:format]]` argument.

    Examples:
        `splunk` -> ("splunk", None, None), meaning use the target's defaults.
        `kusto:sentinel_asim` -> ("kusto", "sentinel_asim", None).
        `splunk:splunk_cim:data_model` -> all three named explicitly.
    """
    parts = spec.split(":")
    target = parts[0]
    pipeline = parts[1] if len(parts) > 1 and parts[1] else None
    fmt = parts[2] if len(parts) > 2 and parts[2] else None
    return target, pipeline, fmt


def resolve_format(pipeline: str | None, explicit: str | None) -> str | None:
    """Choose the output format for a pipeline.

    Some pipelines only make sense with a matching format. `splunk_cim` maps
    fields onto the CIM data model, but without `-f data_model` sigma-cli emits
    an ordinary field filter referencing `Processes.*` attributes that no plain
    search will resolve. That converts cleanly, reports success, and returns
    nothing when run -- the exact silent failure this module exists to prevent.
    """
    if explicit:
        return explicit
    return PIPELINE_FORMATS.get(pipeline or "")


def build_command(
    sigma_binary: str,
    rule_path: Path,
    target: Target,
    pipeline: str | None,
    output_format: str | None = None,
) -> list[str]:
    """Assemble the sigma-cli invocation for one target."""
    argv = [sigma_binary, "convert", "-t", target.identifier]
    if pipeline:
        argv += ["-p", pipeline]
    if output_format:
        argv += ["-f", output_format]
    if target.override_pipeline_check:
        # Some targets reject pipelines whose field mappings they nonetheless
        # apply correctly, because the pipeline never registered itself against
        # that target. See ADR 0002.
        argv.append("--disable-pipeline-check")
    argv.append(str(rule_path))
    return argv


def convert_one(
    rule_path: Path,
    target_spec: str,
    runner: CommandRunner,
    sigma_binary: str,
) -> Conversion:
    """Convert one rule for one target, recording rather than raising on failure."""
    target_name, pipeline_override, format_override = parse_target_spec(target_spec)
    target = TARGETS.get(target_name)
    if target is None:
        known = ", ".join(sorted(TARGETS))
        return _failure(
            target_name,
            target_name,
            pipeline_override,
            format_override,
            "",
            f"Unknown target '{target_name}'. Known targets: {known}.",
        )

    pipeline = pipeline_override or target.default_pipeline
    output_format = resolve_format(pipeline, format_override)
    argv = build_command(sigma_binary, rule_path, target, pipeline, output_format)
    command = shlex.join(argv)

    try:
        result = runner(argv)
    except OSError as exc:
        # Most often: sigma-cli is not installed, or not on PATH. Naming the
        # remedy here saves the hunter a search.
        return _failure(
            target.identifier,
            target.language,
            pipeline,
            output_format,
            command,
            f"Could not run '{sigma_binary}': {exc}. Run setup_sigma.sh.",
        )

    if result.returncode != 0:
        return _failure(
            target.identifier,
            target.language,
            pipeline,
            output_format,
            command,
            result.stderr.strip() or f"Exited {result.returncode} with no message.",
        )

    query = result.stdout.strip()
    if not query:
        # Exit code 0 and an empty query. Without this check the hunter gets an
        # empty file and reads it as "the rule matched nothing".
        return _failure(
            target.identifier,
            target.language,
            pipeline,
            output_format,
            command,
            f"sigma exited 0 but produced no query. stderr: {result.stderr.strip() or '(empty)'}",
        )

    return Conversion(
        target=target.identifier,
        language=target.language,
        pipeline=pipeline,
        output_format=output_format,
        command=command,
        succeeded=True,
        query=query,
        error="",
        output_path=None,
    )


def plan_output_names(stem: str, target_specs: Sequence[str]) -> dict[int, tuple[str, str | None]]:
    """Decide a filename for each requested conversion, before any run.

    Two conversions of the same target -- `kusto:microsoft_xdr` alongside
    `kusto:sentinel_asim` -- would otherwise both land on `<stem>.kql`, and the
    second would silently overwrite the first while the manifest claimed two
    outputs. Where a target appears more than once, the pipeline goes into the
    name to keep them apart.
    """
    parsed = [parse_target_spec(spec) for spec in target_specs]
    counts = Counter(name for name, _, _ in parsed)

    names: dict[int, tuple[str, str | None]] = {}
    for index, (name, pipeline, _) in enumerate(parsed):
        target = TARGETS.get(name)
        if target is None:
            continue
        chosen = pipeline or target.default_pipeline
        if counts[name] > 1 and chosen:
            names[index] = (f"{stem}.{chosen}.{target.extension}", chosen)
        else:
            names[index] = (f"{stem}.{target.extension}", chosen)
    return names


def convert_rule(
    rule_path: Path,
    target_specs: Sequence[str],
    output_dir: Path,
    runner: CommandRunner = subprocess_runner,
    sigma_binary: str | None = None,
) -> list[Conversion]:
    """Convert one rule for every target, writing successes and recording failures.

    Every target is attempted regardless of what happened to the ones before it,
    including when the failure is a disk error rather than a converter error.
    Returns one `Conversion` per requested target, in the order requested.
    """
    binary = resolve_sigma_binary(sigma_binary)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # Nothing can be written, but the caller still deserves per-target
        # results rather than a traceback.
        return [
            _failure(spec, spec, None, None, "", f"Cannot create {output_dir}: {exc}")
            for spec in target_specs
        ]

    stem = rule_path.name.removesuffix(".yml").removesuffix(".yaml").removesuffix(".sigma")
    planned = plan_output_names(stem, target_specs)

    conversions: list[Conversion] = []
    for index, spec in enumerate(target_specs):
        outcome = convert_one(rule_path, spec, runner, binary)
        filename = planned.get(index, (None, None))[0]

        if outcome.succeeded and filename:
            destination = output_dir / filename
            try:
                destination.write_text(outcome.query + "\n", encoding="utf-8")
            except OSError as exc:
                outcome = _failure(
                    outcome.target,
                    outcome.language,
                    outcome.pipeline,
                    outcome.output_format,
                    outcome.command,
                    f"Converted, but could not write {destination}: {exc}",
                )
            else:
                outcome = replace(outcome, output_path=str(destination))

        if not outcome.succeeded and filename:
            outcome = _clear_stale_output(output_dir / filename, outcome)

        conversions.append(outcome)

    _write_manifest(rule_path, output_dir, conversions)
    return conversions


def _clear_stale_output(destination: Path, outcome: Conversion) -> Conversion:
    """Remove an output file left by an earlier run of a now-failing conversion.

    Leaving it is the dangerous option: the manifest says the conversion failed
    while a plausible-looking query sits on disk, and the hunter runs logic that
    no longer matches the rule. Only paths this run would itself have written
    are touched, and the removal is recorded in the error text.
    """
    if not destination.exists():
        return outcome
    try:
        destination.unlink()
    except OSError as exc:
        return replace(
            outcome,
            error=f"{outcome.error}\nStale output remains at {destination} "
            f"and could not be removed: {exc}. Do not run it.",
        )
    return replace(
        outcome,
        error=f"{outcome.error}\nRemoved stale {destination.name} from an earlier run.",
    )


def _write_manifest(rule_path: Path, output_dir: Path, conversions: list[Conversion]) -> None:
    """Record what was run and what happened, beside the generated queries.

    This is the audit trail: which pipeline and format produced which file, and
    the exact error for anything that did not convert. It lives in a sidecar
    because query languages disagree about comment syntax, and a comment that
    breaks the query it documents is worse than no comment.

    A manifest that cannot be written must not discard the conversions that
    succeeded, so the failure is reported and the results still returned.
    """
    manifest = {
        "rule": str(rule_path),
        "converted_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "conversions": [asdict(c) for c in conversions],
    }
    try:
        (output_dir / MANIFEST_NAME).write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        print(f"WARNING: could not write the conversion manifest: {exc}")
