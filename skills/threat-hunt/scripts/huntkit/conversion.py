"""Convert one Sigma rule to every requested platform.

The design rule this module exists to honour: **a failure on one backend never
stops the others.** A hunter with four platforms and a broken Elastic plugin
should still get Splunk, Kusto and NG-SIEM queries, plus a precise statement of
what went wrong on the fourth — not a traceback and nothing.

The matching rule: a step that quietly did nothing must never read as a step
that succeeded. sigma-cli can exit 0 having written no query at all, which is
indistinguishable from success if you only check the return code. That case is
treated as a failure here.

The subprocess call is injected as a `CommandRunner` rather than imported, so
tests can drive every failure mode without a real sigma-cli, a network, or a
temporary shell script. Same pattern as `ContextProvider` in security-tooling-dev.
"""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from huntkit.config import MANIFEST_NAME, SIGMA_BINARY, TARGETS, UV_TOOL_BIN, Target


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
    you "Try 'sigma convert --help'" or "Pipelines not listed here are treated
    as file names" -- true, and not what went wrong. The `Error:` line is the
    one worth putting in front of a hunter.
    """
    lines = [line.strip() for line in error.strip().splitlines() if line.strip()]
    if not lines:
        return "(no error message)"
    for line in lines:
        if line.startswith("Error:"):
            return line.removeprefix("Error:").strip()
    return lines[-1]


@dataclass(frozen=True)
class Conversion:
    """The outcome of converting one rule for one target."""

    target: str
    language: str
    pipeline: str | None
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


def parse_target_spec(spec: str) -> tuple[str, str | None]:
    """Split a `target[:pipeline]` argument.

    Examples:
        `splunk` -> ("splunk", None), meaning use the target's default pipeline.
        `kusto:sentinel_asim` -> ("kusto", "sentinel_asim").
    """
    target, _, pipeline = spec.partition(":")
    return target, pipeline or None


def build_command(
    sigma_binary: str,
    rule_path: Path,
    target: Target,
    pipeline: str | None,
) -> list[str]:
    """Assemble the sigma-cli invocation for one target."""
    argv = [sigma_binary, "convert", "-t", target.identifier]
    if pipeline:
        argv += ["-p", pipeline]
    if target.override_pipeline_check:
        # The ECS pipelines map esql fields correctly but are not registered
        # against the esql target, so sigma-cli rejects a working combination.
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
    target_name, pipeline_override = parse_target_spec(target_spec)
    target = TARGETS.get(target_name)
    if target is None:
        known = ", ".join(sorted(TARGETS))
        return Conversion(
            target=target_name,
            language=target_name,
            pipeline=pipeline_override,
            command="",
            succeeded=False,
            query="",
            error=f"Unknown target '{target_name}'. Known targets: {known}.",
            output_path=None,
        )

    pipeline = pipeline_override or target.default_pipeline
    argv = build_command(sigma_binary, rule_path, target, pipeline)
    command = shlex.join(argv)

    try:
        result = runner(argv)
    except OSError as exc:
        # Most often: sigma-cli is not installed, or not on PATH. Naming the
        # remedy here saves the hunter a search.
        return Conversion(
            target=target.identifier,
            language=target.language,
            pipeline=pipeline,
            command=command,
            succeeded=False,
            query="",
            error=f"Could not run '{sigma_binary}': {exc}. Run setup_sigma.sh.",
            output_path=None,
        )

    if result.returncode != 0:
        return Conversion(
            target=target.identifier,
            language=target.language,
            pipeline=pipeline,
            command=command,
            succeeded=False,
            query="",
            error=result.stderr.strip() or f"Exited {result.returncode} with no message.",
            output_path=None,
        )

    query = result.stdout.strip()
    if not query:
        # Exit code 0 and an empty query. Without this check the hunter gets an
        # empty file and reads it as "the rule matched nothing".
        return Conversion(
            target=target.identifier,
            language=target.language,
            pipeline=pipeline,
            command=command,
            succeeded=False,
            query="",
            error=(
                "sigma exited 0 but produced no query. "
                f"stderr: {result.stderr.strip() or '(empty)'}"
            ),
            output_path=None,
        )

    return Conversion(
        target=target.identifier,
        language=target.language,
        pipeline=pipeline,
        command=command,
        succeeded=True,
        query=query,
        error="",
        output_path=None,
    )


def convert_rule(
    rule_path: Path,
    target_specs: Sequence[str],
    output_dir: Path,
    runner: CommandRunner = subprocess_runner,
    sigma_binary: str | None = None,
) -> list[Conversion]:
    """Convert one rule for every target, writing successes and recording failures.

    Every target is attempted regardless of what happened to the ones before it.
    Returns one `Conversion` per requested target, in the order requested.
    """
    binary = resolve_sigma_binary(sigma_binary)
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = rule_path.name.removesuffix(".yml").removesuffix(".yaml").removesuffix(".sigma")

    conversions: list[Conversion] = []
    for spec in target_specs:
        outcome = convert_one(rule_path, spec, runner, binary)
        if outcome.succeeded:
            target = TARGETS[outcome.target]
            destination = output_dir / f"{stem}.{target.extension}"
            destination.write_text(outcome.query + "\n", encoding="utf-8")
            outcome = Conversion(**{**asdict(outcome), "output_path": str(destination)})
        conversions.append(outcome)

    _write_manifest(rule_path, output_dir, conversions)
    return conversions


def _write_manifest(rule_path: Path, output_dir: Path, conversions: list[Conversion]) -> None:
    """Record what was run and what happened, beside the generated queries.

    This is the audit trail: which pipeline produced which file, and the exact
    error for anything that did not convert. It lives in a sidecar because query
    languages disagree about comment syntax, and a comment that breaks the query
    it documents is worse than no comment.
    """
    manifest = {
        "rule": str(rule_path),
        "converted_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "conversions": [asdict(c) for c in conversions],
    }
    (output_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
