#!/usr/bin/env python3
"""Convert a Sigma rule to every platform the hunt needs.

    convert.py hunts/<hunt>/queries/rule.sigma.yml
    convert.py rule.sigma.yml --targets splunk:splunk_cim kusto:sentinel_asim

A failure on one platform never stops the others: every target is attempted,
successes are written, and failures are reported with the exact error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from huntkit.config import DEFAULT_TARGETS, MANIFEST_NAME, PIPELINE_NOTES, TARGETS
from huntkit.conversion import convert_rule


def _epilog() -> str:
    """Show the alternative pipelines at the point of use."""
    lines = ["targets and their pipelines:"]
    for name, target in TARGETS.items():
        options = PIPELINE_NOTES.get(name, (target.default_pipeline or "-",))
        lines.append(f"  {name:<12} {target.language}")
        lines.append(f"  {'':<12} pipelines: {', '.join(options)}")
    lines.append("\nName a pipeline with target:pipeline, e.g. kusto:sentinel_asim,")
    lines.append("or a format too: splunk:splunk_cim:data_model.")
    lines.append("These are the common ones. For the authoritative list of what is")
    lines.append("installed, run: sigma list pipelines <target>")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Convert the rule and report per-target outcomes."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("rule", type=Path, help="Path to the Sigma rule.")
    parser.add_argument(
        "--targets",
        nargs="+",
        default=list(DEFAULT_TARGETS),
        metavar="TARGET[:PIPELINE]",
        help=f"Conversion targets (default: {' '.join(DEFAULT_TARGETS)}).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Where to write queries (default: <rule dir>/generated).",
    )
    parser.add_argument("--sigma-binary", default=None, help="Path to the sigma executable.")
    args = parser.parse_args(argv)

    if not args.rule.is_file():
        print(f"Rule not found: {args.rule}", file=sys.stderr)
        return 1

    output_dir = args.output_dir or args.rule.parent / "generated"
    conversions = convert_rule(
        rule_path=args.rule,
        target_specs=args.targets,
        output_dir=output_dir,
        sigma_binary=args.sigma_binary,
    )

    # Successes on stdout, failures on stderr, so a caller can pipe the queries
    # it got while a human still sees what broke. Flushing between the two keeps
    # the streams from interleaving out of order in a terminal.
    for conversion in conversions:
        stream = sys.stdout if conversion.succeeded else sys.stderr
        print(conversion.summary, file=stream, flush=True)
        # A converted query that runs and means something other than the rule is
        # the worst thing this tool can hand a hunter, so known-bad emissions are
        # shouted on every run rather than documented once.
        for warning in conversion.warnings:
            print(f"    WARNING [{conversion.target}]: {warning}", file=sys.stderr, flush=True)

    failed = [c for c in conversions if not c.succeeded]
    flagged = [c for c in conversions if c.succeeded and c.warnings]
    clean = [c for c in conversions if c.clean]

    # Counted separately on purpose. "4/4 converted" next to a query the backend
    # is known to emit wrongly is a number that gets believed.
    line = f"\n{len(clean)}/{len(conversions)} converted cleanly"
    if flagged:
        line += f", {len(flagged)} with warnings"
    if failed:
        line += f", {len(failed)} failed"
    print(line)
    manifest = output_dir / MANIFEST_NAME
    if manifest.is_file():
        print(f"Details: {manifest}")
    else:
        print(f"NO MANIFEST at {manifest} - this run is not reproducible.", file=sys.stderr)

    if failed or flagged:
        print(
            "Read each generated query before running it. The converter "
            "guarantees syntax, never that the fields exist in your data -- and "
            "a warned query is known to mean something other than the rule.",
            file=sys.stderr,
        )
    # Exit non-zero only when nothing converted at all. A partial result is the
    # designed behavior, not an error: the hunt continues on what worked.
    return 0 if (len(conversions) - len(failed)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
