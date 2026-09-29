"""Conversion targets, pipelines, and hunt-package layout.

Configuration lives here rather than inside function bodies so that adding a
platform is a one-line edit to a table, reviewable on its own, instead of a
change threaded through conversion logic.

Everything here was verified against sigma-cli 3.1.0 / pySigma 1.5.1.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Where `uv tool install` places executables. Frequently absent from PATH, so
#: the conversion code falls back to it before giving up on finding `sigma`.
UV_TOOL_BIN = "~/.local/bin"

SIGMA_BINARY = "sigma"


@dataclass(frozen=True)
class Target:
    """One sigma-cli conversion target.

    Attributes:
        identifier: The value passed to `sigma convert -t`. Note that these are
            query languages, not plugin names: the CrowdStrike plugin provides
            the `log_scale` target, and the Elasticsearch plugin provides four.
        extension: File extension for the generated query.
        language: Human-readable name, used in reports and error messages.
        default_pipeline: Pipeline used when the caller names no override. A
            pipeline maps Sigma's generic field names onto a platform's real
            schema; converting without the right one yields a query that runs
            and matches nothing.
        override_pipeline_check: Pass `--disable-pipeline-check`. Needed for
            `esql` and `elastalert`, where the ECS pipelines produce correct
            field mappings but never registered themselves against the target,
            so sigma-cli refuses a combination that in fact works. Verified by
            converting the canary rule both ways. See ADR 0002.
    """

    identifier: str
    extension: str
    language: str
    default_pipeline: str | None
    override_pipeline_check: bool = False


TARGETS: dict[str, Target] = {
    "splunk": Target("splunk", "spl", "Splunk SPL", "splunk_windows"),
    "splunk_spl2": Target("splunk_spl2", "spl2", "Splunk SPL2", "splunk_windows"),
    "kusto": Target("kusto", "kql", "Kusto (Sentinel / Defender XDR)", "microsoft_xdr"),
    "lucene": Target("lucene", "lucene", "Elasticsearch Lucene", "ecs_windows"),
    "esql": Target("esql", "esql", "Elasticsearch ES|QL", "ecs_windows", True),
    "eql": Target("eql", "eql", "Elasticsearch EQL", "ecs_windows"),
    "elastalert": Target("elastalert", "yml", "Elastalert", "ecs_windows", True),
    "log_scale": Target(
        "log_scale", "cql", "CrowdStrike NG-SIEM (LogScale CQL)", "crowdstrike_falcon"
    ),
}

#: One target per platform family. Converting to every Elastic dialect at once
#: produces four near-identical files nobody reads.
DEFAULT_TARGETS: tuple[str, ...] = ("splunk", "kusto", "esql", "log_scale")

#: Alternative pipelines worth knowing, surfaced in `--help` so the choice is
#: visible at the point of use rather than buried in a reference file.
PIPELINE_NOTES: dict[str, tuple[str, ...]] = {
    "splunk": ("splunk_windows", "splunk_cim", "splunk_sysmon_acceleration"),
    "kusto": ("microsoft_xdr", "sentinel_asim", "azure_monitor"),
    "lucene": ("ecs_windows", "ecs_windows_old", "ecs_zeek_beats", "ecs_zeek_corelight"),
    "esql": ("ecs_windows",),
    "eql": ("ecs_windows", "ecs_zeek_beats", "ecs_macos_esf", "ecs_kubernetes"),
    "log_scale": ("crowdstrike_falcon", "crowdstrike_fdr"),
}

#: Pipelines that only produce a usable query when paired with an output format.
#:
#: `splunk_cim` maps fields onto the CIM data model. Without `-f data_model`,
#: sigma-cli emits a bare filter over `Processes.*` attributes -- syntactically
#: fine, reports success, and resolves to nothing in an ordinary search. It has
#: to be a tstats query against the data model or it is not a CIM query at all.
PIPELINE_FORMATS: dict[str, str] = {
    "splunk_cim": "data_model",
}

#: Known defects in a backend's generated output, surfaced on every conversion.
#:
#: log_scale: pySigma-backend-crowdstrike declares its operator precedence as
#: (NOT, OR, AND) while emitting AND as juxtaposition, which in LogScale binds
#: TIGHTER than an explicit `or`. Parentheses around an OR group nested inside an
#: AND are therefore omitted, and the AND-ed conjuncts apply only to the first
#: disjunct -- every later disjunct matches unscoped. The query converts, runs,
#: and matches far more than the rule says.
#:
#: Upstream fix merged 2026-09-20 (SigmaHQ/pySigma-backend-crowdstrike#25) but
#: unreleased: 3.0.0, from 2025-11-30, is still the newest on PyPI. Remove this
#: warning once a release carries the fix and the canary converts parenthesized.
BACKEND_WARNINGS: dict[str, str] = {
    "log_scale": (
        "OR groups are emitted WITHOUT parentheses by "
        "pysigma-backend-crowdstrike<=3.0.0, and LogScale binds AND tighter than "
        "or, so the conditions before the first `or` do not apply to the later "
        "disjuncts. This query matches MORE than the rule states. Parenthesize "
        "each OR group by hand before running it. Upstream fix merged "
        "2026-09-20, not yet released."
    ),
}

#: Files copied into a new hunt package, in the order a hunt fills them.
TEMPLATE_FILES: tuple[str, ...] = (
    "00-charter.md",
    "01-data-survey.md",
    "02-gaps.yml",
    "03-findings.md",
    "05-report.md",
    "metadata.yml",
    "04-detections/ADS-0001-template.md",
    "queries/README.md",
    "queries/generated/README.md",
)

#: Placeholders substituted when a template is copied.
PLACEHOLDER_SLUG = "{{SLUG}}"
PLACEHOLDER_DATE = "{{DATE}}"
PLACEHOLDER_HUNTER = "{{HUNTER}}"

#: Written beside generated queries, recording what was run and what happened.
#: Query languages disagree about comment syntax, so the audit trail lives in a
#: sidecar rather than risking a comment that breaks the query it describes.
MANIFEST_NAME = "conversion-manifest.json"
