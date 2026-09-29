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
        override_pipeline_check: Pass `--disable-pipeline-check`. Needed only
            for `esql`, where the ECS pipelines produce correct field mappings
            but do not register themselves against the target, so sigma-cli
            refuses a combination that in fact works. See ADR 0002.
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
    "elastalert": Target("elastalert", "yml", "Elastalert", "ecs_windows"),
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
