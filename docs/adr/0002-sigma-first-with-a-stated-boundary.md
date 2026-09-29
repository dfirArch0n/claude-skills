# ADR 0002: Sigma first, native queries where Sigma cannot reach

- **Status:** Accepted
- **Date:** 2026-09-29

## Context

The `threat-hunt` skill has to produce runnable queries for four platforms:
Splunk, Microsoft Sentinel and Defender XDR, Elastic, and CrowdStrike NG-SIEM.
Writing each one by hand means the same logic drifts four ways and each copy
carries its own syntax errors, discovered in a search bar rather than in review.

Sigma solves that — it is a vendor-neutral detection rule format with a mature
converter, and pySigma has maintained backends for all four targets.

It also does not solve all of it. Sigma describes a **filter over a single log
source**. A large share of hunting is comparison rather than filtering: stack
counting to find the rare, first-seen analysis, joins across sources,
week-over-week diffs, baselining. None of that is expressible in Sigma, and no
amount of wanting it to be changes that.

## Decision

Hunt logic is written as Sigma YAML and converted with `sigma-cli` **when the
logic is a filter over one log source**. Where the logic requires aggregation,
comparison across windows, or a join, it is written natively per platform, and
the query file states why Sigma could not carry it.

The skill carries that boundary as an explicit table rather than as a
preference, so the model does not attempt to express an aggregation in Sigma and
produce something that converts cleanly and means nothing.

Backends are installed into a single `uv tool` environment via `--with`, and the
setup script's `--check` mode verifies each backend by converting a canary rule
rather than by importing a module.

## Alternatives considered

- **Native queries only, no Sigma.** Honest about hunting's real shape, but the
  same logic is then maintained four times, and the model generates each dialect
  from memory. The converter guarantees syntax; a language model does not.
- **Sigma for everything.** Tidier on paper. In practice it forces aggregation
  logic into a filter language, and the failure is silent — the rule converts,
  runs, and answers a different question than the one asked.
- **`rsigma`** (the Rust CLI and MCP server that replaced the retired
  `sigma-backends` skill). Attractive for `engine eval`, which fires a rule
  against sample events. It delegates conversion to `sigma-cli` anyway, needs a
  cargo or binary install, and adds a second tool to keep current. Noted as a
  future addition once rule-versus-sample testing becomes the bottleneck.
- **A hand-maintained query library per platform.** Reusable, but it decays the
  moment a schema changes and nobody owns it.

## Consequences

- One rule, four platforms, verified by the converter rather than by hope.
- A real maintenance split: native queries are per-platform and must be updated
  per-platform. The `why not Sigma` note in each file is what keeps that split
  deliberate instead of accidental.
- Sigma correlation rules give partial aggregation support, unevenly across
  backends — `log_scale` supports them well, others less so. The boundary table
  will need revisiting as backend support matures.
- **`sigma plugin install` cannot be used**, because it shells out to
  `python -m pip` and `uv tool` environments ship without pip. The failure
  surfaces as a `CalledProcessError` traceback with `No module named pip` buried
  in it, which reads like a broken package rather than a missing tool. Installing
  backends as `--with` dependencies avoids it; the setup script encodes this so
  it is discovered once rather than every time.
- **ES|QL and Elastalert have no registered ECS pipeline.** The `ecs_*`
  pipelines declare support for `elasticsearch`, `eql`, `lucene` and
  `opensearch`, omitting both, so `sigma convert -t esql -p ecs_windows` is
  rejected although the mapping is correct. The conversion script passes
  `--disable-pipeline-check` for those two targets and records that it did. If
  the backend later registers the pipelines, the override becomes harmless
  rather than wrong.
- **A pipeline can require an output format to mean anything.** `splunk_cim`
  maps fields onto the CIM data model, and without `-f data_model` sigma-cli
  emits a bare filter over `Processes.*` attributes: it converts, reports
  success, and matches nothing when run. Because that failure is silent and
  looks like a clean hunt result, the format is derived from the pipeline in
  `PIPELINE_FORMATS` rather than left to the caller to remember.
