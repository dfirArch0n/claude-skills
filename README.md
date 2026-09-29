# claude-skills

Personal [agent skills](https://code.claude.com/docs/en/skills) for security
engineering work — detection and response, threat hunting, and the tooling
around them.

A skill is a directory of instructions a coding agent loads when the task calls
for it. Each one here is written to be self-contained: symlink the directory and
it works, with no install step.

## Skills

| Skill | What it does |
|---|---|
| [`threat-hunt`](skills/threat-hunt/) | Hypothesis-driven threat hunting built on the Pyramid of Pain. Climbs a trigger from indicators to TTPs, surveys whether the telemetry to test it actually exists, writes the logic once as Sigma and converts it to Splunk, Sentinel/Defender, Elastic and CrowdStrike NG-SIEM, then triages findings and hands surviving logic to detection engineering. |

## Layout

```
skills/<name>/
  SKILL.md         the workflow; kept short, because it loads on every use
  references/      depth, loaded only when the task reaches it
  assets/          templates copied into output
  scripts/         standard-library Python and shell, no dependencies
  evals/           test prompts used to check the skill actually helps
docs/adr/          why the skills are shaped the way they are
examples/          sanitised worked examples built from public sources
tests/             pytest suite for the bundled scripts
```

## Installing a skill

```sh
ln -s ~/git/claude-skills/skills/<name> ~/.claude/skills/<name>
```

The symlink means edits in this repository take effect immediately, with no
sync step to forget.

## Working in this repository

```sh
uv sync                  # create .venv and install dev dependencies
uv run pytest            # run the test suite
pre-commit run -a        # lint and format (Ruff)
```

Work happens on feature branches and lands through pull requests. Nothing is
merged without human approval. See `CLAUDE.md` for the full workflow and
`docs/adr/` for the reasoning behind the design.

## This repository is public

Nothing here identifies a real environment. No internal hostnames, address
ranges, usernames, index or table names, tenant IDs, or findings from a real
hunt. Worked examples are built from public threat reporting and name their
source.

Output produced *by* these skills — hunt packages, findings, detection
candidates — belongs in a private repository, not this one. `hunts/` is
git-ignored here so that cannot happen by accident.
