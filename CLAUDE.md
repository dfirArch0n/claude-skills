# claude-skills: repository conventions

## Purpose
Personal agent skills for security engineering work. Each skill is a directory
under `skills/`, self-contained enough to be symlinked into `~/.claude/skills/`
and used on its own.

## Owner context
Security leader (detection and response, incident handling, forensics); not a
strong programr. Explain code in plain language and define terms (type hints,
mocks, fixtures, protocols) briefly the first time they appear.

Principles: everything as code; modular packages; prompts and configuration in
their own modules, never inline.

## THIS REPOSITORY IS PUBLIC
Nothing in a commit may identify a real environment. That means no internal
hostnames, IP ranges, usernames, index or table names, tenant IDs, tool
inventories, or findings from a real hunt.

Worked examples are built from public sources — CISA advisories, vendor threat
reports, MITRE ATT&CK — and say which public source they came from.

Real hunt output belongs in a separate, private hunt repository. `hunts/` is
git-ignored here so that a stray `new_hunt.py` run cannot leak into a push.
See `docs/adr/0003`.

## Workflow
1. Plan first. Record meaningful decisions as ADRs in `docs/adr/`.
2. Feature branch, never commit to main.
3. Ruff via pre-commit, then pytest. Write tests for every function and explain
   in plain language what each one protects against.
4. Second-AI review (Codex/Gemini) before the PR. Fix real issues; skip nitpicks.
5. Open a PR with changes, tests, review outcome, and decisions. Do not merge;
   the human approves.

## Writing conventions
- **American English**, everywhere: program, organization, behavior, analyze,
  sanitize, center, judgment. This is a public repository and the audience is a
  US security industry; mixed spelling reads as inattention.

## Skill authoring conventions
- `SKILL.md` carries the workflow and stays under ~350 lines. Depth goes in
  `references/`, loaded only when needed.
- The `description` field is the only thing that decides whether a skill
  triggers. It states what the skill does *and* when to use it, in specifics.
- Bundled `scripts/` use the standard library only. A skill that needs a
  `pip install` before it works is a skill that silently does nothing.
- Templates live in `assets/templates/` and are copied, never generated from
  memory, so the output shape is stable across runs.

## Design rule: a missing input never stops the work
Inherited from `security-tooling-dev`, and it applies to telemetry here exactly
as it applies to enrichment lookups there. An absent log source, an unpopulated
field, or a failed query conversion must not halt the workflow. Record the
specific failure, note the reduced confidence it causes, and continue. Never
swallow a failure silently — a step that quietly did nothing must never read as
a step that succeeded.

## Secrets (1Password CLI)
- Vault `Private`. GitHub token item: `GitHub - claude-dev`, field `credential`.
- ONLY use secrets via `op run --env-file=<path>/.env.op -- <command>`; the human
  approves each use with Touch ID.
- `.env.op` is git-ignored here because this repo is public. Use the one in
  `~/git/security-tooling-dev/`.
- NEVER run bare `op read`, `op item get`, or anything that prints a secret.
  Never write secrets to files, logs, or chat.
