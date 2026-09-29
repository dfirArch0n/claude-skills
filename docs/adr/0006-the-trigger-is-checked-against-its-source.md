# ADR 0006: The trigger is checked against its source, and claims carry citations

- **Status:** Accepted
- **Date:** 2026-09-29

## Context

The skill's evaluation ran four prompts with and against a no-skill baseline.
The headline scores favored the skill, and the most useful result was a case
where it lost.

One prompt said: *"CISA just dropped an advisory on Akira ransomware — big list
of IPs and hashes."* CISA AA24-109A contains 51 file hashes and **zero** IP
addresses, domains or URLs. The baseline run read the advisory, documented the
absence, and told the user to find out where those IPs had actually come from.
The run using this skill accepted the premise and produced a network sweep
against a lookup table that can never be populated.

Stage 0 told the hunter to *name* the trigger and its source. It never told them
to *read* it. Everything downstream — the climb, the hypothesis, the scope, the
queries — inherits whatever the trigger claims, so an unchecked premise is not a
small error discovered late. It is the entire hunt aimed at the wrong thing, and
the discovery happens when someone runs the queries and gets nothing.

Two related failures showed up in the same evaluation. The skill's runs asserted
dated specifics about vendor telemetry — table names, a deprecation date — with
no citations, while the baseline cited twelve primary sources. And one run's
`05-report.md` stated *"Confirmed already: no inventory of sanctioned scheduled
tasks exists"* while its own `02-gaps.yml` marked that same item as a
placeholder.

All three are the same failure wearing different clothes: **the skill produced
confident statements that nothing had verified**, which is precisely what it
exists to prevent. A hunting methodology that manufactures false confidence is
worse than no methodology, because it launders a guess into a finding.

## Decision

Three additions, all in the path a hunt already walks.

**Stage 0 checks the trigger against its source.** Read the source directly.
Count what it actually contains, by indicator type. State where it contradicts
the request, and hunt what the source supports rather than what the request
assumed. Where the source cannot be reached, record that and treat every
conclusion resting on it as provisional. The charter carries a `Source check`
block so the result is recorded rather than merely performed.

**External claims carry citations.** Anything the human might act on — what a
report says, which table holds a log source, a retention default, a deprecation
date, an ATT&CK mapping — carries a link or document reference. Where the claim
is recalled and cannot be checked, it is marked `unverified` rather than
dropped: a flagged recollection is useful, a confident one is a trap.

**No claim in the report outruns the register.** Before writing the report,
search the package for remaining placeholders. Anything unfilled is reported as
unknown. Gaps carry provenance — measured, reported by an owner, or assumed —
because "we believe X is not logged" and "X is not logged" ask different things
of the reader.

## Alternatives considered

- **Treat it as a prompt-quality problem.** The user described the advisory
  loosely; a better prompt would not have misled the skill. True and useless:
  real triggers arrive as a colleague's paraphrase, and a methodology that only
  works on accurate inputs is not a methodology.
- **A separate verification stage.** Cleaner on paper, and it would run only
  when someone remembered to schedule it. The check costs one read and belongs
  where the trigger is already being written down.
- **Require citations for everything.** Unworkable and self-defeating. A hunter
  citing a source for "Sysmon Event ID 1 is process creation" produces a
  document nobody finishes. The bar is *claims the human might act on*, which is
  a judgment, and stating it as a judgment is more honest than pretending a rule
  covers it.
- **A script that blocks a report containing placeholders.** Mechanically
  appealing. It would catch the literal `[FILL` strings and miss the actual
  failure, which was a fluent sentence asserting something the register
  contradicted. No parser distinguishes those; a human reading one instruction
  does.

## Consequences

- One extra read at the start of every hunt, and a charter section to fill.
  Cheap against the failure it prevents.
- Some hunts will end at Stage 0 with "the premise was wrong, here is what the
  source actually says." That is a good outcome reported honestly, and it will
  feel like a wasted morning to whoever asked for the hunt.
- Reports get longer and more hedged. Gap provenance in particular adds a column
  that will often read `assumed`, which is uncomfortable and accurate.
- The citation rule is a judgment call and will be applied unevenly. Stating the
  bar as "claims the human might act on" accepts that, rather than pretending a
  bright line exists.
- None of this is enforced by code. The evaluation found these failures in model
  behavior, and the fix is instruction; `tests/test_examples.py` asserts only
  that the instructions are still present in the shipped templates.
