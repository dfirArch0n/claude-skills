You are performing a critical pre-PR review of a PUBLIC repository of agent
skills for security engineering. The headline artifact is `threat-hunt`: a
hypothesis-driven threat hunting skill built on Bianco's Pyramid of Pain, with
bundled Python helpers that convert Sigma rules to Splunk SPL, Kusto KQL,
Elastic ES|QL and CrowdStrike NG-SIEM LogScale CQL.

Review the diff of the current branch against its base.

Judge it on, in priority order:

1. Correctness bugs in skills/threat-hunt/scripts/. Especially: paths, the
   target/pipeline table in huntkit/config.py, and anything that could destroy
   or half-create a hunt package.
2. DOMAIN ACCURACY of the skill and its references. This is the part a linter
   cannot check and it matters most. Are the Pyramid of Pain levels, the ABLE
   framework, PEAK, TaHiTI, the Hunting Maturity Model, ATT&CK data components
   and the Palantir ADS template described correctly? Is any hunting advice
   wrong, dated, or misleading? Would a Principal-level detection engineer
   disagree with any claim stated as fact?
3. Whether the code upholds the repository's standing design rule: a missing or
   failed input NEVER stops the work. Record the specific failure, record the
   confidence it costs, continue. A step that quietly did nothing must never
   read as a step that succeeded.
4. PUBLICATION SAFETY. This repository is public. Flag anything that identifies
   a real environment: hostnames, address ranges, usernames, index or table
   names, tenant IDs, tool inventories, or findings that read like real hunt
   output rather than a sanitized example built from public reporting.
5. Test coverage gaps -- failure modes claimed in comments or docs but not
   actually tested.
6. Accuracy of docs/adr/ against what the code actually does, and accuracy of
   SKILL.md and references/ against the shipped scripts (command names, flags,
   target identifiers, file paths).

You CAN and SHOULD run things to check your findings:

    uv run pytest -q
    skills/threat-hunt/scripts/setup_sigma.sh --check
    python skills/threat-hunt/scripts/convert.py --help

Use them. Before reporting a defect, try to demonstrate it and run that too. A
finding you have reproduced is worth ten you have merely inferred. State for
each finding whether you REPRODUCED it or are INFERRING it.

Do NOT modify any file in the repository. Write scratch files to $TMPDIR only.
Do NOT create anything under hunts/.

Be specific and terse. Cite file:line. Rank by severity. Explicitly separate
REAL ISSUES from NITPICKS. Report only, do not rewrite.
