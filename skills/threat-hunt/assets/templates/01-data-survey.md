# Data survey: {{SLUG}}

Run before the first query. Answer each cell with a fact, not a belief.

| Evidence needed | ATT&CK data component | Exists | Populated | Retention | Coverage | Fidelity | Verdict |
|---|---|---|---|---|---|---|---|
| | | | | | | | available / partial / absent |

## Why each gap exists

For every partial or absent verdict above, say whether coverage **never existed**
or **stopped**. Never existed is an engineering gap with an owner. Stopped is a
hunt: signals going quiet is one of the shapes ATT&CK Defense Impairment
(TA0112) leaves behind, alongside the positive activity — policy changes, tool
tampering, log clearing — that the tactic also produces. Carry the answer into
`cause` in the gap register.

| Gap | Coverage shape | Cause | What you checked |
|---|---|---|---|
| | never / stopped / thinned | engineering / adversary / undetermined | |

## Blind spots

<What is known to be invisible in this Location: encrypted traffic, unmanaged
hosts, segments without sensors.>

## Confidence carried into findings

One sentence per Evidence item, naming the share of estate, the window, and the
evasion that would survive the gap.

- <evidence item>: <statement>

## Gaps raised

<IDs from 02-gaps.yml, so the two files stay tied together.>
