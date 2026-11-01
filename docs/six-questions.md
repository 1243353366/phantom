# The six questions

PHANTOM is not a tool for investigating other people. It is the set of
investigative techniques turned around: the same methods a broker, a stalker or a
search engine uses, pointed at the person running it.

```console
$ phantom posture
```

One command, six questions, and every answer derived from local data:

| # | Question | Where the answer comes from |
| --- | --- | --- |
| 1 | What can someone discover about me without accessing my accounts? | the operator's own exports and communities |
| 2 | Which websites expose information about me? | not measured until you name the sites |
| 3 | What information connects my accounts across platforms? | the inventory graph |
| 4 | What do search engines and crawlers have access to? | saved `indexability` runs |
| 5 | Which technical identifiers create unnecessary links? | shared identifiers in the graph |
| 6 | What can I remove, restrict, or make harder to discover? | derived from 1-5 |

## The rule that keeps it pointed the right way

No question may be answered by examining anyone else. Question 1 is a simulation
of an observer, and the only data it may use is what the operator published, read
from the operator's own export. A stranger and this tool working from the same
published fields reach the same conclusions, which is exactly what makes the
simulation honest.

Every question also ships with `cannot_see`. That field is not decoration. It is
the difference between a scanner that says "you are exposed" and one that says
what it actually looked at.

## Three honest states, not one

- `answered`: findings exist, derived from local data.
- `nothing_found`: it looked and there was nothing to report yet.
- `not_measured`: it did not look, and says why.

`not_measured` is the state most tools hide. Question 2 is `not_measured` by
design: answering it means fetching sites the operator does not own, so it waits
until those sites are declared in `selfaudit/egress_allowlist.yaml`. Browsing on
the operator's behalf, quietly, would make this tool the thing it audits.

Question 4 has the same discipline at a smaller scale: it reports `unverifiable`
rather than "blocked" when a page disallows crawling, because a disallow hides the
noindex that would settle it. See [`indexability.md`](indexability.md).

## Identifiers without values

Question 5 reports that an email joins three accounts. It never prints the email.
Identifiers are stored as keyed digests, so equality is enough to find the link
and not enough to leak the value. Handles are printed, because a handle is public
by nature and is the thing being mapped.

## Remediation is derived, not written by hand

Question 6 is generated from the first five, and each action carries what it
removes and what it cannot guarantee. "Use a per-platform alias" removes the
identifier as a join key; it does not remove accounts already scraped or shared,
and an alias provider that forwards to one inbox becomes a new single point.

Actions that cannot be verified locally stay words, not buttons. This tool will
not click "delete my data" on your behalf: a removal is a request to a third
party, not a deletion you can perform.

## What it becomes as you use it

Empty install: mostly `not_measured`, with nothing invented to fill the silence.
One export: question 1 fills in, question 5 starts working when a second platform
arrives. Saved indexability runs: question 4 turns on. The report gets more
useful as more of your own data is added, and never by looking at anyone else's.
