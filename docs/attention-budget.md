# Attention budget

A counter-surveillance console has a failure mode that no threat model catches:
the owner checks it compulsively. Who probed the canaries, did the count move, was
a grant requested again. The answer does not change between checks, and the
checking feels like work while producing none.

So PHANTOM measures its own footprint on the person running it. That is the
recursive self-audit pointed inward.

```console
$ phantom attention
$ phantom attention --checks-per-day 8 --continuous-minutes 30
```

## What it counts

Your own commands, from `attention.jsonl`, in `PHANTOM_HOME`. Nothing else.

- `checks_today`: opens of the views whose purpose is checking something
  (`graph`, `exposure`, `mirror-report`, `shadow-report`, `vault-verify`,
  `inventory-report`).
- `longest_sitting_minutes`: the longest run of checking with no gap longer than
  20 minutes. A 4-hour gap ends a sitting, so an afternoon is not one long one.
- `nudges`: raised past the budget you set. Defaults are 12 checks a day and a
  45-minute sitting.

The nudge is written to be true rather than motivational: nothing in the report
expires overnight, and re-reading it does not make you safer.

## What it refuses

Everything a device knows about its owner, and everything about anybody else.
There is no screen-time API, no app-usage integration, no unlock count, no
keyboard or scroll telemetry. `attention.record` accepts only commands on an
allowlist, so the log cannot be made to hold a value it was not designed for.

Two reasons, and the second matters more than the first:

1. **The pipe cannot be bounded once it exists.** An integration that reports
   screen time reports which apps, for how long, at what hour, and then which
   pages. "Just usage counts" is a promise about a data source, not a property of
   one.
2. **"This usage is excessive" is a clinical claim, not an observation.** This
   system's entire discipline is to separate what was observed from what was
   concluded, and to mark the gap. A threshold invented in a config file and
   printed back as a health verdict is exactly the unearned claim that
   `docs/trust-boundaries.md` exists to prevent. The summary says so in its own
   output: these are command counts, not a health measurement.

The word "people" is also load-bearing in the request. Monitoring *someone else's*
usage so the product can safeguard *their* health is the family-mapping refusal
wearing a wellness hat, and it is refused for the same reason.

## What it can and cannot see

It sees this program on this machine. It cannot see the laptop being closed and
four hours of scrolling elsewhere, which is the case anyone would actually want
caught. That limit is not an implementation gap to be closed later; closing it
means becoming the thing this tool audits.

If wellbeing tracking is wanted for its own sake, it is a separate product with
its own consent model and its own evidence standard, and it should not arrive as
a flag in a privacy tool.
