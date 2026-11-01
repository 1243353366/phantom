# Contributing

This project has an unusual contribution rule, and it is worth leading with: some
changes are rejected on principle, not on quality.

## Read these first

1. [`docs/ethics.md`](docs/ethics.md) — the line this project does not cross
2. [`docs/edge-provenance.md`](docs/edge-provenance.md) — the rules everything else depends on
3. [`SECURITY.md`](SECURITY.md) — the commitments a fix must not break

## The five refusals

Proposals that require any of these are closed, however well implemented:

1. Storing a third party's identifiers (names, addresses, phone numbers)
2. Returning an enriched contact list
3. A server component that receives graph data
4. Removing or weakening the per-field consent flags
5. Retaliation of any kind against a host that touched a canary

If you think one of these is wrong, that is a design conversation to have before
writing code, and it needs to survive `docs/ethics.md`, not bypass it.

## Getting set up

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e "backend[dev]"
cd backend && pytest -q
```

The suite runs with no network access and no credentials. If a test needs either,
it is testing the wrong thing.

## What good changes look like

- **Rules over heuristics.** A new edge rule needs an id (`R-XXX-n`), a class, a
  caveat if it is not `observed`, and a test that asserts the ceiling.
- **Evidence or nothing.** If your change can create an edge, demonstrate the
  evidence row it writes.
- **Absence is not explanation.** Negative space records what changed; it never
  asserts why. This is the most common review comment you will get.
- **Registry entries need sources.** A provider attribution without a source note
  is a guess, and guesses do not belong in the data file.
- **Comments explain why.** `# increment counter` is noise.
  `# a single message is one observation, however many hosts revealed it` is not.

## Test conventions

- Every detection heuristic gets a reason assertion, not just a boolean one.
- Every promise in the README should have a test that fails if the promise breaks.
  If you find one that does not, adding that test is a valued contribution.
- Add a fixture message to `samples/` when you add a behaviour; the corpus is how
  the demo stays honest.

## Style

Ruff, line length 100. Type hints on public functions. No new dependencies without
a note explaining why the standard library is insufficient — every dependency is a
future egress path.

## Commit messages

Imperative mood, one line under 72 characters, body only when the reasoning is not
obvious:

```
Cap correlated edges at 0.85

Two senders sharing a provider is real evidence of shared infrastructure and no
evidence of shared ownership. The ceiling is the difference between a graph and
an accusation.
```
