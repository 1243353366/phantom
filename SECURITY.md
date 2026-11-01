# Security policy

## Reporting a vulnerability

Open a private security advisory on the repository, or email the maintainer listed
in `pyproject.toml`. Please do not open a public issue for anything that could be
exploited before a fix exists.

Include: what you did, what happened, what you expected, and the smallest
reproduction you can construct. A redacted `out/report.md` is usually enough.

You can expect an acknowledgement within a few days. This is a small project; be
patient and be specific.

## Scope

In scope:

- Bypasses of the egress allowlist (`phantom/egress.py`)
- Ways to make PHANTOM store data it promises not to store
  (email bodies, contact identifiers, raw source addresses by default)
- Ways to create an edge without provenance
- Ways to inflate confidence on a hypothesized edge past its ceiling
- Consent bypass: storing a contact field without its own explicit flag
- Parser memory exhaustion from a crafted message
- Anything that makes the canary endpoint a vector *against* the person running it

Out of scope:

- Attacks requiring an already-compromised host
- Weaknesses in third-party dependencies with no PHANTOM-specific impact
  (report upstream; tell us too)
- "PHANTOM can be detected as PHANTOM" — a self-hosted tool is not pretending
  otherwise
- Anything about the accuracy of the curated registry. That is a data question:
  open a normal issue with a source.

## Design commitments a fix must not break

1. No endpoint sends mail.
2. No endpoint uploads contacts or enriches them.
3. Unlisted network destinations fail closed.
4. Every edge has at least one evidence row.
5. Hypothesized edges are capped at 0.65 confidence.
6. Retaliation is not implemented and will not be.

If a security fix would require breaking one of these, the fix is wrong, or the
commitment needs an explicit, documented change of direction first.
