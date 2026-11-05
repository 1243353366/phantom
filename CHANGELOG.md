# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is
pre-1.0 and the scope is frozen, so minor versions add a source or a guardrail
and never a new direction.

Nothing here is a service. There is no hosted version, and no release changes
what the tool is allowed to collect: every entry is local, and every data source
needs its own opt-in.

*The 0.1.0 and 0.2.0 entries were written retrospectively on 2026-11-01, from the
commit history. Later entries are written at the time.*

## 2026-11-05 - hardening round

Four defects found by review, none of them visible in the test suite that existed.

- **The database was world-readable.** SQLite creates its files `0644`, and this one
  holds who contacted whom. The key file was already `0600`; the data was not. The
  database and its `-wal`/`-shm` sidecars are now tightened on connect, because the
  sidecars appear after any check performed at startup.
- **Outbound reads had no ceiling.** An allowlisted hostname is a promise about
  identity, not about size: one endpoint streaming without end was a memory
  exhaustion bug that the allowlist made look trustworthy. Reads now stop at 8 MiB,
  raise `ResponseTooLarge`, and the stop itself is recorded.
- **The audit log grew without limit.** Evidence with no ceiling is a disk-filling
  bug that anyone able to trigger a request can reach. It rotates at 2 MiB, keeps one
  generation, and drops the oldest entries: a burst large enough to rotate twice is
  the alert.
- **Request bodies had no upper bound.** `raw_email` and `contacts_csv` are now
  bounded at 20 MiB and 8 MiB and are refused, not truncated. A truncated message
  parses into a graph that quietly omits evidence, which is worse than an error.

What this round did not do: no dynamic exploitation, no fuzzing, no dependency CVE
scan, and no multi-process race testing. The DNS rebinding window described in
`egress.py` is still open and still named there.

## [0.4.0] - 2026-11-01 — scope frozen

No new surface. Boundary audit of account stitching and the attention counter,
four defects fixed, every property pinned by a named test:
`docs/reviews/2026-11-01-stitching-and-attention.md`.

### Fixed
- **Phone identifiers were never normalised.** `+1 (555) 010-0100` and
  `+15550100100` hashed differently, so a phone shared between two accounts was
  silently not matched: the identifier most likely to join accounts was the one
  that never did. Punctuation is now removed and a country code is never inferred,
  so national and international spellings stay apart on purpose.
- **Cluster provenance was dropped.** The report read `Edge.source_ref`, a column
  the writer never populates, so the source of every match was silently `None`.
  It now reads the evidence rows.
- **Observed and correlated links were indistinguishable.** A shared email and a
  reused handle both produced `stitchable: true`. Clusters now carry `link`,
  `link_class`, `confidence` and a `not_proof_of_ownership` caveat.
- **A backwards clock erased a sitting.** Timestamp-sorted sittings reported 30
  minutes as 0 after a clock correction. Measured in append order now, spanning
  each sitting by its earliest and latest look.
- **A naive timestamp crashed `phantom attention`.** Assumed UTC now; unparseable
  lines are skipped rather than taking the command down.

### Changed
- A budget breach is described as a threshold the operator configured being
  crossed: not a diagnosis, not a measure of severity, not evidence of a problem.
- The attention budget day is the operator's local day, not UTC.
- Stored phone digests change with the normalisation fix. Run
  `phantom rebuild-graph`; raw observations are unchanged.

### Frozen
- Release scope is frozen at 0.4.0. The next work is validation against real
  exports, not more collection surface.

## [Unreleased]

### Added
- **Attention budget** (`phantom attention`): counts the operator's own view
  commands on this machine, measures the longest stretch of checking, and nudges
  when a self-set budget is passed. It reads `attention.jsonl` and nothing else:
  no screen time, no app usage, no other person. A guardrail, not a data source,
  so it adds no node, edge or view to the graph.

- **Platform contribution matrix** (`phantom inventory-platforms`): what each
  platform can contribute, generated from code so it cannot drift from what the
  adapters actually read. Each row is measured, guarded, not_in_export,
  adapter_required or refused, and the refusals say why.
- **Discord server membership**, by a name-only reader: `servers/index.csv` is
  read for id and name, and refused outright if it carries any other column. The
  memberships become `member_of` edges (`R-INV-3`, observed) to community nodes,
  which is the findability surface rather than a social graph.
- **Posture assessment** (`phantom posture`): the six exposure questions answered
  in one pass over local data, each with findings, remediation actions that carry
  what they cannot guarantee, and a `cannot_see` list. Questions that need data the
  tool does not have report `not_measured` and say why, rather than filling the gap.
  Question 6 (what to remove or restrict) is derived from the other five.
- **Indexability check** (`phantom indexability`): robots.txt and noindex answered
  separately, because they are different directives. A disallowed path reports
  `unverifiable`, not "private": the crawler never fetches the page, so the
  noindex that would remove it is never read, and the URL can still be indexed.
  Parsing follows RFC 9309, and only allowlisted hosts are reachable. `--out`
  saves a run so `phantom posture` can include it.

### Refused, in writing
- Facebook account connections: friends, pages and groups are other people.
- Device and behavioural monitoring for "excessive use" or doomscrolling. The
  only way to get that data is telemetry that observes behaviour, and a token that
  labels a person's usage unhealthy is a clinical claim this evidence model cannot
  support. Recorded in `docs/scope.md` with the two other refusals.

## [0.3.0] - 2026-11-01

### Added
- **Own-account inventory**: the operator's own presence across platforms, as a
  second observation source rather than a second store, so the rebuild invariant
  covers it. Answers one question: which of my accounts already link to each
  other, and what did the linking.
- `phantom inventory-inspect` prints every field it would read and every field it
  refuses, storing nothing. `inventory-import` checks platform consent before
  opening the file. `inventory-report` shows the clusters.
- Adapters for **Discord** and **Meta** exports. The refusal is a list and the
  denial wins: messages, friends, followers, members, servers, channels, logins
  and payment files are refused by name, and matching is done on the whole
  relative path so a `messages/` directory is caught even when the filename looks
  innocent. Display names are not read at all.
- Two rules with the uncertainty split kept explicit: `R-INV-1` observed (the
  export listed this identifier on this account) and `R-INV-2` correlated (two
  accounts use the same handle string), each carrying its caveat in the graph.

### Changed
- `enroll` accepts `--platform`, so each platform has its own opt-in scope rather
  than a blanket permission.
- `observations.store` takes a reviewed field set per source, so adding the
  inventory source did not loosen the guard on email metadata.

## [0.2.0] - 2026-11-01

### Fixed
Nine of ten findings from the adversarial review, each pinned by a test:
- Egress is HTTPS-only, port 443, no user-info, no IP literals, and the resolved
  address must be public. The DNS rebinding window is narrowed and documented, not
  claimed closed.
- MirrorLock grants need a code derived from the local key, bound to blob and
  duration, printed only by `phantom approve`. Requesting access and authorising
  it are now different acts.
- The evidence vault's canonical form covers all fifteen fields with a version, so
  verification detects rewritten contents, not only chain edits and splices.
- `R-HYP-1` requires shared mail infrastructure before linking two domains: a
  display name is the one field a sender controls completely, and on its own it
  now produces negative space rather than an edge.
- Consent requires attribution and reports `attestation_is_verified_identity:
  false`, because a single-operator install has no participant authentication.
- Retention runs on service start; expired grants stop holding values.
- Canary ingestion is budgeted per token and per hour, and an exhausted budget
  stays invisible at the edge.
- Observations store URLs without query values, keep parameter names only,
  withhold IP literals, and drop the canary token from the recorded path.

### Refused, in writing
- Family and household mapping, and social platform ingestion including the
  participant-authorization variant. Authorization scales per node; the data
  arrives per edge, so a consenting person's graph records non-consenting others.

### Added
- `docs/trust-boundaries.md` and `docs/reviews/2026-11-01-adversarial.md` with a
  pinning test named for each disposition.

## [0.1.0] - 2026-10

### Added
- Email metadata graph with observed, correlated and hypothesized edges, every
  edge carrying provenance and a caveat.
- Negative space analysis: what the absence of a relationship implies, reported as
  an observation about change rather than a conclusion.
- Recursive self-audit of the tool's own egress, with a declared destination list.
- Per-field revocable consent for Gmail, phone and work email, each separately
  opt-in.
- Two-tier Gmail OAuth, metadata only: no message bodies are downloaded or stored.
- Passive counter-observation by canary token: requester origin, client stack and
  timing, plus the infrastructure graph that follows. `RETALIATION_ENABLED = False`,
  tarpitting capped at 2000ms.
- ShadowTrace, MirrorLock and the append-only evidence vault, with strict identity
  separation (`R-SHD-4`) between the surveillance and adversarial graphs.
