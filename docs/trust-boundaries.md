# Trust boundaries

What this system will not do, what it cannot do, and where the risk that remains
actually sits. Written after an adversarial review found ten paths that were real,
because a privacy tool's worst failure is being believed beyond its evidence.

## The refusals are in code, not in prose

| Refusal | Where it lives | Pinned by |
| --- | --- | --- |
| No active probing of third-party systems | `egress` allowlist, HTTPS-only, public-address check | `test_egress_refuses_these_destinations` |
| No retaliation, ever | `RETALIATION_ENABLED = False`, tarpit capped at 2000ms | `tests/test_mirror.py` |
| No credential storage | `shadow/events.py` refuses and records the refusal | `test_the_requester_label_is_recorded_as_a_claim` |
| No message bodies | `observations.to_payload` has no field for one | `tests/test_observations.py` |
| No cloud graph construction | SQLite file under `PHANTOM_HOME` | `tests/test_db.py` |
| No automatic merge of surveillance and adversarial identity | cross-layer edges require a confirmed bridge | `R-SHD-4`, `tests/test_shadow.py` |

A refusal that exists only in a README is a preference. Each row above is a line
of code with a test that fails if someone removes it.

## Consent is an attestation, and the record says so

PHANTOM is a single-operator local install. There is no participant
authentication, no PKI binding a key to a legal identity, and no way for this
software to verify that a person agreed to anything. So `enroll` requires
`attested_by` and `attestation`, stores them verbatim, includes them in the
receipt hash, and returns:

```json
{ "attestation_is_verified_identity": false }
```

That flag is not modesty, it is accuracy. The honest statement is "the person
running this says permission exists". Anything stronger would be a claim this
architecture cannot support, and a privacy tool that overstates its consent model
has already failed at its one job.

Consequence: consent here cannot authorise mapping *other people*. It authorises
the operator's own data sources. See `docs/scope.md` for the two extensions this
rules out and why.

## Residual risk, honestly

1. **DNS rebinding (TOCTOU).** `egress` resolves a host, checks the address is
   public, then connects. A name whose answer changes between those two moments
   can reach a private address. The window is small and closing it properly needs
   a connection pool pinned to the validated address. Documented rather than
   claimed solved.
2. **The tracker registry is a set of claims.** Every entry names a source
   because every entry is an assertion. A vendor can share infrastructure with
   someone unrelated, and a domain absent from the list stays unattributed by
   design: a gap is preferable to an invented attribution.
3. **A canary URL is public by construction.** Anything that can be fetched can
   be fetched repeatedly. Ingestion is budgeted (per-token total and per-hour),
   and an exhausted budget is invisible at the edge: the image is still served.
4. **Identity continuity needs corroboration.** A display name is the one field a
   sender controls completely, so two domains sharing a name no longer creates an
   edge. It becomes a hypothesis only when independent infrastructure agrees, and
   otherwise it is reported as negative space.
5. **Correlation is not attribution.** Shared hosting, repeated addresses, a
   rejected decryption request and a contact relationship are each consistent with
   innocent explanations. Every inferred edge carries its caveat, and the UI is
   required to show it.
6. **The local key is the whole security model.** `phantom approve` reads it, and
   anyone with filesystem access to `PHANTOM_HOME` has everything the operator
   has. There is no defence against a hostile local user, and none is claimed.

## Two invariants that must not be relaxed

- **Provenance.** No edge exists without evidence. The engine is the only writer
  and refuses a claim with no justification.
- **Identity separation.** A node observed on the surveillance side and a node
  observed on the adversarial side are never the same node until a human says so.
  The bridge is a recorded decision, so a rebuild restores it rather than
  recomputing it.
