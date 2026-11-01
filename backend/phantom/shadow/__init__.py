"""ShadowTrace: Layer 3 of the PHANTOM graph.

Layers 1 and 2 map who is positioned to observe you. Layer 3 maps the observable
activity around the things you protect: decoy fetches, refused requests for
protected data, quarantined payloads, and integrity failures.

Its whole discipline is that it only records what arrived. It never probes a
third party, never responds, and never converts an observation about
infrastructure into a statement about a person.

Two invariants hold this module together, and both are enforced by code rather
than by convention:

1. **Layers never merge on their own.** :data:`phantom.engine.classify.CROSS_LAYER_RULES`
   cannot be written during ingestion; the relationship engine raises. The only
   path is a human confirming a proposal in :mod:`phantom.shadow.bridges`.
2. **Every event is signed into a hash chain** (:mod:`phantom.shadow.vault`), so
   the record can be checked for tampering later without trusting the process
   that wrote it.
"""
from __future__ import annotations

LAYER_SURVEILLANCE = "surveillance"
LAYER_RELATIONSHIP = "relationship"
LAYER_ADVERSARIAL = "adversarial"

#: Node kind -> layer. Anything not listed is treated as surveillance, because
#: unclassified things come from the mail graph.
KIND_LAYER: dict[str, str] = {
    "organization": LAYER_SURVEILLANCE,
    "provider": LAYER_SURVEILLANCE,
    "domain": LAYER_SURVEILLANCE,
    "mail_host": LAYER_SURVEILLANCE,
    "dkim_identity": LAYER_SURVEILLANCE,
    "canary": LAYER_ADVERSARIAL,
    "origin": LAYER_ADVERSARIAL,
    "client": LAYER_ADVERSARIAL,
    "asn": LAYER_ADVERSARIAL,
    "decoy": LAYER_ADVERSARIAL,
    "protected_object": LAYER_ADVERSARIAL,
    "payload": LAYER_ADVERSARIAL,
}


def layer_of(kind: str) -> str:
    return KIND_LAYER.get(kind, LAYER_SURVEILLANCE)


def is_adversarial(kind: str) -> bool:
    return layer_of(kind) == LAYER_ADVERSARIAL


class IdentityMergeRefused(RuntimeError):
    """PHANTOM will not collapse a person, an organisation and an address into one node.

    Kept as an explicit refusal rather than an absence of code, so that the
    intent survives the next contributor who thinks a merge helper would tidy
    things up.
    """
