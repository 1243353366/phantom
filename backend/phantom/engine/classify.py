"""Edge classification.

Three classes only, and the line between them is a rule, not a judgement:

  observed     - one message directly shows the relationship
  correlated   - the same overlap recurs across independent observations
  hypothesized - a pattern suggests a relationship that has not been verified

Every rule carries a ``caveat`` that the UI is required to display next to the
edge. A caveat of ``None`` means the relationship is plain and direct.
"""
from __future__ import annotations

from dataclasses import dataclass

OBSERVED = "observed"
CORRELATED = "correlated"
HYPOTHESIZED = "hypothesized"

SHARED_INFRA_CAVEAT = (
    "Shared technical infrastructure. This does not establish common ownership, "
    "coordination, or that data is exchanged between these parties."
)
RELAY_CAVEAT = (
    "Observed mail relay hop. Large providers relay mail for many unrelated "
    "senders, so a shared relay is weak evidence on its own."
)
CONTINUITY_CAVEAT = (
    "Domains that carried the same sender identity and infrastructure pattern "
    "at different times. Possible rebrand, migration, or unrelated reuse of a "
    "common provider."
)
SHARED_ORIGIN_CAVEAT = (
    "Same client stack observed from more than one source address, or picked up "
    "by more than one canary. This groups infrastructure, not people: a shared "
    "scraper, proxy pool or cloud region produces exactly this pattern."
)
CAMPAIGN_CAVEAT = (
    "Grouped because the same client stack touched both canaries. Common tooling "
    "is not proof of a common operator, and a popular crawler will cluster "
    "everything it touches."
)
CANARY_CAVEAT = (
    "An access, not an identity. The request proves something fetched this "
    "canary; it does not establish who, or that a human was involved."
)
SELECTOR_CAVEAT = (
    "Same DKIM selector and provider across senders. Selectors are chosen by "
    "the provider and are frequently shared, so this is a lead to verify, not "
    "a finding."
)


@dataclass(frozen=True)
class Rule:
    id: str
    classification: str
    relation: str
    description: str
    caveat: str | None = None


RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        Rule("R-OBS-1", OBSERVED, "serves_tracking_content",
             "Sender's message embedded content served by this domain."),
        Rule("R-OBS-2", OBSERVED, "uses_provider",
             "Sender's message touched infrastructure attributed to this provider."),
        Rule("R-OBS-3", OBSERVED, "relayed_through",
             "Message traversed this mail host.", RELAY_CAVEAT),
        Rule("R-OBS-4", OBSERVED, "wraps_links_for",
             "Links in the sender's message were rewritten by this redirector."),
        Rule("R-OBS-5", OBSERVED, "routes_mail_via",
             "Sender's Reply-To or Return-Path points at this domain."),
        Rule("R-COR-1", CORRELATED, "shares_infrastructure_with",
             "Recurring overlap on the same provider across independent messages.",
             SHARED_INFRA_CAVEAT),
        Rule("R-HYP-1", HYPOTHESIZED, "possible_identity_overlap",
             "Different sender domains present the same identity and infrastructure pattern.",
             CONTINUITY_CAVEAT),
        Rule("R-HYP-2", HYPOTHESIZED, "shares_dkim_selector_with",
             "Senders share a DKIM selector under the same provider.", SELECTOR_CAVEAT),
        # --- counter-observation -------------------------------------
        Rule("R-MIR-1", OBSERVED, "accessed_canary",
             "A request fetched this canary from this origin.", CANARY_CAVEAT),
        Rule("R-MIR-2", OBSERVED, "presented_client",
             "This origin sent requests with this client stack."),
        Rule("R-MIR-3", OBSERVED, "originates_from",
             "Observation resolved to this network, via a local ASN table only."),
        Rule("R-MIR-4", CORRELATED, "shares_origin_infrastructure_with",
             "Distinct origins presenting the same client stack on the same network.",
             SHARED_ORIGIN_CAVEAT),
        Rule("R-MIR-5", HYPOTHESIZED, "campaign_cluster_with",
             "Two canaries were touched by the same client stack.",
             CAMPAIGN_CAVEAT),
    ]
}


def confidence_for(classification: str, observation_count: int, base: float = 0.5) -> float:
    """Confidence grows with independent observations but is capped per class.

    A hypothesized edge is never allowed above 0.65 no matter how many weak
    signals point at it, because it has not been verified.
    """
    ceiling = {OBSERVED: 0.99, CORRELATED: 0.85, HYPOTHESIZED: 0.65}[classification]
    return round(min(base + 0.1 * max(observation_count - 1, 0), ceiling), 2)


def upgrades_to(observation_count: int, threshold: int) -> bool:
    return observation_count >= threshold
