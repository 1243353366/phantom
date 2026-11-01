"""Six questions about exposure, answered about the operator and nobody else.

This is the whole thesis in one command. The investigative techniques are the
same ones a broker or a stalker uses; the subject is the person running the
tool, and the output is a list of things they can change.

Every question either produces findings from local data or says it has not been
measured. Nothing is inferred to fill a gap, and no question may be answered by
looking at another person.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.inventory import report as inventory_report
from phantom.models import Edge, Node

NO_ACCESS = "discoverable_without_access"
SITES = "site_exposure"
LINKAGE = "account_linkage"
CRAWLERS = "crawler_access"
IDENTIFIERS = "identifier_links"
REMEDIATION = "remediation"

QUESTIONS: tuple[tuple[str, str], ...] = (
    (NO_ACCESS, "What can someone discover about me without accessing my accounts?"),
    (SITES, "Which websites expose information about me?"),
    (LINKAGE, "What information connects my accounts across platforms?"),
    (CRAWLERS, "What do search engines and crawlers have access to?"),
    (IDENTIFIERS, "Which technical identifiers create unnecessary links between my identities?"),
    (REMEDIATION, "What can I remove, restrict, or make harder to discover?"),
)

ANSWERED = "answered"
NOTHING_FOUND = "nothing_found"
NOT_MEASURED = "not_measured"


def _presence_platforms(session: Session) -> dict[str, str]:
    return {
        node.key: node.attrs.get("platform", "?")
        for node in session.scalars(select(Node).where(Node.kind == "presence"))
    }


def _communities(session: Session) -> list[str]:
    return sorted(node.label for node in session.scalars(select(Node).where(Node.kind == "community")))


def _shared_identifiers(session: Session, platforms: dict[str, str]) -> list[dict]:
    """Identifiers the operator has attached to more than one account.

    Equality is enough here: identifiers are stored as keyed digests, so two rows
    with the same digest are the same value without the value being present.
    """
    kinds = {
        node.key: node.attrs.get("kind", "identifier")
        for node in session.scalars(select(Node).where(Node.kind == "identifier"))
    }
    grouped: dict[str, set[str]] = {}
    for edge in session.scalars(select(Edge).where(Edge.relation == "uses_identifier")):
        platform = platforms.get(edge.src_key)
        if platform:
            grouped.setdefault(edge.dst_key, set()).add(platform)

    return [
        {"kind": kinds.get(key, "identifier"), "platforms": sorted(users)}
        for key, users in sorted(grouped.items())
        if len(users) > 1
    ]


def _action(question: str, action: str, why: str, removes: str, cannot: str) -> dict:
    return {
        "question": question,
        "action": action,
        "why": why,
        "removes": removes,
        "cannot_guarantee": cannot,
    }


def build(session: Session, *, indexability: list[dict] | None = None) -> dict:
    platforms = _presence_platforms(session)
    used = sorted(set(platforms.values()))
    communities = _communities(session)
    shared = _shared_identifiers(session, platforms)
    linkage = inventory_report.build(session)
    clusters = [c for c in linkage.get("clusters", []) if c.get("stitchable")]

    answers: dict[str, dict] = {}

    # 1 -- what a stranger sees, using only what the operator publishes.
    findings = []
    if used:
        findings.append(
            f"{len(platforms)} account(s) on {', '.join(used)} are public enough to be "
            "inventoried from an export, which means a stranger can inventory them the "
            "same way by reading the same public fields."
        )
    for cluster in clusters:
        findings.append(
            f"Accounts on {', '.join(cluster['platforms'])} share identifiers, so "
            "finding one leads to the others without any access."
        )
    public_handles = sorted(
        {handle for cluster in linkage.get("clusters", []) for handle in cluster.get("handles", [])}
    )
    if public_handles:
        findings.append(
            f"Your handle(s) {', '.join(public_handles)} are public: they are what a "
            "stranger's first search uses, and they are the cheap link between accounts."
        )
    if communities:
        findings.append(
            f"{len(communities)} community membership(s) are visible: {', '.join(communities[:6])}."
        )
    answers[NO_ACCESS] = {
        "status": ANSWERED if findings else NOTHING_FOUND,
        "findings": findings,
        "cannot_see": [
            "What someone learns from a breach dump, a data broker's purchase history, "
            "or a person who already knows you.",
            "Anything behind a login, which this tool never holds.",
        ],
    }

    # 2 -- third-party sites. Local data cannot answer this, so it says so.
    answers[SITES] = {
        "status": NOT_MEASURED,
        "findings": [],
        "cannot_see": [
            "This one needs fetching sites you do not own, so it is not measured until "
            "you name the sites: add each to selfaudit/egress_allowlist.yaml and the "
            "check becomes egress you declared in advance. PHANTOM will not quietly "
            "browse for you.",
            "Which brokers hold a record is not a fact a page can prove, even when the "
            "page shows one.",
        ],
        "next": "declare the sites to check, then run the check per site",
    }

    # 3 -- what joins the accounts.
    join_findings = [
        f"{len(cluster['platforms'])} accounts on {', '.join(cluster['platforms'])} are "
        f"joinable through {cluster.get('joined_by') and 'a reused handle' or 'a shared identifier'}."
        for cluster in clusters
    ]
    answers[LINKAGE] = {
        "status": ANSWERED if join_findings else NOTHING_FOUND,
        "findings": join_findings,
        "cannot_see": [
            "Joins that need a guess: a similar handle, a reused photo, writing style.",
            "That is the point of the correlated class: no observer needs permission for "
            "a guess, and this tool will not dress one up as an observation.",
        ],
    }

    # 4 -- crawlers, from whatever indexability runs were saved.
    if indexability:
        crawl_findings: list[str] = []
        for row in indexability:
            url = row.get("url", "?")
            state = row.get("indexable")
            if state == "yes":
                crawl_findings.append(f"{url} is indexable: crawl allowed, no noindex declared.")
            elif state == "no":
                crawl_findings.append(f"{url} declares noindex and allows the crawl, so it drops on recrawl.")
            else:
                crawl_findings.append(
                    f"{url} is unverifiable: crawling is disallowed, so a noindex on it can "
                    "never be read and the URL may still be indexed."
                )
        answers[CRAWLERS] = {
            "status": ANSWERED if crawl_findings else NOTHING_FOUND,
            "findings": crawl_findings,
            "cannot_see": ["What a search engine already indexed before you changed anything."],
        }
    else:
        answers[CRAWLERS] = {
            "status": NOT_MEASURED,
            "findings": [],
            "cannot_see": ["Run `phantom indexability <url> --out <file>` to include this."],
        }

    # 5 -- the identifiers doing the linking.
    id_findings = [
        f"A {row['kind']} is attached to {len(row['platforms'])} accounts "
        f"({', '.join(row['platforms'])}), so it alone joins them."
        for row in shared
    ]
    answers[IDENTIFIERS] = {
        "status": ANSWERED if id_findings else NOTHING_FOUND,
        "findings": id_findings,
        "cannot_see": [
            "Identifier kinds no export mentions, such as a device id or an advertising id.",
            "Values are never printed: they are stored as keyed digests, which is enough "
            "to see that a link exists and not enough to leak the value.",
        ],
    }

    # 6 -- what to do, derived from the five above rather than written by hand.
    actions: list[dict] = []
    for row in shared:
        if row["kind"] in {"email", "phone"}:
            actions.append(
                _action(
                    REMEDIATION,
                    f"Use a per-platform alias for the {row['kind']} shared by "
                    f"{', '.join(row['platforms'])}.",
                    f"One {row['kind']} is the join key for {len(row['platforms'])} accounts.",
                    f"removes the {row['kind']} as a link between those accounts.",
                    "It does not remove accounts already scraped or shared, and an alias "
                    "provider that forwards to one inbox becomes a new single point.",
                )
            )
    for cluster in clusters:
        if cluster.get("joined_by"):
            actions.append(
                _action(
                    REMEDIATION,
                    f"Use a distinct handle on {', '.join(cluster['platforms'])} instead of "
                    f"the shared '{cluster['handles'][0]}'.",
                    "The same handle string on both accounts is a join anyone can test in a search box.",
                    "removes the cheapest join an observer has.",
                    "It does not remove joins from reused photos, bios or writing habits.",
                )
            )
    if communities:
        actions.append(
            _action(
                REMEDIATION,
                "Check which communities publish member lists, and restrict profile visibility where yours are listed.",
                "A membership can name an interest or an affiliation on its own.",
                "reduces the chance a stranger ties a community to you.",
                "Some servers expose membership to members regardless of your settings.",
            )
        )
    for row in indexability or []:
        if row.get("indexable") == "yes":
            actions.append(
                _action(
                    REMEDIATION,
                    f"Allow the crawl and serve noindex on {row.get('url')}, then disallow once it drops.",
                    "A disallow hides the page from crawlers and from the noindex that would remove it.",
                    "removes the URL from results after a recrawl.",
                    "It cannot hurry the recrawl, which can take weeks.",
                )
            )
        elif row.get("indexable") == "unverifiable":
            actions.append(
                _action(
                    REMEDIATION,
                    f"Confirm {row.get('url')} in the search engine's URL inspector.",
                    "A disallowed path hides its own noindex, so its state cannot be read from outside.",
                    "settles whether the URL is currently indexed.",
                    "This tool cannot ask the engine on your behalf.",
                )
            )
    answers[REMEDIATION] = {
        "status": ANSWERED if actions else NOTHING_FOUND,
        "findings": [a["action"] for a in actions],
        "actions": actions,
        "cannot_see": [
            "Anything already indexed, archived, scraped or sold before you acted.",
            "Removal from a third party is a request, not a deletion you can perform.",
        ],
    }

    return {
        "thesis": (
            "These are investigative techniques pointed at the person running the tool. "
            "Every finding is derived from the operator's own data, and no question is "
            "answered by examining anyone else."
        ),
        "questions": [
            {"id": qid, "question": text, **answers[qid]} for qid, text in QUESTIONS
        ],
        "actions_total": len(actions),
        "platforms_seen": used,
    }
