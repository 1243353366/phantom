"""Command line interface.

    phantom demo            run the pipeline over the bundled samples
    phantom ingest a.eml    fold a message into the local graph
    phantom graph           print the graph as JSON
    phantom selfaudit       audit PHANTOM's own network footprint
    phantom exposure c.csv  local contact exposure check
    phantom enroll          record an explicit, revocable consent grant
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phantom import egress
from phantom.collector.headers import parse_eml
from phantom.db import get_session, init_db
from phantom.engine.graph import to_cytoscape
from phantom.engine.relationship_engine import RelationshipEngine


def _ingest_files(session, paths: list[Path]) -> list[dict]:
    engine = RelationshipEngine(session)
    out = []
    for path in paths:
        mail = parse_eml(path.read_bytes())
        out.append(engine.ingest(mail, source_ref=f"eml:{path.name}"))
    engine.correlate()
    return out


def cmd_demo(args: argparse.Namespace) -> int:
    from phantom.report import render_markdown
    from phantom.selfaudit.auditor import SelfAuditor
    from phantom.watchdog.negative_space import NegativeSpaceWatchdog

    samples = sorted((Path(args.samples_dir)).glob("*.eml"))
    if not samples:
        print(f"no .eml files in {args.samples_dir}", file=sys.stderr)
        return 1

    init_db()
    session = get_session()
    results = _ingest_files(session, samples)

    watchdog = NegativeSpaceWatchdog(session)
    watchdog.scan()
    negative = watchdog.report()
    audit = SelfAuditor(session).run()
    graph = to_cytoscape(session)

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "graph.json").write_text(json.dumps(graph, indent=2), encoding="utf-8")
    (outdir / "negative-space.json").write_text(json.dumps(negative, indent=2), encoding="utf-8")
    (outdir / "selfaudit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    (outdir / "report.md").write_text(render_markdown(graph, negative, audit), encoding="utf-8")

    print(f"ingested {len(samples)} messages")
    for row in results:
        print(
            f"  {row['sender_domain']:<28} pixels={row['pixels']} "
            f"redirectors={row['redirectors']} dmarc={row['dmarc']} "
            f"providers={','.join(row['providers']) or '-'}"
        )
    stats = graph["stats"]
    print(
        f"\ngraph: {stats['nodes']} nodes, {stats['edges']} edges "
        f"{stats['edges_by_classification']}"
    )
    print(f"negative space: {negative['total']} observation(s) of change")
    print(f"self-audit: {audit['verdict']}")
    print(f"\nwrote {outdir}/report.md, graph.json, negative-space.json, selfaudit.json")
    session.close()
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    init_db()
    session = get_session()
    for row in _ingest_files(session, [Path(p) for p in args.files]):
        print(json.dumps(row, indent=2))
    session.close()
    return 0


def cmd_graph(args: argparse.Namespace) -> int:
    init_db()
    session = get_session()
    print(json.dumps(to_cytoscape(session), indent=2))
    session.close()
    return 0


def cmd_selfaudit(args: argparse.Namespace) -> int:
    from phantom.selfaudit.auditor import SelfAuditor

    init_db()
    session = get_session()
    print(json.dumps(SelfAuditor(session).run(), indent=2))
    session.close()
    return 0


def cmd_exposure(args: argparse.Namespace) -> int:
    from phantom.exposure.local_contacts import ContactExposureAnalyzer

    init_db()
    session = get_session()
    text = Path(args.csv).read_text(encoding="utf-8")
    result = ContactExposureAnalyzer(session).analyze_csv(
        text,
        exclude_domains=set(args.exclude_domain or []),
        exclude_categories=set(args.exclude_category or []),
    )
    print(json.dumps(result.as_dict(), indent=2))
    session.close()
    return 0


def cmd_enroll(args: argparse.Namespace) -> int:
    from phantom.auth.consent import ConsentError, ConsentService

    init_db()
    session = get_session()
    try:
        record = ConsentService(session).enroll(
            platforms=args.platforms,
            gmail_address=args.gmail,
            phone_number=args.phone,
            work_email=args.work_email,
            consent_gmail=args.consent_gmail,
            consent_phone=args.consent_phone,
            consent_work_email=args.consent_work_email,
            ttl_days=args.ttl_days,
            attested_by=args.attested_by,
            attestation=args.attestation,
        )
    except ConsentError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(ConsentService(session).view(record), indent=2))
    session.close()
    return 0


def cmd_attention(args: argparse.Namespace) -> int:
    from phantom import attention

    if args.checks_per_day is not None or args.continuous_minutes is not None:
        attention.set_budget(
            checks_per_day=args.checks_per_day,
            continuous_minutes=args.continuous_minutes,
        )
    print(json.dumps(attention.summary(), indent=2))
    return 0


def _platforms() -> list[str]:
    from phantom.inventory.adapters import ADAPTERS

    return list(ADAPTERS)


def cmd_inventory_inspect(args: argparse.Namespace) -> int:
    from phantom.inventory.adapters import ADAPTERS

    reading = ADAPTERS[args.platform](args.path).read()
    print(
        json.dumps(
            {
                "platform": reading.platform,
                "would_read": [
                    {"facet": f.kind, "field": f.source_field, "value_hint": "withheld"}
                    for f in reading.facets
                ],
                "files_read": reading.files_read,
                "refused": [{"item": r.item, "reason": r.reason} for r in reading.refusals],
                "note": "Nothing was stored. Run inventory-import to record it.",
            },
            indent=2,
        )
    )
    return 0


def cmd_inventory_import(args: argparse.Namespace) -> int:
    from phantom.auth.consent import ConsentError, ConsentService
    from phantom.inventory import store
    from phantom.inventory.adapters import ADAPTERS

    init_db()
    session = get_session()
    try:
        # Consent is checked before the file is opened, so an unauthorised
        # platform never has its export parsed at all.
        try:
            ConsentService(session).require_platform(args.platform)
        except ConsentError as exc:
            print(str(exc), file=sys.stderr)
            return 2

        reading = ADAPTERS[args.platform](args.path).read()
        row = store.record(session, reading)
        session.commit()

        projected = store.project(session)
        session.commit()
        print(
            json.dumps(
                {
                    "stored": row.source_ref,
                    "facets": [f.kind for f in reading.facets],
                    "refused": [r.item for r in reading.refusals],
                    "graph": projected,
                    "note": (
                        "Identifiers are stored as keyed digests. Run "
                        "inventory-report to see what they link."
                    ),
                },
                indent=2,
            )
        )
    finally:
        session.close()
    return 0


def cmd_inventory_report(args: argparse.Namespace) -> int:
    from phantom.inventory.report import build

    init_db()
    session = get_session()
    try:
        print(json.dumps(build(session), indent=2))
    finally:
        session.close()
    return 0


def cmd_canary(args: argparse.Namespace) -> int:
    from phantom.mirror import tokens

    init_db()
    session = get_session()
    try:
        canary = tokens.mint(session, args.label, note=args.note or "")
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"label": canary.label, "url": canary.url}, indent=2))
    session.close()
    return 0


def cmd_mirror_report(args: argparse.Namespace) -> int:
    from phantom.mirror.countergraph import build
    from phantom.mirror.report import asymmetry_report

    init_db()
    session = get_session()
    build(session)
    print(json.dumps(asymmetry_report(session), indent=2))
    session.close()
    return 0


def cmd_mirror_demo(args: argparse.Namespace) -> int:
    """Simulate canary traffic so the mechanism can be inspected offline.

    Uses the real recording path, so what you see is what real traffic produces.
    """
    from phantom.mirror import tokens
    from phantom.mirror.beacon import record_observation
    from phantom.mirror.countergraph import build, to_cytoscape
    from phantom.mirror.report import asymmetry_report

    init_db()
    session = get_session()

    table = Path(args.out) / "asn-demo.csv"
    table.parent.mkdir(parents=True, exist_ok=True)
    table.write_text(
        "203.0.113.0/24,64500,Example Cloud\n"
        "198.51.100.0/24,64501,Example Transit\n"
        "192.0.2.0/24,64502,Example Hosting\n",
        encoding="utf-8",
    )

    scripted = {"user-agent": "python-requests/2.32.3", "accept": "*/*"}
    scrapy = {"user-agent": "Scrapy/2.11 (+https://scrapy.org)"}
    browser = {
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
        "accept": "image/avif,image/webp,*/*",
        "accept-language": "en-US,en;q=0.9",
        "referer": "https://docs.example.com/deck",
    }

    deck = tokens.mint(session, "pitch-deck v3 / acme")
    model = tokens.mint(session, "financial-model v2 / acme")
    memo = tokens.mint(session, "strategy-memo / northwind")

    hits = [
        (deck, "203.0.113.9", scripted),
        (model, "203.0.113.9", scripted),
        (deck, "203.0.113.77", scripted),
        (model, "192.0.2.41", scripted),
        (memo, "192.0.2.41", scripted),
        (memo, "198.51.100.4", scrapy),
        (deck, "198.51.100.19", browser),
    ]
    for canary, ip, headers in hits:
        record_observation(
            session, token=canary.token, source_ip=ip, headers=headers, asn_db=table
        )

    build(session)
    graph = to_cytoscape(session)
    report = asymmetry_report(session)

    outdir = Path(args.out)
    (outdir / "counter-graph.json").write_text(json.dumps(graph, indent=2), encoding="utf-8")
    (outdir / "counter-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    origins = len({ip for _, ip, _ in hits})
    print(f"simulated {len(hits)} canary fetches across {origins} origins")
    for row in report["leaked_copies"]:
        print(f"  leaked: {row['label']:<30} hits={row['hits']} clients={row['client_families']}")
    print(f"\n{report['summary']}")
    print(f"campaign clusters: {len(report['campaigns'])} (hypothesized)")
    print(f"counter-graph: {graph['stats']['nodes']} nodes, {graph['stats']['edges']} edges "
          f"{graph['stats']['edges_by_classification']}")
    print(f"guardrails: retaliation={report['guardrails']['retaliation_enabled']} "
          f"raw_ip_retained={report['guardrails']['raw_ip_retained']}")
    print(f"\nwrote {outdir}/counter-report.json and counter-graph.json")
    session.close()
    return 0


def cmd_shadow_demo(args: argparse.Namespace) -> int:
    """Simulate Layer 3 traffic through the real recording paths."""
    from phantom.shadow import events as shadow_events
    from phantom.shadow import graph as shadow_graph
    from phantom.shadow import mirrorlock, quarantine
    from phantom.shadow import report as shadow_report

    init_db()
    session = get_session()

    locked = mirrorlock.lock(session, "board-pack v4", b"quarterly numbers, do not share")
    model = mirrorlock.lock(session, "model v2", b"assumptions and projections")

    scripted = {"family": "scripted", "tool": "python-requests"}
    scrapy = {"family": "scripted", "tool": "scrapy"}
    browser = {"family": "browser-chromium", "tool": ""}

    # Decoy fetches, the ordinary Layer 3 signal.
    for subject, origin, client, asn, org in [
        ("decoy:pitch-deck v3", "a" * 64, scripted, 64500, "Example Cloud"),
        ("decoy:pitch-deck v3", "b" * 64, scripted, 64500, "Example Cloud"),
        ("decoy:strategy-memo", "b" * 64, scripted, 64500, "Example Cloud"),
        ("decoy:strategy-memo", "c" * 64, scrapy, 64501, "Example Transit"),
    ]:
        shadow_events.record(
            session,
            kind=shadow_events.DECOY_ACCESS,
            subject_ref=subject,
            subject_kind="decoy",
            outcome=shadow_events.OBSERVED,
            origin_hmac=origin,
            client_hash=(origin[::-1] + client["tool"]),
            client_family=client["family"],
            client_tool=client["tool"],
            asn=asn,
            asn_org=org,
            detail=f"Decoy fetched by a {client['family']} client",
        )

    # Two attempts to read a locked object with no grant: refused, and recorded.
    for label, origin, client in [
        ("unknown reader", "d" * 64, browser),
        ("retrying integration", "e" * 64, scrapy),
    ]:
        mirrorlock.request(
            session,
            locked.id,
            requester_label=label,
            origin_hmac=origin,
            client_hash=(origin[::-1] + client["tool"]),
            client_family=client["family"],
            client_tool=client["tool"],
            justification="please send the full pack",
        )

    # One legitimate read inside a grant, so the log is not all refusals.
    # The demo authorises the way an operator would: by minting the code from the
    # local key, not by reaching into the module and skipping the check.
    mirrorlock.grant(
        session,
        model.id,
        minutes=5,
        approval=mirrorlock.approval_code(model.id, 5),
        granted_by="demo operator",
        note="owner reading on a second device",
    )
    mirrorlock.request(session, model.id, requester_label="owner", origin_hmac="f" * 64)

    quarantine.capture(
        session,
        b"MZ\x90\x00" + b"\x00" * 200,
        source_ref="attachment:pricing.exe",
        declared_type="application/pdf",
        origin_hmac="d" * 64,
        client_family="scripted",
        client_tool="python-requests",
    )

    shadow_graph.project(session)
    report = shadow_report.adversarial_report(session)
    view = shadow_graph.to_cytoscape(session)

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "shadow-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (outdir / "shadow-graph.json").write_text(json.dumps(view, indent=2), encoding="utf-8")

    print(f"layer 3 events: {report['events']}  {report['by_kind']}")
    print(f"outcomes: {report['by_outcome']}")
    for row in report["protected_objects_touched"]:
        print(f"  touched: {row['subject']:<32} events={row['events']} {row['outcomes']}")
    print(f"\nrecurring indicators: {len(report['recurring_indicators'])}")
    print(f"co-occurrence candidates: {len(report['co_occurrence_candidates'])} "
          f"(hypothesized, capped)")
    print(f"quarantined payloads: {len(report['quarantined_payloads'])} "
          f"(executed: {report['guardrails']['quarantined_payloads_executed']})")
    print(f"vault: {'intact' if report['vault']['ok'] else 'BROKEN'} "
          f"({report['vault']['checked']} records)")
    print(f"automatic layer merges: {report['guardrails']['automatic_layer_merges']}")
    print(f"bridges pending: {len(report['bridges']['pending'])} "
          f"confirmed: {len(report['bridges']['confirmed'])}")
    print(f"\nwrote {outdir}/shadow-report.json and shadow-graph.json")
    session.close()
    return 0


def cmd_shadow_report(args: argparse.Namespace) -> int:
    from phantom.shadow import graph as shadow_graph
    from phantom.shadow import report as shadow_report

    init_db()
    session = get_session()
    shadow_graph.project(session)
    print(json.dumps(shadow_report.adversarial_report(session), indent=2))
    session.close()
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    """Print the approval code that authorises one decryption window.

    Deliberately a local console command reading the local key. The API cannot
    produce this code for itself, which is what stops a caller from both asking
    for access and granting it.
    """
    from phantom.shadow import mirrorlock

    session = get_session()
    try:
        if session.get(mirrorlock.ProtectedBlob, args.blob_id) is None:
            print(f"no such protected object: {args.blob_id}", file=sys.stderr)
            return 2
    finally:
        session.close()
    print(mirrorlock.approval_code(args.blob_id, args.minutes))
    print(
        f"authorises {args.minutes} minutes of read access to {args.blob_id}. "
        "Single use is not enforced; revoke after the read.",
        file=sys.stderr,
    )
    return 0


def cmd_retention(args: argparse.Namespace) -> int:
    """Enforce every expiry this system claims to enforce."""
    from phantom.auth.consent import ConsentService
    from phantom.mirror.beacon import purge_expired

    init_db()
    session = get_session()
    try:
        purged = purge_expired(session)
        cleared = ConsentService(session).clear_expired()
        scrubbed = egress.scrub_legacy_log()
    finally:
        session.close()
    print(
        json.dumps(
            {
                "canary_observations_purged": purged,
                "consent_values_cleared": cleared,
                "egress_log_lines_scrubbed": scrubbed,
            },
            indent=2,
        )
    )
    return 0


def cmd_vault_verify(args: argparse.Namespace) -> int:
    from phantom.shadow import vault

    init_db()
    session = get_session()
    result = vault.verify(session)
    session.close()
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def cmd_rebuild_graph(args: argparse.Namespace) -> int:
    """Re-derive every claim from the observations that produced it."""
    from phantom import rebuild

    init_db()
    session = get_session()
    result = rebuild.rebuild(session)
    session.close()

    before, after = result["before"], result["after"]
    print(f"mail observations replayed: {result['observations_replayed']}")
    print(f"nodes  {before['nodes']:>4} -> {after['nodes']}")
    print(f"edges  {before['edges']:>4} -> {after['edges']}")
    print(f"evidence rows      {after['evidence']}")
    print(f"bridges restored:  {result['bridges_restored']['restored']}")
    if result["bridges_restored"]["skipped"]:
        print(f"  not restorable:  {len(result['bridges_restored']['skipped'])} "
              f"(an observation behind the decision is gone)")
    print(f"rules digest:      {result['rules_digest']}")
    print(
        "graph reproduced:  "
        + ("yes, byte-identical claim set" if result["reproduced"] else "no, the claims changed")
    )
    if not result["reproduced"]:
        print(
            "  the rule set or the observation set changed since these edges were "
            "written; the digest difference is the record of that"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phantom", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the pipeline over the bundled samples")
    demo.add_argument("--samples-dir", default="samples")
    demo.add_argument("--out", default="out")
    demo.set_defaults(func=cmd_demo)

    ingest = sub.add_parser("ingest", help="ingest .eml files")
    ingest.add_argument("files", nargs="+")
    ingest.set_defaults(func=cmd_ingest)

    sub.add_parser("graph", help="print the graph JSON").set_defaults(func=cmd_graph)
    sub.add_parser("selfaudit", help="audit own footprint").set_defaults(func=cmd_selfaudit)

    exposure = sub.add_parser("exposure", help="local contact exposure check")
    exposure.add_argument("csv")
    exposure.add_argument("--exclude-domain", action="append")
    exposure.add_argument("--exclude-category", action="append")
    exposure.set_defaults(func=cmd_exposure)

    enroll = sub.add_parser("enroll", help="record an explicit consent grant")
    enroll.add_argument("--gmail")
    enroll.add_argument("--phone")
    enroll.add_argument("--work-email", dest="work_email")
    enroll.add_argument("--consent-gmail", action="store_true")
    enroll.add_argument("--consent-phone", action="store_true")
    enroll.add_argument("--consent-work-email", action="store_true")
    enroll.add_argument(
        "--platform", action="append", default=[], dest="platforms",
        help="platform whose export you authorise reading (repeatable)",
    )
    enroll.add_argument("--ttl-days", type=int, default=365)
    enroll.add_argument(
        "--attested-by", dest="attested_by", required=True,
        help="who is stating this permission exists",
    )
    enroll.add_argument(
        "--attestation", required=True,
        help="the words the person used, recorded verbatim",
    )
    enroll.set_defaults(func=cmd_enroll)

    inspect = sub.add_parser(
        "inventory-inspect",
        help="show what an account export would be read for, storing nothing",
    )
    inspect.add_argument("path", help="the export file, or the unzipped package")
    inspect.add_argument("--platform", default="discord", choices=sorted(_platforms()))
    inspect.set_defaults(func=cmd_inventory_inspect)

    inv_import = sub.add_parser(
        "inventory-import", help="read your own account export into the inventory"
    )
    inv_import.add_argument("path")
    inv_import.add_argument("--platform", default="discord", choices=sorted(_platforms()))
    inv_import.set_defaults(func=cmd_inventory_import)

    sub.add_parser(
        "inventory-report", help="what your own accounts already link together"
    ).set_defaults(func=cmd_inventory_report)

    attention_cmd = sub.add_parser(
        "attention", help="how much this tool is drawing on you today"
    )
    attention_cmd.add_argument("--checks-per-day", type=int, dest="checks_per_day")
    attention_cmd.add_argument("--continuous-minutes", type=int, dest="continuous_minutes")
    attention_cmd.set_defaults(func=cmd_attention)

    canary = sub.add_parser("canary", help="mint a canary token and print its URL")
    canary.add_argument("--label", required=True, help="where this canary is placed")
    canary.add_argument("--note", default="")
    canary.set_defaults(func=cmd_canary)

    mirror_report = sub.add_parser("mirror-report", help="report on canary activity")
    mirror_report.set_defaults(func=cmd_mirror_report)

    mirror_demo = sub.add_parser("mirror-demo", help="simulate canary traffic offline")
    mirror_demo.add_argument("--out", default="out")
    mirror_demo.set_defaults(func=cmd_mirror_demo)

    shadow_demo = sub.add_parser("shadow-demo", help="simulate Layer 3 activity offline")
    shadow_demo.add_argument("--out", default="out")
    shadow_demo.set_defaults(func=cmd_shadow_demo)

    shadow_report = sub.add_parser("shadow-report", help="Layer 3 report as JSON")
    shadow_report.set_defaults(func=cmd_shadow_report)

    approve = sub.add_parser(
        "approve", help="print the approval code for one decryption window"
    )
    approve.add_argument("blob_id")
    approve.add_argument("--minutes", type=int, default=15)
    approve.set_defaults(func=cmd_approve)

    sub.add_parser(
        "retention", help="enforce every stated expiry now"
    ).set_defaults(func=cmd_retention)

    vault_verify = sub.add_parser("vault-verify", help="recompute the evidence hash chain")
    vault_verify.set_defaults(func=cmd_vault_verify)

    rebuild_graph = sub.add_parser(
        "rebuild-graph", help="re-derive the graph from stored observations"
    )
    rebuild_graph.set_defaults(func=cmd_rebuild_graph)

    args = parser.parse_args(argv)

    # The tool audits its own draw, silently and before dispatch. Only commands
    # on the allowlist can be recorded: attention.record refuses anything else.
    from phantom import attention

    if args.command in attention.SURVEILLANCE_VIEWS:
        try:
            attention.record(args.command)
        except (ValueError, OSError):
            pass

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
