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

from phantom.db import get_session, init_db
from phantom.engine.graph import to_cytoscape
from phantom.engine.relationship_engine import RelationshipEngine
from phantom.collector.headers import parse_eml


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
            gmail_address=args.gmail,
            phone_number=args.phone,
            work_email=args.work_email,
            consent_gmail=args.consent_gmail,
            consent_phone=args.consent_phone,
            consent_work_email=args.consent_work_email,
            ttl_days=args.ttl_days,
        )
    except ConsentError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(ConsentService(session).view(record), indent=2))
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
    enroll.add_argument("--ttl-days", type=int, default=365)
    enroll.set_defaults(func=cmd_enroll)

    canary = sub.add_parser("canary", help="mint a canary token and print its URL")
    canary.add_argument("--label", required=True, help="where this canary is placed")
    canary.add_argument("--note", default="")
    canary.set_defaults(func=cmd_canary)

    mirror_report = sub.add_parser("mirror-report", help="report on canary activity")
    mirror_report.set_defaults(func=cmd_mirror_report)

    mirror_demo = sub.add_parser("mirror-demo", help="simulate canary traffic offline")
    mirror_demo.add_argument("--out", default="out")
    mirror_demo.set_defaults(func=cmd_mirror_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
