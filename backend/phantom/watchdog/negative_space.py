"""Negative Space Analysis.

The premise: what stops appearing is data too. This module records
disappearances, shortenings and changes as *observations*, and tags every one of
them ``cause_unknown``. It never concludes that tracking stopped, because it
cannot see why an observation ended - the sender may have cleaned up, or moved
to something less visible, or the mail simply failed to load.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.models import Edge, Evidence, NegativeSpaceEvent

CHANGES = (
    "tracker_disappeared",
    "redirect_chain_shortened",
    "redirect_chain_lengthened",
    "infrastructure_switched",
    "domain_reappeared",
)


class NegativeSpaceWatchdog:
    def __init__(self, session: Session) -> None:
        self.session = session

    def _events(self) -> list[Evidence]:
        rows = self.session.execute(
            select(Evidence, Edge).join(Edge, Evidence.edge_id == Edge.id)
        ).all()
        return [(ev, edge) for ev, edge in rows]

    def scan(self, subject_key: str | None = None) -> list[NegativeSpaceEvent]:
        rows = self._events()
        if subject_key:
            rows = [(ev, e) for ev, e in rows if e.src_key == subject_key]

        # Timeline per sender: which message refs, when, and what each carried.
        timeline: dict[str, dict[str, dict]] = defaultdict(dict)
        for ev, edge in rows:
            if not edge.src_key.startswith("org:"):
                continue
            ref = ev.payload.get("message_ref")
            at_raw = ev.payload.get("sent_at")
            if not ref or not at_raw:
                continue
            try:
                at = dt.datetime.fromisoformat(at_raw)
            except ValueError:
                continue
            slot = timeline[edge.src_key].setdefault(
                ref, {"at": at, "targets": {}, "chain": None}
            )
            slot["targets"].setdefault(edge.dst_key, []).append(ev)
            chain = ev.payload.get("chain_length")
            if isinstance(chain, int):
                slot["chain"] = max(slot["chain"] or 0, chain)

        found: list[NegativeSpaceEvent] = []
        for org_key, messages in timeline.items():
            ordered = sorted(messages.items(), key=lambda kv: kv[1]["at"])
            if len(ordered) < 2:
                continue
            for i in range(1, len(ordered)):
                prev_ref, prev = ordered[i - 1]
                cur_ref, cur = ordered[i]
                prev_t, cur_t = prev["targets"], cur["targets"]

                for target in sorted(set(prev_t) - set(cur_t)):
                    found.append(
                        self._emit(
                            org_key, target, "tracker_disappeared", prev["at"], cur["at"],
                            before_value=prev_ref, after_value=cur_ref,
                            note=(
                                f"Observed in {prev_ref} but not in {cur_ref}. "
                                "Recorded as an absence only."
                            ),
                        )
                    )
                for target in sorted(set(cur_t) - set(prev_t)):
                    found.append(
                        self._emit(
                            org_key, target, "domain_reappeared", prev["at"], cur["at"],
                            before_value=prev_ref, after_value=cur_ref,
                            note=f"First appears in {cur_ref} relative to the previous message.",
                        )
                    )

                if isinstance(prev.get("chain"), int) and isinstance(cur.get("chain"), int):
                    if cur["chain"] < prev["chain"]:
                        found.append(
                            self._emit(
                                org_key, "redirect_chain", "redirect_chain_shortened",
                                prev["at"], cur["at"],
                                before_value=str(prev["chain"]), after_value=str(cur["chain"]),
                                note="Fewer redirect hops than the previous message.",
                            )
                        )
                    elif cur["chain"] > prev["chain"]:
                        found.append(
                            self._emit(
                                org_key, "redirect_chain", "redirect_chain_lengthened",
                                prev["at"], cur["at"],
                                before_value=str(prev["chain"]), after_value=str(cur["chain"]),
                                note="More redirect hops than the previous message.",
                            )
                        )

        for ev in found:
            self.session.add(ev)
        self.session.commit()
        return found

    def _emit(self, subject, node_key, change, w_from, w_to, *, before_value, after_value, note):
        return NegativeSpaceEvent(
            subject_key=subject,
            node_key=node_key,
            change=change,
            window_from=w_from,
            window_to=w_to,
            before_value=before_value,
            after_value=after_value,
            cause_unknown=True,
            note=note,
        )

    def report(self) -> dict:
        events = list(self.session.scalars(select(NegativeSpaceEvent)))
        by_change: dict[str, int] = defaultdict(int)
        for e in events:
            by_change[e.change] += 1
        return {
            "total": len(events),
            "by_change": dict(by_change),
            "events": [
                {
                    "subject": e.subject_key,
                    "node": e.node_key,
                    "change": e.change,
                    "window_from": e.window_from.isoformat(),
                    "window_to": e.window_to.isoformat(),
                    "before": e.before_value,
                    "after": e.after_value,
                    "cause_unknown": e.cause_unknown,
                    "note": e.note,
                }
                for e in sorted(events, key=lambda x: x.window_to, reverse=True)
            ],
            "interpretation": (
                "Every entry here is an observation of absence. PHANTOM cannot see "
                "why something stopped appearing, so it does not claim that it did."
            ),
        }
