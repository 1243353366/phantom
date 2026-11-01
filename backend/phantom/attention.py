"""The tool's own draw on the operator, and nothing else.

A counter-surveillance console has a known failure mode: checking it becomes
compulsive. Who probed the canaries, did the count move, did a grant get
requested again. The data does not change between checks, and the activity of
checking feels like work while producing none.

So the thing worth measuring is this program's own footprint on the person
running it. That is the recursive self-audit applied inward, and it is the only
usage this module can see: it counts PHANTOM's own commands, from PHANTOM's own
log, on this machine.

It deliberately has no access to screen time, app usage, unlock counts, heart
rate, or anything a device knows about its owner. Monitoring a person's behaviour
to judge their health is a different product, and one this architecture refuses:
see docs/scope.md. Counts here are not a health measurement and the summary says
so in its own output.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from phantom.config import settings

#: Views whose whole purpose is checking on something. Opening these repeatedly
#: is the loop this module exists to notice.
SURVEILLANCE_VIEWS = frozenset(
    {
        "graph",
        "exposure",
        "mirror-report",
        "shadow-report",
        "vault-verify",
        "inventory-report",
    }
)

#: Commands allowed into the log. An allowlist, because a log that accepts any
#: string is a log that can be made to hold something it should not.
KNOWN_COMMANDS = SURVEILLANCE_VIEWS | {"attention"}

DEFAULT_BUDGET = {"checks_per_day": 12, "continuous_minutes": 45}

#: A run of checking with no gap longer than this counts as one sitting. Twenty
#: minutes rather than five: the loop worth catching is an hour of drifting back
#: to the console, not only rapid-fire refreshing.
SITTING_GAP = dt.timedelta(minutes=20)


def log_path() -> Path:
    return Path(settings.home) / "attention.jsonl"


def budget_path() -> Path:
    return Path(settings.home) / "attention-budget.json"


def budget() -> dict:
    path = budget_path()
    if path.is_file():
        try:
            stored = json.loads(path.read_text(encoding="utf-8"))
            return {**DEFAULT_BUDGET, **{k: int(v) for k, v in stored.items() if k in DEFAULT_BUDGET}}
        except (json.JSONDecodeError, ValueError, TypeError):
            return dict(DEFAULT_BUDGET)
    return dict(DEFAULT_BUDGET)


def set_budget(*, checks_per_day: int | None = None, continuous_minutes: int | None = None) -> dict:
    current = budget()
    if checks_per_day is not None:
        if checks_per_day < 1:
            raise ValueError("checks_per_day must be at least 1")
        current["checks_per_day"] = checks_per_day
    if continuous_minutes is not None:
        if continuous_minutes < 1:
            raise ValueError("continuous_minutes must be at least 1")
        current["continuous_minutes"] = continuous_minutes
    path = budget_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, indent=2), encoding="utf-8")
    return current


def record(command: str, *, at: dt.datetime | None = None) -> None:
    """Append one local command. Refuses anything outside the allowlist."""
    name = (command or "").strip()
    if name not in KNOWN_COMMANDS:
        raise ValueError(
            f"attention log accepts only PHANTOM view commands, not '{name}'. "
            "Nothing was recorded."
        )
    when = at or dt.datetime.now(dt.UTC)
    path = log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"at": when.isoformat(), "command": name}) + "\n")


def entries(*, path: Path | None = None) -> list[dict]:
    target = path or log_path()
    if not target.is_file():
        return []
    rows: list[dict] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            when = dt.datetime.fromisoformat(row["at"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            continue
        # A hand-edited or legacy line can be naive. Assume UTC rather than
        # comparing naive to aware, which raises and takes the whole command down.
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.UTC)
        rows.append({"at": when, "command": str(row["command"])})
    # File order, not timestamp order: the append order is the order the operator
    # actually worked, so a clock that jumps backwards cannot rewrite the sitting.
    return rows


def _streak_minutes(rows: list[dict]) -> float:
    """Longest sitting, where a gap longer than SITTING_GAP ends it.

    Exactly SITTING_GAP is *not* a break: the threshold is a floor on what counts
    as a real gap, so a check every twenty minutes for an hour remains one sitting.
    A negative gap means the clock moved backwards; it is treated as no gap rather
    than as a break, because a clock correction is not a break in attention.
    """
    if not rows:
        return 0.0
    longest = 0.0
    low = high = previous = rows[0]["at"]
    for row in rows[1:]:
        gap = row["at"] - previous
        if gap < dt.timedelta(0):
            gap = dt.timedelta(0)
        if gap > SITTING_GAP:
            longest = max(longest, (high - low).total_seconds() / 60)
            low = high = row["at"]
        else:
            # Span the sitting by its earliest and latest look, so a clock that
            # jumps backwards cannot shorten it.
            low = min(low, row["at"])
            high = max(high, row["at"])
        previous = max(previous, row["at"])
    return round(max(longest, (high - low).total_seconds() / 60), 1)


def summary(*, now: dt.datetime | None = None) -> dict:
    """Today's own-command counts, a sitting length, and a nudge if over budget."""
    moment = now or dt.datetime.now(dt.UTC)
    limits = budget()
    # The budget day is the operator's local day, not UTC: a day that resets at
    # 03:00 local is a day nobody would recognise.
    today = [
        row for row in entries()
        if row["at"].astimezone().date() == moment.astimezone().date()
    ]

    counts: dict[str, int] = {}
    for row in today:
        counts[row["command"]] = counts.get(row["command"], 0) + 1

    checks = sum(n for name, n in counts.items() if name in SURVEILLANCE_VIEWS)
    streak = _streak_minutes(today)

    nudges: list[str] = []
    if checks > limits["checks_per_day"]:
        busiest = max(
            ((n, name) for name, n in counts.items() if name in SURVEILLANCE_VIEWS),
            default=(0, ""),
        )
        nudges.append(
            f"You have opened these views {checks} times today, past the "
            f"{limits['checks_per_day']} you set, and '{busiest[1]}' {busiest[0]} "
            "of those. Nothing here expires overnight: the canary hits and the "
            "event chain will be identical tomorrow, and re-reading them does not "
            "make you safer."
        )
    if streak > limits["continuous_minutes"]:
        nudges.append(
            f"Your longest stretch today was {streak:.0f} minutes of checking, with "
            f"no gap longer than {int(SITTING_GAP.total_seconds() // 60)} between one "
            "look and the next. Close it and do something that is not this."
        )

    return {
        "date": moment.date().isoformat(),
        "commands_today": counts,
        "checks_today": checks,
        "checks_per_day_budget": limits["checks_per_day"],
        "longest_sitting_minutes": streak,
        "continuous_minutes_budget": limits["continuous_minutes"],
        "over_budget": bool(nudges),
        "nudges": nudges,
        "note": (
            "These are counts of your own commands on this machine, kept in "
            "attention.jsonl next to your graph. A breach means a threshold you "
            "configured was crossed. It is not a diagnosis, it is not a measure of "
            "severity, and it does not mean there is a problem. This module has no "
            "access to anything outside PHANTOM: no screen time, no app usage, no "
            "other person."
        ),
    }
