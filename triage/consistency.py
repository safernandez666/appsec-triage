"""Zone 3 — Consistency Gate. Anti flip-flop across runs. Pure Python.

Reads `.triage_history.jsonl` (append-only) and compares this cycle's verdict
to the last recorded verdict for the same (repo, CVE+package). Decides what
the Issue manager (Phase 10) should do:

  FIRST  no prior history for this (repo, identity) — normal post.
  SKIP   same verdict as last time — no new comment, no re-post.
  POST   verdict flipped AND new confidence is high — post the override.
  GUARD  verdict flipped AND new confidence is low — post a "please review
         before closing" guard message so a human sees the wobble.

`.triage_history.jsonl` is gitignored and append-only. Phase 11 will piggyback
on it for org-wide consensus (same CVE+package marked false_positive in ≥3
repos → default to that consensus before invoking the Judge).

REVERSAL_CONFIDENCE_FLOOR = 0.85. Same order of magnitude as the Tier 2/3
post floors — a flip below it is suspicious enough to want a human to see it
before any state mutation happens.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from triage.types import Alert, RepoProfile, Verdict

REVERSAL_CONFIDENCE_FLOOR = 0.85


class ConsistencyAction(Enum):
    FIRST = "first"   # no prior; standard post
    SKIP = "skip"     # same verdict; no new post
    POST = "post"     # confident reversal; post override
    GUARD = "guard"   # weak flip; post guard message ("please review before closing")


@dataclass(frozen=True)
class ConsistencyDecision:
    action: ConsistencyAction
    reason: str                       # plain English; safe to put in comment if posted
    prior_verdict: str | None
    prior_confidence: float | None

    @property
    def should_post(self) -> bool:
        return self.action in (ConsistencyAction.FIRST, ConsistencyAction.POST, ConsistencyAction.GUARD)


def evaluate(
    new_verdict: Verdict,
    repo: RepoProfile,
    alert: Alert,
    history_path: Path,
) -> ConsistencyDecision:
    prior = _latest_for(history_path, repo.full_name, alert.identity)
    if prior is None:
        return ConsistencyDecision(
            action=ConsistencyAction.FIRST,
            reason="first observation of this alert in this repository",
            prior_verdict=None,
            prior_confidence=None,
        )

    prior_kind = prior.get("verdict")
    try:
        prior_conf = float(prior.get("confidence", 0.0))
    except (TypeError, ValueError):
        prior_conf = 0.0
    new_kind = new_verdict.kind.value

    if prior_kind == new_kind:
        return ConsistencyDecision(
            action=ConsistencyAction.SKIP,
            reason="verdict is unchanged since the last run; no new comment posted",
            prior_verdict=prior_kind,
            prior_confidence=prior_conf,
        )

    if new_verdict.confidence >= REVERSAL_CONFIDENCE_FLOOR:
        return ConsistencyDecision(
            action=ConsistencyAction.POST,
            reason=(
                f"verdict changed from {prior_kind} to {new_kind}; the new "
                "conclusion is supported with sufficient evidence to override"
            ),
            prior_verdict=prior_kind,
            prior_confidence=prior_conf,
        )

    return ConsistencyDecision(
        action=ConsistencyAction.GUARD,
        reason=(
            f"verdict changed from {prior_kind} to {new_kind}, but the new "
            "conclusion is not strong enough to act on automatically. "
            "Please review before closing."
        ),
        prior_verdict=prior_kind,
        prior_confidence=prior_conf,
    )


def append_history(
    history_path: Path,
    repo: RepoProfile,
    alert: Alert,
    verdict: Verdict,
) -> None:
    """Append one JSON line. Append-only — never rewrite past entries."""
    entry: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "repo": repo.full_name,
        "identity": alert.identity,
        "alert_number": alert.number,
        "verdict": verdict.kind.value,
        "confidence": verdict.confidence,
        "source": verdict.source,
    }
    history_path.parent.mkdir(parents=True, exist_ok=True)
    with history_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")


def _latest_for(history_path: Path, repo_full_name: str, identity: str) -> dict | None:
    if not history_path.exists():
        return None
    latest: dict | None = None
    with history_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                # Skip malformed lines rather than aborting — history is append-only
                # and a partial line on crash should not poison future cycles.
                continue
            if entry.get("repo") == repo_full_name and entry.get("identity") == identity:
                latest = entry
    return latest
