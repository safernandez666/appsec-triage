"""Zone 1 — Routing. Fast-paths that bypass the LLM entirely.

Two reasons to fast-path:
1. The alert is already resolved upstream (`state in {fixed, dismissed, auto_dismissed}`)
   — produce a 1-line close note, no Zone 2/3.
2. The fetch itself failed — emit an error note at the call site (cli.py wraps
   the GitHub calls in try/except). That branch lives in cli.py because it is
   per-cycle, not per-alert.

Routing returns a structured decision; the caller decides whether to print, post
as Issue comment, or hand off to Zone 2. Keeping the side-effect out of here
makes it trivial to unit-test in later phases.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from triage.types import Alert

# Dependabot states that we treat as "already resolved upstream" — no triage
# work to do. Includes `auto_dismissed` for alerts that GitHub itself dismissed
# (e.g. because the affected version range no longer matches the lockfile).
RESOLVED_STATES = frozenset({"fixed", "dismissed", "auto_dismissed"})


# ---- v2 extension hooks (not wired in v1) ----------------------------------
#
# CodeQL alerts: add a sibling resolution table — code-scanning alerts have
#   their own state vocabulary ("open", "dismissed", "fixed", "auto_dismissed").
#   The fast-path semantics are the same: anything non-open closes the Issue
#   with a one-line note. Extend with a `CodeScanningRoute.route(alert)` that
#   shares this module's RoutingDecision shape.
#
# Secret scanning alerts: SHORT-CIRCUIT before this router. A fresh secret
#   scanning alert needs a "rotate now" Issue with the leak location, no Zone 2,
#   no Zone 3, no LLM. Different risk model: there is no "is it reproducible?"
#   question — a leaked secret is leaked. Auto-transition is permanently OFF
#   for this source; humans must confirm rotation.
# ---------------------------------------------------------------------------


class FastPath(Enum):
    CLOSE_ALREADY_RESOLVED = "close_already_resolved"
    CONTINUE = "continue"


@dataclass(frozen=True)
class RoutingDecision:
    path: FastPath
    note: str  # one-line summary; becomes the Issue comment body when CLOSE_*

    @property
    def is_fast_path(self) -> bool:
        return self.path is not FastPath.CONTINUE


def route(alert: Alert) -> RoutingDecision:
    if alert.state in RESOLVED_STATES:
        return RoutingDecision(
            path=FastPath.CLOSE_ALREADY_RESOLVED,
            note=f"Alert is already `{alert.state}` upstream; closing without triage.",
        )
    return RoutingDecision(path=FastPath.CONTINUE, note="")
