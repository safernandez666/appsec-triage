"""Zone 3 — Critic. Silent quality gate, pure Python, never appears in the Issue.

If `verdict.confidence < tier.post_floor`, degrade to `needs_review`.
Otherwise pass the verdict through unchanged.

Rules:
- NEVER promotes. A high confidence is necessary, not sufficient — earlier
  components may already have degraded for their own reasons.
- NEVER mentions itself. `human_conclusion` of the degraded verdict is plain
  English about the repository, not "the Critic decided…". The `source` field
  carries the diagnostic but is gated behind logs and audit.
- ALREADY-needs_review verdicts are passed through. Degrading a failure state
  to itself adds noise without changing anything.

needs_review is a failure state by spec, not a comfortable hedge. The Critic
exists specifically to refuse to let a wobbly verdict auto-act.
"""
from __future__ import annotations

from triage.truth_table import TierClassification
from triage.types import Verdict, VerdictKind


def critique(verdict: Verdict, tier: TierClassification) -> Verdict:
    if verdict.kind is VerdictKind.NEEDS_REVIEW:
        return verdict
    if verdict.confidence >= tier.post_floor:
        return verdict
    return Verdict(
        kind=VerdictKind.NEEDS_REVIEW,
        confidence=0.0,
        human_conclusion=(
            "The available evidence was not strong enough to act on this alert at the "
            "level of certainty this repository requires. A human reviewer should decide."
        ),
        source=f"critic:below_floor:{tier.tier.name.lower()}",
    )
