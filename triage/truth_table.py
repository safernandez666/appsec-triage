"""Zone 2 — Pre-flight Truth Table. Pure Python, no LLM.

Two jobs:
1. Classify the repo into a Tier (1 critical, 2 deployed, 3 internal, 4 archived)
   and fix the confidence floors that downstream agents read:
     - `post_floor`: minimum confidence to post a verdict at face value;
       below it, the Critic (Phase 9) degrades to needs_review.
     - `transition_floor`: minimum confidence to auto-dismiss the alert.
       Tier 1 sets this to +∞ — the non-negotiable guardrail. Issue manager
       (Phase 10) checks `confidence >= transition_floor` before dismissing,
       so the guardrail is enforced by the float, not by a separate if.

2. Try to FORCE a verdict without invoking the LLM. Two rules:
     A) `archived AND direct_code_hits == 0` → false_positive
        Archived + zero usage = the vulnerable code path cannot run here.
     B) `advisory_has_specific_apis AND direct_code_hits == 0 AND
         (repo_active OR age_days >= 180)` → false_positive
        Absence of evidence as evidence: when the advisory tells us exactly
        which APIs to look for and they are nowhere in the default branch of
        a repo whose default branch is representative (active, or simply old
        enough that it stabilized), absence stops being noise.

If neither rule fires, `forced_verdict=None` and the alert continues to the
Final Judge (Phase 7).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from triage.types import Alert, AlertSource, EvidenceMatrix, RepoProfile, Tier, Verdict, VerdictKind

# v2: heuristic test-path detector. Conservative — matches the conventional
# layouts only. Edge cases (e.g. tests embedded inside a package using
# `_test.py` suffix) get caught downstream by the Judge.
_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|e2e)(/|$)",
    re.IGNORECASE,
)

# (post_floor, transition_floor) per tier.
# Transition for CRITICAL is +inf — auto-dismiss is structurally impossible.
TIER_FLOORS: dict[Tier, tuple[float, float]] = {
    Tier.CRITICAL: (0.95, float("inf")),
    Tier.DEPLOYED: (0.85, 0.95),
    Tier.INTERNAL: (0.75, 0.85),
    Tier.ARCHIVED: (0.60, 0.70),
}

# Repo is "active enough" for absence-as-evidence to be meaningful.
ACTIVE_AGE_DAYS = 180


@dataclass(frozen=True)
class TierClassification:
    tier: Tier
    post_floor: float
    transition_floor: float
    reason: str  # plain-English why this tier was assigned

    @classmethod
    def for_tier(cls, tier: Tier, reason: str) -> "TierClassification":
        post, transition = TIER_FLOORS[tier]
        return cls(tier=tier, post_floor=post, transition_floor=transition, reason=reason)


@dataclass(frozen=True)
class TruthTableResult:
    tier: TierClassification
    forced_verdict: Verdict | None  # None → continue to Final Judge

    @property
    def forced(self) -> bool:
        return self.forced_verdict is not None


def classify_tier(
    repo: RepoProfile,
    evidence: EvidenceMatrix,
    tier_override: Tier | None = None,
) -> TierClassification:
    """Pick a Tier from repo signals plus an optional explicit override.

    Order:
      1. `archived` always wins → Tier 4. Even if someone overrides to tier 1,
         an archived repo cannot meaningfully be customer-facing.
      2. `tier_override`, when given (from config / fixture / topic), is used.
         This is how `Tier 1` actually gets set — there is no automatic
         heuristic for "customer-facing" that does not produce false positives.
      3. Has Dockerfile → Tier 2 (deployed).
      4. Otherwise → Tier 3 (internal).
    """
    if repo.archived:
        return TierClassification.for_tier(Tier.ARCHIVED, reason="repo.archived = true")
    if tier_override is not None:
        return TierClassification.for_tier(
            tier_override,
            reason=f"explicit tier_override = {tier_override.name}",
        )
    if evidence.has_dockerfile:
        return TierClassification.for_tier(
            Tier.DEPLOYED,
            reason="Dockerfile present in default branch → deployed surface",
        )
    return TierClassification.for_tier(
        Tier.INTERNAL,
        reason="no deploy artifacts and no override → internal",
    )


def preflight(
    alert: Alert,
    repo: RepoProfile,
    evidence: EvidenceMatrix,
    tier_override: Tier | None = None,
) -> TruthTableResult:
    tier = classify_tier(repo, evidence, tier_override)
    # v2: dispatch by source — Dependabot and CodeQL have different forcing rules.
    # Secret scanning never reaches here (Z1 short-circuits in v2-4).
    if alert.source is AlertSource.CODE_SCANNING:
        forced = _try_force_code_scanning_verdict(alert, repo)
    else:
        forced = _try_force_dependabot_verdict(repo, evidence)
    return TruthTableResult(tier=tier, forced_verdict=forced)


def _try_force_code_scanning_verdict(alert: Alert, repo: RepoProfile) -> Verdict | None:
    """v2 — CodeQL / code-scanning forcing rules.

    Rule C — `location_path` matches a test directory → `false_positive`. A
        SAST finding inside a test file describes a vulnerability that lives
        in test scaffolding, not in runtime code. The dismiss reason for CodeQL
        will be `used in tests` (see issue_manager._dismiss_reason).

    Rule D — `archived AND state == "open"` → `false_positive`. Analogous to
        Dependabot's Rule A: an archived repo cannot be exploited even if the
        rule still flags it.
    """
    # Rule C: location in tests/
    if alert.location_path and _TEST_PATH_RE.search(alert.location_path):
        return Verdict(
            kind=VerdictKind.FALSE_POSITIVE,
            confidence=0.92,
            human_conclusion=(
                f"The CodeQL finding at `{alert.location_path}` is inside a test "
                "directory. The vulnerability described by this rule cannot be "
                "exercised from production runtime; it lives in test scaffolding."
            ),
            source="truth_table:codeql_in_tests",
        )
    # Rule D: archived repo
    if repo.archived:
        return Verdict(
            kind=VerdictKind.FALSE_POSITIVE,
            confidence=0.93,
            human_conclusion=(
                f"This finding lives in `{repo.full_name}`, an archived repository. "
                "Code in archived repos is not deployed or executed; the finding "
                "cannot be exploited from any live surface."
            ),
            source="truth_table:codeql_archived",
        )
    return None


def _try_force_dependabot_verdict(repo: RepoProfile, evidence: EvidenceMatrix) -> Verdict | None:
    # Rule A — archived + no direct code hits.
    if repo.archived and evidence.direct_package_hits == 0:
        return Verdict(
            kind=VerdictKind.FALSE_POSITIVE,
            confidence=0.95,
            human_conclusion=(
                f"Repository is archived and contains no usage of `{evidence.package_name}` "
                "in the default branch. The vulnerable code path cannot run here."
            ),
            source="truth_table:archived_no_hits",
        )
    # Rule B — advisory pinpoints APIs + none of them (and no package usage)
    # show up, and the default-branch view is representative.
    if evidence.advisory_has_specific_apis and evidence.direct_package_hits == 0:
        if not repo.archived or repo.age_days >= ACTIVE_AGE_DAYS:
            apis = ", ".join(evidence.advisory_apis)
            why_representative = (
                "the repository is active"
                if not repo.archived
                else f"the repository is {repo.age_days} days old"
            )
            return Verdict(
                kind=VerdictKind.FALSE_POSITIVE,
                confidence=0.90,
                human_conclusion=(
                    f"The advisory identifies specific vulnerable APIs ({apis}), and none of "
                    f"them — nor any other reference to `{evidence.package_name}` — appears "
                    f"in the default branch. Because {why_representative}, the absence is "
                    "treated as evidence rather than noise."
                ),
                source="truth_table:advisory_apis_no_hits",
            )
    return None
