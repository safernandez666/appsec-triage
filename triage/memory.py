"""Memory — org-wide false_positive consensus over `.triage_history.jsonl`.

Consulted in the pipeline between the Truth Table and the Final Judge:

  Z2 Truth Table → forced verdict?
     ├─ yes  → skip consensus (forced wins, by spec)
     └─ no   → org-wide consensus for this CVE+package marked FP in ≥3 other repos?
              ├─ yes  → emit consensus verdict, SKIP the Judge
              └─ no   → invoke the Judge

The consensus is org-wide but EXCLUDES the current repo. We never count a
repository's own past verdict toward the consensus that decides its current
alert — that would be a self-feedback loop.

Threshold: CONSENSUS_REPO_THRESHOLD = 3 distinct other repos. Per spec.

Confidence cap: 0.93 (suave, no penaliza el consenso pero queda BAJO el
post_floor=0.95 de Tier 1 — los repos críticos terminan en needs_review por
el Critic, lo cual es defensivo apropiado: cross-repo evidence no es
sustituto de evidence local en repos críticos).

The consensus verdict is NOT final — it still flows through the Prosecutor,
which will deterministically degrade to needs_review if the evidence in THIS
repo contradicts the cross-repo claim (e.g. direct_package_hits > 0 +
vuln_apis_seen). Belt + suspenders.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from triage.types import Alert, Verdict, VerdictKind

CONSENSUS_REPO_THRESHOLD = 3
CONSENSUS_CONFIDENCE_CAP = 0.93


@dataclass(frozen=True)
class ConsensusResult:
    has_consensus: bool
    fp_repos: tuple[str, ...]       # distinct other repos that latest-marked FP
    other_repos_seen: int           # distinct other repos seen with any verdict
    avg_confidence: float           # over the fp_repos entries
    note: str                       # one-line log


def find_fp_consensus(
    alert: Alert,
    history_path: Path,
    *,
    exclude_repo: str,
    threshold: int = CONSENSUS_REPO_THRESHOLD,
) -> ConsensusResult:
    """Per-repo latest verdict for this alert's identity; count distinct other repos at FP."""
    if not history_path.exists():
        return ConsensusResult(False, (), 0, 0.0, "no history file yet")

    # repo → latest entry for this identity. We walk the file in order and
    # overwrite, so the last appearance per repo wins (append-only semantics).
    per_repo_latest: dict[str, dict] = {}
    with history_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("identity") != alert.identity:
                continue
            repo = entry.get("repo")
            if not repo or repo == exclude_repo:
                continue
            per_repo_latest[repo] = entry

    fp_repos = tuple(
        repo for repo, e in per_repo_latest.items()
        if e.get("verdict") == VerdictKind.FALSE_POSITIVE.value
    )
    other_seen = len(per_repo_latest)

    if len(fp_repos) < threshold:
        return ConsensusResult(
            has_consensus=False,
            fp_repos=fp_repos,
            other_repos_seen=other_seen,
            avg_confidence=0.0,
            note=(
                f"{len(fp_repos)} other repo(s) at false_positive "
                f"(threshold {threshold}, {other_seen} other repo(s) seen for this alert)"
            ),
        )

    confs = [float(per_repo_latest[r].get("confidence", 0.0)) for r in fp_repos]
    avg = sum(confs) / len(confs) if confs else 0.0
    return ConsensusResult(
        has_consensus=True,
        fp_repos=fp_repos,
        other_repos_seen=other_seen,
        avg_confidence=avg,
        note=f"{len(fp_repos)} other repos marked this alert false_positive",
    )


def consensus_verdict(consensus: ConsensusResult, alert: Alert) -> Verdict:
    """Materialize the FP verdict implied by org-wide consensus.

    Confidence is capped at CONSENSUS_CONFIDENCE_CAP so consensus alone cannot
    clear a tier-1 post_floor — that's intentional. Critical repos always get
    Judge + Critic + Prosecutor on the verdict, never auto-FP on hearsay.
    """
    repos_preview = ", ".join(consensus.fp_repos[:5])
    if len(consensus.fp_repos) > 5:
        repos_preview += f", and {len(consensus.fp_repos) - 5} more"
    cve = alert.cve_id or alert.ghsa_id
    confidence = min(CONSENSUS_CONFIDENCE_CAP, consensus.avg_confidence)
    return Verdict(
        kind=VerdictKind.FALSE_POSITIVE,
        confidence=confidence,
        human_conclusion=(
            f"This advisory ({cve}) for `{alert.package_name}` has been classified as a "
            f"false positive in {len(consensus.fp_repos)} other repositories in this "
            f"organization ({repos_preview}). The same classification is being applied "
            "here as the organization-wide default."
        ),
        source=f"consensus:org_wide:{len(consensus.fp_repos)}",
    )
