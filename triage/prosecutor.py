"""Zone 3 — Prosecutor. Adversarial review of the verdict.

Two stages, in this order:
1. Deterministic contradiction checks (pure Python). Cheap, cannot fail, cannot
   hallucinate. If a contradiction is found, the verdict is degraded to
   needs_review and no LLM is involved.
2. Optional LLM attack: only if step 1 found nothing. The LLM is explicitly
   asked to FALSIFY the verdict from the evidence — not to confirm it.

May request a single evidence recompute. The CLI is responsible for honoring
the one-shot limit by passing `is_recomputed=True` on the second pass.

The Prosecutor NEVER promotes a verdict. It can only:
- pass it through unchanged, or
- degrade it to needs_review with a `source` that names which check fired.

That asymmetry matches the spec: needs_review is a failure state, not a hedge,
and a Prosecutor that could promote a verdict would be doing the Judge's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from triage.llm import LLMNotConfigured, chat
from triage.truth_table import TierClassification
from triage.types import Alert, EvidenceMatrix, RepoProfile, Verdict, VerdictKind


@dataclass(frozen=True)
class Contradiction:
    code: str  # discriminator for logs / source field
    why: str   # plain English, becomes part of the degraded human_conclusion


@dataclass(frozen=True)
class ProsecutorResult:
    verdict: Verdict                       # original or degraded
    contradictions: tuple[Contradiction, ...]
    attacked_by_llm: bool                  # True iff the LLM attack actually ran
    request_recompute: bool                # True iff Prosecutor wants one more pass
    note: str                              # one-line summary for logs

    @property
    def degraded(self) -> bool:
        return self.verdict.source.startswith("prosecutor:")


PROSECUTOR_SYSTEM_PROMPT = """You are an adversarial reviewer of an AppSec triage \
verdict. You will be shown a verdict and the evidence that produced it. Your job is \
to try to FALSIFY the verdict using only the evidence provided — you are explicitly \
looking for a reason the verdict is wrong.

Output strict JSON only, no prose around it:
{"found_issue": <true|false>, "argument": "<plain English, 1-2 sentences>"}

Rules:
- "found_issue": true only when you can show, from the evidence, a concrete reason
  the verdict is wrong. Vague unease is not enough.
- If you cannot falsify the verdict from the evidence, set "found_issue": false
  and "argument": "".
- The "argument" must not mention agent names, scores, or first-person voice.
- Reason only from the evidence provided. Do not invent imports, code paths,
  or APIs that are not listed."""


def prosecute(
    verdict: Verdict,
    alert: Alert,
    repo: RepoProfile,
    evidence: EvidenceMatrix,
    tier: TierClassification,
    *,
    enable_llm_attack: bool = True,
    is_recomputed: bool = False,
) -> ProsecutorResult:
    # Stage 1: deterministic checks.
    contradictions = _find_contradictions(verdict, evidence)
    if contradictions:
        return ProsecutorResult(
            verdict=_degrade(contradictions),
            contradictions=tuple(contradictions),
            attacked_by_llm=False,
            request_recompute=(not is_recomputed),
            note=f"deterministic contradictions: {[c.code for c in contradictions]}",
        )

    # Stage 2: optional LLM attack.
    if not enable_llm_attack:
        return ProsecutorResult(
            verdict=verdict,
            contradictions=(),
            attacked_by_llm=False,
            request_recompute=False,
            note="no contradictions; LLM attack disabled",
        )

    attack = _llm_attack(verdict, alert, repo, evidence, tier)
    if attack is None:
        return ProsecutorResult(
            verdict=verdict,
            contradictions=(),
            attacked_by_llm=False,
            request_recompute=False,
            note="no contradictions; LLM attack unavailable",
        )
    if not attack.found_issue:
        return ProsecutorResult(
            verdict=verdict,
            contradictions=(),
            attacked_by_llm=True,
            request_recompute=False,
            note="no contradictions; LLM attack found no issue",
        )

    c = Contradiction(code="llm_attack", why=attack.argument or "LLM attack found an issue")
    return ProsecutorResult(
        verdict=_degrade([c]),
        contradictions=(c,),
        attacked_by_llm=True,
        request_recompute=(not is_recomputed),
        note=f"LLM attack: {c.why[:80]}",
    )


def _find_contradictions(v: Verdict, em: EvidenceMatrix) -> list[Contradiction]:
    """Pure checks. Each rule is one direction only — never propose the opposite verdict."""
    out: list[Contradiction] = []
    if v.kind is VerdictKind.FALSE_POSITIVE:
        if em.direct_package_hits > 0 and em.vuln_api_hits > 0:
            out.append(Contradiction(
                code="fp_but_pkg_and_vuln_apis_used",
                why=(
                    f"The verdict is false_positive, but the code shows "
                    f"{em.direct_package_hits} references to `{em.package_name}` "
                    f"and {em.vuln_api_hits} hits on vulnerable APIs "
                    f"({list(em.vuln_apis_seen)})."
                ),
            ))
        elif em.advisory_has_specific_apis and em.vuln_apis_seen:
            out.append(Contradiction(
                code="fp_but_vuln_apis_seen",
                why=(
                    "The verdict is false_positive, but the advisory identifies "
                    f"specific vulnerable APIs and {list(em.vuln_apis_seen)} appear "
                    "in the code."
                ),
            ))
    elif v.kind is VerdictKind.REPRODUCIBLE:
        if em.direct_package_hits == 0:
            out.append(Contradiction(
                code="repro_but_no_pkg_use",
                why=(
                    f"The verdict is reproducible, but no references to "
                    f"`{em.package_name}` appear in the default branch."
                ),
            ))
        elif em.advisory_has_specific_apis and em.vuln_api_hits == 0:
            out.append(Contradiction(
                code="repro_but_no_vuln_apis",
                why=(
                    "The verdict is reproducible, but the advisory identifies specific "
                    "vulnerable APIs and none of them appear in the code."
                ),
            ))
    # NEEDS_REVIEW is never contradicted — by spec it is the failure state.
    return out


def _degrade(contradictions: list[Contradiction]) -> Verdict:
    codes = ",".join(c.code for c in contradictions)
    return Verdict(
        kind=VerdictKind.NEEDS_REVIEW,
        confidence=0.0,
        human_conclusion=(
            "The initial verdict conflicts with the evidence available, so this alert "
            "is being flagged for human review rather than auto-closed."
        ),
        source=f"prosecutor:contradiction:{codes}",
    )


# ---- LLM attack -----------------------------------------------------------


@dataclass(frozen=True)
class _LLMAttack:
    found_issue: bool
    argument: str


def _llm_attack(
    verdict: Verdict,
    alert: Alert,
    repo: RepoProfile,
    em: EvidenceMatrix,
    tier: TierClassification,
) -> _LLMAttack | None:
    try:
        raw = chat(
            messages=[
                {"role": "system", "content": PROSECUTOR_SYSTEM_PROMPT},
                {"role": "user", "content": _build_attack_payload(verdict, alert, repo, em, tier)},
            ],
            response_format={"type": "json_object"},
        )
    except LLMNotConfigured:
        return None
    except Exception:
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    found = data.get("found_issue")
    if not isinstance(found, bool):
        return None
    argument = data.get("argument", "")
    if not isinstance(argument, str):
        return None
    return _LLMAttack(found_issue=found, argument=argument.strip())


def _build_attack_payload(
    verdict: Verdict,
    alert: Alert,
    repo: RepoProfile,
    em: EvidenceMatrix,
    tier: TierClassification,
) -> str:
    advisory_apis = list(em.advisory_apis) if em.advisory_apis else "none extracted"
    vuln_apis_seen = list(em.vuln_apis_seen) if em.vuln_apis_seen else "none"
    return (
        f"VERDICT TO ATTACK: {verdict.kind.value}\n"
        f"Stated conclusion: {verdict.human_conclusion}\n"
        f"\n"
        f"Package: {alert.package_name} ({alert.package_ecosystem}/{alert.scope})\n"
        f"Advisory: {alert.ghsa_id} / {alert.cve_id or 'no CVE'}  severity={alert.severity}\n"
        f"Summary: {alert.summary}\n"
        f"Description:\n{alert.description}\n"
        f"\n"
        f"Repository: {repo.full_name}\n"
        f"  archived: {repo.archived}\n"
        f"  age in days: {repo.age_days}\n"
        f"  tier: {tier.tier.name.lower()}\n"
        f"\n"
        f"Evidence:\n"
        f"  direct package usage hits: {em.direct_package_hits}\n"
        f"  vulnerable API usage hits: {em.vuln_api_hits}\n"
        f"  vulnerable APIs seen: {vuln_apis_seen}\n"
        f"  advisory-provided vulnerable APIs: {advisory_apis}\n"
        f"  manifest present: {em.has_manifest}\n"
        f"  lockfile present: {em.has_lockfile}\n"
        f"  Dockerfile present: {em.has_dockerfile}\n"
    )
