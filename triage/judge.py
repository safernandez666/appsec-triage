"""Zone 3 — Final Judge. LLM, strict JSON contract, temperature=0.

Returns a `Verdict` in {false_positive, reproducible, needs_review} with a
`confidence` in [0,1] and a `human_conclusion` written for the humans reading
the Issue, not for ops chasing logs.

Three blocks defend the contract:
1. The system prompt narrows the response shape and forbids scores / agent
   names / first-person voice in `human_conclusion`.
2. `response_format={"type":"json_object"}` is requested upstream.
3. `_parse_response` validates every field and rejects anything that doesn't
   fit. Malformed output → `needs_review` fallback. We never coerce a
   close-but-wrong response into a verdict.

needs_review is a failure state, by spec. The Judge never returns it as a
hedge; only the fallback paths emit it (no LLM / call failed / malformed).
The Critic (Phase 9) may degrade an honest Judge verdict to needs_review when
confidence falls below the tier floor — that's a separate concern handled
elsewhere.
"""
from __future__ import annotations

import json
from typing import Any

from triage.llm import LLMNotConfigured, chat
from triage.truth_table import TierClassification
from triage.types import Alert, EvidenceMatrix, RepoProfile, Verdict, VerdictKind

JUDGE_SYSTEM_PROMPT = """You are a defensive AppSec triage judge. You receive \
evidence about a Dependabot alert in a specific repository and return a verdict.

CONTRACT — strict JSON only, no prose around it:
{
  "verdict": "false_positive" | "reproducible" | "needs_review",
  "confidence": <number between 0 and 1>,
  "human_conclusion": "<plain English, 1 to 3 sentences>"
}

VERDICT MEANINGS:
- "false_positive": the alert does NOT affect this repository (vulnerable code
  path unreachable, package unused, the specific API in question is not called).
- "reproducible": the alert DOES affect this repository — the vulnerable code
  path can be reached.
- "needs_review": evidence is genuinely insufficient to decide. This is a
  failure state, not a comfortable hedge. Prefer it only when the evidence
  is ambiguous and a wrong call either way would mislead the team.

HUMAN_CONCLUSION RULES (hard constraints):
- Plain English, 1 to 3 sentences.
- No numbers, no scores, no confidence values.
- No agent names ("Evidence Agent", "Truth Table", "Advisory Agent" — never).
- No first person ("I", "we", "the model").
- Speak about the repository and the alert directly.
- Justify the verdict with the concrete facts you were given.

REASONING RULES:
- Reason only from the evidence provided. Do not invent imports, code paths,
  or APIs not listed in the evidence.
- Code search only indexes the default branch and files smaller than 384 KB —
  absence of hits is suggestive, not proof.
- If something that would change your verdict is missing from the evidence,
  return "needs_review"."""


def judge(
    alert: Alert,
    repo: RepoProfile,
    evidence: EvidenceMatrix,
    tier: TierClassification,
) -> Verdict:
    """Produce a Verdict. Always returns one — fallback paths emit needs_review."""
    try:
        content = chat(
            messages=[
                {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_payload(alert, repo, evidence, tier)},
            ],
            response_format={"type": "json_object"},
        )
    except LLMNotConfigured:
        return _fallback("llm_not_configured")
    except Exception as e:
        return _fallback(f"llm_call_failed:{type(e).__name__}")

    parsed = _parse_response(content)
    if parsed is None:
        return _fallback("malformed_response")
    return parsed


def _build_user_payload(
    alert: Alert,
    repo: RepoProfile,
    em: EvidenceMatrix,
    tier: TierClassification,
) -> str:
    cve = alert.cve_id or "no CVE"
    advisory_apis = list(em.advisory_apis) if em.advisory_apis else "none extracted"
    vuln_apis_seen = list(em.vuln_apis_seen) if em.vuln_apis_seen else "none"
    return (
        f"Package: {alert.package_name} ({alert.package_ecosystem}/{alert.scope})\n"
        f"Advisory: {alert.ghsa_id} / {cve}  severity={alert.severity}\n"
        f"Summary: {alert.summary}\n"
        f"Description:\n{alert.description}\n"
        f"\n"
        f"Repository: {repo.full_name}\n"
        f"  archived: {repo.archived}\n"
        f"  primary language: {repo.language or 'unknown'}\n"
        f"  age in days: {repo.age_days}\n"
        f"  tier: {tier.tier.name.lower()}\n"
        f"\n"
        f"Evidence (counts and booleans only, no interpretation):\n"
        f"  direct package usage hits in default branch: {em.direct_package_hits}\n"
        f"  vulnerable API usage hits: {em.vuln_api_hits}\n"
        f"  specific vulnerable APIs seen in code: {vuln_apis_seen}\n"
        f"  advisory-provided vulnerable APIs: {advisory_apis}\n"
        f"  manifest present ({alert.manifest_path or 'unspecified'}): {em.has_manifest}\n"
        f"  lockfile present: {em.has_lockfile}\n"
        f"  Dockerfile present: {em.has_dockerfile}\n"
    )


def _parse_response(text: str) -> Verdict | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    verdict_str = data.get("verdict")
    if not isinstance(verdict_str, str):
        return None
    try:
        kind = VerdictKind(verdict_str)
    except ValueError:
        return None
    confidence_raw: Any = data.get("confidence")
    if isinstance(confidence_raw, bool) or not isinstance(confidence_raw, (int, float)):
        return None
    confidence = float(confidence_raw)
    if not (0.0 <= confidence <= 1.0):
        return None
    conclusion = data.get("human_conclusion")
    if not isinstance(conclusion, str):
        return None
    conclusion = conclusion.strip()
    if not conclusion:
        return None
    return Verdict(
        kind=kind,
        confidence=confidence,
        human_conclusion=conclusion,
        source="judge",
    )


def _fallback(reason: str) -> Verdict:
    """needs_review with a debug-friendly source and a human-friendly conclusion.

    `human_conclusion` is what humans will see on the Issue — it must obey the
    no-internals rule. `source` carries the diagnostic, gated behind logs.
    """
    return Verdict(
        kind=VerdictKind.NEEDS_REVIEW,
        confidence=0.0,
        human_conclusion=(
            "The available evidence was not sufficient to deliver a verdict on this alert. "
            "A human reviewer should decide."
        ),
        source=f"judge:fallback:{reason}",
    )
