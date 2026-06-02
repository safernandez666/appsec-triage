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
from triage.types import Alert, AlertSource, EvidenceMatrix, RepoProfile, Verdict, VerdictKind


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
verdict on a DEPENDABOT (vulnerable dependency) finding. You will be shown a \
verdict and the evidence that produced it. Your job is to try to FALSIFY the \
verdict using only the evidence provided — you are explicitly looking for a \
reason the verdict is wrong.

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


PROSECUTOR_SYSTEM_PROMPT_CODE_SCANNING = """You are an adversarial reviewer of an \
AppSec triage verdict on a CODE SCANNING finding (CodeQL or other SAST). You will \
be shown the rule_id, the file path + line, and the verdict reasoning. Your job \
is to try to FALSIFY the verdict — find a CONCRETE reason it is wrong.

Output strict JSON only, no prose around it:
{"found_issue": <true|false>, "argument": "<plain English, 1-2 sentences>"}

Rules:
- "found_issue": true only when you can show a CONCRETE reason the verdict is
  wrong. Vague unease ("might not be exploitable") is not enough.
- DO NOT use "no reachability evidence" or "absence of package usage" as an
  argument. Code-scanning findings have no package — that line of reasoning is
  structurally meaningless for this source.
- Legitimate attack angles (use these when applicable):
  * VENDORED THIRD-PARTY code paths: `/node_modules/`, `/vendor/`,
    `/third_party/`, `/dist/`, `/build/`, files ending in `.min.js`,
    bundled libraries like `bootstrap-*.js`, `jquery-*.js`, `lodash-*.js`.
    The repo did not author this code, so a `reproducible` verdict on
    library internals is often a vendor-side issue, not application risk.
  * GENERATED or COMPILED output: `.min.`, `.bundle.`, sourcemap-adjacent
    files, anything obviously machine-emitted.
  * The rule_id is one known for high false-positive rates on library
    code (e.g. `js/xss-through-dom` against any DOM-manipulation library
    that uses `.html()` legitimately).
  * The verdict's stated reasoning is internally inconsistent with the
    file path or rule shown.
- If none of these apply and you cannot falsify the verdict, set
  "found_issue": false and "argument": "".
- The "argument" must not mention agent names, scores, or first-person voice."""


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
    contradictions = _find_contradictions(verdict, evidence, alert)
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
    # Recompute only makes sense when there's new evidence to gather. The
    # online Evidence agent calls `/search/code` only for Dependabot alerts;
    # for code-scanning and secret-scanning the EvidenceMatrix is constant
    # by construction (no package, no advisory APIs to extract). Asking for
    # a recompute on those sources doubles the token spend and produces the
    # same verdict, then the same LLM-attack contradiction. The decision was
    # only ever useful for Dependabot.
    can_recompute = (
        not is_recomputed and alert.source is AlertSource.DEPENDABOT
    )
    return ProsecutorResult(
        verdict=_degrade([c]),
        contradictions=(c,),
        attacked_by_llm=True,
        request_recompute=can_recompute,
        note=f"LLM attack: {c.why[:80]}",
    )


def _find_contradictions(
    v: Verdict, em: EvidenceMatrix, alert: Alert
) -> list[Contradiction]:
    """Pure checks. Each rule is one direction only — never propose the opposite verdict.

    All deterministic rules below reason about *package use* in the default
    branch (`direct_package_hits`, `vuln_api_hits`, `vuln_apis_seen`). That
    concept is Dependabot-specific. Code-scanning alerts identify a code
    location, not a package, and the EvidenceMatrix produced for them is
    intentionally empty — applying these rules to a code-scanning verdict
    would, for example, degrade *every* code-scanning `reproducible` to
    `needs_review` because `direct_package_hits == 0` is always true.
    The LLM-attack stage (downstream in `prosecute()`) still runs for all
    sources, so adversarial review is not lost — only the package-use rules
    are scoped.
    """
    out: list[Contradiction] = []
    if alert.source is not AlertSource.DEPENDABOT:
        return out
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
    # Dispatch system prompt + user payload by source. The Dependabot
    # prompt reasons about package usage and advisory APIs; that frame
    # is structurally empty for code-scanning, so a different prompt
    # asks for a different class of contradiction (vendored paths,
    # generated files, rule_id false-positive patterns).
    if alert.source is AlertSource.CODE_SCANNING:
        system_prompt = PROSECUTOR_SYSTEM_PROMPT_CODE_SCANNING
        user_payload = _build_attack_payload_code_scanning(verdict, alert, repo, tier)
    else:
        system_prompt = PROSECUTOR_SYSTEM_PROMPT
        user_payload = _build_attack_payload(verdict, alert, repo, em, tier)
    try:
        raw = chat(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_payload},
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


def _build_attack_payload_code_scanning(
    verdict: Verdict,
    alert: Alert,
    repo: RepoProfile,
    tier: TierClassification,
) -> str:
    """Code-scanning-specific payload.

    Deliberately omits Dependabot-only fields (package, advisory APIs,
    /search/code hit counts) — keeping them around just confuses the
    LLM into using "all zero" as a contradiction. Includes the path
    prominently because that's where most legitimate FP attacks come
    from (vendored libraries, generated files).
    """
    loc = f"{alert.location_path or '?'}"
    if alert.location_line is not None:
        loc = f"{loc}:{alert.location_line}"
    return (
        f"VERDICT TO ATTACK: {verdict.kind.value}\n"
        f"Stated conclusion: {verdict.human_conclusion}\n"
        f"\n"
        f"Rule: {alert.rule_id or '?'}\n"
        f"Location: {loc}\n"
        f"Severity: {alert.severity}\n"
        f"Summary: {alert.summary}\n"
        f"Description:\n{alert.description}\n"
        f"\n"
        f"Repository: {repo.full_name}\n"
        f"  default branch: {repo.default_branch}\n"
        f"  language: {repo.language or 'unknown'}\n"
        f"  archived: {repo.archived}\n"
        f"  tier: {tier.tier.name.lower()}\n"
    )
