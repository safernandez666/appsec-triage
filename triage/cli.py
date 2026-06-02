"""CLI dispatch.

Phase 3 scope: per-alert Zone 1 routing (`triage.routing.route`) + per-fetch
error notes when the GitHub fetch fails (the second Z1 fast-path).

Exit codes:
    0  ok
    1  no fixtures / empty input
    2  argument or auth error
    3  fetch error (Z1 fast-path: error note)
"""
from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from triage.advisory_agent import AdvisoryResult, extract_vulnerable_apis
from triage.banner import print_banner
from triage import colors as col
from triage.config import TierConfig, load_config
from triage.env_loader import load_dotenv
from triage.consistency import (
    ConsistencyAction,
    ConsistencyDecision,
    append_history,
    evaluate as evaluate_consistency,
)
from triage.critic import critique
from triage.evidence_agent import (
    collect_evidence_offline,
    collect_evidence_online,
    empty_evidence_for_non_dependabot,
)
from triage.github_client import GitHubClient, OfflineGitHubClient, RepoAlertSet
from triage.issue_manager import (
    CycleFlags,
    ISSUE_LABEL,
    IssueAction,
    handle as handle_issue,
    handle_fast_path_close,
)
from triage.judge import judge
from triage.memory import ConsensusResult, consensus_verdict, find_fp_consensus
from triage.prosecutor import ProsecutorResult, prosecute
from triage.routing import FastPath, route
from triage.secret_scanning import build_rotate_now_verdict
from triage.truth_table import TierClassification, TruthTableResult, preflight
from triage.types import Alert, AlertSource, EvidenceMatrix, RepoProfile, Tier, Verdict

# v2: --sources flag accepts these string tokens.
_SOURCE_BY_TOKEN: dict[str, AlertSource] = {
    "dependabot": AlertSource.DEPENDABOT,
    "code-scanning": AlertSource.CODE_SCANNING,
    "codeql": AlertSource.CODE_SCANNING,  # ergonomic alias
    "secret-scanning": AlertSource.SECRET_SCANNING,
    "secret": AlertSource.SECRET_SCANNING,  # ergonomic alias
}
ALL_SOURCES: frozenset[AlertSource] = frozenset(AlertSource)


def _parse_sources(arg: str) -> frozenset[AlertSource]:
    """Parse `--sources` value into a concrete set.

    Accepts `all`, a single token, or a comma-separated list. Unknown tokens
    are rejected with a clear error so typos do not silently degrade to
    "Dependabot only" behavior.
    """
    arg = (arg or "").strip().lower()
    if not arg or arg == "all":
        return ALL_SOURCES
    out: set[AlertSource] = set()
    unknown: list[str] = []
    for token in (t.strip() for t in arg.split(",")):
        if not token:
            continue
        if token in _SOURCE_BY_TOKEN:
            out.add(_SOURCE_BY_TOKEN[token])
        else:
            unknown.append(token)
    if unknown:
        valid = sorted(set(_SOURCE_BY_TOKEN) | {"all"})
        raise ValueError(f"unknown --sources token(s) {unknown!r}; valid: {valid}")
    if not out:
        return ALL_SOURCES
    return frozenset(out)

def _resolve_fixtures_dir() -> Path:
    """Find fixtures/alerts/ across install layouts.

    - Editable install (`pip install -e .`): triage/cli.py is in <repo>/triage/,
      so fixtures live one level up at <repo>/fixtures/alerts/.
    - Non-editable install (`pip install .`): the package lives under
      site-packages/triage/, but the user usually invokes `appsec-triage --offline`
      from a checkout. Fall back to cwd/fixtures/alerts.
    - If neither exists, return the editable-install path so the error message
      ("no fixtures found under …") points at the conventional spot.
    """
    pkg_adjacent = Path(__file__).resolve().parent.parent / "fixtures" / "alerts"
    cwd_adjacent = Path.cwd() / "fixtures" / "alerts"
    for candidate in (pkg_adjacent, cwd_adjacent):
        if candidate.exists():
            return candidate
    return pkg_adjacent


def _resolve_history_path() -> Path:
    """`.triage_history.jsonl` follows the fixtures: editable install → repo root,
    non-editable → cwd. The Issue manager mutates this file; in CI it is uploaded
    as an artifact for audit (see the workflow)."""
    pkg_root = Path(__file__).resolve().parent.parent
    if (pkg_root / "fixtures" / "alerts").exists():
        return pkg_root / ".triage_history.jsonl"
    return Path.cwd() / ".triage_history.jsonl"


FIXTURES_DIR = _resolve_fixtures_dir()
HISTORY_PATH = _resolve_history_path()


# ---- Output verbosity -----------------------------------------------------
#
# Three levels, set once in main() by -v / -q flags:
#   - QUIET   : alert details suppressed; only banner + repo header + summary
#   - NORMAL  : one condensed line per alert + summary (default)
#   - VERBOSE : full Z1 → Z2 → Z3 → Z4 tree per alert (the debug view)
#
# Module-global because the CLI processes one cycle per process; passing
# a verbosity arg through every formatter call adds noise without value.

class _OutputLevel(Enum):
    QUIET = "quiet"
    NORMAL = "normal"
    VERBOSE = "verbose"


_LEVEL: _OutputLevel = _OutputLevel.NORMAL

# Loaded once in main() from `.appsec-triage.toml` in cwd. Empty when
# the file is absent, which means every repo falls back to the Truth
# Table's heuristic tier classification.
_TIER_CONFIG: TierConfig = TierConfig(by_repo={})


def _vprint(*args: object, **kwargs: object) -> None:
    """Print only in VERBOSE mode (debug-style Z1-Z4 tree)."""
    if _LEVEL is _OutputLevel.VERBOSE:
        print(*args, **kwargs)  # type: ignore[arg-type]


def _nprint(*args: object, **kwargs: object) -> None:
    """Print at NORMAL or VERBOSE — i.e. anything that isn't quiet-only."""
    if _LEVEL is not _OutputLevel.QUIET:
        print(*args, **kwargs)  # type: ignore[arg-type]


# ---- Summary tally --------------------------------------------------------
#
# Module-level mutable counters reset at the start of every `_route_and_print`
# call. The CLI runs one cycle per process so there is no contention; the
# tradeoff is one global vs. plumbing a Summary object through five frames.
# We choose the global for surface-area minimality.

_VERDICT_COUNTS: dict[str, int] = {}
_ACTION_COUNTS: dict[str, int] = {}


def _reset_summary() -> None:
    _VERDICT_COUNTS.clear()
    _ACTION_COUNTS.clear()


def _tally_verdict(v: Verdict) -> None:
    _VERDICT_COUNTS[v.kind.value] = _VERDICT_COUNTS.get(v.kind.value, 0) + 1


def _tally_action(ia: IssueAction) -> None:
    """Tally compound kinds (`create+dismissed`, `comment+nodismiss`, …)
    into separate primary and dismiss buckets so the summary stays a
    flat breakdown instead of a cartesian product."""
    parts = ia.kind.split("+", 1)
    primary = parts[0]
    _ACTION_COUNTS[primary] = _ACTION_COUNTS.get(primary, 0) + 1
    if len(parts) > 1 and parts[1] == "dismissed":
        _ACTION_COUNTS["dismiss"] = _ACTION_COUNTS.get("dismiss", 0) + 1


def _fmt_summary(prefix: str = "[cycle]") -> str:
    """Render verdict and action counters as two aligned, colored lines."""
    v_order = ("false_positive", "reproducible", "needs_review", "rotate_now")
    a_order = ("create", "comment", "skip", "close", "dismiss", "blocked")
    v_parts = [
        f"{n} {col.verdict(k, k, strong=False)}"
        for k in v_order
        if (n := _VERDICT_COUNTS.get(k, 0)) or k in _VERDICT_COUNTS
    ]
    if not v_parts:
        v_parts = [f"0 {col.verdict(k, k, strong=False)}" for k in v_order]
    a_parts = [
        f"{n} {col.action(k)}"
        for k in a_order
        if (n := _ACTION_COUNTS.get(k, 0)) or k in _ACTION_COUNTS
    ]
    if not a_parts:
        a_parts = [f"0 {col.action(k)}" for k in a_order]
    return (
        f"{prefix} verdicts:  " + " · ".join(v_parts) + "\n"
        f"{prefix} actions:   " + " · ".join(a_parts)
    )


def _condensed_alert_body(a: Alert) -> str:
    """Compact one-line identity for an alert. No severity/state — those
    go in dedicated columns of the condensed line."""
    if a.source is AlertSource.CODE_SCANNING:
        loc = a.location_path or "?"
        if a.location_line is not None:
            loc = f"{loc}:{a.location_line}"
        return f"{a.rule_id or '?'} @ {loc}"
    if a.source is AlertSource.SECRET_SCANNING:
        return f"secret: {a.secret_type or '?'}"
    cve = a.cve_id or a.ghsa_id or "?"
    return f"{a.package_name} — {cve}"


_SOURCE_SHORT = {
    AlertSource.DEPENDABOT: "dep",
    AlertSource.CODE_SCANNING: "cs ",
    AlertSource.SECRET_SCANNING: "sec",
}

_SEV_SHORT = {
    "critical": "crit",
    "high":     "high",
    "medium":   "med ",
    "low":      "low ",
}


def _emit_condensed(
    a: Alert,
    verdict: Verdict | None,
    action_kind: str,
    *,
    verdict_source_hint: str | None = None,
    note: str | None = None,
) -> None:
    """Print one compressed line for an alert under NORMAL verbosity.

    Format:  `<ACTION>  #N  <sev>  <src>  <identity>  → <verdict>  (<source>)  <note?>`

    `verdict` may be None for fast-path closes (where no verdict was produced).
    `verdict_source_hint` overrides verdict.source — used to surface the
    Z3 stage that actually decided (truth_table / consensus / judge /
    prosecutor / critic) when the final source field is too generic.

    Skipped in QUIET (no per-alert output) and in VERBOSE (the full tree
    already shows the same data; the condensed line would just duplicate).
    """
    if _LEVEL is not _OutputLevel.NORMAL:
        return
    sev = _SEV_SHORT.get((a.severity or "").lower(), (a.severity or "?")[:4])
    src = _SOURCE_SHORT.get(a.source, a.source.value[:3])
    head = f"  {col.action(action_kind):<7}  #{a.number:<3} {sev}  {src}  {_condensed_alert_body(a)}"
    if verdict is None:
        # Fast-path or other no-verdict outcome — surface the note instead.
        tail = f"  {col.dim(note or '—')}"
        _nprint(head + tail)
        return
    src_str = verdict_source_hint or verdict.source
    verdict_label = col.verdict(verdict.kind.value)
    src_dim = col.dim(f"({src_str})")
    note_str = f"  {col.dim(note)}" if note else ""
    _nprint(f"{head}  → {verdict_label}  {src_dim}{note_str}")


def _fmt_repo(r: RepoProfile) -> str:
    return col.dim(
        f"  repo {r.full_name} archived={r.archived} "
        f"language={r.language or '?'} age_days={r.age_days} "
        f"default_branch={r.default_branch}"
    )


def _fmt_alert_header(a: Alert) -> str:
    """v2: source-aware header. Bold + colored severity for fast scanning."""
    sev = col.severity(a.severity)
    state = f"state={a.state}"
    if a.source is AlertSource.CODE_SCANNING:
        loc = f"{a.location_path or '?'}:{a.location_line or '?'}"
        head = (
            f"    #{a.number} [code-scanning] {a.rule_id or '?'} @ {loc} "
            f"—"
        )
        return f"{col.header(head)} {sev} {state}"
    if a.source is AlertSource.SECRET_SCANNING:
        head = f"    #{a.number} [secret] {a.secret_type or '?'} —"
        return f"{col.header(head)} {sev} {state}"
    # Default = Dependabot (semantics match v1; only the rendering is richer)
    cve = a.cve_id or a.ghsa_id or "?"
    head = (
        f"    #{a.number} {a.package_name} ({a.package_ecosystem}/{a.scope}) "
        f"— {cve}"
    )
    return f"{col.header(head)} {sev} {state}"


def _fmt_evidence(em: EvidenceMatrix) -> str:
    return (
        f"      {col.z2('[Z2 evidence]')} pkg={em.package_name} "
        f"direct_hits={em.direct_package_hits} "
        f"vuln_api_hits={em.vuln_api_hits} "
        f"vuln_apis_seen={list(em.vuln_apis_seen)} "
        f"manifest={em.has_manifest} lockfile={em.has_lockfile} "
        f"dockerfile={em.has_dockerfile} "
        f"advisory_apis_known={em.advisory_has_specific_apis}"
    )


def _fmt_tier(tc: TierClassification) -> str:
    transition = (
        "∞ (guardrail)" if tc.transition_floor == float("inf") else f"{tc.transition_floor:.2f}"
    )
    return (
        f"      {col.z2('[Z2 tier]')} {tc.tier.name} "
        f"post_floor={tc.post_floor:.2f} transition_floor={transition} "
        f"({tc.reason})"
    )


def _fmt_forced_verdict(v: Verdict) -> str:
    return (
        f"      {col.ok('[Z2 truth_table: FORCED]')} "
        f"verdict={col.verdict(v.kind.value)} "
        f"confidence={v.confidence:.2f} source={v.source}\n"
        f"        \"{v.human_conclusion}\""
    )


def _fmt_judge_verdict(v: Verdict) -> str:
    return (
        f"      {col.z3('[Z3 judge]')} "
        f"verdict={col.verdict(v.kind.value)} "
        f"confidence={v.confidence:.2f} source={v.source}\n"
        f"        \"{v.human_conclusion}\""
    )


def _fmt_prosecutor(pr: ProsecutorResult) -> str:
    if pr.contradictions:
        codes = [c.code for c in pr.contradictions]
        via = "LLM attack" if pr.attacked_by_llm else "deterministic"
        # Reasons drive everything — without them we cannot tell whether the
        # Prosecutor is finding a real flaw or rejecting a verdict on
        # structural grounds (e.g. "no reachability evidence" against a
        # code-scanning alert, which by definition has none). Show the why
        # alongside the code on its own indented line.
        reasons = "\n".join(
            f"          • {c.code}: {c.why}" for c in pr.contradictions
        )
        return (
            f"      {col.bad(f'[Z3 prosecutor: CONTRADICTION via {via}]')} "
            f"codes={codes} request_recompute={pr.request_recompute}\n"
            f"{reasons}\n"
            f"        {col.bad('verdict degraded → needs_review')} "
            f"(source={pr.verdict.source})"
        )
    stage = "deterministic + LLM attack" if pr.attacked_by_llm else "deterministic only"
    return f"      {col.dim(f'[Z3 prosecutor: OK ({stage})]')} {col.dim(pr.note)}"


def _fmt_critic(before: Verdict, after: Verdict) -> str:
    from triage.types import VerdictKind
    if before.kind is VerdictKind.NEEDS_REVIEW:
        return (
            f"      {col.dim('[Z3 critic: PASS-THROUGH]')} "
            f"{col.dim('verdict already needs_review; nothing to degrade')}"
        )
    if after.source != before.source:
        return (
            f"      {col.bad('[Z3 critic: DEGRADED]')} confidence={before.confidence:.2f} "
            f"below tier floor → {col.verdict('needs_review')} (source={after.source})"
        )
    return (
        f"      {col.ok('[Z3 critic: OK]')} "
        f"confidence={before.confidence:.2f} ≥ tier post_floor"
    )


def _fmt_consistency(d: ConsistencyDecision) -> str:
    prior = "—"
    if d.prior_verdict is not None and d.prior_confidence is not None:
        prior = f"prior={d.prior_verdict} @ {d.prior_confidence:.2f}"
    action = d.action.value.upper()
    # SKIP is the boring case — fade it. POST/GUARD/FIRST are meaningful.
    tag = f"[Z3 consistency: {action}]"
    if action == "SKIP":
        return f"      {col.dim(tag)} {col.dim(prior)}  {col.dim('reason: ' + d.reason)}"
    return f"      {col.z3(tag)} {prior}  reason: {d.reason}"


def _fmt_issue_action(ia: IssueAction) -> str:
    issue = f"#{ia.issue_number}" if ia.issue_number is not None else "—"
    kind = ia.kind.upper()
    # SKIP fades; CREATE/CLOSE/DISMISS stay visible.
    if ia.kind.lower() == "skip":
        return f"      {col.dim(f'[Z4 issue: {kind}]')} {col.dim(f'issue={issue}  {ia.detail}')}"
    return f"      {col.z4(f'[Z4 issue: {kind}]')} issue={issue}  {ia.detail}"


def _fmt_consensus(c: ConsensusResult) -> str:
    if c.has_consensus:
        return (
            f"      {col.ok('[Z2 consensus: FOUND]')} {len(c.fp_repos)} other repos at FP "
            f"(avg_conf={c.avg_confidence:.2f}); skipping Judge"
        )
    return f"      {col.dim(f'[Z2 consensus: NONE] {c.note}')}"


def _fmt_consensus_verdict(v: Verdict) -> str:
    return (
        f"      {col.z2('[Z2 consensus: APPLIED]')} "
        f"verdict={col.verdict(v.kind.value)} "
        f"confidence={v.confidence:.2f} source={v.source}\n"
        f"        \"{v.human_conclusion}\""
    )


def _tier_override_from_meta(alert: Alert) -> Tier | None:
    """Pull a tier override from the fixture's _meta.repo_profile_hint.tier.

    Only used offline. In online mode this would come from a config file or
    repo topic — not wired yet; documented as TODO for v2.
    """
    raw = (alert.meta.get("repo_profile_hint") or {}).get("tier")
    if raw is None:
        return None
    try:
        return Tier(int(raw))
    except (ValueError, TypeError):
        return None


def _route_and_print(
    sets: list[RepoAlertSet],
    client: GitHubClient | OfflineGitHubClient,
    flags: CycleFlags,
) -> tuple[int, int]:
    """Run Z1 routing + Z2 + Z3 + Z4 across all (repo, alerts).

    Returns (fast_path_count, continue_count). `client` is real or offline;
    the pipeline picks the right Evidence backend by isinstance.
    """
    # NB: counters are NOT reset here — callers reset before invoking so
    # multi-repo drivers can snapshot per-repo and also tally an aggregate.
    fast = 0
    cont = 0
    for s in sets:
        _nprint(_fmt_repo(s.repo))
        for a in s.alerts:
            _vprint(_fmt_alert_header(a))
            decision = route(a)
            if decision.path is FastPath.CLOSE_ALREADY_RESOLVED:
                _vprint(f"      {col.z1('[Z1 fast-path: close]')} {decision.note}")
                ia = handle_fast_path_close(client, s.repo, a, decision.note, flags)
                _tally_action(ia)
                _vprint(_fmt_issue_action(ia))
                _emit_condensed(
                    a, verdict=None, action_kind=ia.kind,
                    note=f"fast-path: {decision.note}",
                )
                fast += 1
                expected = a.meta.get("expected_verdict")
                if expected:
                    _vprint(col.dim(f"      (fixture expects: {expected})"))
                continue

            if a.source is AlertSource.SECRET_SCANNING:
                _vprint(f"      {col.z1('[Z1 continue]')} → Z4 short-circuit (secret scanning)")
            else:
                _vprint(f"      {col.z1('[Z1 continue]')} → Zone 2 investigation")
            cont += 1
            _process_alert(a, s.repo, client, flags)
            expected = a.meta.get("expected_verdict")
            if expected:
                _vprint(col.dim(f"      (fixture expects: {expected})"))
    return fast, cont


def _process_alert(
    a: Alert,
    repo: RepoProfile,
    client: GitHubClient | OfflineGitHubClient,
    flags: CycleFlags,
) -> Verdict:
    """Z2 + Z3 + Z4 with at most one Prosecutor-requested recompute.

    v2 short-circuit: secret scanning alerts bypass Z2/Z3 entirely. They go
    from Z1 straight to Z4 with a ROTATE_NOW verdict. No advisory, no
    evidence, no truth table, no judge, no prosecutor, no critic. The
    Consistency Gate and history still apply (we don't duplicate Issues for
    the same secret), but the verdict cannot flip.
    """
    if a.source is AlertSource.SECRET_SCANNING:
        return _process_secret_alert(a, repo, client, flags)
    verdict, want_recompute = _run_pipeline_once(a, repo, client, flags, is_recomputed=False)
    if want_recompute:
        _vprint(f"      {col.z3('[Z3 prosecutor]')} requesting evidence recompute (one-shot allowed)")
        verdict, _ = _run_pipeline_once(a, repo, client, flags, is_recomputed=True)
    return verdict


def _process_secret_alert(
    a: Alert,
    repo: RepoProfile,
    client: GitHubClient | OfflineGitHubClient,
    flags: CycleFlags,
) -> Verdict:
    """Z1 → Z4 short-circuit for secret scanning. No LLM, no judgment."""
    _vprint(f"      {col.dim('[Z2 SKIPPED]')} {col.dim('secret scanning — no investigation, no judgment')}")
    v = build_rotate_now_verdict(a)
    _vprint(
        f"      {col.verdict('rotate_now', '[Z3 verdict: ROTATE_NOW]')} "
        f"confidence={v.confidence:.2f} source={v.source}"
    )
    _vprint(f"        \"{v.human_conclusion}\"")
    # Use a synthetic Tier classification at INTERNAL — the secret pipeline
    # does not consult tier floors for dismiss (dismiss is structurally
    # blocked), but the Critic and history append still want a value.
    tier = TierClassification.for_tier(Tier.INTERNAL, reason="secret scanning bypass — tier is informational only")
    return _finalize(a, repo, v, tier, client, flags)


def _run_pipeline_once(
    a: Alert,
    repo: RepoProfile,
    client: GitHubClient | OfflineGitHubClient,
    flags: CycleFlags,
    *,
    is_recomputed: bool,
) -> tuple[Verdict, bool]:
    """Run Z2 + Z3 + Z4 a single time. Returns (verdict, want_recompute)."""
    prefix = "  [recompute]" if is_recomputed else ""
    offline = isinstance(client, OfflineGitHubClient)

    # v2: source-dependent Advisory + Evidence build.
    if a.source is AlertSource.DEPENDABOT:
        adv = extract_vulnerable_apis(a)
        if offline:
            em = collect_evidence_offline(a, repo, advisory_apis=adv.apis)
        else:
            em = collect_evidence_online(a, repo, client, advisory_apis=adv.apis)  # type: ignore[arg-type]
        available_str = "yes" if adv.available else "no"
        _vprint(
            f"      {col.z2(f'[Z2 advisory{prefix}]')} llm_available={available_str} "
            f"apis={list(adv.apis)} ({adv.note})"
        )
        _vprint(_fmt_evidence(em))
    else:
        # CodeQL: the rule.description IS the advisory; no extraction needed.
        # Secret scanning: never reaches here in v2-4+ (Z1 short-circuits).
        _vprint(
            f"      {col.z2(f'[Z2 advisory{prefix}]')} N/A for source={a.source.value} "
            f"(rule already names the finding)"
        )
        em = empty_evidence_for_non_dependabot(a)
        _vprint(
            f"      {col.z2('[Z2 evidence]')} source={a.source.value} "
            f"rule={a.rule_id or '—'} "
            f"location={a.location_path or '—'}:{a.location_line or '—'}"
        )

    # Tier override sources, in priority order:
    #   1. Fixture meta hint (offline only, for deterministic test scenarios).
    #   2. `.appsec-triage.toml` config (online — operator-declared intent).
    #   3. Truth Table's automatic heuristic (default).
    if offline:
        tier_override = _tier_override_from_meta(a)
    else:
        tier_override = _TIER_CONFIG.lookup(repo.full_name)
    tt = preflight(a, repo, em, tier_override=tier_override)
    _vprint(_fmt_tier(tt.tier))

    if tt.forced:
        _vprint(_fmt_forced_verdict(tt.forced_verdict))  # type: ignore[arg-type]
        # Forced verdicts get a confirm-only Prosecutor: no LLM attack, no recompute.
        pr = prosecute(
            tt.forced_verdict,  # type: ignore[arg-type]
            a, repo, em, tt.tier,
            enable_llm_attack=False,
            is_recomputed=True,
        )
        _vprint(_fmt_prosecutor(pr))
        final = _finalize(a, repo, pr.verdict, tt.tier, client, flags)
        return final, False

    # Org-wide consensus check — runs before the Judge. If ≥3 OTHER repos
    # have already classified this CVE+package as a false_positive, default
    # to that consensus and skip the LLM. Prosecutor downstream can still
    # degrade if local evidence contradicts.
    consensus = find_fp_consensus(a, HISTORY_PATH, exclude_repo=repo.full_name)
    _vprint(_fmt_consensus(consensus))
    if consensus.has_consensus:
        v = consensus_verdict(consensus, a)
        _vprint(_fmt_consensus_verdict(v))
    else:
        _vprint(f"      {col.dim('[Z2 truth_table]')} {col.dim('no forced verdict → invoking Final Judge')}")
        v = judge(a, repo, em, tt.tier)
        _vprint(_fmt_judge_verdict(v))

    # LLM-attack uses a source-aware prompt + payload:
    #   - DEPENDABOT     → asks about package use, vuln-API hits, manifests.
    #   - CODE_SCANNING  → asks about vendored paths, generated files,
    #                       rule_id false-positive patterns. The previous
    #                       single Dependabot prompt against code-scanning
    #                       was degrading 32/32 real findings to
    #                       needs_review on structural grounds — see
    #                       prosecutor.PROSECUTOR_SYSTEM_PROMPT_CODE_SCANNING.
    # Secret-scanning never reaches here (Z1 short-circuits to Z4).
    pr = prosecute(
        v, a, repo, em, tt.tier,
        enable_llm_attack=True,
        is_recomputed=is_recomputed,
    )
    _vprint(_fmt_prosecutor(pr))
    want_recompute = pr.request_recompute and not is_recomputed
    if want_recompute:
        # Throwaway pass: do NOT critique, do NOT touch consistency / history /
        # Issues. The second iteration produces the canonical verdict that
        # actually gets recorded and acted on.
        return pr.verdict, True
    final = _finalize(a, repo, pr.verdict, tt.tier, client, flags)
    return final, False


def _finalize(
    a: Alert,
    repo: RepoProfile,
    v: Verdict,
    tier: TierClassification,
    client: GitHubClient | OfflineGitHubClient,
    flags: CycleFlags,
) -> Verdict:
    """Silent gates + history + Issue/Dependabot side-effects."""
    critiqued = critique(v, tier)
    _vprint(_fmt_critic(v, critiqued))
    decision = evaluate_consistency(critiqued, repo, a, HISTORY_PATH)
    _vprint(_fmt_consistency(decision))
    # History is part of the side-effect surface — it drives the Consistency
    # Gate on subsequent runs, and feeds the org-wide false-positive consensus
    # check. Dry-run mode must leave it untouched, otherwise a `--dry-run`
    # rehearsal silently teaches the bot "we already handled these alerts"
    # and the next real run will SKIP them via consistency. The original
    # design wrote to history unconditionally; that bit us against
    # safernandez666/Controls where 25 reproducible XSS verdicts had been
    # recorded by dry-runs and a subsequent live run created 0 Issues for
    # them. Same gate as Issue creation: respect dry-run.
    if not flags.dry_run:
        append_history(HISTORY_PATH, repo, a, critiqued)
    ia = handle_issue(client, repo, a, critiqued, tier, decision, flags)
    _vprint(_fmt_issue_action(ia))
    _tally_verdict(critiqued)
    _tally_action(ia)
    # NORMAL mode: emit one compressed line summarizing this alert's outcome.
    # The consistency action (GUARD/POST/FIRST/SKIP) is surfaced as a note
    # because GUARD is operator-actionable: "verdict flipped, please review".
    note = None
    if decision.action.value.upper() == "GUARD":
        note = "[guard] please review"
    _emit_condensed(a, critiqued, ia.kind, note=note)
    return critiqued


def run_offline(flags: CycleFlags | None = None) -> int:
    flags = flags or CycleFlags()
    # Use a single OfflineGitHubClient instance for the whole cycle so the
    # in-memory Issue store accumulates correctly across alerts (e.g. fast-path
    # close + later create on the same repo).
    client = OfflineGitHubClient(FIXTURES_DIR)
    try:
        with client:
            sets = client.load_repo_alert_sets(sources=flags.sources)
            if not sets:
                if flags.sources != ALL_SOURCES:
                    sources_str = ",".join(sorted(s.value for s in flags.sources))
                    print(
                        f"[offline] no fixtures matching sources={{{sources_str}}} "
                        f"under {FIXTURES_DIR}",
                        file=sys.stderr,
                    )
                else:
                    print(f"[offline] no fixtures found under {FIXTURES_DIR}", file=sys.stderr)
                return 1
            total = sum(len(s.alerts) for s in sets)
            sources_str = ",".join(sorted(s.value for s in flags.sources))
            print(
                f"[offline] loaded {total} alert(s) across {len(sets)} synthetic repo(s) "
                f"from {FIXTURES_DIR}  "
                f"flags={{dry_run={flags.dry_run}, auto_transition={flags.auto_transition}, "
                f"sources={sources_str}}}"
            )
            _reset_summary()
            fast, cont = _route_and_print(sets, client, flags)
    except Exception as e:
        # Z1 fast-path: fetch (load) failed — error note, no Zone 2/3.
        print(f"[Z1 error note] offline cycle failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 3
    print(_fmt_summary("[offline]"))
    print(
        f"[offline] cycle complete — "
        f"fast_path={fast} continue={cont}"
    )
    return 0


@dataclass(frozen=True)
class _RepoResult:
    """v0.2.1: per-repo result used by the multi-repo summary."""
    repo: str
    exit_code: int
    fast_path: int
    cont: int
    error: str = ""
    # Snapshot of the global verdict/action counters taken right after the
    # repo's pipeline finished, before the next repo resets them. Optional
    # so callers that don't need them (errors before pipeline) can omit.
    verdict_counts: dict[str, int] | None = None
    action_counts: dict[str, int] | None = None


def _normalize_repo_arg(arg: str) -> str:
    """Accept owner/name, github.com/owner/name, full URLs, or SSH form.

    Real users paste GitHub URLs straight from the browser; refusing them
    burns a CLI invocation on a silent split-into-wrong-pieces. This
    accepts the common surface shapes and normalizes them to `owner/name`.
    """
    a = arg.strip()
    for prefix in (
        "https://",
        "http://",
        "ssh://git@github.com/",
        "git@github.com:",
    ):
        if a.startswith(prefix):
            a = a[len(prefix):]
            break
    if a.startswith("github.com/"):
        a = a[len("github.com/"):]
    a = a.rstrip("/")
    if a.endswith(".git"):
        a = a[: -len(".git")]
    return a


def _process_single_repo_online(
    repo_arg: str,
    token: str,
    flags: CycleFlags,
) -> _RepoResult:
    """Run the full pipeline against ONE online repo. Never raises.

    Returns _RepoResult so the multi-repo driver can decide how to react.
    The single-repo `run_online` wraps this and exits with the returned code;
    the multi-repo `run_online_multi` collects N of these and prints a summary.
    """
    normalized = _normalize_repo_arg(repo_arg)
    try:
        owner, name = normalized.split("/", 1)
    except ValueError:
        msg = (
            f"--repo / --repos entry must be owner/name or a GitHub URL, "
            f"got {repo_arg!r}"
        )
        print(f"[args] {msg}", file=sys.stderr)
        return _RepoResult(repo_arg, 2, 0, 0, "invalid name")
    if not owner or "/" in name:
        msg = (
            f"--repo / --repos entry parsed to {owner!r}/{name!r}; expected "
            f"a single owner/name pair from {repo_arg!r}"
        )
        print(f"[args] {msg}", file=sys.stderr)
        return _RepoResult(repo_arg, 2, 0, 0, "invalid name")
    try:
        client = GitHubClient(token)
    except ImportError:
        print(
            "[online] httpx is not installed. Run: pip install -r requirements.txt",
            file=sys.stderr,
        )
        return _RepoResult(repo_arg, 2, 0, 0, "httpx not installed")
    try:
        with client:
            try:
                repo = client.get_repo(owner, name)
                # Ensure the autotriage label exists before any Issue is created.
                # Without this, GitHub silently drops the label on Issue create,
                # and `_find_existing`'s label-filtered query returns nothing →
                # duplicate Issues on every CREATE. Idempotent (no-op on 422).
                if not flags.dry_run:
                    try:
                        client.ensure_label(owner, name, ISSUE_LABEL)
                    except Exception as e:
                        # Don't fail the cycle for a label-create permission
                        # issue — the dedupe fallback still works.
                        print(
                            f"[warn] could not ensure label {ISSUE_LABEL!r}: "
                            f"{type(e).__name__}: {e}",
                            file=sys.stderr,
                        )
                alerts: list[Alert] = []
                if AlertSource.DEPENDABOT in flags.sources:
                    alerts.extend(client.list_dependabot_alerts(owner, name))
                if AlertSource.CODE_SCANNING in flags.sources:
                    alerts.extend(client.list_code_scanning_alerts(owner, name))
                if AlertSource.SECRET_SCANNING in flags.sources:
                    alerts.extend(client.list_secret_scanning_alerts(owner, name))
            except Exception as e:
                msg = f"{type(e).__name__}: {e}"
                print(
                    f"[Z1 error note] GitHub fetch failed for {repo_arg}: {msg}",
                    file=sys.stderr,
                )
                return _RepoResult(repo_arg, 3, 0, 0, msg)

            sets = [RepoAlertSet(repo, alerts)]
            sources_str = ",".join(sorted(s.value for s in flags.sources))
            by_src = {s.value: 0 for s in flags.sources}
            for a in alerts:
                by_src[a.source.value] = by_src.get(a.source.value, 0) + 1
            breakdown = ",".join(f"{k}={v}" for k, v in sorted(by_src.items()))
            print(
                f"[online] {len(alerts)} open alert(s) in {repo.full_name} "
                f"[{breakdown}]  "
                f"flags={{dry_run={flags.dry_run}, auto_transition={flags.auto_transition}, "
                f"sources={sources_str}}}"
            )
            _reset_summary()
            fast, cont = _route_and_print(sets, client, flags)
            # Snapshot before any subsequent reset clears globals.
            v_snap = dict(_VERDICT_COUNTS)
            a_snap = dict(_ACTION_COUNTS)
            return _RepoResult(
                repo_arg, 0, fast, cont,
                verdict_counts=v_snap, action_counts=a_snap,
            )
    except Exception as e:
        # Catch-all so one repo crashing inside the pipeline cannot kill a
        # batch of 50. The single-repo path also benefits: any unexpected
        # bug surfaces as a clean exit 3 with a message, not a stack trace.
        return _RepoResult(repo_arg, 3, 0, 0, f"{type(e).__name__}: {e}")


def run_online(repo_arg: str, flags: CycleFlags | None = None) -> int:
    flags = flags or CycleFlags()
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("[online] GITHUB_TOKEN not set in env. See .env.example.", file=sys.stderr)
        return 2
    result = _process_single_repo_online(repo_arg, token, flags)
    if result.exit_code == 0:
        # Restore snapshot so _fmt_summary reads the per-repo numbers.
        if result.verdict_counts is not None:
            _VERDICT_COUNTS.clear()
            _VERDICT_COUNTS.update(result.verdict_counts)
        if result.action_counts is not None:
            _ACTION_COUNTS.clear()
            _ACTION_COUNTS.update(result.action_counts)
        print(_fmt_summary("[online]"))
        print(
            f"[online] cycle complete — fast_path={result.fast_path} continue={result.cont}"
        )
    return result.exit_code


def run_online_multi(repos_arg: str, flags: CycleFlags | None = None) -> int:
    """v0.2.1: iterate a comma-separated list of repos with error isolation.

    Returns 0 only if EVERY repo returned 0. If any repo failed we return the
    worst exit code seen so callers (cron, CI) can still detect partial failure
    without losing the per-repo summary. One blown-up repo can never abort the
    batch — that is the whole point of this driver vs running --repo in a bash
    loop with `set -e`.
    """
    flags = flags or CycleFlags()
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("[online] GITHUB_TOKEN not set in env. See .env.example.", file=sys.stderr)
        return 2
    repos = [r.strip() for r in repos_arg.split(",") if r.strip()]
    if not repos:
        print("[online] --repos was empty after parsing", file=sys.stderr)
        return 2
    print(f"[online-batch] processing {len(repos)} repo(s)")
    results: list[_RepoResult] = []
    for i, repo_arg in enumerate(repos, 1):
        print(f"\n[online-batch] ({i}/{len(repos)}) {repo_arg}")
        results.append(_process_single_repo_online(repo_arg, token, flags))
    # Per-repo summary so a 50-repo run still leaves a readable trail.
    print("\n[online-batch] summary")
    ok = sum(1 for r in results if r.exit_code == 0)
    fast_total = sum(r.fast_path for r in results)
    cont_total = sum(r.cont for r in results)
    # Rebuild aggregate counters so _fmt_summary can color the batch totals.
    _reset_summary()
    for r in results:
        if r.verdict_counts:
            for k, v in r.verdict_counts.items():
                _VERDICT_COUNTS[k] = _VERDICT_COUNTS.get(k, 0) + v
        if r.action_counts:
            for k, v in r.action_counts.items():
                _ACTION_COUNTS[k] = _ACTION_COUNTS.get(k, 0) + v
        if r.exit_code == 0:
            print(f"  ok    {r.repo}  fast_path={r.fast_path} continue={r.cont}")
        else:
            print(f"  {col.bad('FAIL')}  {r.repo}  exit={r.exit_code}  {r.error}")
    print(_fmt_summary("[online-batch]"))
    print(
        f"[online-batch] complete — {ok}/{len(results)} ok  "
        f"fast_path={fast_total} continue={cont_total}"
    )
    # Worst exit code wins so `cron` / CI still sees partial failure.
    return max((r.exit_code for r in results), default=0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        # No fixed `prog=` — argparse infers from sys.argv[0] so help reads
        # `appsec-triage --offline` when invoked via the console script and
        # `triage_cycle.py --offline` when invoked as the legacy shim.
        description=(
            "AppSec triage bot — defensive vulnerability triage of Dependabot alerts. "
            "Multi-agent architecture; the LLM never acts alone."
        ),
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--offline",
        action="store_true",
        help="Run against bundled fixtures, no network, no LLM. Heuristic-only.",
    )
    mode.add_argument(
        "--repo",
        metavar="OWNER/NAME",
        help="Target a single repo as owner/name. Requires GITHUB_TOKEN in env.",
    )
    mode.add_argument(
        "--repos",
        metavar="LIST",
        help=(
            "v0.2.1: comma-separated list of repos (e.g. org/a,org/b,org/c). "
            "Iterates with fail-fast off — if one repo errors, the rest still run. "
            "Prints a per-repo summary at the end. Same GITHUB_TOKEN must have "
            "access to every listed repo. Useful for batch runs from a laptop "
            "or a single cron without setting up an Actions matrix."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="No state mutations on GitHub (no issue posts, no alert dismisses).",
    )
    p.add_argument(
        "--auto-transition",
        action="store_true",
        help=(
            "Auto-dismiss alerts judged false_positive above the tier's transition "
            "floor. Tier-1 (critical) repos are NEVER auto-dismissed. Secret scanning "
            "alerts are NEVER auto-dismissed regardless of flag (humans rotate)."
        ),
    )
    p.add_argument(
        "--sources",
        default="dependabot",
        metavar="LIST",
        help=(
            "Comma-separated alert sources to ingest. Tokens: dependabot, "
            "code-scanning (alias: codeql), secret-scanning (alias: secret). "
            "Use 'all' for the three of them. Default: dependabot (v1 compat)."
        ),
    )
    verb = p.add_mutually_exclusive_group()
    verb.add_argument(
        "-v", "--verbose",
        action="store_true",
        help=(
            "Print the full Z1 → Z2 → Z3 → Z4 tree for every alert. "
            "Use this when debugging the bot itself. Default is a single "
            "condensed line per alert."
        ),
    )
    verb.add_argument(
        "-q", "--quiet",
        action="store_true",
        help=(
            "Suppress per-alert output. Only the banner, repo headers, "
            "and the final verdict/action summary are printed. Use this "
            "for cron and Slack-style notifications."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    # Load .env from cwd before anything reads os.environ. Existing shell
    # exports always win (see env_loader docstring), so explicit overrides
    # like `GITHUB_TOKEN=other appsec-triage …` still work for one-offs.
    load_dotenv()
    print_banner()
    args = build_parser().parse_args(argv)
    global _LEVEL, _TIER_CONFIG
    if args.verbose:
        _LEVEL = _OutputLevel.VERBOSE
    elif args.quiet:
        _LEVEL = _OutputLevel.QUIET
    else:
        _LEVEL = _OutputLevel.NORMAL
    # Load per-repo tier overrides from .appsec-triage.toml if present.
    # Missing file → empty config → heuristic classification (unchanged
    # behavior). Stays a noop on offline mode (the fixture meta hint
    # path is preferred for those).
    _TIER_CONFIG = load_config()
    try:
        sources = _parse_sources(args.sources)
    except ValueError as e:
        print(f"[args] {e}", file=sys.stderr)
        return 2
    flags = CycleFlags(
        dry_run=args.dry_run,
        auto_transition=args.auto_transition,
        sources=sources,
    )
    if args.offline:
        return run_offline(flags)
    if args.repo:
        return run_online(args.repo, flags)
    if args.repos:
        return run_online_multi(args.repos, flags)
    build_parser().print_help()
    return 0
