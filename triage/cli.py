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
from pathlib import Path

from triage.advisory_agent import AdvisoryResult, extract_vulnerable_apis
from triage.banner import print_banner
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


def _fmt_repo(r: RepoProfile) -> str:
    return (
        f"  repo {r.full_name} archived={r.archived} "
        f"language={r.language or '?'} age_days={r.age_days} "
        f"default_branch={r.default_branch}"
    )


def _fmt_alert_header(a: Alert) -> str:
    """v2: source-aware header.

    Dependabot: #N pkg (ecosystem/scope) — CVE severity=X state=Y
    CodeQL:     #N [code-scanning] rule_id @ path:line — severity=X state=Y
    Secret:     #N [secret] secret_type — severity=critical state=Y
    """
    if a.source is AlertSource.CODE_SCANNING:
        loc = f"{a.location_path or '?'}:{a.location_line or '?'}"
        return (
            f"    #{a.number} [code-scanning] {a.rule_id or '?'} @ {loc} "
            f"— severity={a.severity} state={a.state}"
        )
    if a.source is AlertSource.SECRET_SCANNING:
        return (
            f"    #{a.number} [secret] {a.secret_type or '?'} "
            f"— severity={a.severity} state={a.state}"
        )
    # Default = Dependabot (matches v1 output verbatim)
    cve = a.cve_id or a.ghsa_id or "?"
    return (
        f"    #{a.number} {a.package_name} ({a.package_ecosystem}/{a.scope}) "
        f"— {cve} severity={a.severity} state={a.state}"
    )


def _fmt_evidence(em: EvidenceMatrix) -> str:
    return (
        f"      [Z2 evidence] pkg={em.package_name} "
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
        f"      [Z2 tier] {tc.tier.name} "
        f"post_floor={tc.post_floor:.2f} transition_floor={transition} "
        f"({tc.reason})"
    )


def _fmt_forced_verdict(v: Verdict) -> str:
    return (
        f"      [Z2 truth_table: FORCED] verdict={v.kind.value} "
        f"confidence={v.confidence:.2f} source={v.source}\n"
        f"        \"{v.human_conclusion}\""
    )


def _fmt_judge_verdict(v: Verdict) -> str:
    return (
        f"      [Z3 judge] verdict={v.kind.value} "
        f"confidence={v.confidence:.2f} source={v.source}\n"
        f"        \"{v.human_conclusion}\""
    )


def _fmt_prosecutor(pr: ProsecutorResult) -> str:
    if pr.contradictions:
        codes = [c.code for c in pr.contradictions]
        via = "LLM attack" if pr.attacked_by_llm else "deterministic"
        return (
            f"      [Z3 prosecutor: CONTRADICTION via {via}] codes={codes} "
            f"request_recompute={pr.request_recompute}\n"
            f"        verdict degraded → needs_review (source={pr.verdict.source})"
        )
    stage = "deterministic + LLM attack" if pr.attacked_by_llm else "deterministic only"
    return f"      [Z3 prosecutor: OK ({stage})] {pr.note}"


def _fmt_critic(before: Verdict, after: Verdict) -> str:
    from triage.types import VerdictKind
    if before.kind is VerdictKind.NEEDS_REVIEW:
        return "      [Z3 critic: PASS-THROUGH] verdict already needs_review; nothing to degrade"
    if after.source != before.source:
        return (
            f"      [Z3 critic: DEGRADED] confidence={before.confidence:.2f} below tier floor "
            f"→ needs_review (source={after.source})"
        )
    return f"      [Z3 critic: OK] confidence={before.confidence:.2f} ≥ tier post_floor"


def _fmt_consistency(d: ConsistencyDecision) -> str:
    prior = "—"
    if d.prior_verdict is not None and d.prior_confidence is not None:
        prior = f"prior={d.prior_verdict} @ {d.prior_confidence:.2f}"
    return f"      [Z3 consistency: {d.action.value.upper()}] {prior}  reason: {d.reason}"


def _fmt_issue_action(ia: IssueAction) -> str:
    issue = f"#{ia.issue_number}" if ia.issue_number is not None else "—"
    return f"      [Z4 issue: {ia.kind.upper()}] issue={issue}  {ia.detail}"


def _fmt_consensus(c: ConsensusResult) -> str:
    if c.has_consensus:
        return (
            f"      [Z2 consensus: FOUND] {len(c.fp_repos)} other repos at FP "
            f"(avg_conf={c.avg_confidence:.2f}); skipping Judge"
        )
    return f"      [Z2 consensus: NONE] {c.note}"


def _fmt_consensus_verdict(v: Verdict) -> str:
    return (
        f"      [Z2 consensus: APPLIED] verdict={v.kind.value} "
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
    fast = 0
    cont = 0
    for s in sets:
        print(_fmt_repo(s.repo))
        for a in s.alerts:
            print(_fmt_alert_header(a))
            decision = route(a)
            if decision.path is FastPath.CLOSE_ALREADY_RESOLVED:
                print(f"      [Z1 fast-path: close] {decision.note}")
                ia = handle_fast_path_close(client, s.repo, a, decision.note, flags)
                print(_fmt_issue_action(ia))
                fast += 1
                expected = a.meta.get("expected_verdict")
                if expected:
                    print(f"      (fixture expects: {expected})")
                continue

            if a.source is AlertSource.SECRET_SCANNING:
                print("      [Z1 continue] → Z4 short-circuit (secret scanning)")
            else:
                print("      [Z1 continue] → Zone 2 investigation")
            cont += 1
            _process_alert(a, s.repo, client, flags)
            expected = a.meta.get("expected_verdict")
            if expected:
                print(f"      (fixture expects: {expected})")
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
        print("      [Z3 prosecutor] requesting evidence recompute (one-shot allowed)")
        verdict, _ = _run_pipeline_once(a, repo, client, flags, is_recomputed=True)
    return verdict


def _process_secret_alert(
    a: Alert,
    repo: RepoProfile,
    client: GitHubClient | OfflineGitHubClient,
    flags: CycleFlags,
) -> Verdict:
    """Z1 → Z4 short-circuit for secret scanning. No LLM, no judgment."""
    print("      [Z2 SKIPPED] secret scanning — no investigation, no judgment")
    v = build_rotate_now_verdict(a)
    print(
        f"      [Z3 verdict: ROTATE_NOW] confidence={v.confidence:.2f} "
        f"source={v.source}"
    )
    print(f"        \"{v.human_conclusion}\"")
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
        print(
            f"      [Z2 advisory{prefix}] llm_available={available_str} "
            f"apis={list(adv.apis)} ({adv.note})"
        )
        print(_fmt_evidence(em))
    else:
        # CodeQL: the rule.description IS the advisory; no extraction needed.
        # Secret scanning: never reaches here in v2-4+ (Z1 short-circuits).
        print(
            f"      [Z2 advisory{prefix}] N/A for source={a.source.value} "
            f"(rule already names the finding)"
        )
        em = empty_evidence_for_non_dependabot(a)
        print(
            f"      [Z2 evidence] source={a.source.value} "
            f"rule={a.rule_id or '—'} "
            f"location={a.location_path or '—'}:{a.location_line or '—'}"
        )

    tier_override = _tier_override_from_meta(a) if offline else None
    tt = preflight(a, repo, em, tier_override=tier_override)
    print(_fmt_tier(tt.tier))

    if tt.forced:
        print(_fmt_forced_verdict(tt.forced_verdict))  # type: ignore[arg-type]
        # Forced verdicts get a confirm-only Prosecutor: no LLM attack, no recompute.
        pr = prosecute(
            tt.forced_verdict,  # type: ignore[arg-type]
            a, repo, em, tt.tier,
            enable_llm_attack=False,
            is_recomputed=True,
        )
        print(_fmt_prosecutor(pr))
        final = _finalize(a, repo, pr.verdict, tt.tier, client, flags)
        return final, False

    # Org-wide consensus check — runs before the Judge. If ≥3 OTHER repos
    # have already classified this CVE+package as a false_positive, default
    # to that consensus and skip the LLM. Prosecutor downstream can still
    # degrade if local evidence contradicts.
    consensus = find_fp_consensus(a, HISTORY_PATH, exclude_repo=repo.full_name)
    print(_fmt_consensus(consensus))
    if consensus.has_consensus:
        v = consensus_verdict(consensus, a)
        print(_fmt_consensus_verdict(v))
    else:
        print("      [Z2 truth_table] no forced verdict → invoking Final Judge")
        v = judge(a, repo, em, tt.tier)
        print(_fmt_judge_verdict(v))

    pr = prosecute(
        v, a, repo, em, tt.tier,
        enable_llm_attack=True,
        is_recomputed=is_recomputed,
    )
    print(_fmt_prosecutor(pr))
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
    print(_fmt_critic(v, critiqued))
    decision = evaluate_consistency(critiqued, repo, a, HISTORY_PATH)
    print(_fmt_consistency(decision))
    append_history(HISTORY_PATH, repo, a, critiqued)
    ia = handle_issue(client, repo, a, critiqued, tier, decision, flags)
    print(_fmt_issue_action(ia))
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
            fast, cont = _route_and_print(sets, client, flags)
    except Exception as e:
        # Z1 fast-path: fetch (load) failed — error note, no Zone 2/3.
        print(f"[Z1 error note] offline cycle failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 3
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
    try:
        owner, name = repo_arg.split("/", 1)
    except ValueError:
        msg = f"--repo / --repos entry must be owner/name, got {repo_arg!r}"
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
            fast, cont = _route_and_print(sets, client, flags)
            return _RepoResult(repo_arg, 0, fast, cont)
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
    for r in results:
        if r.exit_code == 0:
            print(f"  ok    {r.repo}  fast_path={r.fast_path} continue={r.cont}")
        else:
            print(f"  FAIL  {r.repo}  exit={r.exit_code}  {r.error}")
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
    return p


def main(argv: list[str] | None = None) -> int:
    print_banner()
    args = build_parser().parse_args(argv)
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
