# AppSec Triage Bot

<!-- README-I18N:START -->

**English** | [Español](./README.es.md)

<!-- README-I18N:END -->

Multi-agent defensive triage of Dependabot alerts. Reduces false positives and the team's alert fatigue. GitHub-native. Python 3.11+. Single runtime dependency: `httpx`.

> **Status:** v0.2.1. Ingests three sources: Dependabot, GitHub Code Scanning (CodeQL + 3rd-party SAST), and Secret Scanning. See [Sources](#sources). Multi-repo batch mode via `--repos` — see [Batch mode](#batch-mode-multi-repo).

## Why this exists

Dependabot is great at finding vulnerable dependencies and noisy at telling you which ones actually affect *your* repository. After a few months you have a backlog of advisories nobody triages, a Slack channel of resolved-to-stale alerts, and the team starts ignoring real findings.

This bot reads Dependabot alerts and answers, per alert: **does this affect us?** It produces a `false_positive` / `reproducible` / `needs_review` verdict with a plain-English conclusion you can read in a GitHub Issue. False positives can be auto-dismissed (configurable, never in tier-1 repos). Reproducibles stay open for the team to fix. `needs_review` means the bot itself isn't sure — humans decide.

<p align="center">
  <img src="docs/architecture.svg" alt="Pipeline architecture: Z1 routing → Z2 investigation → Z3 judgment → Z4 output. Tier-1 guardrail in coral." width="720"/>
</p>

## Quick start

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e .                 # source of truth: pyproject.toml
cp .env.example .env             # fill LLM_BASE_URL / LLM_API_KEY / LLM_MODEL / GITHUB_TOKEN

# Offline demo: no creds, fixtures only. Pure heuristic flow, no tokens spent.
appsec-triage --offline

# Online dry-run: reads alerts, computes verdicts, mutates nothing.
appsec-triage --repo owner/name --dry-run

# Online with auto-dismiss for high-confidence false positives.
# Tier-1 (critical) repos are NEVER auto-dismissed. Non-negotiable.
appsec-triage --repo owner/name --auto-transition

# v0.2.1: batch a small fleet from one invocation. If one repo errors the
# rest still run; a summary is printed at the end and the worst exit code wins.
appsec-triage --repos owner/a,owner/b,owner/c --dry-run
```

`--offline`, `--repo`, and `--repos` are mutually exclusive. `--dry-run` and `--auto-transition` apply to every mode.

> The console script `appsec-triage` and the legacy `python triage_cycle.py` are interchangeable. The shim exists so the spec wording (`python triage_cycle.py …`) keeps working, but post-install the console script is the idiomatic entry point.

### Dev install

```bash
pip install -e ".[dev]"          # adds pytest + ruff
```

### Required env vars

| Var             | Purpose                                                                                                       |
|-----------------|---------------------------------------------------------------------------------------------------------------|
| `LLM_BASE_URL`  | OpenAI-compatible chat completions endpoint. Defaults to `https://api.openai.com/v1`. Point at your gateway. |
| `LLM_API_KEY`   | Bearer token for the LLM. If missing, Advisory returns `()`, Judge degrades to `needs_review` fallback.       |
| `LLM_MODEL`     | Model id. Defaults to `gpt-4o-mini`. Any model that honors `temperature=0` and `response_format=json_object`. |
| `GITHUB_TOKEN`  | Fine-grained PAT (or App token) — see [GitHub PAT permissions](#github-pat-permissions) for the exact scopes.|

All LLM calls use `temperature=0` by contract. Same input → same verdict, by design.

The bot auto-loads `.env` from the current working directory at startup, so a populated `.env` is enough — you do not need to `source` it in your shell. Existing shell exports always win over the file, matching the python-dotenv default.

### GitHub PAT permissions

The bot performs five categories of GitHub API calls. A real-world rollout against `safernandez666/Controls` surfaced two failure modes — Issue **creates** worked but **comments** returned `403 "Resource not accessible by personal access token"`, and **label creation** also returned `403`. The table below is the minimum surface the bot uses, with the exact symptom you will see when each permission is missing.

#### Fine-grained PAT (recommended)

| Permission                                | Access            | Used for                                                                                                                                   | Symptom when missing                                                                  |
|-------------------------------------------|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|
| **Metadata**                              | Read (auto)       | `GET /repos/{o}/{r}` — `archived`, `language`, default branch, age                                                                         | Cannot select the repo at all                                                          |
| **Contents**                              | Read              | `GET /search/code` — reachability evidence (Dependabot only)                                                                                | Every Dependabot evidence row reports `direct_hits=0` even when the package is used    |
| **Issues**                                | **Read and write**| `GET /repos/{o}/{r}/issues`, `POST .../issues`, `POST .../issues/{n}/comments`, `PATCH .../issues/{n}` (close)                              | `403` on comment endpoint — verdict-flips show up in the summary as `BLOCKED` actions  |
| **Dependabot alerts**                     | Read for dry-run, **Read and write** for `--auto-transition` | `GET /repos/{o}/{r}/dependabot/alerts` and `PATCH .../dependabot/alerts/{n}` to dismiss                                                    | `403` on `--auto-transition` dismiss step                                              |
| **Code scanning alerts**                  | Read for dry-run, **Read and write** for `--auto-transition` | `GET /repos/{o}/{r}/code-scanning/alerts` and `PATCH .../code-scanning/alerts/{n}` to dismiss                                              | Same as above                                                                          |
| **Secret scanning alerts**                | Read              | `GET /repos/{o}/{r}/secret-scanning/alerts` only — **the bot never dismisses secrets** regardless of flags                                  | Secret source returns empty                                                            |
| ~~Administration~~                        | ~~Write~~         | Used by `ensure_label` (creates the `autotriage` label). **Not recommended** — `Administration: write` is a very strong scope.             | One-time `403` warning at cycle start. Workaround: create the `autotriage` label manually once (see below). |

If you only need read access for a `--dry-run` rehearsal, the bot will compute every verdict but mutate nothing — you can use Read-only on the three alert sources and skip the label create. Once you graduate to live mode, raise Issues and the two alert categories you want auto-dismissed to Read and write.

#### Classic PAT (if fine-grained is unavailable)

- `repo` for private repos or `public_repo` for public repos (covers Issues + Search Code)
- `security_events` (covers Dependabot + Code Scanning read + write)
- Secret Scanning Alerts ride on `repo` automatically — there is no separate scope in classic PATs, which is one reason fine-grained is preferred

#### Pre-flight check

After updating the PAT, verify the comment endpoint before re-running the bot:

```bash
python -c "
import os, httpx
from triage.env_loader import load_dotenv
load_dotenv()
tok = os.environ['GITHUB_TOKEN']
r = httpx.post(
    f'https://api.github.com/repos/<owner>/<repo>/issues/<existing-issue-#>/comments',
    headers={'Authorization': f'token {tok}', 'Accept': 'application/vnd.github+json'},
    json={'body': 'PAT permission test — ignore, will delete'},
)
print(r.status_code, r.text[:200])
"
```

`201 Created` means comments work — delete the test comment, run the bot. `403` means the PAT still needs the Issues write upgrade.

## Architecture — the LLM never acts alone

Every alert passes through deterministic gates on the way in (Truth Table) and on the way out (Prosecutor + Critic + Consistency). The Final Judge is an LLM but it is sandwiched between layers that can override it without involving any model.

```
Z1 routing  →  Z2 investigation (deterministic + LLM-extraction)  →  Z3 judgment  →  Z4 output
```

<p align="center">
  <img src="docs/sequence.svg" alt="One alert traced end to end across CLI, GitHub, LLM, deterministic engine, and history store. Coral = primary return from the Judge." width="880"/>
</p>

<p align="center"><sub><em>An alert traced end to end. The coral arrow is the Judge's verdict — the central decision; everything else is plumbing.</em></sub></p>

### Zone 1 — Routing

Fast-paths without LLM:
- `state in {fixed, dismissed, auto_dismissed}` → close any existing Issue with a one-line note. No Zone 2/3.
- Fetch failure (network, auth) → error note, no Zone 2/3.

### Zone 2 — Investigation (runs before any verdict-producing LLM)

- **Advisory Agent** (LLM, extraction only): pulls dotted symbol names of vulnerable APIs (`requests.Session`, `yaml.load`, …) from the advisory text. No LLM → `()`. The model never decides anything here; the contract is a strict JSON list of names.
- **Evidence Agent** (pure Python): code search reachability (uses of the package and the symbols the Advisory surfaced), repo profile (archived / language / age), manifest / lockfile / Dockerfile presence. Returns an `EvidenceMatrix` of counts and booleans, **no interpretation**.
- **Pre-flight Truth Table** (pure Python): assigns a tier and may **force** a verdict, bypassing the LLM entirely:
  - **Rule A** — `archived AND direct_package_hits == 0` → `false_positive`. The vulnerable code path cannot run in an archived repo with no usage.
  - **Rule B** — `advisory_has_specific_apis AND direct_package_hits == 0 AND (repo_active OR age_days ≥ 180)` → `false_positive`. Absence of evidence treated as evidence, but only when the advisory pinpoints which APIs to look for AND the default branch is representative.
- **Org-wide consensus** (`triage/memory.py`): if the same `CVE+package` has been classified as `false_positive` in ≥ 3 **other** repositories of this org, the bot defaults to that consensus and **skips the Judge**. The current repo never contributes to its own consensus. Confidence is capped at 0.93 — high enough to clear Tier 2/3/4 floors, **below Tier 1's 0.95 floor** so critical repos never auto-FP on hearsay.

### Zone 3 — Judgment

- **Final Judge** (LLM, strict JSON contract, `temperature=0`): returns `{verdict, confidence, human_conclusion}`. `human_conclusion` is plain English, no scores, no agent names, no first-person voice — what the human reading the Issue will see. Three defensive layers protect the contract: system prompt + `response_format={"type":"json_object"}` + a `_parse_response` validator that drops malformed responses and falls back to `needs_review`.
- **Prosecutor** (`triage/prosecutor.py`): adversarial review. Deterministic contradiction checks first (cheap, unhallucinatable), optional LLM attack after if there's nothing concrete to flag. Can request **one** evidence recompute. Only ever **degrades** to `needs_review`; never promotes. Asymmetry intentional: a Prosecutor that could promote would be doing the Judge's job.
- **Critic** (`triage/critic.py`): silent quality gate. If `confidence < tier.post_floor`, degrade to `needs_review`. Never appears in the Issue body. `needs_review` is a failure state by spec, not a comfortable hedge.
- **Consistency Gate** (`triage/consistency.py`): anti flip-flop across runs. Reads `.triage_history.jsonl` and compares with the prior verdict for this `(repo, CVE+package)`:
  - **SKIP** — same verdict as last cycle → no new comment, no re-post.
  - **POST** — verdict flipped AND new confidence ≥ 0.85 → post the override.
  - **GUARD** — verdict flipped AND new confidence < 0.85 → post a "please review before closing" guard message. No auto-action.
  - **FIRST** — no prior history → standard post.

### Zone 4 — Output (GitHub-first, no Jira)

- One Issue per alert. Label `autotriage`. Hidden HTML marker `<!-- triage:CVE::ecosystem::package -->` in the body for state tracking.
- The triage conclusion goes as a comment. The Issue body is created once.
- Auto-transition: when `--auto-transition` is set AND `verdict == false_positive` AND `confidence ≥ tier.transition_floor`, the Dependabot alert is dismissed via `PATCH /repos/{o}/{r}/dependabot/alerts/{n}` with `state=dismissed`. Dismissal reason is `not_used` for Truth Table no-hits rules, `inaccurate` otherwise. **Never** `tolerable_risk` automatically — that is a human policy decision.

## Guardrails (non-negotiable)

- **Tier-1 (critical) repos are NEVER auto-dismissed**, regardless of confidence. Enforced two ways: `TIER_FLOORS[CRITICAL].transition_floor = float("inf")` (the confidence comparison cannot pass) AND an explicit `if tier.tier is Tier.CRITICAL: block` in `_maybe_dismiss`. Belt + suspenders. If anyone edits the floors to a finite value, the early return is the safety net.
- **Never clone repos.** Reachability comes from `/search/code` only.
- **Never write code in target repos.**
- **Never dismiss alerts outside the rules above.** No "tolerable_risk" auto-reason.
- **`temperature=0`** on every LLM call. Same input → same verdict.

## Memory and org-wide consensus

`.triage_history.jsonl` is append-only. One JSON line per alert per cycle:

```json
{"ts":"2026-05-30T12:00:00+00:00","repo":"org/svc","identity":"CVE-2023-32681::pip::requests","alert_number":202,"verdict":"false_positive","confidence":0.92,"source":"judge"}
```

Two consumers:
1. **Consistency Gate** — last entry for `(repo, identity)` defines SKIP/POST/GUARD.
2. **Org-wide consensus** — latest entry per other repo for this `identity`; if ≥ 3 of them are `false_positive`, default to that before invoking the Judge.

In CI the runner is ephemeral and the file does not survive between runs by default. The shipped workflow uploads it as an artifact for audit. For production persist it to S3, a private gist, or a dedicated state repository.

## Batch mode (multi-repo)

`--repos` runs the full pipeline against a comma-separated list of repos from a single invocation. It exists because real teams own more than one repo, and the realistic alternatives — a bash loop with `set -e`, or a GitHub Actions matrix — are either fragile or heavy.

```bash
# Dry-run a fleet
appsec-triage --repos org/svc-api,org/svc-web,org/internal-tools --dry-run

# Same with all three sources and auto-dismiss enabled.
# Tier-1 guardrails still apply per repo — no batch-wide override.
appsec-triage \
  --repos org/svc-api,org/svc-web,org/internal-tools \
  --sources all \
  --auto-transition
```

What you get over a bash loop:

- **Error isolation.** A failing repo (auth, fetch, unexpected crash) does not abort the batch. The driver catches everything, records a `_RepoResult`, and moves to the next repo. The single-repo `--repo` path now reuses the same helper, so both paths share the same defensive behavior.
- **Per-repo summary.** At the end you get `ok` / `FAIL` lines per repo with fast-path counts, continue counts, and the failure message when applicable — auditable in a `cron` log without scrolling.
- **Honest exit code.** The overall exit code is the worst per-repo code, so `cron` / CI / Slack notifications still detect partial failure instead of swallowing it.

What it does **not** do:

- Per-repo `--sources` overrides — `--sources` is global to the batch. If you need different sources per repo, run multiple invocations.
- Parallelism. The driver iterates serially. GitHub rate limits make parallel batches across one PAT a foot-gun more than a feature; an Actions matrix is still the right tool past ~20 repos.
- Configuration files. The flag intentionally accepts a flat comma-separated list. If your fleet is large enough to need a YAML config, you have already outgrown this mode.

Tier-1 guardrails are evaluated **per repo**: a critical repo inside a batch of fifty is still never auto-dismissed, regardless of the surrounding flags.

## Putting it in production

A step-by-step that mirrors what we did to onboard the first real repository. Follow it in order — each step is meant to surface failures cheaply before the next one mutates state.

### Step 1 — Generate the PAT correctly the first time

Use a fine-grained PAT scoped to **only the repos you intend to triage**. See [GitHub PAT permissions](#github-pat-permissions) for the exact matrix. Do not skip the pre-flight check at the end of that section — it costs ten seconds and catches the most common misconfiguration (Issues: Read only instead of Read and write).

### Step 2 — Seed the `autotriage` label manually

The bot tries to create the label at cycle start, but `Administration: write` is a stronger permission than you should give a triage bot. Create the label once via the GitHub UI: **Repo → Issues → Labels → New label**, name `autotriage`, color of your choice (the bot uses `#d97706` amber by default). Without the label, dedupe still works via the hidden HTML marker in each Issue body, but the per-page query is slower and you cannot filter Issues by `label:autotriage` in the UI.

### Step 3 — `--offline` smoke test

```bash
appsec-triage --offline
```

This runs the full Z1 → Z2 → Z3 → Z4 pipeline against the bundled fixtures, with no network and no LLM calls. The expected output ends with `[offline] cycle complete — fast_path=1 continue=2`. If this fails, the install is broken — fix that before touching real credentials.

### Step 4 — Dry-run against a real repo

```bash
appsec-triage --repo <owner>/<name> --dry-run --sources all
```

Reads alerts, computes verdicts, and mutates nothing. Look at the output:

- Number of alerts per source in the breakdown line (`[dependabot=N,code_scanning=M,secret_scanning=K]`)
- The verdict distribution in the summary footer
- That no `BLOCKED` actions appear (those would indicate a permission gap that the live run will hit)

Adjust the PAT if any source returns 0 alerts unexpectedly, or if `BLOCKED` appears.

### Step 5 — First live run

```bash
appsec-triage --repo <owner>/<name> --sources all
```

This creates Issues and posts comments but **does not dismiss any alerts** (no `--auto-transition`). Verify in the GitHub UI:

- One Issue per `(rule_id, file)` for code-scanning, one per `(CVE, package)` for Dependabot — there should be no duplicates
- The `autotriage` label is applied (assuming you seeded it in Step 2)
- The hidden marker `<!-- triage:... -->` is present in each Issue body — search for it in the UI to confirm dedupe will work next run

If a verdict on a subsequent run flips relative to the prior one, the bot will **comment** on the existing Issue with the new conclusion. That requires `Issues: Read and write` — confirmed by Step 4's pre-flight check.

### Step 6 — Enable auto-dismiss (optional, only after building trust)

```bash
appsec-triage --repo <owner>/<name> --sources all --auto-transition
```

The bot now dismisses Dependabot and Code Scanning alerts judged `false_positive` above the tier's `transition_floor`. **Tier-1 (critical) repos never auto-dismiss**, secret scanning never auto-dismisses, and `tolerable_risk` is never used as a dismiss reason automatically — those are guardrails enforced in code, not flags.

Recommended progression: run with `--auto-transition` on a non-critical repo for two or three cycles. Manually audit the dismissed alerts. If you trust the FPs the bot is closing, expand to more repos.

### Step 7 — Persist `.triage_history.jsonl`

The history file drives the Consistency Gate (anti flip-flop) and the org-wide false-positive consensus check (`≥3 other repos at FP` → skip the Judge). In CI the runner is ephemeral by default, so the file does not survive between runs. Options, in increasing order of robustness:

1. **GitHub Actions artifact** (shipped workflow). Auditable, but downloading + re-uploading on every run is slow once history grows.
2. **S3 / GCS bucket**. The workflow downloads at cycle start, uploads at cycle end. Standard for production deployments.
3. **Dedicated state repo** (commit the JSONL on every cycle). Gives you a git history of every triage decision, at the cost of one commit per cycle.
4. **Private gist**. Lightweight middle ground when you do not want infrastructure but want persistence.

The file is append-only and one JSON object per line — handle it accordingly.

### Step 8 — Schedule

```yaml
# .github/workflows/triage.yml — daily 04:30 UTC, manual override available
on:
  schedule: [{cron: "30 4 * * *"}]
  workflow_dispatch:
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -e .
      - run: appsec-triage --repos org/svc-api,org/svc-web,org/internal --sources all --auto-transition
        env:
          GITHUB_TOKEN: ${{ secrets.APPSEC_TRIAGE_PAT }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
          LLM_BASE_URL: ${{ vars.LLM_BASE_URL }}
          LLM_MODEL: ${{ vars.LLM_MODEL }}
      - uses: actions/upload-artifact@v4
        with: { name: triage-history, path: .triage_history.jsonl }
```

For batches over ~20 repos, switch from `--repos` to a GitHub Actions matrix — one parallel job per repo — to stay under GitHub rate limits on a single PAT.

### Step 9 — Monitor

What to alert on:

- **Exit code != 0**: any non-zero indicates a fetch error (3), auth error (2), or empty input (1). Pipe `appsec-triage … || notify "triage exited $?"` in cron.
- **`BLOCKED` count > 0** in the summary: PAT permission drift. Re-run the pre-flight check from Step 1.
- **`needs_review` count keeps growing run-over-run**: the bot is not converging. Either the LLM Judge is being too conservative (raise floors), or your repos have genuinely new findings (expected during a backlog burn-down).
- **`rotate_now` count > 0**: a secret was leaked. Treat as a paging incident — the bot will create an Issue but cannot rotate the credential for you.

## Modes (recap)

| Command                                                              | What it does                                                                                              |
|----------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `appsec-triage --offline`                                            | Bundled fixtures, no network, no LLM. Demonstrates both branches end-to-end.                              |
| `appsec-triage --repo owner/name --dry-run`                          | Hits GitHub for one repo, computes verdicts, **mutates nothing**.                                         |
| `appsec-triage --repo owner/name --auto-transition`                  | Hits GitHub for one repo, posts/closes Issues, dismisses high-confidence FPs (tier-1 still blocked).      |
| `appsec-triage --repos owner/a,owner/b --dry-run`                    | v0.2.1: batch mode. Same pipeline per repo with error isolation and a per-repo summary.                   |
| `appsec-triage --repos owner/a,owner/b --auto-transition`            | v0.2.1: batch mode with auto-dismiss. Tier-1 still blocked per repo.                                      |

Exit codes: `0` ok · `1` empty input · `2` arg or auth error · `3` fetch error (Z1 error-note path). In batch mode, the worst code seen across the batch is returned.

## Limitations (PoC)

- **`/search/code` only indexes the default branch and files smaller than 384 KB.** Code on feature branches, in vendored subtrees, or in oversized generated files is invisible to reachability. The Truth Table treats absence-of-hits as evidence only under explicit conditions; the Judge is told about the caveat in its prompt.
- v2 ingests Dependabot, CodeQL/SAST, and Secret Scanning. New sources (Dependency Review API at PR time, supply chain attestations, runtime telemetry) are not wired.
- The LLM endpoint must speak the OpenAI chat completions API. Anything that doesn't (raw Anthropic API, Bedrock InvokeModel) needs a thin adapter.
- History persistence in CI is artifact-only. See [Memory](#memory-and-org-wide-consensus).
- Self-feedback is excluded but cross-org coupling is not modeled. If your "org" has subgroups with different risk postures, partition the history file per group.

## Sources

Three GitHub security signals, three risk models. Pick what to ingest with `--sources` (`dependabot` | `code-scanning` (alias `codeql`) | `secret-scanning` (alias `secret`) | `all` | comma-separated). Default = `dependabot` for v1 compatibility.

### Dependabot

Full Z1 → Z2 → Z3 → Z4 pipeline. Truth Table Rules A (`archived AND no hits`) and B (`advisory APIs AND no hits AND repo representative`) can force `false_positive` without invoking the Judge. Org-wide consensus over `(CVE+package)` works across repositories of the same org. Dismiss vocabulary: `not_used` / `inaccurate` / `tolerable_risk` (the last one is **never** chosen automatically).

### Code Scanning (CodeQL + 3rd-party SAST)

Same pipeline shape but **the question is different**: "is this finding actionable in this repo?" rather than "does this dependency affect this repo?".

- Advisory Agent is skipped (the rule already names what is vulnerable).
- Evidence Agent is replaced by location metadata from the alert itself.
- Two Truth Table rules unique to CodeQL:
  - **Rule C** — `location_path` inside a test directory (`tests/`, `__tests__/`, `spec/`, `e2e/`, …) → `false_positive`. SAST findings inside test scaffolding are not exploitable from runtime.
  - **Rule D** — repo archived → `false_positive` (analogous to Dependabot's Rule A).
- Judge prompt is a different file (`JUDGE_SYSTEM_PROMPT_CODE_SCANNING`) so the model frames its reasoning around reachability of the rule pattern, not dependency usage.
- Dismiss vocabulary: `"false positive"` / `"won't fix"` / `"used in tests"` (note the spaces — that's the CodeQL API contract).

### Secret Scanning — short-circuit

**Different risk model entirely.** A leaked credential is leaked; there is no "is it reproducible?" question to ask. The pipeline collapses to:

```
Z1 routing  →  Z4 output  (no Z2, no Z3, no LLM)
```

- `VerdictKind.ROTATE_NOW` is the only verdict a secret alert can have. `confidence=1.0` — this is structural, not probabilistic.
- Issue body is an urgent "rotate now" template with rotation steps, the location of the leak, the commit SHA, and an explicit reminder that removing the secret from git history is not sufficient (it may have been scraped already).
- Auto-dismiss is **structurally impossible** for this source: (1) the `GitHubClient` does not expose a `dismiss_secret_scanning_alert` method, (2) `issue_manager._maybe_dismiss` short-circuits with `GUARDRAIL: secret scanning alerts are never auto-dismissed`. Belt + suspenders.
- The Consistency Gate still applies — a re-detected secret yields SKIP, not a duplicate Issue.

## Project layout

```
appsec-triage/
├── triage_cycle.py              # CLI entry point
├── triage/
│   ├── cli.py                   # argparse + pipeline driver
│   ├── types.py                 # Alert, EvidenceMatrix, Verdict, Tier — frozen dataclasses
│   ├── llm.py                   # OpenAI-compatible client (httpx, temperature=0)
│   ├── github_client.py         # Real + offline backends behind one shape
│   ├── routing.py               # Z1 fast-paths
│   ├── advisory_agent.py        # Z2 LLM extraction of vulnerable API names
│   ├── evidence_agent.py        # Z2 deterministic facts (counts + booleans)
│   ├── truth_table.py           # Z2 tier + forced verdicts (Rules A/B)
│   ├── memory.py                # org-wide consensus reader (≥3 other repos)
│   ├── judge.py                 # Z3 LLM Judge, strict JSON contract (per-source prompts)
│   ├── prosecutor.py            # Z3 adversarial — deterministic + LLM attack
│   ├── critic.py                # Z3 silent quality gate (tier floor)
│   ├── consistency.py           # Z3 anti flip-flop + history append
│   ├── secret_scanning.py       # v2: Z1→Z4 short-circuit + rotate-now Issue body
│   └── issue_manager.py         # Z4 Issue + source-aware dismiss + tier-1 guardrail
├── fixtures/alerts/             # offline demo data
├── docs/                        # diagrams (architecture.svg + sequence.svg + HTML versions)
├── .github/workflows/triage.yml # cron + workflow_dispatch
├── pyproject.toml               # package metadata + entry point (source of truth)
├── requirements.txt             # kept for ad-hoc local installs (httpx only)
├── .env.example
├── .gitignore                   # ignores .env, .triage_history.jsonl, .venv, __pycache__
└── .triage_history.jsonl        # append-only memory (gitignored)
```

## License

PoC. Adopt freely. Audit before production.
