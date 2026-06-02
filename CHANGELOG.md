# Changelog

All notable changes to **appsec-triage** are documented here.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] — 2026-06-02

### Added

- **Per-repo tier overrides via `.appsec-triage.toml`.** New `triage/config.py`
  module reads a TOML file (stdlib `tomllib`, no new runtime dep) at CLI start
  and maps `owner/name` → tier (`critical | deployed | internal | archived`).
  Overrides the Truth Table's heuristic tier classification — useful when the
  repo's static structure (deploy artifacts, archived flag) doesn't reflect
  the actual blast radius. Missing file is silent; malformed entries log to
  stderr and are skipped. Bundled example: `.appsec-triage.example.toml`.
- **Code-scanning-aware Prosecutor LLM-attack.** v0.2.1 disabled the stage-2
  LLM-attack for non-Dependabot because the Dependabot prompt + EvidenceMatrix
  produced 32/32 identical "no direct package usage hits or vulnerable API
  usage hits" contradictions against a real code-scanning batch — structurally
  vacuous reasoning about fields that don't apply to the source. v0.2.2 ships
  a `PROSECUTOR_SYSTEM_PROMPT_CODE_SCANNING` system prompt and a dedicated
  `_build_attack_payload_code_scanning` payload that explicitly forbid the
  "no reachability evidence" line of reasoning and enumerate legitimate
  attack angles for this source: vendored third-party paths
  (`/node_modules/`, `/vendor/`, `/third_party/`, `/dist/`, `/build/`,
  `.min.js`, `bootstrap-*.js`, `jquery-*.js`, `lodash-*.js`); generated or
  compiled output; rule_ids with known FP rates against library code (e.g.
  `js/xss-through-dom` against any DOM-manipulation library); internally
  inconsistent verdict reasoning. `_llm_attack` dispatches on `alert.source`
  to pick the right prompt/payload pair.
- LLM-attack is **re-enabled for code-scanning** in `cli.py`; secret-scanning
  still bypasses `prosecute()` via the Z1 short-circuit, so this is safe.

### Verified

- Run against `safernandez666/Controls` (32 code-scanning XSS findings,
  all in vendored `bootstrap-*.js` / `jquery-*.js`). The verdict counts
  did not move much — the Prosecutor still flips most to `needs_review`,
  which is the correct outcome for XSS in vendored libraries that the
  repo does not author — but every flip now carries a specific,
  auditable argument like "The file 'bootstrap-material-design.js' is
  a vendored third-party library, and the XSS risk identified is a
  common false positive when analyzing libraries that manipulate the
  DOM" instead of the previous useless "no reachability evidence"
  loop. That argument lands in the Issue body, so the reviewer can
  immediately decide whether to update Bootstrap or accept the risk.

## [0.2.1] — 2026-06-02

## [0.2.1] — 2026-06-02

### Added

- **Multi-repo batch mode.** New `--repos owner/a,owner/b,owner/c` CLI flag
  iterates the full triage pipeline over a comma-separated list of repos in a
  single invocation. Mutually exclusive with `--offline` and `--repo`. Useful
  for running the bot from a laptop or a single cron against a small fleet of
  repos without setting up a GitHub Actions matrix.
- **Error isolation between repos.** Each repo is processed inside
  `_process_single_repo_online`, which never raises — argument errors, missing
  `httpx`, GitHub fetch failures, and unexpected pipeline crashes are caught
  and recorded as a `_RepoResult` with a non-zero exit code. One repo blowing
  up cannot abort the batch. The single-repo `--repo` path now reuses the
  same helper so it gets the same defensive behavior for free.
- **Per-repo summary.** The batch run prints a final summary listing each
  repo with `ok` / `FAIL`, fast-path count, continue count, and the error
  message when applicable. The overall exit code is the worst exit code seen
  across the batch, so `cron` / CI still detects partial failure.
- **Startup banner.** Truecolor `APPSEC` banner with a violet → orange
  gradient is printed to **stderr** at CLI start so it never pollutes
  stdout. Auto-disabled when stderr is not a TTY (cron, pipes, CI). Set
  `APPSEC_NO_BANNER=1` or `NO_COLOR=1` for an explicit opt-out. New module
  `triage/banner.py` (no new runtime dependencies).
- **Auto-load `.env` from cwd.** `triage/env_loader.py` reads `KEY=VALUE`
  pairs at CLI start so users no longer need `set -a; source .env; set +a`
  before every invocation. Existing shell exports always win, matching
  the python-dotenv default — explicit overrides like
  `GITHUB_TOKEN=other appsec-triage …` keep working for one-off runs.
  Tolerates `# comments`, `export KEY=…` lines, quoted values, and
  inline `# trailing` comments on unquoted values.
- **`--repo` / `--repos` accept GitHub URLs.** `_normalize_repo_arg` peels
  off `https://`, `http://`, `git@github.com:`, `ssh://git@github.com/`,
  bare `github.com/`, trailing `/`, and a trailing `.git` so that
  `--repo https://github.com/owner/name` or
  `git@github.com:owner/name.git` both normalize to `owner/name` instead
  of silently splitting into wrong pieces.

### Unchanged (still enforced)

- Tier-1 (critical) repos are still NEVER auto-dismissed, even inside a batch.
- Secret-scanning alerts are still never auto-dismissed regardless of flag.
- `--sources` and per-source filtering apply identically to every repo in the
  batch. No way to ingest different sources per repo from one invocation;
  that would require a config file and is intentionally out of scope.

## [0.2.0] — 2026-06-01

### Added

- **Multi-source ingestion.** The bot now consumes three GitHub security signals
  through one CLI:
  - **Dependabot** (the v1 surface, unchanged behavior at default).
  - **Code Scanning** — CodeQL and 3rd-party SAST alerts. Endpoint:
    `GET /repos/{o}/{r}/code-scanning/alerts`. Requires `security-events` scope.
  - **Secret Scanning** — leaked-credential alerts. Endpoint:
    `GET /repos/{o}/{r}/secret-scanning/alerts`. Requires
    `secret-scanning-alerts: read`. **Read-only by design** — no dismiss path.
- `--sources` CLI flag (default `dependabot` for v1 compat). Tokens:
  `dependabot`, `code-scanning` (alias `codeql`), `secret-scanning`
  (alias `secret`), `all`, or any comma-separated subset.
- `AlertSource` enum (`DEPENDABOT` / `CODE_SCANNING` / `SECRET_SCANNING`).
  `Alert.source` field on every `Alert`. Source-specific factories:
  `from_dependabot_payload`, `from_code_scanning_payload`,
  `from_secret_scanning_payload`. `Alert.from_payload` is preserved as a
  shape-dispatching back-compat shim.
- **Truth Table Rule C** (CodeQL): `location_path` inside a test directory
  (`tests/`, `__tests__/`, `spec/`, `e2e/`, …) → `false_positive` with
  `source=truth_table:codeql_in_tests`. Matches case-insensitively, anywhere
  in the path.
- **Truth Table Rule D** (CodeQL): repo `archived` → `false_positive` with
  `source=truth_table:codeql_archived`. Analogous to Rule A for Dependabot.
- **Final Judge — CodeQL-specific system prompt.** Different framing:
  "is this finding actionable in this repo?" instead of "does this dependency
  affect this repo?". Same strict JSON contract. Dispatched by
  `alert.source` inside `judge.py`.
- **Source-aware dismiss vocabulary** in `issue_manager._dismiss_reason`:
  - Dependabot: `not_used` (from Truth Table no-hits rules) / `inaccurate`
    (everything else). Never `tolerable_risk` automatically.
  - Code scanning: `"used in tests"` (Rule C) / `"won't fix"` (Rule D) /
    `"false positive"` (Judge or consensus). Note the spaces — that is the
    CodeQL API contract.
- **`VerdictKind.ROTATE_NOW`** for secret scanning. The only verdict a secret
  alert can produce. `confidence=1.0` — structural, not probabilistic.
- **`triage/secret_scanning.py`** — Z1 → Z4 short-circuit. Secret alerts
  bypass Z2 investigation, Z3 judgment, and every LLM call. The Issue body
  is an urgent "rotate now" template with the leak location, commit SHA,
  rotation steps, and explicit reminder that git-history scrubbing is not
  sufficient.
- **Code-scanning fixtures:** `codeql_sql_injection_prod.json` (actionable)
  and `codeql_fp_used_in_tests.json` (Rule C forced FP).
- **Secret scanning fixture:** `secret_aws_key_leaked.json`.
- **Workflow** `workflow_dispatch` gains a `sources` input. `permissions:`
  adds `secret-scanning-alerts: read`.

### Changed

- **Issue body builder** in `issue_manager._build_issue_body` dispatches by
  `alert.source`. Dependabot body unchanged (v1 compat). CodeQL body shows
  rule + location + analyzer. Secret body is the urgent rotate-now template.
- **Alert header** in CLI output is source-aware. Examples:
  - Dependabot: `#202 requests (pip/runtime) — CVE-2023-32681 severity=medium`
  - Code scanning: `#401 [code-scanning] py/sql-injection @ app/db.py:87`
  - Secret: `#501 [secret] aws_access_key_id — severity=critical`
- `OfflineGitHubClient.load_repo_alert_sets()` accepts an optional `sources`
  filter for offline runs scoped to one or more sources.
- Default `Alert.from_payload` now dispatches by payload shape so v1 callers
  keep working when fed any of the three source payloads.

### Removed

- The `Extending to v2` README section is gone — its content moved into the
  new `Sources` section as implemented features.

### Security / Guardrails (non-negotiable, two-layer defense)

- **Secret scanning is never auto-dismissed.** Enforced two ways:
  1. The `GitHubClient` does NOT expose a `dismiss_secret_scanning_alert`
     method. If a future caller reaches for it, it does not exist.
  2. `issue_manager._maybe_dismiss` early-returns on
     `alert.source is AlertSource.SECRET_SCANNING` with
     `GUARDRAIL: secret scanning alerts are never auto-dismissed — humans
     must confirm rotation`.
- **Tier-1 (critical) repos still never auto-dismiss** for any source. The
  v1 belt-and-suspenders (`transition_floor = float("inf")` + explicit
  `if tier.tier is Tier.CRITICAL: block`) is unchanged.

### Notes

- The pipeline shape for Dependabot is unchanged. v1 callers that did not
  pass `--sources` see identical behavior.
- The Consistency Gate works across all three sources via `Alert.identity`,
  which is source-specific: `CVE::ecosystem::package` for Dependabot,
  `rule_id::path` for CodeQL, `secret_type::first_commit_sha` for Secret.

## [0.1.0] — 2026-05-30

### Added

- Initial PoC. Multi-agent defensive triage of Dependabot alerts.
- Four-zone pipeline: Z1 routing → Z2 investigation → Z3 judgment → Z4 output.
- Truth Table with Rules A and B that can force `false_positive` without
  invoking the Judge LLM.
- Final Judge LLM with strict JSON contract, `temperature=0`,
  `response_format={"type":"json_object"}`, and a defensive `_parse_response`
  validator that falls back to `needs_review` on any contract violation.
- Prosecutor (deterministic checks first, optional LLM attack after,
  recompute-once).
- Critic (silent quality gate, degrade-only on `confidence < tier.post_floor`).
- Consistency Gate (anti flip-flop across runs over append-only
  `.triage_history.jsonl`).
- Org-wide false_positive consensus reader (≥3 other repos, current repo
  excluded, confidence capped at `0.93` so it never clears Tier-1).
- Tier-1 guardrail (`transition_floor = float("inf")` + explicit
  early-return). Auto-dismiss permanently blocked in tier-1 repos.
- `appsec-triage` console script and `python triage_cycle.py` shim. Packaged
  via `pyproject.toml` with `httpx` as the single runtime dependency.
- GitHub Actions workflow with cron + `workflow_dispatch`. History uploaded
  as an artifact.
- Offline demo with three fixtures (FP forced via Rule A, reproducible,
  Z1 fast-path close).
- Architecture and sequence diagrams in `docs/`. English and Spanish READMEs
  with language switcher.

[0.2.0]: https://github.com/safernandez666/appsec-triage/releases/tag/v0.2.0
[0.1.0]: https://github.com/safernandez666/appsec-triage/releases/tag/v0.1.0
