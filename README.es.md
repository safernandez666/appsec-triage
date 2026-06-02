# AppSec Triage Bot

<!-- README-I18N:START -->

[English](./README.md) | **Español**

<!-- README-I18N:END -->

Triaje defensivo multi-agente de alertas de Dependabot. Reduce los falsos positivos y la fatiga de alertas del equipo. GitHub-native. Python 3.11+. Única dependencia runtime: `httpx`.

> **Estado:** v0.2.1. Ingiere tres fuentes: Dependabot, GitHub Code Scanning (CodeQL + SAST de terceros), y Secret Scanning. Ver [Fuentes](#fuentes). Modo batch multi-repo via `--repos` — ver [Modo batch](#modo-batch-multi-repo).

## Por qué existe

Dependabot es bueno encontrando dependencias vulnerables y ruidoso a la hora de decirte cuáles afectan *realmente* a tu repositorio. Después de unos meses tenés un backlog de advisories que nadie triagea, un canal de Slack con alertas que envejecieron a stale, y el equipo empieza a ignorar findings reales.

Este bot lee las alertas de Dependabot y responde, por alerta: **¿esto nos afecta?** Produce un veredicto `false_positive` / `reproducible` / `needs_review` con una conclusión en lenguaje plano que podés leer en un GitHub Issue. Los falsos positivos pueden auto-dismissearse (configurable, nunca en repos tier-1). Los reproducibles quedan abiertos para que el equipo los corrija. `needs_review` significa que el bot mismo no está seguro — deciden los humanos.

<p align="center">
  <img src="docs/architecture.svg" alt="Arquitectura del pipeline: Z1 routing → Z2 investigación → Z3 juicio → Z4 salida. Guardrail tier-1 en coral." width="720"/>
</p>

## Inicio rápido

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e .                 # source of truth: pyproject.toml
cp .env.example .env             # llená LLM_BASE_URL / LLM_API_KEY / LLM_MODEL / GITHUB_TOKEN

# Demo offline: sin credenciales, solo fixtures. Flujo heurístico puro, sin gastar tokens.
appsec-triage --offline

# Online dry-run: lee alertas, computa veredictos, no muta nada.
appsec-triage --repo owner/name --dry-run

# Online con auto-dismiss para falsos positivos de alta confianza.
# Los repos tier-1 (críticos) NUNCA se auto-dismissean. No negociable.
appsec-triage --repo owner/name --auto-transition

# v0.2.1: batch sobre una flota chica desde una sola invocación. Si un repo
# falla, el resto sigue corriendo; al final se imprime un resumen y gana el
# peor exit code.
appsec-triage --repos owner/a,owner/b,owner/c --dry-run
```

`--offline`, `--repo` y `--repos` son mutuamente excluyentes. `--dry-run` y `--auto-transition` aplican a todos los modos.

> El console script `appsec-triage` y el legacy `python triage_cycle.py` son intercambiables. El shim existe para que el wording original del spec (`python triage_cycle.py …`) siga funcionando, pero después de instalar el console script es el entry point idiomático.

### Instalación dev

```bash
pip install -e ".[dev]"          # agrega pytest + ruff
```

### Variables de entorno requeridas

| Var             | Propósito                                                                                                       |
|-----------------|-----------------------------------------------------------------------------------------------------------------|
| `LLM_BASE_URL`  | Endpoint de chat completions OpenAI-compatible. Default `https://api.openai.com/v1`. Apuntá a tu gateway.       |
| `LLM_API_KEY`   | Bearer token para el LLM. Si falta, Advisory devuelve `()` y el Judge degrada al fallback `needs_review`.       |
| `LLM_MODEL`     | Id del modelo. Default `gpt-4o-mini`. Cualquier modelo que respete `temperature=0` y `response_format=json_object`. |
| `GITHUB_TOKEN`  | PAT (o App token) con `security_events:write` + `issues:write`.                                                 |

Toda llamada al LLM usa `temperature=0` por contrato. Mismo input → mismo veredicto, by design.

## Arquitectura — el LLM nunca actúa solo

Cada alerta atraviesa gates determinísticos a la entrada (Truth Table) y a la salida (Prosecutor + Critic + Consistency). El Final Judge es un LLM, pero queda sandwicheado entre capas que pueden anularlo sin involucrar a ningún modelo.

```
Z1 routing  →  Z2 investigation (deterministic + LLM-extraction)  →  Z3 judgment  →  Z4 output
```

<p align="center">
  <img src="docs/sequence.svg" alt="Una alerta trazada end-to-end a través de CLI, GitHub, LLM, motor determinístico y store de historial. Coral = retorno primario del Judge." width="880"/>
</p>

<p align="center"><sub><em>Una alerta trazada end-to-end. La flecha coral es el veredicto del Judge — la decisión central; todo lo demás es plomería.</em></sub></p>

### Zona 1 — Routing

Fast-paths sin LLM:
- `state in {fixed, dismissed, auto_dismissed}` → cerrar cualquier Issue existente con una nota de una línea. Sin Zona 2/3.
- Fetch fallido (red, auth) → nota de error, sin Zona 2/3.

### Zona 2 — Investigación (corre antes de cualquier LLM que produzca veredicto)

- **Advisory Agent** (LLM, solo extracción): saca los nombres de símbolos punteados de APIs vulnerables (`requests.Session`, `yaml.load`, …) del texto del advisory. Sin LLM → `()`. El modelo nunca decide nada acá; el contrato es una lista JSON estricta de nombres.
- **Evidence Agent** (Python puro): code search de alcanzabilidad (usos del paquete y de los símbolos que sacó el Advisory), perfil del repo (archived / lenguaje / edad), presencia de manifest / lockfile / Dockerfile. Devuelve una `EvidenceMatrix` de counts y booleanos, **sin interpretación**.
- **Pre-flight Truth Table** (Python puro): asigna un tier y puede **forzar** un veredicto, salteándose el LLM por completo:
  - **Rule A** — `archived AND direct_package_hits == 0` → `false_positive`. El code path vulnerable no puede correr en un repo archivado sin uso del paquete.
  - **Rule B** — `advisory_has_specific_apis AND direct_package_hits == 0 AND (repo_active OR age_days ≥ 180)` → `false_positive`. Ausencia de evidencia tratada como evidencia, pero solo cuando el advisory nombra APIs específicas Y el default branch es representativo.
- **Consenso org-wide** (`triage/memory.py`): si el mismo `CVE+package` fue clasificado como `false_positive` en ≥ 3 **otros** repositorios de esta org, el bot defaultea a ese consenso y **saltea al Judge**. El repo actual nunca contribuye a su propio consenso. La confianza se capea en 0.93 — lo suficiente para superar los floors de Tier 2/3/4, **por debajo del floor 0.95 de Tier 1** para que los repos críticos nunca auto-FP por hearsay.

### Zona 3 — Juicio

- **Final Judge** (LLM, contrato JSON estricto, `temperature=0`): devuelve `{verdict, confidence, human_conclusion}`. `human_conclusion` es plain English, sin scores, sin nombres de agentes, sin primera persona — es lo que va a leer el humano en el Issue. Tres capas defensivas protegen el contrato: system prompt + `response_format={"type":"json_object"}` + un validador `_parse_response` que descarta respuestas malformadas y cae al fallback `needs_review`.
- **Prosecutor** (`triage/prosecutor.py`): revisión adversarial. Checks determinísticos de contradicción primero (baratos, no alucinables), LLM attack opcional después si no hubo nada concreto que marcar. Puede pedir **un** recompute de evidencia. Solo **degrada** a `needs_review`; nunca promueve. Asimetría intencional: un Prosecutor que pudiera promover estaría haciendo el laburo del Judge.
- **Critic** (`triage/critic.py`): silent quality gate. Si `confidence < tier.post_floor`, degrada a `needs_review`. Nunca aparece en el body del Issue. `needs_review` es un estado de falla por spec, no un hedge cómodo.
- **Consistency Gate** (`triage/consistency.py`): anti flip-flop entre corridas. Lee `.triage_history.jsonl` y compara con el veredicto previo para este `(repo, CVE+package)`:
  - **SKIP** — mismo veredicto que el ciclo anterior → no postear comment nuevo, no re-postear.
  - **POST** — el veredicto flippeó Y la nueva confianza ≥ 0.85 → postear la corrección.
  - **GUARD** — el veredicto flippeó Y la nueva confianza < 0.85 → postear un mensaje guard de "please review before closing". Sin acción automática.
  - **FIRST** — sin historial previo → post estándar.

### Zona 4 — Salida (GitHub-first, sin Jira)

- Una Issue por alerta. Label `autotriage`. Marker HTML oculto `<!-- triage:CVE::ecosystem::package -->` en el body para tracking de estado.
- La conclusión del triaje va como comentario. El body de la Issue se crea una vez.
- Auto-transition: cuando `--auto-transition` está set Y `verdict == false_positive` Y `confidence ≥ tier.transition_floor`, la alerta de Dependabot se dismissea vía `PATCH /repos/{o}/{r}/dependabot/alerts/{n}` con `state=dismissed`. La razón del dismiss es `not_used` para las reglas no-hits de la Truth Table, `inaccurate` en otro caso. **Nunca** `tolerable_risk` automáticamente — esa es una decisión humana de política.

## Guardrails (no negociables)

- **Los repos tier-1 (críticos) NUNCA se auto-dismissean**, sin importar la confianza. Se enforce en dos lugares: `TIER_FLOORS[CRITICAL].transition_floor = float("inf")` (la comparación de confianza no puede pasar) Y un `if tier.tier is Tier.CRITICAL: block` explícito en `_maybe_dismiss`. Cinturón + tiradores. Si alguien edita los floors a un valor finito, el early return es la red de seguridad.
- **Nunca clonar repos.** La alcanzabilidad viene de `/search/code` solamente.
- **Nunca escribir código en los repos target.**
- **Nunca dismissear alertas fuera de las reglas de arriba.** Sin auto-reason de `tolerable_risk`.
- **`temperature=0`** en cada llamada al LLM. Mismo input → mismo veredicto.

## Memoria y consenso org-wide

`.triage_history.jsonl` es append-only. Una línea JSON por alerta por ciclo:

```json
{"ts":"2026-05-30T12:00:00+00:00","repo":"org/svc","identity":"CVE-2023-32681::pip::requests","alert_number":202,"verdict":"false_positive","confidence":0.92,"source":"judge"}
```

Dos consumers:
1. **Consistency Gate** — la última entry para `(repo, identity)` define SKIP/POST/GUARD.
2. **Consenso org-wide** — última entry por otro repo para este `identity`; si ≥ 3 de ellos son `false_positive`, defaultea a ese consenso antes de invocar al Judge.

En CI el runner es efímero y el archivo no sobrevive entre runs por default. El workflow incluido sube el archivo como artifact para auditoría. Para producción, persistilo en S3, un gist privado, o un repositorio de estado dedicado.

## Modo batch (multi-repo)

`--repos` corre el pipeline completo contra una lista separada por comas de repos en una sola invocación. Existe porque los equipos reales tienen más de un repo, y las alternativas — un loop de bash con `set -e`, o una matrix de GitHub Actions — son frágiles o pesadas.

```bash
# Dry-run sobre una flota
appsec-triage --repos org/svc-api,org/svc-web,org/internal-tools --dry-run

# Lo mismo con las tres fuentes y auto-dismiss activado.
# Los guardrails tier-1 siguen aplicando por repo — no hay override batch-wide.
appsec-triage \
  --repos org/svc-api,org/svc-web,org/internal-tools \
  --sources all \
  --auto-transition
```

Qué ganás contra un loop de bash:

- **Aislamiento de errores.** Un repo que falla (auth, fetch, crash inesperado) no aborta el batch. El driver atrapa todo, registra un `_RepoResult`, y pasa al siguiente. El camino single-repo `--repo` ahora reusa el mismo helper, así que ambos paths comparten la misma postura defensiva.
- **Resumen por repo.** Al final ves líneas `ok` / `FAIL` por repo con fast-path counts, continue counts, y el mensaje de error cuando aplica — auditeable en un log de `cron` sin scrollear.
- **Exit code honesto.** El exit code global es el peor exit code visto por repo, así que `cron` / CI / notificaciones a Slack siguen detectando fallas parciales en lugar de tragárselas.

Qué **no** hace:

- Override de `--sources` por repo — `--sources` es global al batch. Si necesitás distintas fuentes por repo, corré múltiples invocaciones.
- Paralelismo. El driver itera serial. Los rate limits de GitHub hacen que batches paralelos sobre un PAT sean más foot-gun que feature; una matrix de Actions sigue siendo la herramienta correcta más allá de ~20 repos.
- Archivos de configuración. El flag acepta a propósito una lista plana separada por comas. Si tu flota necesita un YAML, ya superaste este modo.

Los guardrails tier-1 se evalúan **por repo**: un repo crítico dentro de un batch de cincuenta sigue sin ser auto-dismisseado, sin importar los flags alrededor.

## Modos (recap)

| Comando                                                            | Qué hace                                                                                            |
|--------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `appsec-triage --offline`                                          | Fixtures incluidas, sin red, sin LLM. Demuestra ambas ramas end-to-end.                             |
| `appsec-triage --repo owner/name --dry-run`                        | Llama a GitHub para un repo, computa veredictos, **no muta nada**.                                  |
| `appsec-triage --repo owner/name --auto-transition`                | Llama a GitHub para un repo, postea/cierra Issues, dismissea FPs de alta confianza (tier-1 sigue bloqueado). |
| `appsec-triage --repos owner/a,owner/b --dry-run`                  | v0.2.1: modo batch. Mismo pipeline por repo con error isolation y resumen por repo.                 |
| `appsec-triage --repos owner/a,owner/b --auto-transition`          | v0.2.1: modo batch con auto-dismiss. Tier-1 sigue bloqueado por repo.                               |

Exit codes: `0` ok · `1` input vacío · `2` error de argumentos o auth · `3` error de fetch (camino Z1 error-note). En modo batch, el peor exit code del batch es el que retorna.

## Limitaciones (PoC)

- **`/search/code` solo indexa la rama por default y archivos menores a 384 KB.** Código en feature branches, en subtrees vendored, o en archivos generados grandes es invisible para la alcanzabilidad. La Truth Table trata la ausencia de hits como evidencia solo bajo condiciones explícitas; al Judge se le informa del caveat en su prompt.
- v2 ingiere Dependabot, CodeQL/SAST y Secret Scanning. Fuentes nuevas (Dependency Review API en PR time, attestations de supply chain, telemetría de runtime) no están wireadas.
- El endpoint del LLM tiene que hablar la API de chat completions de OpenAI. Cualquier cosa que no la hable (API cruda de Anthropic, Bedrock InvokeModel) necesita un adapter delgado.
- La persistencia del historial en CI es solo via artifact. Ver [Memoria](#memoria-y-consenso-org-wide).
- El auto-feedback queda excluido pero el coupling cross-org no está modelado. Si tu "org" tiene subgrupos con posturas de riesgo distintas, particioná el archivo de historial por grupo.

## Fuentes

Tres señales de seguridad de GitHub, tres modelos de riesgo. Elegís qué ingestar con `--sources` (`dependabot` | `code-scanning` (alias `codeql`) | `secret-scanning` (alias `secret`) | `all` | lista separada por coma). Default = `dependabot` para compat con v1.

### Dependabot

Pipeline Z1 → Z2 → Z3 → Z4 completo. Las Truth Table Rules A (`archived AND no hits`) y B (`advisory APIs AND no hits AND repo representativo`) pueden forzar `false_positive` sin invocar al Judge. El consenso org-wide sobre `(CVE+package)` funciona entre repositorios de la misma org. Vocabulario de dismiss: `not_used` / `inaccurate` / `tolerable_risk` (este último **nunca** se elige automáticamente).

### Code Scanning (CodeQL + SAST de terceros)

Misma forma del pipeline pero **la pregunta es distinta**: "¿este finding es accionable en este repo?" en lugar de "¿esta dependencia afecta a este repo?".

- El Advisory Agent se saltea (la rule ya nombra lo que está vulnerable).
- El Evidence Agent se reemplaza por la metadata de location de la alerta misma.
- Dos rules de Truth Table únicas para CodeQL:
  - **Rule C** — `location_path` dentro de un directorio de tests (`tests/`, `__tests__/`, `spec/`, `e2e/`, …) → `false_positive`. Los findings de SAST adentro de scaffolding de tests no son explotables desde runtime.
  - **Rule D** — repo archivado → `false_positive` (análoga a la Rule A de Dependabot).
- El prompt del Judge es un archivo distinto (`JUDGE_SYSTEM_PROMPT_CODE_SCANNING`) para que el modelo encuadre su razonamiento alrededor de la alcanzabilidad del patrón de la rule, no del uso de dependencias.
- Vocabulario de dismiss: `"false positive"` / `"won't fix"` / `"used in tests"` (notar los espacios — es el contrato de la API de CodeQL).

### Secret Scanning — short-circuit

**Modelo de riesgo completamente distinto.** Una credencial leakeada está leakeada; no hay pregunta de "¿es reproducible?" para responder. El pipeline colapsa a:

```
Z1 routing  →  Z4 output  (sin Z2, sin Z3, sin LLM)
```

- `VerdictKind.ROTATE_NOW` es el único veredicto que una secret alert puede tener. `confidence=1.0` — esto es estructural, no probabilístico.
- El body de la Issue es un template urgente "rotate now" con pasos de rotación, la location del leak, el commit SHA, y un recordatorio explícito de que sacar el secret de la historia de git no es suficiente (puede haber sido scrapeado ya).
- Auto-dismiss es **estructuralmente imposible** para esta fuente: (1) el `GitHubClient` no expone método `dismiss_secret_scanning_alert`, (2) `issue_manager._maybe_dismiss` short-circuitea con `GUARDRAIL: secret scanning alerts are never auto-dismissed`. Cinturón + tiradores.
- La Consistency Gate sigue aplicando — un secret re-detectado da SKIP, no una Issue duplicada.

## Estructura del proyecto

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

## Licencia

PoC. Adoptar libremente. Auditar antes de producción.
