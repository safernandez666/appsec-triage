# AppSec Triage Bot

<!-- README-I18N:START -->

[English](./README.md) | **Español**

<!-- README-I18N:END -->

Triaje defensivo multi-agente de alertas de Dependabot. Reduce los falsos positivos y la fatiga de alertas del equipo. GitHub-native. Python 3.11+. Única dependencia runtime: `httpx`.

> **Estado:** Proof of Concept. v1 consume solo alertas de Dependabot. CodeQL y secret scanning están documentados como [extension hooks](#extensiones-para-v2) para v2.

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
```

`--offline` y `--repo` son mutuamente excluyentes. `--dry-run` y `--auto-transition` aplican tanto a corridas online como a dry runs.

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

## Modos (recap)

| Comando                                                | Qué hace                                                                              |
|--------------------------------------------------------|---------------------------------------------------------------------------------------|
| `python triage_cycle.py --offline`                     | Fixtures incluidas, sin red, sin LLM. Demuestra ambas ramas end-to-end.               |
| `python triage_cycle.py --repo owner/name --dry-run`   | Llama a GitHub, computa veredictos, **no muta nada**.                                 |
| `python triage_cycle.py --repo owner/name --auto-transition` | Llama a GitHub, postea/cierra Issues, dismissea FPs de alta confianza (tier-1 sigue bloqueado). |

Exit codes: `0` ok · `1` input vacío · `2` error de argumentos o auth · `3` error de fetch (camino Z1 error-note).

## Limitaciones (PoC)

- **`/search/code` solo indexa la rama por default y archivos menores a 384 KB.** Código en feature branches, en subtrees vendored, o en archivos generados grandes es invisible para la alcanzabilidad. La Truth Table trata la ausencia de hits como evidencia solo bajo condiciones explícitas; al Judge se le informa del caveat en su prompt.
- v1 consume solo alertas de Dependabot. CodeQL y secret scanning están documentados como hooks para v2.
- El endpoint del LLM tiene que hablar la API de chat completions de OpenAI. Cualquier cosa que no la hable (API cruda de Anthropic, Bedrock InvokeModel) necesita un adapter delgado.
- La persistencia del historial en CI es solo via artifact. Ver [Memoria](#memoria-y-consenso-org-wide).
- El auto-feedback queda excluido pero el coupling cross-org no está modelado. Si tu "org" tiene subgrupos con posturas de riesgo distintas, particioná el archivo de historial por grupo.

## Extensiones para v2

Dos extension hooks viven justo después de la resolución de fuente en Zona 1. Ambos están deliberadamente sin wirear:

### Alertas de CodeQL

- Extender `GitHubClient` con `list_code_scanning_alerts(owner, name)` apuntando a `/repos/{o}/{r}/code-scanning/alerts`.
- Agregar un classmethod `Alert.from_code_scanning_payload` que llene el mismo shape plano (el resto del pipeline es agnostic).
- Extender la `EvidenceMatrix` para llevar señales específicas de CodeQL (rule id, location, dataflow class). El prompt del Judge crece una sección; las reglas de la Truth Table se pueden dejar o agregarles análogos CodeQL.
- Reusar Advisory + Judge + Prosecutor + Critic + Consistency sin cambios.

### Alertas de Secret scanning

- Modelo de riesgo distinto: no existe la pregunta "¿es reproducible?" — un secreto leakeado quedó leakeado.
- **Short-circuit** en Z1 routing: una alerta nueva de secret scanning → abrir una Issue de "rotate now" con la location del leak y qué tipo de secreto, sin involucrar al LLM, sin Truth Table, sin Prosecutor.
- La Consistency Gate sigue aplicando (SKIP si el mismo secreto ya fue reportado).
- Auto-transition queda permanentemente off para esta fuente — los humanos tienen que confirmar la rotación.

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
│   ├── judge.py                 # Z3 LLM Judge, strict JSON contract
│   ├── prosecutor.py            # Z3 adversarial — deterministic + LLM attack
│   ├── critic.py                # Z3 silent quality gate (tier floor)
│   ├── consistency.py           # Z3 anti flip-flop + history append
│   └── issue_manager.py         # Z4 Issue + Dependabot dismiss + tier-1 guardrail
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
