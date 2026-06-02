# LinkedIn teaser — v0.2.0 release

**Cover image:** `docs/blog-cover.png` (1600×840 PNG, ya commiteado en el repo).
**Length:** ~1700 chars (entra sin "ver más" en mobile).
**Cierre con pregunta** → engagement hook para LinkedIn.

---

## Versión principal (ES) — copy-paste

> **v0.2.0 del bot que tría tus alertas de Dependabot, CodeQL y Secret scanning está vivo.**
>
> La decisión arquitectónica más importante: el LLM nunca actúa solo. Está sandwicheado entre dos capas determinísticas en Python puro.
>
> Antes del LLM, una Truth Table resuelve ~40% de los casos sin gastar un token (archivado + sin uso → false positive; advisory nombra APIs específicas y ninguna aparece en el código → false positive). Después del LLM, un Prosecutor adversarial puede degradar el veredicto si la evidencia local lo contradice, y un Critic silencioso lo baja a `needs_review` si la confianza no llega al floor del tier. El LLM aporta donde solo el lenguaje natural puede aportar — extraer APIs del advisory, redactar la conclusión legible que ve el reviewer. El resto es Python determinístico que vos podés auditar línea por línea.
>
> Tres guardrails no-negociables, los tres con cinturón y tiradores (dos capas independientes):
>
> 1️⃣ Tier-1 nunca auto-dismissea. `transition_floor = float("inf")` para que la comparación numérica no pueda pasar, más early return explícito en el dismiss handler.
>
> 2️⃣ Secret scanning nunca auto-dismissea. El método dismiss directamente no existe en el GitHub client, más un guard return explícito en el handler. Una credencial leakeada no es una pregunta de "¿es reproducible?", es "rotar ya".
>
> 3️⃣ `temperature=0` en cada llamada LLM. Mismo input → mismo veredicto, por contrato. Sin esto el Consistency Gate persigue su propia cola entre corridas.
>
> Stack: Python 3.11, una sola dependencia runtime (`httpx`), GitHub Actions con cron + workflow_dispatch. README en EN y ES. Modo `--offline` con fixtures para probarlo sin gastar tokens ni tocar tu repo.
>
> Código: https://github.com/safernandez666/appsec-triage
> Blog post completo con la historia: en breve.
>
> ¿Qué heurísticas determinísticas usás antes de meter un LLM en tu pipeline de seguridad?
>
> #AppSec #SecurityEngineering #LLM #OpenSource

---

## Versión corta (~900 chars) — si tu feed prefiere posts breves

> **v0.2.0 vivo.** Bot multi-agente que tría alertas de Dependabot, CodeQL y Secret scanning.
>
> La decisión que más me costó pensar: el LLM nunca actúa solo. Lo sandwicheo entre dos capas determinísticas en Python puro. Una Truth Table resuelve ~40% sin tocar el modelo. Después, Prosecutor + Critic + Consistency pueden degradar el veredicto si la evidencia local lo contradice.
>
> Tres guardrails con belt + suspenders:
>
> — Tier-1 nunca auto-dismissea (`transition_floor = inf` + early return).
> — Secret scanning nunca auto-dismissea (el método dismiss no existe en el client + guard explícito).
> — `temperature=0` en cada llamada LLM.
>
> https://github.com/safernandez666/appsec-triage
>
> ¿Qué heurísticas determinísticas tenés antes del LLM en tu pipeline?
>
> #AppSec #LLM #OpenSource

---

## Versión en inglés — para alcance internacional

> **v0.2.0 of the bot that triages your Dependabot, CodeQL, and Secret scanning alerts is live.**
>
> The most important architectural decision: the LLM never acts alone. It's sandwiched between two deterministic layers in pure Python.
>
> Before the LLM, a Truth Table resolves ~40% of cases without spending a token (archived + unused → false positive; advisory names specific APIs and none appear in code → false positive). After the LLM, an adversarial Prosecutor can downgrade the verdict when local evidence contradicts it, and a silent Critic drops it to `needs_review` if confidence doesn't clear the tier floor. The LLM contributes where only natural language can — extracting APIs from advisories, writing the human-readable conclusion. The rest is deterministic Python you can audit line by line.
>
> Three non-negotiable guardrails, each with belt + suspenders (two independent layers):
>
> 1️⃣ Tier-1 repos never auto-dismiss. `transition_floor = float("inf")` so the numeric comparison can't pass, plus an explicit early return in the dismiss handler.
>
> 2️⃣ Secret scanning never auto-dismisses. The dismiss method doesn't exist on the GitHub client at all, plus a guard return in the handler. A leaked credential is not a "is this reproducible?" question — it's "rotate now".
>
> 3️⃣ `temperature=0` on every LLM call. Same input → same verdict, by contract. Otherwise the Consistency Gate chases its own tail across runs.
>
> Stack: Python 3.11, single runtime dependency (`httpx`), GitHub Actions cron + `workflow_dispatch`. README in EN and ES. An `--offline` mode with fixtures lets you exercise the whole pipeline without spending tokens or touching your repo.
>
> Code: https://github.com/safernandez666/appsec-triage
> Full blog post: coming soon.
>
> What deterministic heuristics do you run before reaching for the LLM in your security pipeline?
>
> #AppSec #SecurityEngineering #LLM #OpenSource

---

## Notas de uso

- **Cover image** → arrastrá `docs/blog-cover.png` (1600×840) al editor de LinkedIn antes de pegar el texto. LinkedIn lo va a mostrar arriba del post automáticamente.

- **Hashtags** → mantené 3-5 max. LinkedIn premia engagement, no etiquetas. Para AppSec específicamente, los más rankeantes hoy son `#AppSec`, `#SecurityEngineering`, `#DevSecOps`, `#LLM`, `#OpenSource`. Evitá los genéricos (`#cybersecurity`, `#tech`).

- **Timing recomendado** (Argentina, audiencia LATAM + global):
  - Martes/jueves 9-11am ART (12-14 UTC) — captura LATAM mañana + Europa tarde.
  - Evitá viernes tarde y lunes temprano.

- **Cuando salga el blog post de Hashnode**: editás el post de LinkedIn y reemplazás "Blog post completo: en breve" por la URL directa. LinkedIn permite editar sin perder engagement (a diferencia de Twitter/X).

- **Cross-post a Twitter/X**: si querés, recortás la **versión corta** a 280 chars + screenshot del cover. Misma quote del callout funciona como tweet único.

- **Engagement hooks que funcionan**:
  - La pregunta abierta del cierre (el algoritmo prioriza posts con replies).
  - Citar a alguien específico que sepas que tiene opinión técnica sobre el tema (en comments, no en el post — el @ en el body baja reach).
  - Responder vos mismo el primer comment con un detalle extra ("una cosa que no entró: …") — duplica las replies.
