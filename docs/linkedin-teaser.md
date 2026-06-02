# LinkedIn teaser — v0.2.1 release

**Cover image:** `docs/blog-cover.png` (1600×840 PNG, ya commiteado en el repo).
**Length:** ~1700 chars (entra sin "ver más" en mobile).
**Cierre con pregunta** → engagement hook para LinkedIn.

> **Nota:** Esto reemplaza al teaser de v0.2.0. La narrativa de v0.2.0 (tres fuentes, LLM sandwicheado, guardrails con belt + suspenders) sigue intacta — la novedad de v0.2.1 es **operacional**: pasar de "un repo" a "una flota chica" sin perder los guardrails.

---

## Versión principal (ES) — copy-paste

> **v0.2.1 del bot que tría tus alertas de Dependabot, CodeQL y Secret scanning está vivo.**
>
> La v0.2.0 le enseñó al bot a leer tres fuentes de seguridad de GitHub. La v0.2.1 le enseñó a correr contra una flota chica sin perder los guardrails. Un flag nuevo: `--repos org/a,org/b,org/c`.
>
> Tres cosas que el modo batch hace y un loop de bash con `set -e` no:
>
> 1️⃣ Error isolation. Cada repo se procesa en un helper que **nunca lanza excepciones** — fallas de auth, fetch errors, crashes inesperados se atrapan, se registran con su exit code, y el batch sigue con el próximo. Un repo que se rompe no aborta los otros cuarenta y nueve. El camino single-repo `--repo` ahora comparte el mismo helper.
>
> 2️⃣ Resumen por repo al final. `ok` / `FAIL` por repo con fast-path count, continue count, y el mensaje de error cuando aplica. Auditeable en un `cron` log sin scrollear miles de líneas.
>
> 3️⃣ Exit code honesto. El batch retorna el peor exit code visto — si tres de cincuenta repos fallaron, `cron` lo detecta. Nada de que el último repo salga ok y se trague la falla parcial.
>
> Lo que **no** hace, a propósito: no es paralelo (los rate limits de GitHub sobre un PAT lo hacen foot-gun), no acepta config por archivo (si tu flota necesita YAML, ya superaste este modo), no permite `--sources` por repo (las fuentes son globales al batch).
>
> Y lo importante: **los guardrails tier-1 se evalúan por repo dentro del batch**. Un repo crítico adentro de un batch de cincuenta sigue sin ser auto-dismisseado. El `transition_floor = inf` + early return explícito del tier-1, y el "secret-scanning no tiene método dismiss en el client" — todo intacto, todo aplica por repo.
>
> Stack: Python 3.11, una sola dependencia runtime (`httpx`), GitHub Actions cron + `workflow_dispatch`. README EN y ES. Modo `--offline` con fixtures para probarlo sin gastar tokens.
>
> Código: https://github.com/safernandez666/appsec-triage
> Blog post completo: en breve.
>
> Cuando armás un wrapper de batch sobre un pipeline existente, ¿lo hacés wrappear la función single o reescribís la lógica adentro del loop?
>
> #AppSec #SecurityEngineering #LLM #OpenSource

---

## Versión corta (~900 chars) — si tu feed prefiere posts breves

> **v0.2.1 vivo.** El bot multi-agente que tría Dependabot + CodeQL + Secret scanning ahora corre contra una flota: `--repos org/a,org/b,org/c`.
>
> Tres cosas que el modo batch hace y un loop de bash con `set -e` no:
>
> — Error isolation. Cada repo se procesa en un helper que **nunca lanza**. Un repo roto no aborta los demás.
> — Resumen por repo al final (`ok` / `FAIL` + counts + error). Auditeable en un cron log.
> — Exit code honesto. El batch retorna el peor exit code visto — `cron` detecta fallas parciales.
>
> Los guardrails tier-1 se evalúan **por repo dentro del batch**. Un crítico adentro de un batch de cincuenta sigue sin ser auto-dismisseado.
>
> https://github.com/safernandez666/appsec-triage
>
> Cuando wrappeás un pipeline existente con batch mode, ¿reusás la función single o reescribís la lógica?
>
> #AppSec #LLM #OpenSource

---

## Versión en inglés — para alcance internacional

> **v0.2.1 of the bot that triages your Dependabot, CodeQL, and Secret scanning alerts is live.**
>
> v0.2.0 taught the bot to read three GitHub security signals. v0.2.1 teaches it to run against a small fleet without losing the guardrails. New flag: `--repos org/a,org/b,org/c`.
>
> Three things the batch mode does that a bash loop with `set -e` does not:
>
> 1️⃣ Error isolation. Each repo runs inside a helper that **never raises** — auth failures, fetch errors, unexpected crashes are caught, recorded with their exit code, and the batch moves to the next repo. One blown-up repo cannot abort the other forty-nine. The single-repo `--repo` path now shares the same helper.
>
> 2️⃣ Per-repo summary at the end. `ok` / `FAIL` per repo with fast-path count, continue count, and the failure message when applicable. Auditable in a `cron` log without scrolling thousands of lines.
>
> 3️⃣ Honest exit code. The batch returns the worst exit code seen — if three out of fifty repos failed, `cron` detects it. Nothing about the last repo succeeding silently swallowing the partial failure.
>
> What it does **not** do, on purpose: it isn't parallel (GitHub rate limits on a shared PAT make parallel batches a foot-gun), it doesn't accept a config file (if your fleet needs YAML, you've outgrown this mode), and it doesn't allow `--sources` overrides per repo (sources are global to the batch).
>
> And the important part: **tier-1 guardrails are evaluated per repo inside the batch**. A critical repo inside a fifty-repo batch still never auto-dismisses. The `transition_floor = inf` + explicit early return for tier-1, and the "secret scanning has no dismiss method on the client at all" — all intact, all per repo.
>
> Stack: Python 3.11, single runtime dependency (`httpx`), GitHub Actions cron + `workflow_dispatch`. EN and ES READMEs. `--offline` mode with fixtures lets you exercise the whole pipeline without spending tokens.
>
> Code: https://github.com/safernandez666/appsec-triage
> Full blog post: coming soon.
>
> When you wrap a batch driver around an existing single-target pipeline, do you make it reuse the single-target function, or do you rewrite the logic inside the loop?
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

- **Si querés mantener la v0.2.0 viva**: el teaser de v0.2.0 está en el git history (commit `d43c15f`). Si todavía no posteaste v0.2.0, considerá postearla primero y dejar v0.2.1 para una semana después — dos releases en el mismo día se canibalizan el algoritmo.
