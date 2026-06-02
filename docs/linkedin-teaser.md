# LinkedIn teaser — v0.2.1 release

**Cover image:** `docs/blog-cover.png` (1600×840 PNG, ya commiteado en el repo).
**Length:** ~1700 chars (entra sin "ver más" en mobile).
**Cierre con pregunta** → engagement hook para LinkedIn.
**Release:** https://github.com/safernandez666/appsec-triage/releases/tag/v0.2.1

> **Nota:** Esto reemplaza al teaser de v0.2.0. El "qué hace el bot" sigue siendo la misma historia (tres fuentes, LLM sandwicheado, guardrails con belt + suspenders). Lo nuevo de v0.2.1 es **operacional**: cómo pasar de un PoC que funciona con fixtures a un bot que efectivamente labura en un repo real, y la lista de bugs que solo aparecieron en la primera corrida productiva.

---

## Versión principal (ES) — copy-paste

> **v0.2.1 del bot multi-agente de triage de Dependabot + CodeQL + Secret scanning está vivo, y por primera vez está corriendo contra un repo real.**
>
> Lo que prometía la v0.2.0 — el LLM nunca actúa solo, sandwicheado entre dos capas determinísticas — terminó pasando un test mucho más duro que mis fixtures: 38 alertas reales, 32 CodeQL XSS + 6 Dependabot, en un repo con Bootstrap vendored adentro.
>
> Primera corrida: 0 reproducibles, 34 needs_review. El LLM-Prosecutor estaba atacando 32/32 alertas de code-scanning con el mismo argumento: "no direct package usage hits or vulnerable API usage hits." Repetido textual 32 veces. Bug estructural — el Prosecutor recibe un EvidenceMatrix que solo tiene datos cuando la fuente es Dependabot. Para code-scanning todos los campos son cero por construcción, y el LLM concluye "no explotable" sobre nada.
>
> Mismo bug que ya había arreglado en la capa determinística. Se mudó de capa. Lección: **cuando agregás un step adversarial con LLM, asegurate que pueda razonar con la evidencia que recibe.** Pedirle que falsifique un verdict basándose en campos que no aplican garantiza que va a falsificar todo.
>
> Otros bugs que solo aparecieron en producción:
>
> — `--dry-run` envenenaba el `.triage_history.jsonl`. El "modo no muta nada" tiene que listar TODAS las cosas que muta. Fácil olvidarse del archivo de history porque "es solo un log".
>
> — La label `autotriage` no existía en el repo, GitHub la droppeó silenciosamente, el dedupe basado en label dejó de funcionar. Cada CREATE creaba duplicados. Las APIs externas hacen cosas silenciosas — defendete contra side-effects que no ocurrieron.
>
> — Mi PAT podía CREATE Issues pero NO COMMENT (403). Los permisos de PATs fine-grained son inauditables sin pegarle al API. Ahora el bot tiene un pre-flight check documentado y soft-fail con visibilidad.
>
> Después de los cuatro fixes: 11 Issues sin duplicados, 25 XSS reproducibles correctamente clasificadas, 4 false positives auto-archivables, 9 needs_review legítimos. **Eso sí es un bot productivo.**
>
> El README ahora tiene una guía de 9 pasos para llevarlo a producción — cada paso es un sandbox un poquito más cerca del real, cada uno destapa una clase de bugs que el anterior no podía.
>
> https://github.com/safernandez666/appsec-triage/releases/tag/v0.2.1
>
> ¿Cuál fue tu bug "que solo aparece en producción" más memorable? Yo me llevo el del Prosecutor de hoy.
>
> #AppSec #SecurityEngineering #LLM #OpenSource

---

## Versión corta (~900 chars) — si tu feed prefiere posts breves

> **v0.2.1 vivo, primera corrida real contra un repo de verdad.**
>
> La suite offline pasaba. La fixture estaba feliz. La primera corrida live destapó cuatro bugs invisibles ante tests:
>
> — El LLM-Prosecutor atacaba 32/32 code-scanning alerts con la misma razón. Razonaba sobre evidencia que no aplicaba a esa fuente.
>
> — `--dry-run` escribía al history. Las rehearsals envenenaban las corridas live posteriores.
>
> — La label inexistente rompía el dedupe silenciosamente. 4 duplicados de la misma CVE.
>
> — Mi PAT podía CREATE Issues pero no COMMENT. 403 silencioso, ciclo entero abortado.
>
> Lección general: **el camino del PoC a producción no es "más tests" — es ejercitar contra realidad lo antes posible, con postura de pre-mortem.**
>
> Guía de 9 pasos en el README ahora.
>
> https://github.com/safernandez666/appsec-triage/releases/tag/v0.2.1
>
> ¿Tu bug favorito "solo aparece en producción"?
>
> #AppSec #LLM #OpenSource

---

## Versión en inglés — para alcance internacional

> **v0.2.1 of the multi-agent Dependabot + CodeQL + Secret scanning triage bot is out — and for the first time, it ran against a real repo.**
>
> What v0.2.0 promised — LLM never acts alone, sandwiched between two deterministic layers — got audited by something harder than my fixtures: 38 real alerts in a repo with vendored Bootstrap inside.
>
> First live run: 0 reproducibles, 34 needs_review. The LLM-Prosecutor was attacking 32/32 code-scanning alerts with the same verbatim argument: "no direct package usage hits or vulnerable API usage hits." 32 times in a row. Structural bug — the Prosecutor reads an EvidenceMatrix that only has data when the source is Dependabot. For code-scanning every field is zero by construction, and the LLM concludes "not exploitable" out of nothing.
>
> Same bug I had already fixed in the deterministic layer. It moved layers. Lesson: **when you add an adversarial LLM step, make sure it can reason about the evidence it receives.** Asking it to falsify a verdict from fields that don't apply guarantees it will falsify everything.
>
> Other bugs that only appeared in production:
>
> — `--dry-run` was polluting `.triage_history.jsonl`. "Mutates nothing" must enumerate *every* mutation; it's easy to forget the history log because "it's just a log."
>
> — The `autotriage` label did not exist on the repo, GitHub silently dropped it, label-filtered dedupe broke. Every CREATE produced duplicates. External APIs do silent things — defend against side-effects that didn't actually happen.
>
> — My PAT could CREATE Issues but not COMMENT (403). Fine-grained PAT permissions are unauditable without poking the API. The bot now has a documented pre-flight check and soft-fail with visibility.
>
> After the four fixes: 11 unique Issues, 25 XSS correctly classified as reproducible, 4 false positives ready for auto-archive, 9 legitimate needs_review. **That's a productive bot.**
>
> The README now ships a 9-step production guide — each step is a slightly-closer-to-real sandbox, each one surfaces a class of bugs the previous step can't.
>
> https://github.com/safernandez666/appsec-triage/releases/tag/v0.2.1
>
> What's your most memorable "only appears in production" bug? Today I'm cashing in the Prosecutor one.
>
> #AppSec #SecurityEngineering #LLM #OpenSource

---

## Notas de uso

- **Cover image** → arrastrá `docs/blog-cover.png` (1600×840) al editor de LinkedIn antes de pegar el texto. LinkedIn lo va a mostrar arriba del post automáticamente.

- **Release URL** → ya está en las tres versiones (`https://github.com/safernandez666/appsec-triage/releases/tag/v0.2.1`). Cuando salga el blog post de Hashnode, agregalo arriba del URL del release: `Blog post: <url>` en una línea propia para que se vea como link visual prominente.

- **Hashtags** → mantené 3-5 max. LinkedIn premia engagement, no etiquetas. Para AppSec específicamente, los más rankeantes hoy son `#AppSec`, `#SecurityEngineering`, `#DevSecOps`, `#LLM`, `#OpenSource`. Evitá los genéricos (`#cybersecurity`, `#tech`).

- **Timing recomendado** (Argentina, audiencia LATAM + global):
  - Martes/jueves 9-11am ART (12-14 UTC) — captura LATAM mañana + Europa tarde.
  - Evitá viernes tarde y lunes temprano.

- **Cross-post a Twitter/X**: si querés, recortás la **versión corta** a 280 chars + screenshot del cover. La pregunta del cierre funciona como tweet único.

- **Engagement hooks que funcionan**:
  - La pregunta abierta del cierre (el algoritmo prioriza posts con replies).
  - Citar a alguien específico que sepas que tiene opinión técnica sobre el tema (en comments, no en el post — el @ en el body baja reach).
  - Responder vos mismo el primer comment con un detalle extra ("el bug del LLM-Prosecutor pegó tan bien que tuve que agregar un modo verbose nuevo para descubrirlo…") — duplica las replies.

- **Bug-confession framing**: La narrativa "cuatro bugs que solo aparecen en producción" tiene mejor engagement que "feature nueva". La gente comenta más sobre fallas que sobre wins — usá eso. Si bajás la guardia y mostrás que tu bot rompía cosas, la audiencia confía más.
