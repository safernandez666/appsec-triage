# Cómo construí un bot que tría tus alertas de Dependabot (sin dejar que el LLM rompa nada)

> **Estimado de lectura:** ~15 min · **Audiencia:** AppSec, DevSecOps, Platform · **Stack:** Python 3.11, GitHub API, LLM OpenAI-compat

En seguridad aplicada hay un problema que conocés muy bien si trabajaste con Dependabot por más de un par de meses: **la fatiga de alertas**. Empezás con tres repos y diez alertas, todo lindo, todo bajo control. Seis meses después tenés 47 repos, 1.200 alertas abiertas, y nadie las mira. El que las mira sabe que la mitad ni siquiera aplica: el paquete está declarado en `requirements-dev.txt` pero no se usa en runtime, o el repo está archivado, o la API vulnerable nunca se invoca desde el código. Pero verificar cada una a mano cuesta media hora. Multiplicalo por 1.200.

Lo que termina pasando es lo peor: el equipo deja de leer las alertas. Y cuando viene la real, también se la pierde.

Yo me cansé y construí algo para resolverlo. Un bot multi-agente que decide por vos cuáles aplican, con justificación en lenguaje plano, sin hacer macanas. Vamos a ver cómo lo armé.

> El código está en https://github.com/safernandez666/appsec-triage. Sentite libre de clonarlo y romperlo.

---

## El desafío real

El planteo parece simple: "agarrá las alertas de Dependabot y decidí si son falsos positivos". El problema es que cualquier persona con experiencia en herramientas de seguridad sabe que esto sale mal de muchas formas:

- **Si el bot es demasiado agresivo**, va a cerrar una alerta real porque el paquete "no parece estar en uso" — y al mes siguiente hay un incidente de RCE.
- **Si el bot es demasiado conservador**, deja todo abierto y no resolvés nada.
- **Si metés un LLM a decidir**, te encontrás que un día responde "false_positive" y al día siguiente "reproducible" para la misma alerta, sin que cambie nada del repo. Esto no es teórico: pasa.

Entonces el laburo real no es "meter un LLM". Es **diseñar el sistema alrededor del LLM** para que cuando alucine —y va a alucinar— el daño esté contenido.

💡 Esta es la idea central de toda la arquitectura que vas a ver más abajo: **el LLM nunca actúa solo**. Hay reglas determinísticas en Python puro antes que él, y revisores también determinísticos después. El LLM es una pieza, no el sistema.

---

## La arquitectura: cuatro zonas

Vamos a la foto general. El bot procesa cada alerta a través de cuatro zonas, en orden:

![Pipeline architecture](https://github.com/safernandez666/appsec-triage/raw/main/docs/architecture.svg)

- **Zona 1 — Routing.** Decisiones rápidas sin LLM. Si la alerta ya está `fixed` o `dismissed` upstream, cerramos el Issue con una nota de una línea y listo.
- **Zona 2 — Investigación.** Acá entra el primer LLM, pero solo para una cosa muy puntual: **extraer nombres de APIs vulnerables** del texto del advisory. Después de eso, todo es Python puro: code search, perfil del repo, evidencia, una "Truth Table" que puede forzar un veredicto sin tocar el LLM, y un check de consenso org-wide.
- **Zona 3 — Juicio.** Acá sí entra el LLM "Judge" como tal, pero queda sandwicheado entre tres componentes determinísticos que pueden anularlo: el Prosecutor (revisión adversarial), el Critic (silent quality gate), y el Consistency Gate (anti flip-flop entre corridas).
- **Zona 4 — Salida.** Crear/comentar la Issue, y opcionalmente dismissear la alerta de Dependabot. Acá vive el guardrail no-negociable que vamos a ver más abajo.

Mirá lo que hace una alerta cuando entra al pipeline:

![Sequence](https://github.com/safernandez666/appsec-triage/raw/main/docs/sequence.svg)

La única flecha en coral es el retorno del Judge con el veredicto. Es la decisión central. Todo lo demás —y "lo demás" es bastante— es plomería que existe para que el LLM se equivoque lo menos posible, y cuando se equivoque, no haga daño.

---

## El LLM nunca actúa solo

Esta es la decisión arquitectónica más importante de todo el proyecto. Voy a explicarla por partes porque le di muchas vueltas.

### Gates determinísticos a la entrada

Antes de que el Judge LLM vea una sola línea, dos cosas ya pueden cerrar el caso:

**Rule A** — Si el repo está archivado Y el code search no encuentra ni una referencia al paquete vulnerable, el veredicto es `false_positive` con confianza 0.95. Sin LLM. La lógica es trivial: el código vulnerable no puede correr si el paquete no está siendo usado, y si el repo está archivado, mañana tampoco se va a usar.

**Rule B** — Si el advisory nombra APIs específicas (por ejemplo "`requests.Session` afectado en versiones < 2.31.0") Y ninguna de esas APIs aparece en el código Y el repo es lo suficientemente activo o maduro para que el default branch sea representativo, también es `false_positive`. Esto es lo que se llama "ausencia de evidencia como evidencia": cuando el advisory te dice exactamente qué buscar y no lo encontrás, en un repo cuyo default branch refleja el código real, la ausencia deja de ser ruido.

Estas dos reglas resuelven aproximadamente el 30-40% de los casos sin gastar un solo token. Si dispara Rule A o Rule B, el Judge LLM ni se entera de que existió la alerta.

### Consenso org-wide

Hay un tercer gate antes del Judge: el check de **consenso org-wide**. Si la misma `CVE+package` fue clasificada como `false_positive` en al menos 3 **otros** repos de tu organización, el bot defaultea a ese consenso y se saltea al LLM Judge.

Hay dos detalles que valen la pena acá:

1. El repo actual nunca cuenta para su propio consenso. Si lo dejaras contar, generás un loop autoreferencial donde un FP de hoy "vota" por tu próximo FP.
2. La confianza del consenso se capea en 0.93 — un número específico, no inventado: pasa los floors de Tier 2, 3 y 4 pero queda por debajo del floor de 0.95 de Tier 1. **Los repos críticos nunca se auto-cierran por hearsay.** Si fue FP en 50 otros repos pero acá es tier-1, el Critic lo va a degradar a `needs_review` y un humano lo mira.

### El Final Judge

Cuando las reglas determinísticas no resolvieron y no hay consenso, recién ahí entra el Final Judge. Tres capas defensivas protegen el contrato:

- **System prompt estricto** que prohíbe scores en la conclusión humana, primera persona, nombres de agentes, e invención de imports o APIs que no estén en la evidencia.
- **`response_format={"type":"json_object"}`** se le pide al modelo. No alcanza, pero ayuda.
- **Un validador en Python** que parsea la respuesta y rechaza todo lo que no cumple el contrato exacto. Si el `confidence` viene como booleano (algo que pasa más seguido de lo que pensarías porque en Python `isinstance(True, int)` es `True`), si el `verdict` viene con un valor desconocido, si el JSON está malformado: cae a `needs_review` con `confidence=0.0`.

💡 **`needs_review` es estado de falla, no de hedge**. Esto está explícito en el spec del proyecto. Si el bot termina en `needs_review`, significa que no pudo decidir. Es failure. Por eso todos los fallback paths convergen ahí con confianza cero. Si fuera "el default cómodo cuando no sé", el bot se transformaría en una máquina de generar tickets que nadie atiende — exactamente el problema que vinimos a resolver.

### Gates determinísticos a la salida

El Judge entregó un veredicto. ¿Lo aceptamos? Todavía no.

**Prosecutor** — Revisión adversarial. Primero corren checks determinísticos: ¿el veredicto es `false_positive` pero el código muestra 12 referencias al paquete y 3 hits a APIs vulnerables del advisory? Contradicción obvia, degrada a `needs_review` sin tocar el LLM. ¿Es `reproducible` pero no hay ninguna referencia al paquete en todo el repo? Contradicción, degrada. Solo si los checks determinísticos pasan, el Prosecutor opcionalmente le pide al LLM que **falsifique** el veredicto (no que lo confirme — el prompt es explícito en esa asimetría).

El Prosecutor solo puede **degradar**. Nunca promueve. Si pudiera promover, estaría haciendo el laburo del Judge, y `needs_review` dejaría de ser failure state para volverse hedge.

**Critic** — Silent quality gate. Compara la confianza contra el `post_floor` del tier del repo. Si la confianza está debajo, degrada a `needs_review`. Nunca aparece en el body del Issue. La conclusión humana que ve el reviewer no menciona "el Critic decidió X" — habla del repo y de la alerta directamente.

**Consistency Gate** — Anti flip-flop entre corridas. Lee el historial append-only y compara con el veredicto previo para esta `(repo, CVE+package)`. Si es lo mismo: SKIP (no postea nada nuevo). Si cambió con alta confianza: POST. Si cambió con confianza baja: GUARD (un comment de "please review before closing", sin auto-acción).

---

## El guardrail no-negociable

Llegamos al punto que más me importa de toda la implementación, y el que define la frontera entre "esto es un bot de seguridad" y "esto es un bot que rompe cosas en seguridad".

**Los repos tier-1 (críticos, customer-facing) NUNCA se auto-dismissean.** Sin importar la confianza, sin importar el consenso org-wide, sin importar si el LLM, el Prosecutor, el Critic y el Consistency Gate están todos de acuerdo. Nunca.

Lo implementé en dos capas independientes, una atrás de la otra:

```python
# Capa 1: estructural
TIER_FLOORS = {
    Tier.CRITICAL: (0.95, float("inf")),  # transition_floor = inf
    Tier.DEPLOYED: (0.85, 0.95),
    Tier.INTERNAL: (0.75, 0.85),
    Tier.ARCHIVED: (0.60, 0.70),
}

# El issue_manager hace:
if verdict.confidence >= tier.transition_floor:
    dismiss_alert(...)
# Como transition_floor = inf para CRITICAL, la comparación
# estructuralmente no puede pasar.
```

```python
# Capa 2: explicita, segunda línea
def _maybe_dismiss(...):
    if verdict.kind is not VerdictKind.FALSE_POSITIVE:
        return False, None
    if not flags.auto_transition:
        return False, "--auto-transition off"
    # GUARDRAIL: tier 1 NUNCA dismissea, regardless of confidence
    if tier.tier is Tier.CRITICAL:
        return False, "GUARDRAIL: tier-1 repo, auto-dismiss blocked"
    ...
```

Esto se llama "belt and suspenders" — cinturón y tiradores. La capa 1 hace que el dismiss sea **estructuralmente imposible** en tier-1 (la comparación numérica nunca puede ser verdadera contra infinito). La capa 2 es un check explícito redundante. Si dentro de seis meses alguien viene, edita los floors a un valor finito por descuido, la capa 2 sigue ahí salvándote.

Cuando estás trabajando con seguridad, no alcanza con "es difícil que pase". Tiene que ser **imposible que pase**, y aún así tener un segundo cerrojo por las dudas.

💡 Diseñar el guardrail así me costó pensarlo, pero en producción es la diferencia entre "el bot dismisseó por error una alerta crítica" y "el bot rechazó dismissear una alerta crítica por diseño". Y para vos como AppSec engineer, esa diferencia es todo.

---

## Memoria y consenso org-wide

El bot escribe un `.triage_history.jsonl` que es append-only — una línea JSON por alerta por ciclo:

```json
{
  "ts": "2026-05-30T12:00:00+00:00",
  "repo": "org/svc",
  "identity": "CVE-2023-32681::pip::requests",
  "alert_number": 202,
  "verdict": "false_positive",
  "confidence": 0.92,
  "source": "judge"
}
```

Este archivo lo consumen dos cosas:

1. **El Consistency Gate** lee la última entry para `(repo, identity)` y decide si la alerta es SKIP/POST/GUARD/FIRST en esta corrida.
2. **El consenso org-wide** lee la última entry por **otro** repo para esta `identity`, cuenta cuántos están en `false_positive`, y si son ≥ 3, el bot defaultea a ese consenso antes de invocar al Judge.

Lo elegante de esto es que **un archivo, dos consumers**. No hay base de datos, no hay servicio adicional, no hay API que mantener. Es un JSONL gitignored.

En CI el runner es efímero y el archivo no sobrevive entre runs por default. El workflow incluido lo sube como artifact para auditoría. Para producción real lo persistís en S3, un gist privado, o un repo de estado dedicado. Eso lo dejo como ejercicio del lector porque depende mucho de tu setup, pero la mecánica del bot no cambia: sigue siendo "leé el archivo, escribí el archivo".

---

## El stack y los números

Quería que el proyecto fuera lo más simple posible. La regla autoimpuesta: **una sola dependencia runtime externa, `httpx`**. Si lo podía hacer con stdlib de Python, lo hacía con stdlib. No hay ORM, no hay framework, no hay SDK de OpenAI — todo va por requests HTTP directos.

Los números finales:

| Métrica | Valor |
|---|---|
| Lenguaje | Python 3.11+ |
| Módulos | 12 (uno por responsabilidad) |
| LOC totales | ~1.800 |
| Dependencia runtime | httpx (única) |
| Empaquetado | pyproject.toml + setuptools |
| Entry point | `appsec-triage` console script |
| Workflow CI | GitHub Actions (cron + workflow_dispatch) |
| Test demo | `appsec-triage --offline` con 3 fixtures |

Los 12 módulos siguen la división de zonas:

- **Tipos** (`types.py`) — dataclasses frozen, sin lógica.
- **Cliente** (`github_client.py`) — dos backends (real httpx + offline fixtures) detrás de un Protocol.
- **LLM** (`llm.py`) — wrapper OpenAI-compat con temperature=0 hardcoded.
- **Z1** (`routing.py`) — fast-paths.
- **Z2** (`advisory_agent.py`, `evidence_agent.py`, `truth_table.py`, `memory.py`) — extracción LLM + facts determinísticos + reglas + consenso.
- **Z3** (`judge.py`, `prosecutor.py`, `critic.py`, `consistency.py`) — juicio + gates de salida.
- **Z4** (`issue_manager.py`) — side-effects a GitHub + guardrail tier-1.

Cada módulo tiene un docstring arriba que explica qué hace y qué decisiones de diseño tiene. Si te interesa el código, ese docstring es el mejor punto de entrada por archivo.

---

## Lo que más me sirvió aprender

Si tuviera que quedarme con una sola conclusión del proyecto, es esta:

**La mayoría del valor está fuera del LLM.**

Las reglas determinísticas resuelven la mayoría de los casos correctamente y casi gratis. El LLM aporta donde solo el lenguaje natural puede aportar:

- **Extraer APIs específicas** de un advisory escrito en inglés técnico ambiguo.
- **Redactar una conclusión legible** para que el reviewer la lea en el Issue sin tener que entender la matrix de evidencia.

Y nada más.

Si dejás que el LLM decida si una alerta aplica al repo o no, **va a alucinar**. Va a inventar imports que no existen, va a confundir packages parecidos, va a cambiar de opinión entre corridas. Eso no significa que el LLM es inútil — significa que tenés que diseñar el sistema asumiendo que va a alucinar, y poner las decisiones reales en código determinístico que vos podés auditar.

Esto, dicho de otra forma: **el LLM es un componente, no un sistema**. Construir alrededor de esa asimetría es lo que hace confiable un sistema con LLM en producción de seguridad. Si lo ponés en el centro, te termina mordiendo. Si lo ponés en la periferia, donde solo el lenguaje natural lo justifica, te ahorra horas reales sin causar daño.

💡 Esta lección no es exclusiva de triage de vulnerabilidades. Aplica a cualquier sistema de seguridad con IA: SOC automation, log analysis, threat intel correlation. La parte interesante siempre va a ser **lo que pasa antes y después del LLM**, no el LLM mismo.

---

## Próximos pasos

El bot v1 consume solo alertas de Dependabot. Los dos hooks de extensión más obvios están documentados inline en el código:

- **CodeQL**: extender el GitHubClient con `/code-scanning/alerts`, agregar un `Alert.from_code_scanning_payload` que produzca el mismo shape, reusar todo el pipeline.
- **Secret scanning**: short-circuit en Z1 — un secreto leakeado es un "rotate now", no es una pregunta de "¿es reproducible?". Modelo de riesgo distinto, no pasa por el Judge.

Y un par de cosas que quedaron como deuda técnica honesta y documentada en el README:

- Persistencia real del historial en CI (hoy es artifact-only).
- Adapter para LLMs no-OpenAI-compatible.
- Particionado del archivo de historial cuando tu "org" tiene subgrupos con posturas de riesgo distintas.

Si querés probarlo en tu propio repo, el README tiene un quick start de tres comandos:

```bash
pip install -e .
cp .env.example .env       # poné tu PAT + LLM_API_KEY
appsec-triage --repo owner/name --dry-run
```

Y si te animás al `--auto-transition`, el guardrail tier-1 está ahí para vos.

Seguiremos explorando esto en próximas entregas — me interesa especialmente meterle CodeQL en serio, y compartir las métricas reales después de un par de meses corriéndolo en producción.

¡Listo! Espero que les sirva. Si lo levantan en su propio entorno, contame qué encontraron.

---

> **Código:** https://github.com/safernandez666/appsec-triage
> **Licencia:** MIT. Auditá antes de producción.
