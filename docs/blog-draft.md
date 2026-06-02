# Cómo construí un bot que tría tus alertas de seguridad (sin dejar que el LLM rompa nada)

> **Estimado de lectura:** ~20 min · **Audiencia:** AppSec, DevSecOps, Platform · **Stack:** Python 3.11, GitHub API, LLM OpenAI-compat

En seguridad aplicada hay un problema que conocés muy bien si trabajaste con Dependabot por más de un par de meses: **la fatiga de alertas**. Empezás con tres repos y diez alertas, todo lindo, todo bajo control. Seis meses después tenés 47 repos, 1.200 alertas abiertas, y nadie las mira. El que las mira sabe que la mitad ni siquiera aplica: el paquete está declarado en `requirements-dev.txt` pero no se usa en runtime, o el repo está archivado, o la API vulnerable nunca se invoca desde el código. Pero verificar cada una a mano cuesta media hora. Multiplicalo por 1.200.

Lo que termina pasando es lo peor: el equipo deja de leer las alertas. Y cuando viene la real, también se la pierde.

Yo me cansé y construí algo para resolverlo. Un bot multi-agente que decide por vos cuáles aplican, con justificación en lenguaje plano, sin hacer macanas. Después extendí lo mismo a CodeQL y Secret scanning, porque el problema de fatiga no es solo de dependencias. Vamos a ver cómo lo armé.

> El código está en https://github.com/safernandez666/appsec-triage. Está en MIT, sentite libre de clonarlo y romperlo. Hay versión en español del README también.

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
# Capa 2: explícita, segunda línea
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

## De Dependabot a tres fuentes (la v0.2.0)

Cuando terminé la v0.1.0 y la dejé andando, salté al siguiente problema obvio: Dependabot no es la única fuente de fatiga. **CodeQL** te tira findings con su propio nivel de ruido (y de falsos positivos cuando la rule se dispara en código de tests o en patrones que en tu contexto son seguros). **Secret scanning** te tira credenciales leakeadas, que ni siquiera son la misma pregunta: no querés saber si "afecta al repo", querés rotar el secreto ya.

Tres fuentes, **tres modelos de riesgo distintos**. Y eso me parece la cosa más interesante que aprendí extendiendo:

💡 No alcanza con tener "un pipeline genérico para alertas de seguridad". Cada signal tiene su propia pregunta. Diseñar un pipeline único que las atienda a todas con la misma lógica sería exactamente el tipo de over-abstraction que termina haciendo más daño que el ruido original.

### Cómo la separación es honesta

Lo primero que toqué fue el tipo `Alert`. Pasó a tener un campo `source` que vale `DEPENDABOT`, `CODE_SCANNING` o `SECRET_SCANNING`, y tres factories distintas:

```python
@classmethod
def from_dependabot_payload(cls, payload): ...

@classmethod
def from_code_scanning_payload(cls, payload): ...

@classmethod
def from_secret_scanning_payload(cls, payload): ...
```

La identidad para el Consistency Gate también es source-dependiente, y eso resulta importante:

```python
@property
def identity(self) -> str:
    if self.source is AlertSource.DEPENDABOT:
        return f"{self.cve_id}::{self.package_ecosystem}::{self.package_name}"
    if self.source is AlertSource.CODE_SCANNING:
        return f"{self.rule_id}::{self.location_path}"
    if self.source is AlertSource.SECRET_SCANNING:
        return f"{self.secret_type}::{first_commit_sha}"
```

Para Dependabot, `(CVE+package)` es estable cross-repo y permite consenso org-wide. Para CodeQL, `(rule+path)` es lo más estable que tenés (el mismo rule en el mismo path es probablemente el mismo finding). Para secrets, el `secret_type` más el primer commit donde apareció. Cada uno tiene su propia clave porque **cada uno representa una pregunta distinta sobre el repo**.

Y desde el CLI: `--sources dependabot` (default, para no romper a quien usaba la v0.1.0) o `--sources all` o `--sources codeql,secret` o cualquier combinación.

### CodeQL: misma forma, distinta pregunta

CodeQL pasa por las mismas cuatro zonas que Dependabot, pero con dos cambios importantes:

**Primero**: la pregunta del Judge cambia. Para Dependabot es "¿esta dependencia afecta a este repo?". Para CodeQL es "¿este finding es accionable en este repo?". Los dos prompts son distintos archivos:

```python
JUDGE_SYSTEM_PROMPT_DEPENDABOT = """..."""
JUDGE_SYSTEM_PROMPT_CODE_SCANNING = """..."""

def judge(alert, repo, evidence, tier):
    system_prompt = (
        JUDGE_SYSTEM_PROMPT_CODE_SCANNING
        if alert.source is AlertSource.CODE_SCANNING
        else JUDGE_SYSTEM_PROMPT_DEPENDABOT
    )
    ...
```

Hubiera sido tentador hacer un prompt único "generic security verdict" que sirva para los dos. No. El framing afecta el razonamiento del modelo. Un prompt que dice "decidí si el dependency apply" lleva al modelo a buscar imports. Uno que dice "decidí si el finding es accionable" lleva al modelo a buscar reachability del pattern desde un entry point. Son razonamientos distintos. Mezclarlos en un solo prompt es pedirle al modelo que adivine cuál de los dos estás pidiendo.

**Segundo**: agregué dos rules nuevas a la Truth Table, específicas para CodeQL:

- **Rule C** — Si el `location_path` matchea un directorio de tests (`tests/`, `__tests__/`, `spec/`, `e2e/`, etc.) → `false_positive`. La regex es case-insensitive y matchea en cualquier parte del path. Un finding de SQL injection en `tests/test_queries.py` no es explotable desde runtime; vive en código que solo corre en CI.

- **Rule D** — Si el repo está archivado → `false_positive`. Análoga a Rule A para Dependabot.

Estas rules las hacen exactamente lo mismo que A y B para Dependabot: **resuelven una buena fracción de las alertas sin invocar al LLM**. Y el vocabulario de dismiss que mandamos a la API de CodeQL es distinto al de Dependabot:

```python
def _dismiss_reason(verdict, alert):
    if alert.source is AlertSource.CODE_SCANNING:
        if "codeql_in_tests" in verdict.source:
            return "used in tests"
        if "codeql_archived" in verdict.source:
            return "won't fix"
        return "false positive"
    # Dependabot
    if "no_hits" in verdict.source:
        return "not_used"
    return "inaccurate"
```

GitHub espera literalmente esos strings con esos espacios para la API de code-scanning. Si le mandás `not_used` te da 422. La API es la API; el adapter es del bot, no al revés.

### Secret scanning: modelo de riesgo completamente distinto

Acá es donde más se nota la lección. Para Dependabot y CodeQL las cuatro zonas tienen sentido. Para Secret scanning la pregunta no es "¿es real?" — el secreto está leakeado. La pregunta es "¿está rotado?", y eso solo lo puede contestar un humano que vaya al provider y rote la credencial.

Entonces el pipeline se colapsa:

```
Z1 routing  →  Z4 output  (sin Z2, sin Z3, sin LLM)
```

Hay un nuevo `VerdictKind.ROTATE_NOW` que es el único veredicto posible para una alerta de secret. La confianza es 1.0 — y eso es honest, no inventado: no es una decisión probabilística, es estructural. Cada secreto leakeado necesita rotación.

Y el Issue que se abre no es la conclusión típica de Dependabot/CodeQL. Es un template urgente:

```markdown
# 🔥 ROTATE NOW

A **AWS Access Key ID** was detected in this repository.

**Location:** `scripts/deploy.sh:12` (commit a1b2c3d4…)
**Alert:** https://github.com/...

## Steps

1. **Rotate the credential at the issuing provider** (cloud console,
   IdP, service dashboard). Do NOT skip this step — removing it from
   git history is insufficient because the value may already have been
   scraped by automated crawlers.
2. Deploy any service or job that depends on the rotated credential.
3. Audit access logs for use of the leaked credential between the
   commit time and the rotation time.
4. Close this Issue manually once rotation is confirmed.
```

### Y otra vez "cinturón y tiradores", esta vez para secrets

Acá entra la lección más importante de v0.2.0. **Auto-dismiss de secretos está prohibido**. Punto. ¿Cómo lo enforce?

**Capa 1** — El `GitHubClient` simplemente **no tiene** un método `dismiss_secret_scanning_alert`. Si en algún punto del código alguien intenta llamarlo, no existe. Es `AttributeError` instantáneo.

**Capa 2** — El `_maybe_dismiss` del Issue manager hace este check explícito antes de cualquier otra cosa:

```python
def _maybe_dismiss(client, repo, alert, verdict, tier, flags):
    if verdict.kind is not VerdictKind.FALSE_POSITIVE:
        return False, None
    if not flags.auto_transition:
        return False, "--auto-transition off, no dismiss attempted"
    
    # v2 GUARDRAIL — Secret scanning is never auto-dismissed. Humans rotate.
    if alert.source is AlertSource.SECRET_SCANNING:
        return False, (
            "GUARDRAIL: secret scanning alerts are never auto-dismissed — "
            "humans must confirm rotation"
        )
    
    # Continúa con tier-1 guardrail, etc...
```

**Es exactamente la misma técnica de cinturón y tiradores que usamos para tier-1, aplicada a un problema diferente.** Capa 1 hace imposible la mutación (el método no existe), capa 2 corta antes de llegar (early-return explícito). Si alguien dentro de seis meses por descuido le agrega un `dismiss_secret_scanning_alert` al client, la capa 2 sigue protegiéndolo.

💡 Esto vale la pena internalizarlo: la propiedad "no se puede romper accidentalmente" no es magia. Es **redundancia ortogonal entre capas**. Una capa hace que la operación destructiva no exista; la otra hace que aunque exista no se invoque. Ninguna de las dos solas es suficiente. Las dos juntas, aunque parezcan over-engineering, son lo que hace que el sistema sobreviva los seis meses que faltan para que el próximo dev lea ese código.

---

## El stack y los números

Lo más simple posible. Una sola dependencia runtime externa: `httpx`. Si lo podía hacer con stdlib de Python, lo hacía con stdlib. No hay ORM, no hay framework, no hay SDK de OpenAI — todo va por requests HTTP directos.

Los números finales en v0.2.0:

| Métrica | v0.1.0 | v0.2.0 |
|---|---|---|
| Lenguaje | Python 3.11+ | Python 3.11+ |
| Módulos | 12 | 13 |
| LOC totales | ~1.800 | ~3.000 |
| Dependencia runtime | `httpx` (única) | `httpx` (única) |
| Fuentes soportadas | Dependabot | Dependabot + CodeQL + Secret |
| Truth Table rules | 2 (A, B) | 4 (A, B, C, D) |
| Capas de guardrail tier-1 | 2 | 2 |
| Capas de guardrail secret no-dismiss | — | 2 |
| Empaquetado | `pyproject.toml` + setuptools | (igual) |
| Entry point | `appsec-triage` | (igual) |

Lo que **no** crecí: la dependencia runtime sigue siendo `httpx` solo, el entry point sigue siendo el mismo console script, y `--sources dependabot` (default) sigue produciendo output verbatim al de v0.1.0. Backward compatibility por contrato.

---

## Lo que más me sirvió aprender

Dos lecciones, una por versión.

### Lección de v0.1.0: la mayoría del valor está fuera del LLM

Las reglas determinísticas resuelven la mayoría de los casos correctamente y casi gratis. El LLM aporta donde solo el lenguaje natural puede aportar:

- **Extraer APIs específicas** de un advisory escrito en inglés técnico ambiguo.
- **Redactar una conclusión legible** para que el reviewer la lea en el Issue sin tener que entender la matrix de evidencia.

Y nada más.

Si dejás que el LLM decida si una alerta aplica al repo o no, **va a alucinar**. Va a inventar imports que no existen, va a confundir packages parecidos, va a cambiar de opinión entre corridas. Eso no significa que el LLM es inútil — significa que tenés que diseñar el sistema asumiendo que va a alucinar, y poner las decisiones reales en código determinístico que vos podés auditar.

### Lección de v0.2.0: el modelo de riesgo manda

Cuando extendí a CodeQL y Secret scanning, la tentación obvia era "lo mismo pero con otro adapter de entrada". Resistí esa tentación y construí dispatchers en varias capas:

- El `Alert.from_*_payload` por source.
- El `Alert.identity` por source.
- El system prompt del Judge por source.
- El vocabulario de dismiss por source.
- El pipeline mismo: Dependabot y CodeQL pasan por las cuatro zonas; Secret scanning saltea Z2 y Z3 directo a Z4.

¿Por qué? Porque **cada signal de seguridad responde una pregunta distinta sobre el repo**:

- Dependabot: "¿está esta dependencia siendo usada y la API vulnerable es alcanzable?"
- CodeQL: "¿esta detección de pattern es accionable en este contexto?"
- Secret scanning: "¿está rotado?"

Si forzás una pipeline única para los tres, en el mejor caso obtenés un Judge confundido que aluciña más, y en el peor obtenés un bot que cierra automáticamente secrets que están en producción porque "el confidence superó el threshold".

💡 La técnica "belt + suspenders" del tier-1 también se generalizó: dos capas independientes protegen también el no-dismiss de secrets. La técnica no es exclusiva de tier-1; es **el patrón general** para cualquier guardrail no negociable. Una capa estructural (el método no existe, el float es infinito) y una capa explícita (early-return con mensaje claro). Si una de las dos se rompe en el futuro, la otra sigue.

Esto no es exclusivo de triage de vulnerabilidades. Aplica a cualquier sistema de seguridad con IA: SOC automation, log analysis, threat intel correlation. La parte interesante siempre va a ser **lo que pasa antes y después del LLM**, y **cómo diseñás las restricciones que el LLM no puede romper**, no el LLM mismo.

---

## Próximos pasos

La v0.2.0 cubre las tres fuentes "obvias" de GitHub. Lo que viene después tiene varias direcciones posibles:

- **Persistencia real del historial en CI**. Hoy es artifact-only. En producción lo persistís en S3, un gist privado o un repo dedicado de estado. Lo dejo documentado en el README.
- **Otras fuentes de seguridad de GitHub**: la Dependency Review API en PR time (para bloquear merges con vulns sin tener que esperar al cron de Dependabot), supply chain attestations (cuando GitHub lo expanda a más ecosistemas), y eventualmente telemetría de runtime cuando exista una API estable.
- **Adapter para otros LLMs**. Hoy asumo OpenAI-compatible. Bedrock InvokeModel, raw Anthropic API, o modelos self-hosted necesitan un adapter delgado. No es difícil, solo no estaba en scope.
- **Métricas reales después de correrlo unos meses**. Cuántas alertas resuelve sin LLM (Truth Table). Cuántas resuelve por consenso. Cuántas terminan en `needs_review` y por qué. Tasa de revocación del Prosecutor. Eso es contenido para un Part 3 cuando tenga data.

Si querés probarlo en tu propio repo, el README tiene un quick start de tres comandos:

```bash
pip install -e .
cp .env.example .env       # poné tu PAT + LLM_API_KEY
appsec-triage --repo owner/name --dry-run --sources all
```

Y si te animás al `--auto-transition`, los guardrails tier-1 + secret-no-dismiss están ahí para vos.

Seguiremos explorando esto en próximas entregas. Para mí lo más interesante del proyecto sigue siendo **la asimetría LLM/determinístico**, y cada extensión nueva la hace más evidente. Le estoy tomando el gusto.

¡Listo! Espero que les sirva. Si lo levantan en su propio entorno, contame qué encontraron — sobre todo el ratio de alertas que terminan resueltas sin LLM en su org, que ese número es el que más me interesa saber.

---

> **Código:** https://github.com/safernandez666/appsec-triage
> **Licencia:** MIT. Auditá antes de producción.
> **Releases:** https://github.com/safernandez666/appsec-triage/releases
