"""Hook PreToolUse del auto mode de agy: decide sobre cada llamada a herramienta.

Solo reglas estáticas declaradas en `policy.toml`. Sin red y sin dependencias
externas: una dependencia rota sería un auto mode caído.

Contrato (documentado dentro del binario de agy):
    stdin  <- {"toolCall": {"name": ..., "args": {...}}, "stepIdx": N,
               "conversationId": ..., "workspacePaths": [...], "transcriptPath": ...}
    stdout -> {"decision": "allow"|"ask"|"deny"|"force_ask", "reason": "..."}

Principio rector: este script **nunca falla hacia `allow`**. Cualquier excepción,
entrada malformada o regla ausente degrada a `ask`, devolviendo la decisión a la
persona. `stdout` transporta únicamente el JSON de decisión; todo diagnóstico va al
registro de auditoría.
"""
import json
import os
import pathlib
import re
import sys
import tempfile
import tomllib
from datetime import datetime

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    from transcript import detect_phase, extract_user_intent, read_work_objective
except ImportError:
    try:
        from automode.transcript import detect_phase, extract_user_intent, read_work_objective
    except ImportError:
        def extract_user_intent(*args, **kwargs):
            return ""

        def read_work_objective(*args, **kwargs):
            return ""

        def detect_phase(*args, **kwargs):
            return None

try:
    from checkpoint import ensure_checkpoint, restore_hint
except ImportError:
    try:
        from automode.checkpoint import ensure_checkpoint, restore_hint
    except ImportError:
        def ensure_checkpoint(*args, **kwargs):
            return False, "módulo de capturas no disponible"

        def restore_hint(*args, **kwargs):
            return ""

try:
    from classifier_agy import INFLIGHT_VAR, TECHNICAL_MARK, classify_with_agy
except ImportError:
    try:
        from automode.classifier_agy import INFLIGHT_VAR, TECHNICAL_MARK, classify_with_agy
    except ImportError:
        INFLIGHT_VAR = "AGY_AUTOMODE_INFLIGHT"
        TECHNICAL_MARK = "[sin veredicto]"

        def classify_with_agy(*args, **kwargs):
            return "deny", f"{TECHNICAL_MARK} Clasificador agy no disponible."


HERE = pathlib.Path(__file__).resolve().parent
POLICY_FILE = HERE / "policy.toml"
# Estado de la conversación en curso. `main()` lo fija con `state_dir_for` antes de
# decidir; este valor solo rige si la llamada no pudo leerse.
STATE_DIR = pathlib.Path(tempfile.gettempdir()) / "automode_sin_conversacion"

# Separadores de shell que encadenan acciones independientes.
SEPARATORS = ("&&", "||", ";", "|", "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Utilidades
# ─────────────────────────────────────────────────────────────────────────────

def load_policy() -> dict:
    with POLICY_FILE.open("rb") as fh:
        return tomllib.load(fh)


def safe_id(conversation_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", conversation_id or "no_id")[:64]


def state_dir_for(payload: dict, policy: dict) -> pathlib.Path:
    """Carpeta de estado de la conversación: audit, contadores, capturas y caché.

    Vive en la carpeta que agy crea para cada conversación (`brain/<id>/`), no en
    `.agents`: con una instalación compartida por varios proyectos, dos conversaciones
    escribirían a la vez en los mismos archivos. La subcarpeta se llama `.agents` para
    que la auto-protección impida al agente manipular su propio estado, aunque `brain/`
    esté entre sus raíces de escritura.
    """
    conversation_id = payload.get("conversationId") or ""
    # La batería de pruebas redirige el estado a un directorio efímero, con una
    # subcarpeta por conversación simulada.
    override = os.environ.get("AGY_AUTOMODE_STATE")
    if override:
        return pathlib.Path(override) / safe_id(conversation_id)

    artifact = payload.get("artifactDirectoryPath") or ""
    if artifact:
        base = pathlib.Path(os.path.expandvars(os.path.expanduser(artifact)))
    elif conversation_id:
        plan_root = policy.get("classifier", {}).get("plan_root", "~/.gemini/antigravity-cli/brain")
        base = pathlib.Path(os.path.expandvars(os.path.expanduser(plan_root))) / safe_id(conversation_id)
    else:
        return pathlib.Path(tempfile.gettempdir()) / "automode_sin_conversacion"
    return base / ".agents" / "automode"


def collect_strings(value, acc: list, skip_keys: set | None = None) -> list:
    """Recolecta recursivamente toda cadena dentro de los argumentos.

    Los nombres de argumento varían por herramienta, así que inspeccionamos todos los
    valores en lugar de confiar en claves concretas. La excepción son las claves de
    `skip_keys`: el **contenido** de un archivo que se va a escribir no es una ruta ni
    un comando, y tratarlo como tal produce falsos positivos. Se observó en el corpus:
    escribir un `README.md` cuyo texto mencionaba `pruebas/banco` se clasificó como
    "escritura fuera del proyecto".
    """
    skip_keys = skip_keys or set()
    if isinstance(value, str):
        acc.append(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            if k in skip_keys:
                continue
            collect_strings(v, acc, skip_keys)
    elif isinstance(value, (list, tuple)):
        for v in value:
            collect_strings(v, acc, skip_keys)
    return acc


def looks_like_path(text: str) -> bool:
    if not text or len(text) > 4096:
        return False
    return bool(
        "/" in text
        or "\\" in text
        or re.match(r"^[A-Za-z]:", text)
        or re.search(r"\.\w{1,8}$", text)
    )


def unwrap_quotes(text: str) -> str:
    """Quita comillas externas equilibradas.

    Se observó en transcripts reales que `CommandLine` a veces llega envuelto en
    comillas adicionales.
    """
    t = text.strip()
    while len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
        t = t[1:-1].strip()
    return t


def split_segments(command: str) -> list:
    """Divide un comando en acciones independientes, respetando las comillas."""
    segments, current, quote, i = [], [], None, 0
    while i < len(command):
        c = command[i]
        if quote:
            current.append(c)
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "\"'":
            quote = c
            current.append(c)
            i += 1
            continue
        for sep in SEPARATORS:
            if command.startswith(sep, i):
                segments.append("".join(current))
                current = []
                i += len(sep)
                break
        else:
            current.append(c)
            i += 1
    segments.append("".join(current))
    return [s.strip() for s in segments if s.strip()]


def command_tokens(command: str) -> list:
    """Piezas de un comando que pueden ser rutas.

    Las reglas de rutas están escritas para una ruta aislada, no para un comando entero:
    en `cat .env` el `.env` va precedido de un espacio y en
    `git show HEAD:.agents/policy.toml` el `.agents` va precedido de `:`. Sin partir el
    comando, las dos lecturas pasaban como comandos seguros.
    """
    return [t for t in re.split(r"""[\s"'`=:(),;|&<>{}\[\]]+""", command) if t]


# Construcciones que ejecutan código dentro de un comando de apariencia inofensiva:
# subexpresiones `$(...)`, bloques de script `{...}` (Select-Object @{e={...}}), el
# acento grave de sustitución y la redirección `>`, que sobrescribe archivos.
EMBEDDED_CODE = re.compile(r"\$\(|[{}`>]")


def match_any(text: str, patterns) -> str | None:
    for p in patterns:
        try:
            if re.search(p, text, re.IGNORECASE):
                return p
        except re.error:
            continue
    return None


def within_roots(path: str, roots: list) -> bool:
    """¿La ruta resuelta cae bajo alguna de las raíces del workspace?"""
    if not roots:
        return False
    try:
        target = pathlib.Path(os.path.expandvars(os.path.expanduser(path)))
        if not target.is_absolute():
            target = pathlib.Path(roots[0]) / target
        target = pathlib.Path(os.path.realpath(target))
    except (OSError, ValueError):
        return False
    for root in roots:
        try:
            if target.is_relative_to(pathlib.Path(os.path.realpath(root))):
                return True
        except (OSError, ValueError):
            continue
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Cortacircuitos
# ─────────────────────────────────────────────────────────────────────────────

def counters_path() -> pathlib.Path:
    # La carpeta de estado ya es de la conversación: el nombre no necesita el id.
    return STATE_DIR / "counters.json"


def read_counters() -> dict:
    try:
        return json.loads(counters_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"consecutive": 0, "total": 0}


def write_counters(data: dict) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        counters_path().write_text(
            json.dumps(data, ensure_ascii=False), encoding="utf-8"
        )
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Motor de decisión
# ─────────────────────────────────────────────────────────────────────────────

def judge_disabled() -> bool:
    """¿La persona lanzó la sesión con `AGY_AUTOMODE=off`?

    Apaga solo lo que cuesta tiempo: el clasificador y la captura git. Las líneas rojas
    —auto-protección, credenciales y comandos bloqueados— se siguen aplicando, porque son
    instantáneas y son el freno ante un desastre. La variable la fija quien abre la sesión:
    un `$env:` dentro de un comando del agente no llega al proceso de agy que lanza el hook.
    """
    return os.environ.get("AGY_AUTOMODE", "").strip().lower() == "off"


def get_active_mode(policy: dict, payload: dict | None = None) -> str:
    """Modo vigente, por precedencia: entorno > conversación > política.

    La variable `AGY_MODE` manda porque es un override deliberado de la persona. Por
    debajo, la conversación: quien escribe `/plan` está poniendo a agy en modo plan, y
    ese mismo mensaje pone aquí la fase de planeación. Al final, el valor fijo de
    `policy.toml`, que es lo que rige cuando no hay transcript ni override.
    """
    env_mode = os.environ.get("AGY_MODE", "").strip().lower()
    if env_mode in ("plan", "auto"):
        return env_mode

    modo = policy.get("mode", {})
    if payload and modo.get("follow_conversation", True):
        fase = detect_phase(
            payload.get("transcriptPath"),
            modo.get("plan_triggers", []),
            modo.get("auto_triggers", []),
        )
        if fase in ("plan", "auto"):
            return fase

    return modo.get("active", "auto").strip().lower()


def command_targets_outside(command: str, roots: list) -> str | None:
    """Devuelve la primera ruta del comando que cae fuera del proyecto, si la hay.

    Le dice al clasificador si el comando se sale del proyecto. Python ya no tiene vía
    rápida en modo plan: juzgarlo por su primera palabra dejaba pasar sin revisión
    tanto `python -m pip install` como un `python -c` que borrase archivos (conversación
    68da1f0a, s12). Como hace el auto mode de Claude Code con `Bash(python*)`, todo
    intérprete pasa por el clasificador.
    """
    if not roots:
        return None
    # Se rastrean rutas dentro de todo el comando, no argumentos sueltos: dentro de un
    # `python -c "..."` la ruta viaja anidada entre comillas y pegada al código que la
    # rodea, de modo que partir por espacios no la encuentra.
    fin = r"""[^\s"'()\[\],;:]*"""
    patrones = [
        # C:\... o C:/... El lookbehind descarta esquemas de URL (`https://`), donde la
        # letra anterior haría pasar `s:/` por una unidad.
        rf"(?<![\w])[A-Za-z]:[\\/]{fin}",
        rf"~[\\/]{fin}",                  # ~/...
        rf"\.\.[\\/]{fin}",               # traversal hacia arriba
        # POSIX absolutas. El lookbehind evita que `./out/fig.png` se lea como `/out/...`.
        rf"(?<![\w.~/:])/(?:[\w.-]+/){{1,}}{fin}",
    ]
    for patron in patrones:
        for encontrada in re.findall(patron, command):
            ruta = encontrada.rstrip("\\/")
            if ruta and not within_roots(ruta, roots):
                return ruta
    return None


def root_of(roots: list) -> pathlib.Path:
    """Raíz del proyecto según el payload, con el repositorio como último recurso."""
    return pathlib.Path(roots[0]) if roots else HERE.parent.parent


def work_objective(payload: dict | None, policy: dict) -> str:
    """Define contra qué se mide si una acción pertenece al trabajo en curso.

    Dos fuentes, complementarias: el **plan aprobado** —que es el encargo formal, y en
    modo auto la autorización misma— y las **últimas instrucciones auténticas** del
    usuario, que es lo único disponible mientras aún se está planificando. Ambas pasan
    por filtros reasoning-blind: nunca entra aquí el razonamiento del propio modelo.
    """
    if not payload:
        return ""
    cfg = policy.get("classifier", {})
    partes = []

    plan = read_work_objective(
        payload.get("conversationId") or "",
        plan_root=cfg.get("plan_root", "~/.gemini/antigravity-cli/brain"),
        max_chars=int(cfg.get("plan_max_chars", 4000)),
        artifact_dir=payload.get("artifactDirectoryPath") or "",
    )
    if plan:
        partes.append(f"PLAN DE TRABAJO APROBADO:\n{plan}")

    intent = extract_user_intent(payload.get("transcriptPath"))
    if intent:
        partes.append(f"INSTRUCCIONES RECIENTES DEL USUARIO:\n{intent}")

    return "\n\n".join(partes)


def sin_respaldo(detalle: str) -> str:
    """Motivo accionable cuando no hay respaldo posible.

    El hook fiscaliza, no muta el proyecto: no ejecuta `git init` por su cuenta, porque
    un guardián con efectos sobre el disco puede sorprender dentro de un monorepo. En su
    lugar nombra el obstáculo y la salida, y el agente la toma por el camino normal
    —`git init` está entre los comandos seguros—, sin que nadie tenga que aprobar nada.
    """
    return (
        f"Sin respaldo del proyecto ({detalle}). Ejecuta `git init` en la raíz del "
        "proyecto y reintenta: el auto mode necesita poder deshacer antes de modificar."
    )


def guard_checkpoint(payload: dict | None, policy: dict, roots: list) -> tuple:
    """Asegura que exista una captura del proyecto antes de un cambio destructivo.

    Devuelve (hay_respaldo, capturado, detalle). Con `require = false` la ausencia de
    respaldo se reporta pero no frena: es la salida para proyectos que no son repositorios y
    donde la persona acepta ese riesgo a conciencia. `capturado` dice si de verdad existe una
    captura: con `AGY_AUTOMODE=off`, con las capturas desactivadas o con `require = false` se
    deja pasar sin ella, y entonces el motivo no puede prometer que el cambio se pueda deshacer.
    """
    if judge_disabled():
        return True, False, "sesión con AGY_AUTOMODE=off"
    cfg = policy.get("checkpoint", {})
    if not cfg.get("enabled", True):
        return True, False, "capturas desactivadas por política"

    conversation_id = (payload or {}).get("conversationId") or ""
    ok, detalle = ensure_checkpoint(
        root_of(roots),
        conversation_id,
        STATE_DIR,
        min_interval_seconds=float(cfg.get("min_interval_seconds", 300)),
        exclude_patterns=policy.get("paths", {}).get("sensitive", []),
    )
    if ok:
        return True, True, f"{detalle}; deshacer con `{restore_hint(conversation_id)}`"
    if cfg.get("require", True):
        return False, False, detalle
    return True, False, detalle


def classify(
    policy: dict,
    user_intent: str,
    tool_name: str,
    tool_args: dict,
    root_dir: pathlib.Path,
    context: dict | None = None,
) -> tuple:
    """Consulta al clasificador `agy`.

    El veredicto es binario: `allow` o `deny`. Ante un fallo del propio clasificador se
    deniega con la marca técnica, nunca se deja pasar (ver `[classifier] on_failure`).
    """
    if judge_disabled():
        return "allow", "Sin clasificador: sesión lanzada con AGY_AUTOMODE=off."
    # La batería de pruebas pone AGY_AUTOMODE_BACKEND=none para no lanzar agy en cada caso.
    if os.environ.get("AGY_AUTOMODE_BACKEND", "").strip().lower() == "none":
        salida = policy.get("classifier", {}).get("on_failure", "deny")
        return salida, f"{TECHNICAL_MARK} Clasificador desactivado: no hay quien juzgue esta acción."
    return classify_with_agy(
        user_intent=user_intent,
        tool_name=tool_name,
        tool_args=tool_args,
        policy=policy,
        state_dir=STATE_DIR,
        root_dir=root_dir,
        context=context,
    )


def is_technical(reason: str) -> bool:
    """¿La denegación viene de un fallo del clasificador y no de un juicio de política?"""
    return str(reason or "").lstrip().startswith(TECHNICAL_MARK)


def evaluate_command(command: str, policy: dict, payload: dict | None = None) -> tuple:
    """Evalúa un comando de shell. Devuelve (decision, reason, rule)."""
    command = unwrap_quotes(command)
    blocked = policy.get("commands", {}).get("blocked", [])
    safe = policy.get("commands", {}).get("safe", [])
    active_mode = get_active_mode(policy, payload)

    # 1. Reglas críticas de bloqueo (se aplican en ambos modos)
    for rule in blocked:
        pattern = rule.get("pattern", "")
        try:
            if pattern and re.search(pattern, command, re.IGNORECASE):
                return "deny", rule.get("reason", "Acción bloqueada por política."), pattern
        except re.error:
            continue

    segments = split_segments(command)
    if not segments:
        return "deny", "Comando vacío o no interpretable: no hay nada que autorizar.", None

    # 2. Comprobar si todos los segmentos son comandos inequívocamente seguros. Un comando
    #    de la lista deja de serlo si lleva código incrustado o si apunta fuera del
    #    proyecto: leer fuera no destruye nada, pero se juzga igual que con view_file.
    all_safe = all(
        match_any(seg, [r"^\s*" + p for p in safe]) and not EMBEDDED_CODE.search(seg)
        for seg in segments
    )
    roots = (payload.get("workspacePaths") if payload else []) or []
    fuera = command_targets_outside(command, roots)

    if all_safe and not fuera:
        return "allow", "Todos los segmentos son comandos de solo consulta o verificación.", None

    # 3. Todo lo demás lo juzga el clasificador, en ambos modos. La fase viaja como
    #    contexto: no es lo mismo compilar mientras se planifica que tras la aprobación,
    #    y esa diferencia la pondera quien tiene el objetivo del trabajo delante.
    if not policy.get("classifier", {}).get("enabled", True):
        return "deny", f"Clasificador deshabilitado por política; comando no reconocido como seguro: {command[:120]}", None

    tool_name = payload.get("toolCall", {}).get("name", "run_command") if payload else "run_command"
    tool_args = payload.get("toolCall", {}).get("args", {}) if payload else {"CommandLine": command}
    motivo_consulta = (
        f"Comando fuera del alcance de las reglas estáticas. Toca la ruta {fuera[:80]}, fuera del proyecto."
        if fuera else
        "Comando fuera del alcance de las reglas estáticas: no figura entre los seguros ni entre los bloqueados."
    )
    dec, reason = classify(
        policy, work_objective(payload, policy), tool_name, tool_args, root_of(roots),
        context={"phase": active_mode, "rule": motivo_consulta},
    )
    if dec == "allow":
        # Un comando aprobado puede escribir o borrar: se respalda igual que una
        # edición, para que la aprobación no dependa de adivinar qué hará.
        respaldado, capturado, detalle = guard_checkpoint(payload, policy, roots)
        if not respaldado:
            return "deny", sin_respaldo(detalle), None
        reason = f"{reason} {'Respaldo' if capturado else 'Sin respaldo'}: {detalle}."
    return dec, reason, None


def decide(payload: dict, policy: dict) -> tuple:
    """Devuelve (decision, reason, rule) para una llamada a herramienta."""
    tool = payload.get("toolCall") or {}
    name = (tool.get("name") or "").strip()
    args = tool.get("args") or {}
    roots = payload.get("workspacePaths") or []
    active_mode = get_active_mode(policy, payload)

    tools = policy.get("tools", {})
    paths = policy.get("paths", {})
    strings = collect_strings(args, [], set(tools.get("content_args", [])))
    read_only = name in tools.get("read_only", [])

    # En un comando, las rutas van mezcladas con el resto: se revisan también pieza a pieza.
    key = tools.get("command_arg", {}).get(name)
    tokens = command_tokens(args[key]) if key and isinstance(args.get(key), str) else []

    # 1. Auto-protección. Se deniega siempre, sin excepción configurable: un guardián
    #    que puede editarse a sí mismo no es un guardián.
    if not read_only:
        for text in strings + tokens:
            hit = match_any(text, paths.get("self_protected", []))
            if hit:
                return (
                    "deny",
                    "El auto mode no puede modificarse a sí mismo. Si la política "
                    "necesita cambiar, edítala tú directamente.",
                    hit,
                )

    # 2. Rutas sensibles. Leer credenciales es exploración de credenciales aunque
    #    técnicamente sea una operación de lectura.
    for text in strings:
        if not looks_like_path(text):
            continue
        hit = match_any(text, paths.get("sensitive", []))
        if hit:
            return "deny", f"Acceso a una ruta con credenciales: {text[:120]}", hit
    # Una pieza suelta como `id_rsa` no parece una ruta, pero dentro de un comando lo es.
    for text in tokens:
        hit = match_any(text, paths.get("sensitive", []))
        if hit:
            return "deny", f"Acceso a una ruta con credenciales: {text[:120]}", hit

    # 3. Herramientas que ejecutan comandos: se juzga la carga real.
    if key and isinstance(args.get(key), str):
        return evaluate_command(args[key], policy, payload)

    # 4. Nivel 1 — solo lectura. Libre dentro del proyecto; fuera, se fiscaliza.
    #
    #    Leer no destruye nada, pero explorar fuera del encargo sí es una desviación:
    #    subir a una carpeta de jerarquía superior "a ver qué hay" no pertenece al
    #    trabajo. Dentro del workspace se aprueba por regla y en milisegundos, que es
    #    el caso normal; solo la lectura que se sale pasa por el clasificador, con el
    #    objetivo del trabajo como vara. Aplica en ambos modos.
    if read_only:
        # Búsquedas de credenciales: la regla equivalente para comandos de shell no
        # cubría los argumentos de las herramientas de búsqueda.
        for text in strings:
            hit = match_any(text, paths.get("credential_terms", []))
            if hit:
                return (
                    "deny",
                    "Búsqueda de credenciales. Si necesitas una, pídela explícitamente.",
                    hit,
                )

        fuera = [t for t in strings if looks_like_path(t) and not within_roots(t, roots)]
        if not fuera:
            return "allow", "Lectura dentro del proyecto.", None
        dec, reason = classify(
            policy, work_objective(payload, policy), name, args, root_of(roots),
            context={"phase": active_mode,
                     "rule": f"Lectura fuera del proyecto: {fuera[0][:120]}"},
        )
        if dec == "allow":
            return "allow", reason, None
        return dec, f"Lectura fuera del proyecto ({fuera[0][:80]}). {reason}", None

    # 5. Nivel 2 — escritura dentro del proyecto.
    if name in tools.get("write", []):
        # Las raíces adicionales cubren directorios legítimos fuera del workspace,
        # como el `brain/` donde agy guarda sus propios artefactos de planeación.
        write_roots = list(roots) + [
            os.path.expandvars(os.path.expanduser(r))
            for r in paths.get("extra_write_roots", [])
        ]
        outside = [t for t in strings if looks_like_path(t) and not within_roots(t, write_roots)]

        # El motivo nombra el destino real: si una escritura en scratch se etiqueta como
        # "archivo del proyecto", el agente concluye que scratch también está vetado, y que
        # la captura del proyecto la cubre, cuando no es así.
        en_proyecto = any(looks_like_path(t) and within_roots(t, roots) for t in strings)

        # Escribir fuera del proyecto, o escribir mientras se planifica, no son casos que
        # una regla pueda zanjar: dependen de si la acción pertenece al encargo. Los juzga
        # el clasificador, que es quien tiene delante el objetivo del trabajo y la fase.
        if outside or active_mode == "plan":
            motivo = (
                f"Escritura fuera del proyecto: {outside[0][:120]}" if outside else
                "Edición de un archivo del proyecto durante la fase de planeación." if en_proyecto else
                "Escritura en el directorio de trabajo de agy (scratch) durante la fase de "
                "planeación; no toca el proyecto."
            )
            dec, reason = classify(
                policy, work_objective(payload, policy), name, args, root_of(roots),
                context={"phase": active_mode, "rule": motivo},
            )
            if dec != "allow":
                return dec, f"{motivo} {reason}", None
            if outside:
                return "allow", reason, None
            # Aprobado en modo plan: sigue necesitando respaldo, como toda edición.

        # La libertad de modificar se apoya en poder deshacer. Antes del primer cambio
        # del bloque se captura el estado del proyecto; si no se puede, la afirmación
        # "reversible" sería falsa, así que se deniega diciendo cómo habilitarlo.
        respaldado, capturado, detalle = guard_checkpoint(payload, policy, roots)
        if not respaldado:
            return "deny", sin_respaldo(detalle), None
        if not en_proyecto:
            return ("allow", "Escritura en el directorio de trabajo de agy (scratch), fuera del "
                    "proyecto: la captura git no la cubre.", None)
        if capturado:
            return "allow", f"Edición dentro del proyecto, reversible: {detalle}.", None
        return ("allow", f"Edición dentro del proyecto, sin respaldo ({detalle}): no se puede "
                "deshacer con git.", None)

    # 6. Herramientas complejas o externas (always_evaluate, etc.). El clasificador
    #    interviene en ambos modos: la fase es contexto para su juicio, no un motivo
    #    para prescindir de él.
    if policy.get("classifier", {}).get("enabled", True):
        conocida = name in tools.get("always_evaluate", [])
        dec, reason = classify(
            policy, work_objective(payload, policy), name, args, root_of(roots),
            context={"phase": active_mode,
                     "rule": ("Herramienta con efectos externos o destructivos." if conocida
                              else f"Herramienta no declarada en la política: {name}.")},
        )
        if dec == "allow" and name in tools.get("destructive", []):
            respaldado, capturado, detalle = guard_checkpoint(payload, policy, roots)
            if not respaldado:
                return "deny", sin_respaldo(detalle), None
            reason = f"{reason} {'Respaldo' if capturado else 'Sin respaldo'}: {detalle}."
        return dec, reason, None

    return "deny", f"Clasificador deshabilitado por política y herramienta no cubierta por reglas: {name}", None


# ─────────────────────────────────────────────────────────────────────────────
# Auditoría
# ─────────────────────────────────────────────────────────────────────────────

def audit(record: dict) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with (STATE_DIR / "audit.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def permission_overrides(payload: dict, policy: dict, decision: str) -> list:
    """Concesiones temporales que acompañan a un `allow` sobre un comando.

    Se observó que, en el modo plan de agy, un `allow` del hook no siempre basta:
    agy vuelve a pedir confirmación con su propia interfaz —la que ofrece «permitir
    siempre los comandos que empiezan por…»—, sin mostrar nuestro motivo. Ese es
    justamente el permiso que `permissionOverrides` concede, según el contrato
    documentado en el binario: `["command(npm test)"]`.

    Se concede el comando exacto que ya se aprobó, ni un prefijo más amplio: la
    concesión no añade autoridad, solo evita volver a preguntar por lo mismo.
    """
    if decision != "allow":
        return []
    if not policy.get("mode", {}).get("emit_permission_overrides", True):
        return []
    tool = (payload.get("toolCall") or {})
    nombre = (tool.get("name") or "").strip()
    clave = policy.get("tools", {}).get("command_arg", {}).get(nombre)
    if not clave:
        return []
    comando = (tool.get("args") or {}).get(clave)
    if not isinstance(comando, str) or not comando.strip():
        return []
    return [f"command({unwrap_quotes(comando)})"]


def respond(decision: str, reason: str, overrides: list | None = None) -> None:
    salida = {"decision": decision, "reason": reason}
    if overrides:
        salida["permissionOverrides"] = overrides
    print(json.dumps(salida, ensure_ascii=False))


# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    global STATE_DIR

    # Guardia anti-recursión. Si esta variable está definida, quien nos invoca es el
    # `agy` que el propio auto mode lanzó para clasificar. Ese agente razona sobre
    # texto y no tiene por qué usar herramienta alguna: denegar corta de raíz la
    # posibilidad de que el clasificador se llame a sí mismo sin fin. Va antes de leer
    # la política para que ni siquiera un error de configuración abra el ciclo.
    if os.environ.get(INFLIGHT_VAR):
        respond("deny", "El clasificador del auto mode no ejecuta herramientas.")
        return 0

    try:
        # Se lee en binario y se decodifica con utf-8-sig: en Windows la entrada
        # puede llegar con BOM, y json.loads lo rechaza.
        raw = sys.stdin.buffer.read().decode("utf-8-sig", errors="replace")
        payload = json.loads(raw) if raw.strip() else {}
    except (ValueError, OSError) as exc:
        respond("ask", f"El auto mode no pudo leer la llamada ({exc}). Decide tú.")
        return 0

    try:
        policy = load_policy()
    except (OSError, ValueError) as exc:
        respond("ask", f"Política ilegible ({exc}). Decide tú.")
        audit({"ts": datetime.now().isoformat(timespec="seconds"),
               "error": f"policy: {exc}"})
        return 0

    STATE_DIR = state_dir_for(payload, policy)

    try:
        decision, reason, rule = decide(payload, policy)
    except Exception as exc:  # el hook nunca puede tumbar la sesión
        respond("ask", f"Error interno del auto mode ({exc}). Decide tú.")
        audit({"ts": datetime.now().isoformat(timespec="seconds"),
               "error": f"decide: {exc}"})
        return 0

    mode = policy.get("mode", {})
    effective = decision

    # Cortacircuitos: insistir en caminos prohibidos indica que el agente está
    # atascado, no corrigiéndose.
    #
    # Las denegaciones por fallo del clasificador quedan fuera de la cuenta. Un timeout
    # o un corte de red no es el agente empujando contra una prohibición, y tres seguidos
    # detendrían la sesión por un problema de infraestructura.
    tecnica = is_technical(reason)
    conversation_id = payload.get("conversationId") or ""
    counters = read_counters()
    if decision == "deny" and not tecnica:
        counters["consecutive"] = counters.get("consecutive", 0) + 1
        counters["total"] = counters.get("total", 0) + 1
    elif decision == "allow":
        counters["consecutive"] = 0
    write_counters(counters)

    breaker = policy.get("circuit_breaker", {})
    # Sin supervisión, agy ejecuta un `force_ask` igual que un `ask`: se midió en la
    # conversación 68da1f0a, donde tras escalar el agente leyó la configuración del hook.
    # Por eso el cortacircuitos no escala: mantiene la denegación y le pide al agente que
    # pare, como el auto mode de Claude Code en sesiones que no pueden preguntar. Solo
    # actúa sobre denegaciones de política, y el total se reinicia al dispararse: de lo
    # contrario, pasadas 20 denegaciones se bloquearía el resto de la sesión.
    total_agotado = counters.get("total", 0) >= breaker.get("total_denials", 20)
    if decision == "deny" and not tecnica and (
            counters.get("consecutive", 0) >= breaker.get("consecutive_denials", 3)
            or total_agotado):
        reason = (
            f"Cortacircuitos activado ({counters['consecutive']} denegaciones seguidas, "
            f"{counters['total']} en la sesión): {reason} No insistas por esta vía; "
            "cambia de enfoque o detente y explica al usuario qué necesitas."
        )
        if total_agotado:
            counters["total"] = 0
            write_counters(counters)

    if effective != "allow" or mode.get("audit_allow", True):
        call = payload.get("toolCall") or {}
        audit({
            "ts": datetime.now().isoformat(timespec="seconds"),
            # Qué instalación actuó: con el plugin en un proyecto y en global a la vez,
            # es lo único que distingue sus registros.
            "hook": str(HERE),
            "conversation": conversation_id,
            "step": payload.get("stepIdx"),
            "tool": call.get("name"),
            "args": call.get("args"),
            "tecnica": tecnica,
            "decision": decision,
            "effective": effective,
            "reason": reason,
            "rule": rule,
        })

    respond(effective, reason, permission_overrides(payload, policy, effective))
    return 0


if __name__ == "__main__":
    sys.exit(main())
