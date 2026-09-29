import json
import os
import pathlib
import re
import sys
import tempfile
import time
import tomllib
from datetime import datetime

from checkpoint import ensure_checkpoint, omitted_paths, restore_hint
from classifier_agy import INFLIGHT_VAR, TECHNICAL_MARK, classify_with_agy
from transcript import detect_phase, extract_user_intent, read_work_objective

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# El código vive en src/; la política y hooks.json, en la raíz del plugin.
PLUGIN_ROOT = pathlib.Path(__file__).resolve().parent.parent
POLICY_FILE = PLUGIN_ROOT / "policy.toml"
# Estado de la conversación en curso. `main()` lo fija con `resolve_state_dir` antes de
# decidir; este valor solo rige si la llamada no pudo leerse.
STATE_DIR = pathlib.Path(tempfile.gettempdir()) / "automode_no_conversation"
# Conversación en curso: cada una tiene su propio juez precargado.
CONVERSATION_ID = ""

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


def resolve_state_dir(payload: dict, policy: dict) -> pathlib.Path:
    """Estado de la conversación, en `brain/<id>/.agents/automode/`: fuera del alcance del agente."""
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
        return pathlib.Path(tempfile.gettempdir()) / "automode_no_conversation"
    return base / ".agents" / "automode"


def collect_strings(value, acc: list, skip_keys: set | None = None) -> list:
    """Todas las cadenas de los argumentos, salvo las de `skip_keys`, que son contenido y no rutas."""
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


def is_path_candidate(text: str) -> bool:
    if not text or len(text) > 4096:
        return False
    return bool(
        "/" in text
        or "\\" in text
        or re.match(r"^[A-Za-z]:", text)
        or re.search(r"\.\w{1,8}$", text)
    )


def unwrap_quotes(text: str) -> str:
    """Quita comillas externas equilibradas: `CommandLine` a veces llega envuelto en ellas."""
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
    """Piezas de un comando que pueden ser rutas, como `.env` en `cat .env`."""
    return [t for t in re.split(r"""[\s"'`=:(),;|&<>{}\[\]]+""", command) if t]


# Código incrustado en un comando de apariencia inofensiva: `$(...)`, `{...}`, acento grave y `>`.
EMBEDDED_CODE = re.compile(r"\$\(|[{}`>]")

# Redirecciones que solo descartan o unen la salida de errores: no escriben en el proyecto.
HARMLESS_REDIRECT = re.compile(r"\s*(?:[12*]?>\s*(?:\$null|/dev/null|nul)\b|[12]>&[12])", re.I)

# Con variables o unidades de PowerShell (`env:` guarda claves de API) la ruta real no se conoce.
UNRESOLVED_PATH = re.compile(
    r"\$[\w{:]|%\w+%|(?<![\w-])(?:env|variable|function|alias|hklm|hkcu|cert|wsman):", re.I)


def match_any(text: str, patterns) -> str | None:
    for p in patterns:
        try:
            if re.search(p, text, re.IGNORECASE):
                return p
        except re.error:
            continue
    return None


def is_contained(path: str, roots: list) -> bool:
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
# Motor de decisión
# ─────────────────────────────────────────────────────────────────────────────

def get_active_mode(policy: dict, payload: dict) -> str:
    """Modo vigente, por precedencia: `AGY_MODE` > lo que escribió la persona > `policy.toml`."""
    env_mode = os.environ.get("AGY_MODE", "").strip().lower()
    if env_mode in ("plan", "auto"):
        return env_mode

    mode_cfg = policy.get("mode", {})
    phase = detect_phase(
        payload.get("transcriptPath"),
        mode_cfg.get("plan_triggers", []),
        mode_cfg.get("auto_triggers", []),
    )
    if phase in ("plan", "auto"):
        return phase
    return mode_cfg.get("active", "auto").strip().lower()


def command_targets_outside(command: str, roots: list) -> str | None:
    """Primera ruta del comando que cae fuera del proyecto, si la hay."""
    if not roots:
        return None
    # Se rastrea el comando entero: en `python -c "..."` la ruta va pegada al código.
    tail = r"""[^\s"'()\[\],;:]*"""
    patterns = [
        # C:\... o C:/... El lookbehind descarta esquemas de URL (`https://`), donde la
        # letra anterior haría pasar `s:/` por una unidad.
        rf"(?<![\w])[A-Za-z]:[\\/]{tail}",
        rf"~[\\/]{tail}",                  # ~/...
        rf"\.\.[\\/]{tail}",               # traversal hacia arriba
        # POSIX absolutas. El lookbehind evita que `./out/fig.png` se lea como `/out/...`.
        rf"(?<![\w.~/:])/(?:[\w.-]+/){{1,}}{tail}",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, command):
            path = match.rstrip("\\/")
            if path and not is_contained(path, roots):
                return path
    return None


def primary_root(roots: list) -> pathlib.Path:
    """Raíz del proyecto según el payload, con el repositorio como último recurso."""
    return pathlib.Path(roots[0]) if roots else PLUGIN_ROOT.parent.parent


def work_objective(payload: dict, policy: dict) -> str:
    """Vara del trabajo: el plan aprobado y las últimas instrucciones del usuario."""
    cfg = policy.get("classifier", {})
    parts = []

    plan = read_work_objective(
        payload.get("conversationId") or "",
        plan_root=cfg.get("plan_root", "~/.gemini/antigravity-cli/brain"),
        max_chars=int(cfg.get("plan_max_chars", 4000)),
        artifact_dir=payload.get("artifactDirectoryPath") or "",
    )
    if plan:
        parts.append(f"PLAN DE TRABAJO APROBADO:\n{plan}")

    intent = extract_user_intent(payload.get("transcriptPath"))
    if intent:
        parts.append(f"INSTRUCCIONES RECIENTES DEL USUARIO:\n{intent}")

    return "\n\n".join(parts)


def explain_missing_backup(detail: str) -> str:
    """Motivo cuando no hay respaldo: el hook no ejecuta `git init`, le pide al agente que lo haga."""
    return (
        f"Sin respaldo del proyecto ({detail}). Ejecuta `git init` en la raíz del "
        "proyecto y reintenta: el auto mode necesita poder deshacer antes de modificar."
    )


def guard_checkpoint(payload: dict, policy: dict, roots: list) -> tuple:
    """Captura el proyecto antes de un cambio. Devuelve (hay_respaldo, detalle)."""
    cfg = policy.get("checkpoint", {})
    conversation_id = payload.get("conversationId") or ""
    ok, detail = ensure_checkpoint(
        primary_root(roots),
        conversation_id,
        STATE_DIR,
        min_interval_seconds=float(cfg.get("min_interval_seconds", 300)),
        exclude_patterns=policy.get("paths", {}).get("sensitive", []),
        max_file_bytes=int(float(cfg.get("max_file_mb", 0)) * 1024 * 1024),
        keep_last=int(cfg.get("keep_last", 0)),
    )
    if not ok:
        return False, detail
    hint = restore_hint(conversation_id, omitted_paths(STATE_DIR, conversation_id))
    return True, f"{detail}; deshacer con `{hint}`"


def classify(policy: dict, user_intent: str, tool_name: str, tool_args: dict,
             context: dict | None = None) -> tuple:
    """Consulta al juez `agy`. Ante un fallo del juez, deniega."""
    # La batería de pruebas pone AGY_AUTOMODE_BACKEND=none para no lanzar agy en cada caso.
    if os.environ.get("AGY_AUTOMODE_BACKEND", "").strip().lower() == "none":
        return "deny", f"{TECHNICAL_MARK} Clasificador desactivado: no hay quien juzgue esta acción."
    return classify_with_agy(
        user_intent=user_intent,
        tool_name=tool_name,
        tool_args=tool_args,
        policy=policy,
        context=context,
        conversation_id=CONVERSATION_ID,
    )


def evaluate_command(command: str, policy: dict, payload: dict) -> tuple:
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

    # 2. Seguro si todos los segmentos lo son, sin código incrustado ni rutas fuera del proyecto.
    def is_safe(segment: str) -> bool:
        cleaned = HARMLESS_REDIRECT.sub("", segment)
        return bool(match_any(cleaned, [r"^\s*" + p for p in safe])
                    and not EMBEDDED_CODE.search(cleaned) and not UNRESOLVED_PATH.search(cleaned))

    all_safe = all(is_safe(segment) for segment in segments)
    roots = payload.get("workspacePaths") or []
    outside_paths = command_targets_outside(command, roots)

    if all_safe and not outside_paths:
        return "allow", "Todos los segmentos son comandos de solo consulta o verificación.", None

    # 3. Todo lo demás lo juzga el clasificador, con la fase como contexto.
    tool = payload.get("toolCall", {})
    rule_text = (
        f"Comando fuera del alcance de las reglas estáticas. Toca la ruta {outside_paths[:80]}, fuera del proyecto."
        if outside_paths else
        "Comando fuera del alcance de las reglas estáticas: no figura entre los seguros ni entre los bloqueados."
    )
    verdict, reason = classify(
        policy, work_objective(payload, policy), tool.get("name", "run_command"),
        tool.get("args", {}), context={"phase": active_mode, "rule": rule_text},
    )
    if verdict == "allow":
        # Un comando aprobado puede escribir o borrar: se respalda igual que una
        # edición, para que la aprobación no dependa de adivinar qué hará.
        backed_up, detail = guard_checkpoint(payload, policy, roots)
        if not backed_up:
            return "deny", explain_missing_backup(detail), None
        reason = f"{reason} Respaldo: {detail}."
    return verdict, reason, None


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
        if not is_path_candidate(text):
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

    # 4. Solo lectura: libre dentro del proyecto; fuera, la juzga el clasificador.
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

        outside_paths = [t for t in strings if is_path_candidate(t) and not is_contained(t, roots)]
        if not outside_paths:
            return "allow", "Lectura dentro del proyecto.", None
        verdict, reason = classify(
            policy, work_objective(payload, policy), name, args,
            context={"phase": active_mode,
                     "rule": f"Lectura fuera del proyecto: {outside_paths[0][:120]}"},
        )
        if verdict == "allow":
            return "allow", reason, None
        return verdict, f"Lectura fuera del proyecto ({outside_paths[0][:80]}). {reason}", None

    # 5. Nivel 2 — escritura dentro del proyecto.
    if name in tools.get("write", []):
        # Las raíces adicionales cubren directorios legítimos fuera del workspace,
        # como el `brain/` donde agy guarda sus propios artefactos de planeación.
        write_roots = list(roots) + [
            os.path.expandvars(os.path.expanduser(r))
            for r in paths.get("extra_write_roots", [])
        ]
        outside = [t for t in strings if is_path_candidate(t) and not is_contained(t, write_roots)]

        # El motivo nombra el destino real: scratch no es el proyecto ni lo cubre la captura.
        touches_project = any(is_path_candidate(t) and is_contained(t, roots) for t in strings)

        # Escribir fuera del proyecto o durante la planeación lo juzga el clasificador.
        if outside or active_mode == "plan":
            rule_text = (
                f"Escritura fuera del proyecto: {outside[0][:120]}" if outside else
                "Edición de un archivo del proyecto durante la fase de planeación." if touches_project else
                "Escritura en el directorio de trabajo de agy (scratch) durante la fase de "
                "planeación; no toca el proyecto."
            )
            verdict, reason = classify(
                policy, work_objective(payload, policy), name, args,
                context={"phase": active_mode, "rule": rule_text},
            )
            if verdict != "allow":
                return verdict, f"{rule_text} {reason}", None
            if outside:
                return "allow", reason, None
            # Aprobado en modo plan: sigue necesitando respaldo, como toda edición.

        # Sin captura posible no se modifica: "reversible" sería falso.
        backed_up, detail = guard_checkpoint(payload, policy, roots)
        if not backed_up:
            return "deny", explain_missing_backup(detail), None
        if not touches_project:
            return ("allow", "Escritura en el directorio de trabajo de agy (scratch), fuera del "
                    "proyecto: la captura git no la cubre.", None)
        return "allow", f"Edición dentro del proyecto, reversible: {detail}.", None

    # 6. Herramientas sin regla fija (efectos externos o no declaradas): las juzga el clasificador.
    verdict, reason = classify(
        policy, work_objective(payload, policy), name, args,
        context={"phase": active_mode, "rule": f"Herramienta sin regla fija: {name}."},
    )
    if verdict == "allow" and name in tools.get("destructive", []):
        backed_up, detail = guard_checkpoint(payload, policy, roots)
        if not backed_up:
            return "deny", explain_missing_backup(detail), None
        reason = f"{reason} Respaldo: {detail}."
    return verdict, reason, None


# ─────────────────────────────────────────────────────────────────────────────
# Auditoría y respuesta
# ─────────────────────────────────────────────────────────────────────────────

def audit(record: dict) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with (STATE_DIR / "audit.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def permission_overrides(payload: dict, policy: dict, decision: str) -> list:
    """Concede el comando exacto ya aprobado, para que agy no vuelva a preguntar en su modo plan."""
    if decision != "allow":
        return []
    tool = (payload.get("toolCall") or {})
    arg_key = policy.get("tools", {}).get("command_arg", {}).get((tool.get("name") or "").strip())
    command = (tool.get("args") or {}).get(arg_key) if arg_key else None
    if not isinstance(command, str) or not command.strip():
        return []
    return [f"command({unwrap_quotes(command)})"]


def respond(decision: str, reason: str, overrides: list | None = None) -> None:
    output = {"decision": decision, "reason": reason}
    if overrides:
        output["permissionOverrides"] = overrides
    print(json.dumps(output, ensure_ascii=False))


def main() -> int:
    global STATE_DIR, CONVERSATION_ID
    start = time.monotonic()

    # Anti-recursión: quien llama es el agy del juez, que no usa herramientas. Va antes de
    # leer la política para que ni un error de configuración abra el ciclo.
    if os.environ.get(INFLIGHT_VAR):
        respond("deny", "El clasificador del auto mode no ejecuta herramientas.")
        return 0

    try:
        # Se lee en binario y se decodifica con utf-8-sig: en Windows la entrada
        # puede llegar con BOM, y json.loads lo rechaza.
        raw = sys.stdin.buffer.read().decode("utf-8-sig", errors="replace")
        payload = json.loads(raw) if raw.strip() else {}
    except (ValueError, OSError) as exc:
        respond("deny", f"El auto mode no pudo leer la llamada ({exc}). Pide al usuario que lo revise.")
        return 0

    try:
        policy = load_policy()
    except (OSError, ValueError) as exc:
        respond("deny", f"Política ilegible ({exc}). Pide al usuario que revise policy.toml.")
        audit({"ts": datetime.now().isoformat(timespec="seconds"), "error": f"policy: {exc}"})
        return 0

    STATE_DIR = resolve_state_dir(payload, policy)
    CONVERSATION_ID = payload.get("conversationId") or ""

    try:
        decision, reason, rule = decide(payload, policy)
    except Exception as exc:  # el hook nunca puede tumbar la sesión
        respond("deny", f"Error interno del auto mode ({exc}). Pide al usuario que lo revise.")
        audit({"ts": datetime.now().isoformat(timespec="seconds"), "error": f"decide: {exc}"})
        return 0

    call = payload.get("toolCall") or {}
    audit({
        "ts": datetime.now().isoformat(timespec="seconds"),
        # Qué instalación actuó: con el plugin en un proyecto y en global a la vez,
        # es lo único que distingue sus registros.
        "hook": str(PLUGIN_ROOT),
        "conversation": CONVERSATION_ID,
        "step": payload.get("stepIdx"),
        "tool": call.get("name"),
        "args": call.get("args"),
        "decision": decision,
        "reason": reason,
        "rule": rule,
        # Cuánto tardó la decisión: las reglas resuelven en milisegundos, el juez en segundos.
        "ms": int((time.monotonic() - start) * 1000),
    })

    respond(decision, reason, permission_overrides(payload, policy, decision))
    return 0


if __name__ == "__main__":
    sys.exit(main())
