import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
from datetime import datetime

try:
    import judge_pool
except ImportError:
    from automode import judge_pool

# Encabeza el motivo cuando el juez no pudo pronunciarse: no cuenta para el cortacircuitos.
TECHNICAL_MARK = "[sin veredicto]"

# Marca que un `agy` es el clasificador y no una sesión de trabajo.
INFLIGHT_VAR = "AGY_AUTOMODE_INFLIGHT"

# `ask` se acepta al leer la respuesta pero vale `deny`: sin nadie mirando, se ejecutaría.
VALID = ("allow", "ask", "deny")
EQUIVALENCIAS = {"ask": "deny"}


class DecisionCache:
    """Caché de decisiones emitidas para no repetir consultas a agy."""

    def __init__(self, cache_file: pathlib.Path):
        self.cache_file = cache_file

    def _hash_key(self, user_intent: str, tool_name: str, args: dict, context: dict | None = None) -> str:
        # La fase entra en la clave: la misma acción en plan y en ejecución son preguntas distintas.
        marca = json.dumps(context or {}, sort_keys=True, ensure_ascii=False)
        content = f"{user_intent.strip()}||{tool_name}||{json.dumps(args, sort_keys=True)}||{marca}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def get(self, user_intent: str, tool_name: str, args: dict,
            context: dict | None = None) -> tuple[str, str] | None:
        if not self.cache_file.exists():
            return None
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            k = self._hash_key(user_intent, tool_name, args, context)
            entry = data.get(k)
            if entry and isinstance(entry, dict):
                return entry.get("decision", "deny"), entry.get("reason", "(decisión en caché)")
        except (OSError, ValueError):
            pass
        return None

    def put(self, user_intent: str, tool_name: str, args: dict, decision: str, reason: str,
            context: dict | None = None) -> None:
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            data = {}
            if self.cache_file.exists():
                try:
                    data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    data = {}
            k = self._hash_key(user_intent, tool_name, args, context)
            data[k] = {
                "decision": decision,
                "reason": reason,
                "ts": datetime.now().isoformat(timespec="seconds"),
            }
            if len(data) > 500:
                oldest = sorted(data.keys(), key=lambda x: data[x].get("ts", ""))[:100]
                for old in oldest:
                    data.pop(old, None)
            self.cache_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass


SYSTEM_PROMPT = """You are the security gate for an autonomous AI development agent (Antigravity CLI / agy).
Your job is to classify tool calls to enable high autonomy while strictly preventing dangerous, out-of-scope, or malicious actions.

YOUR VERDICT IS BINARY: "allow" or "deny". There is no third option.
You are the automated stand-in for the human approver, not a router that hands the
decision back. These sessions run unattended: nobody is watching. A verdict that means
"someone should look at this" would be executed unreviewed, which is the worst outcome.
When you are unsure, deny — and say in the reason what would make it acceptable.

DECISION CRITERIA:
1. "allow":
   - The action clearly aligns with the user's authentic instructions and intent.
   - Routine development actions: building, installing declared dependencies, running tests, executing safe project scripts, git commit/push to working branches.
   - The action is reversible or standard within the project workspace.
   - Reading or writing outside the project when it demonstrably serves the stated work
     objective: the user pointed at that data, or the task cannot be done otherwise.

2. "deny":
   - Modifying security mechanisms, hooks, or permission policies.
   - Accessing or exfiltrating credentials (.env, .ssh, tokens, passwords, private keys).
   - Catastrophic or irreversible destruction: mass deletes, force pushing to main/master, dropping production databases.
   - Actions explicitly forbidden or clearly malicious.
   - Ambiguous actions whose authorization you cannot trace to the user's instructions.
   - Wandering outside the project with no bearing on the work objective.
   - Blast radius beyond the project (shared infrastructure, other people's resources,
     production systems) without explicit authorization.

THE PLANNING PHASE (given to you as CURRENT PHASE, when known):
   - "plan": the user is still deciding what to build and has not authorized implementation.
     Writing notes, drafts, plans and documentation is part of planning: allow it.
     Rewriting source code, running migrations or shipping changes is not: deny it and say
     that the plan has to be approved first.
   - "auto": the user approved the plan. Implementation is authorized; judge the action
     against the work objective as usual.

DENIALS ARE NOT DEAD ENDS. The agent receives your reason as tool output and will try
another way, so write the reason as guidance: name the obstacle and, when there is one,
the legitimate route (for example: run `git init` first, or ask the user to approve the plan).

Always return JSON adhering strictly to:
{
  "decision": "allow" | "deny",
  "reason": "<one concise sentence in Spanish explaining why>"
}
"""


def render_context(context: dict | None) -> str:
    """Fase del trabajo y motivo de la consulta, que el juez necesita para decidir."""
    if not context:
        return ""
    partes = []
    fase = (context.get("phase") or "").strip()
    if fase:
        partes.append(f"CURRENT PHASE: {fase}")
    regla = (context.get("rule") or "").strip()
    if regla:
        partes.append(f"WHY YOU ARE BEING ASKED: {regla}")
    return "\n".join(partes) + "\n\n" if partes else ""


def build_prompt(user_intent: str, tool_name: str, tool_args: dict,
                 context: dict | None = None) -> str:
    """Prompt completo: en modo print la instrucción de sistema viaja al inicio."""
    return (
        f"{SYSTEM_PROMPT}\n\n"
        f"USER INTENT:\n{user_intent or '(No explicit user instruction found in transcript)'}\n\n"
        f"{render_context(context)}"
        f"TOOL CALL TO EVALUATE:\n"
        f"Tool: {tool_name}\n"
        f"Arguments:\n{json.dumps(tool_args, ensure_ascii=False, indent=2)}\n\n"
        "Responde ÚNICAMENTE con el objeto JSON, sin texto alrededor, sin explicación "
        "y sin bloque de código markdown."
    )


def resolve_binary(binary: str) -> str:
    """Ruta de agy: el PATH del hook no siempre incluye `%LOCALAPPDATA%\\agy\\bin`."""
    found = shutil.which(binary)
    if found:
        return found
    local = os.environ.get("LOCALAPPDATA")
    if local:
        # Se busca el mismo nombre configurado: el respaldo no sustituye un binario por otro.
        candidate = pathlib.Path(local) / "agy" / "bin" / f"{pathlib.Path(binary).stem}.exe"
        if candidate.is_file():
            return str(candidate)
    return binary


def extract_decision(text: str) -> tuple[str, str] | None:
    """Extrae (decision, reason) aunque venga con prosa o cercos markdown; None si no hay."""
    if not text:
        return None
    candidates = []
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        candidates.append(fenced.group(1))
    candidates.extend(re.findall(r"\{[^{}]*\}", text, re.DOTALL))
    candidates.append(text.strip())

    for raw in candidates:
        try:
            parsed = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(parsed, dict):
            continue
        decision = str(parsed.get("decision", "")).strip().lower()
        if decision in VALID:
            reason = str(parsed.get("reason", "")).strip() or "Decisión emitida por agy."
            return EQUIVALENCIAS.get(decision, decision), reason
    return None


def _cold_envelope(binary: str, prompt: str, model: str, timeout: float):
    """Juzga lanzando un `agy --print` nuevo. Devuelve la envoltura o ("deny", motivo)."""
    # El agy anidado corre en un directorio vacío, sin workspace ni hooks.
    env = dict(os.environ)
    env[INFLIGHT_VAR] = "1"

    cmd = [
        resolve_binary(binary),
        "--print", prompt,
        "--output-format", "json",
        "--model", model,
        "--print-timeout", f"{int(timeout)}s",
    ]

    try:
        with tempfile.TemporaryDirectory(prefix="automode_agy_") as sandbox:
            proc = subprocess.run(
                cmd + judge_pool.write_agent(sandbox),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=sandbox,
                env=env,
                stdin=subprocess.DEVNULL,
                timeout=timeout + 15,
            )
    # Los fallos se marcan como técnicos: no son una prohibición ni cuentan como insistencia.
    except FileNotFoundError:
        return "deny", f"{TECHNICAL_MARK} No se encontró el ejecutable '{binary}': el clasificador no pudo emitir veredicto."
    except subprocess.TimeoutExpired:
        return "deny", f"{TECHNICAL_MARK} El clasificador agy no respondió en {timeout:.0f}s: sin veredicto, no se ejecuta."
    except OSError as exc:
        return "deny", f"{TECHNICAL_MARK} No se pudo lanzar el clasificador agy ({exc}): sin veredicto, no se ejecuta."

    if proc.returncode != 0:
        detalle = (proc.stderr or "").strip().splitlines()
        cola = detalle[-1][:120] if detalle else f"código {proc.returncode}"
        return "deny", f"{TECHNICAL_MARK} El clasificador agy falló ({cola}): sin veredicto, no se ejecuta."

    # La envoltura de `--output-format json` es una línea JSON con `status` y `response`.
    envelope = None
    for line in reversed((proc.stdout or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                envelope = json.loads(line)
                break
            except ValueError:
                continue

    if not isinstance(envelope, dict):
        return "deny", f"{TECHNICAL_MARK} Salida de agy no interpretable: sin veredicto, no se ejecuta."

    return envelope


def classify_with_agy(
    user_intent: str,
    tool_name: str,
    tool_args: dict,
    policy: dict,
    state_dir: pathlib.Path,
    root_dir: pathlib.Path | None = None,
    context: dict | None = None,
    conversation_id: str = "",
) -> tuple[str, str]:
    """Juzga la acción con `agy --print`. Ante cualquier fallo devuelve `deny`."""
    cfg = policy.get("classifier", {}).get("agy", {})
    binary = cfg.get("binary", "agy")
    model = cfg.get("model", "gemini-3.8-flash-low")
    timeout = float(cfg.get("timeout_seconds", 30))

    cache = DecisionCache(state_dir / "decision_cache.json")
    cached = cache.get(user_intent, tool_name, tool_args, context)
    if cached:
        return cached

    prompt = build_prompt(user_intent, tool_name, tool_args, context)
    envelope = None
    # Sin juez de repuesto listo, se arranca para la próxima y esta se juzga en frío.
    if cfg.get("persistent", False):
        envelope = judge_pool.ask(conversation_id, prompt, model, timeout)
        if envelope is None:
            judge_pool.ensure_server(conversation_id, model, int(cfg.get("reuse_turns", 1)),
                                     int(cfg.get("idle_seconds", 900)))
    if envelope is None:
        envelope = _cold_envelope(binary, prompt, model, timeout)
        if isinstance(envelope, tuple):
            return envelope

    status = str(envelope.get("status", "")).upper()
    if status and status != "SUCCESS":
        return "deny", f"{TECHNICAL_MARK} El clasificador agy devolvió estado {status}: sin veredicto, no se ejecuta."

    extracted = extract_decision(envelope.get("response", ""))
    if not extracted:
        return "deny", f"{TECHNICAL_MARK} agy no devolvió una decisión en el formato esperado: sin veredicto, no se ejecuta."

    decision, reason = extracted
    cache.put(user_intent, tool_name, tool_args, decision, reason, context)
    return decision, reason
