import json
import os
import re
import subprocess
import tempfile

import judge_pool

# Encabeza el motivo cuando el juez no pudo pronunciarse.
TECHNICAL_MARK = "[sin veredicto]"
INFLIGHT_VAR = judge_pool.INFLIGHT_VAR

# `ask` se acepta al leer la respuesta pero vale `deny`: sin nadie mirando, se ejecutaría.
VALID = ("allow", "ask", "deny")
ALIASES = {"ask": "deny"}


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
  "reason": "<one concise sentence explaining why>"
}
"""


def render_context(context: dict | None) -> str:
    """Fase del trabajo y motivo de la consulta, que el juez necesita para decidir."""
    if not context:
        return ""
    parts = []
    phase = (context.get("phase") or "").strip()
    if phase:
        parts.append(f"CURRENT PHASE: {phase}")
    rule = (context.get("rule") or "").strip()
    if rule:
        parts.append(f"WHY YOU ARE BEING ASKED: {rule}")
    return "\n".join(parts) + "\n\n" if parts else ""


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
            return ALIASES.get(decision, decision), reason
    return None


def _cold_envelope(prompt: str, model: str, timeout: float):
    """Juzga lanzando un `agy --print` nuevo. Devuelve la envoltura o ("deny", motivo)."""
    # El agy anidado corre en un directorio vacío, sin workspace ni hooks.
    env = dict(os.environ)
    env[INFLIGHT_VAR] = "1"
    cmd = [judge_pool.resolve_binary(), "--print", prompt, "--output-format", "json",
           "--model", model, "--print-timeout", f"{int(timeout)}s"]
    try:
        with tempfile.TemporaryDirectory(prefix="automode_agy_") as sandbox:
            proc = subprocess.run(
                cmd + judge_pool.write_agent(sandbox), capture_output=True, text=True,
                encoding="utf-8", errors="replace", cwd=sandbox, env=env,
                stdin=subprocess.DEVNULL, timeout=timeout + 15,
            )
    except subprocess.TimeoutExpired:
        return "deny", f"{TECHNICAL_MARK} El clasificador agy no respondió en {timeout:.0f}s: sin veredicto, no se ejecuta."
    except OSError as exc:
        return "deny", f"{TECHNICAL_MARK} No se pudo lanzar el clasificador agy ({exc}): sin veredicto, no se ejecuta."

    if proc.returncode != 0:
        stderr_lines = (proc.stderr or "").strip().splitlines()
        last_line = stderr_lines[-1][:120] if stderr_lines else f"código {proc.returncode}"
        return "deny", f"{TECHNICAL_MARK} El clasificador agy falló ({last_line}): sin veredicto, no se ejecuta."

    # La envoltura de `--output-format json` es una línea JSON con `status` y `response`.
    for line in reversed((proc.stdout or "").strip().splitlines()):
        if line.strip().startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return "deny", f"{TECHNICAL_MARK} Salida de agy no interpretable: sin veredicto, no se ejecuta."


def classify_with_agy(
    user_intent: str,
    tool_name: str,
    tool_args: dict,
    policy: dict,
    context: dict | None = None,
    conversation_id: str = "",
) -> tuple[str, str]:
    """Juzga la acción con agy. Ante cualquier fallo devuelve `deny`."""
    cfg = policy.get("classifier", {}).get("agy", {})
    model = cfg.get("model", "gemini-3.8-flash-low")
    timeout = float(cfg.get("timeout_seconds", 30))

    prompt = build_prompt(user_intent, tool_name, tool_args, context)
    envelope = None
    # Sin juez precargado listo, se arranca para la próxima y esta se juzga en frío.
    if cfg.get("persistent", False):
        envelope = judge_pool.ask(conversation_id, prompt, timeout)
        if envelope is None:
            judge_pool.ensure_server(conversation_id, model, int(cfg.get("idle_seconds", 900)))
    if envelope is None:
        envelope = _cold_envelope(prompt, model, timeout)
        if isinstance(envelope, tuple):
            return envelope

    status = str(envelope.get("status", "")).upper()
    if status and status != "SUCCESS":
        return "deny", f"{TECHNICAL_MARK} El clasificador agy devolvió estado {status}: sin veredicto, no se ejecuta."

    extracted = extract_decision(envelope.get("response", ""))
    if not extracted:
        return "deny", f"{TECHNICAL_MARK} agy no devolvió una decisión en el formato esperado: sin veredicto, no se ejecuta."
    return extracted
