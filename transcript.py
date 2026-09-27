import json
import re
import os
import pathlib


def extract_user_intent(
    transcript_path: str | pathlib.Path | None,
    max_turns: int = 3,
    fallback: str = "",
) -> str:
    """Últimas instrucciones auténticas del usuario, sin nada escrito por el modelo."""
    if not transcript_path:
        return fallback.strip()

    path = pathlib.Path(transcript_path)
    if not path.exists() or not path.is_file():
        return fallback.strip()

    user_messages: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue

                source = record.get("source", "")
                step_type = record.get("type", "")

                is_user = (
                    source in ("USER_EXPLICIT", "USER")
                    or step_type in ("USER_INPUT", "USER_REQUEST")
                )

                if is_user:
                    content = record.get("content", "")
                    if isinstance(content, str) and content.strip():
                        user_messages.append(content.strip())
                    elif isinstance(content, list):
                        # Caso de contenido estructurado o multipart
                        parts = []
                        for p in content:
                            if isinstance(p, dict) and "text" in p:
                                parts.append(p["text"])
                            elif isinstance(p, str):
                                parts.append(p)
                        if parts:
                            user_messages.append(" ".join(parts).strip())
    except (OSError, UnicodeDecodeError):
        return fallback.strip()

    if not user_messages:
        return fallback.strip()

    recent = user_messages[-max_turns:]
    return "\n---\n".join(recent)


def read_work_objective(
    conversation_id: str,
    plan_root: str = "~/.gemini/antigravity-cli/brain",
    max_chars: int = 4000,
    artifact_dir: str = "",
) -> str:
    """Markdown más reciente de la carpeta de artefactos de la conversación, o "" si no hay."""
    # Manda `artifactDirectoryPath` del payload: la ruta cambia entre CLI, IDE y Antigravity 2.0.
    base = None
    if artifact_dir:
        candidata = pathlib.Path(os.path.expandvars(os.path.expanduser(artifact_dir)))
        if candidata.is_dir():
            base = candidata
    if base is None:
        if not conversation_id:
            return ""
        base = pathlib.Path(os.path.expandvars(os.path.expanduser(plan_root))) / conversation_id
    if not base.is_dir():
        return ""
    try:
        planes = sorted(base.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return ""
    if not planes:
        return ""
    try:
        texto = planes[0].read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    if len(texto) > max_chars:
        texto = texto[:max_chars] + "\n[...plan truncado...]"
    return texto


# Etiquetas con que agy envuelve el mensaje del usuario en el transcript.
_ENVOLTURAS = ("<USER_REQUEST>", "</USER_REQUEST>")


def _limpiar(contenido) -> str:
    """Devuelve el texto del usuario sin las etiquetas que agy le añade."""
    if isinstance(contenido, list):
        partes = [p.get("text", "") if isinstance(p, dict) else str(p) for p in contenido]
        contenido = " ".join(partes)
    texto = str(contenido or "")
    for etiqueta in _ENVOLTURAS:
        texto = texto.replace(etiqueta, " ")
    return texto.strip()


def detect_phase(
    transcript_path: str | pathlib.Path | None,
    plan_triggers: list,
    auto_triggers: list,
) -> str | None:
    """Fase según lo que escribió la persona: "plan", "auto" o None. Gana el último disparador."""
    if not transcript_path:
        return None
    path = pathlib.Path(transcript_path)
    if not path.exists() or not path.is_file():
        return None

    fase = None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if record.get("source") not in ("USER_EXPLICIT", "USER"):
                    continue
                texto = _limpiar(record.get("content", "")).lower()
                if not texto:
                    continue
                for patron in auto_triggers:
                    if re.search(patron, texto, re.IGNORECASE):
                        fase = "auto"
                        break
                else:
                    for patron in plan_triggers:
                        if re.search(patron, texto, re.IGNORECASE):
                            fase = "plan"
                            break
    except (OSError, UnicodeDecodeError):
        return None
    return fase
