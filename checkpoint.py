"""Capturas del estado del proyecto antes de que el agente lo modifique.

El motivo «reversible por control de versiones» que el auto mode emite al aprobar una
edición es una promesa que nadie verificaba: en un proyecto sin git, o con trabajo sin
commitear, no hay nada a lo que volver. Este módulo la convierte en un hecho.

Antes del primer cambio destructivo de cada bloque de trabajo se guarda un commit con
el árbol completo —incluidos los archivos sin seguimiento— y se apunta con una
referencia bajo `refs/automode/`. Recuperar es entonces una orden de git corriente.

La captura **no toca nada del trabajo en curso**: usa un índice temporal propio
(`GIT_INDEX_FILE`), de modo que el índice de la persona, su directorio de trabajo, su
lista de `stash` y su rama actual quedan exactamente como estaban. Tampoco se cuelga
del historial: el commit no tiene padre y solo lo alcanza su referencia.

Respeta `.gitignore`, así que lo excluido del repositorio también queda fuera de la
captura. Un proyecto que ignora sus datos no los verá respaldados aquí.

Además excluye siempre las rutas sensibles de la política (`[paths].sensitive`), diga lo
que diga el `.gitignore` del proyecto: se observó un `.env` con credenciales copiado en
todas las capturas de un repositorio cuyo `.gitignore` no lo mencionaba.
"""
import json
import os
import pathlib
import re
import subprocess
import tempfile
from datetime import datetime

REF_PREFIX = "refs/automode"


def _git(args: list, root: pathlib.Path, env_extra: dict | None = None, timeout: float = 20.0):
    """Ejecuta git en el proyecto. Devuelve (ok, salida)."""
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or f"código {proc.returncode}").strip()
    return True, (proc.stdout or "").strip()


def is_repository(root: pathlib.Path) -> bool:
    ok, salida = _git(["rev-parse", "--is-inside-work-tree"], root)
    return ok and salida.lower().startswith("true")


def _safe_ref(conversation_id: str) -> str:
    limpio = "".join(c if c.isalnum() or c in "-_" else "_" for c in (conversation_id or "sin_id"))
    return f"{REF_PREFIX}/{limpio[:64]}"


def _registry(state_dir: pathlib.Path) -> pathlib.Path:
    return state_dir / "checkpoints.json"


def _read_registry(state_dir: pathlib.Path) -> dict:
    try:
        return json.loads(_registry(state_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_registry(state_dir: pathlib.Path, data: dict) -> None:
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        _registry(state_dir).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass


def ref_exists(root: pathlib.Path, ref: str) -> bool:
    """¿La referencia sigue existiendo en ESTE repositorio?"""
    ok, _ = _git(["rev-parse", "--verify", "--quiet", ref], root)
    return ok


def _es_sensible(ruta: str, patrones) -> bool:
    for patron in patrones:
        try:
            if re.search(patron, ruta, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def create_checkpoint(root: pathlib.Path, conversation_id: str,
                      exclude_patterns=()) -> tuple[bool, str]:
    """Captura el árbol completo del proyecto. Devuelve (ok, sha o motivo del fallo).

    `exclude_patterns` son expresiones regulares de rutas que nunca entran en la captura.
    """
    if not is_repository(root):
        return False, "el proyecto no es un repositorio git"

    # Índice temporal: `git add -A` sobre él no altera el índice real de la persona.
    tmp_index = pathlib.Path(tempfile.gettempdir()) / f"automode_index_{os.getpid()}_{id(root)}"
    entorno = {"GIT_INDEX_FILE": str(tmp_index)}
    try:
        ok, detalle = _git(["add", "-A"], root, entorno)
        if not ok:
            return False, f"no se pudo preparar el índice ({detalle[:120]})"

        # Se sacan del índice temporal antes de escribir el árbol: lo que no está en el
        # índice no llega al commit.
        if exclude_patterns:
            ok, listado = _git(["ls-files", "-z"], root, entorno)
            if not ok:
                return False, f"no se pudo listar el índice ({listado[:120]})"
            sensibles = [r for r in listado.split("\0") if r and _es_sensible(r, exclude_patterns)]
            if sensibles:
                ok, detalle = _git(["rm", "--cached", "-q", "--", *sensibles], root, entorno)
                if not ok:
                    return False, f"no se pudieron excluir las rutas sensibles ({detalle[:120]})"

        ok, tree = _git(["write-tree"], root, entorno)
        if not ok or not tree:
            return False, f"no se pudo escribir el árbol ({detalle[:120]})"

        marca = datetime.now().isoformat(timespec="seconds")
        mensaje = f"checkpoint automode {marca} (conversacion {conversation_id or 'sin_id'})"
        # Sin padre: la captura queda fuera del historial de trabajo y solo la alcanza
        # su referencia, así que no ensucia `git log` ni la rama actual.
        ok, sha = _git(["commit-tree", tree, "-m", mensaje], root, entorno)
        if not ok or not sha:
            return False, f"no se pudo crear el commit ({sha[:120]})"

        ok, detalle = _git(["update-ref", _safe_ref(conversation_id), sha], root)
        if not ok:
            return False, f"no se pudo apuntar la referencia ({detalle[:120]})"
        return True, sha
    finally:
        try:
            tmp_index.unlink(missing_ok=True)
        except OSError:
            pass


def _mismo_proyecto(previo: dict, root: pathlib.Path) -> bool:
    """¿La captura registrada se hizo sobre este mismo directorio?"""
    anterior = previo.get("root")
    if not anterior:
        return False
    try:
        return pathlib.Path(os.path.realpath(anterior)) == pathlib.Path(os.path.realpath(root))
    except (OSError, ValueError):
        return False


def ensure_checkpoint(
    root: pathlib.Path,
    conversation_id: str,
    state_dir: pathlib.Path,
    min_interval_seconds: float = 300.0,
    exclude_patterns=(),
) -> tuple[bool, str]:
    """Garantiza una captura reciente antes de un cambio destructivo.

    Devuelve (hay_respaldo, detalle). No recaptura si ya hay una dentro del intervalo:
    el objetivo es poder volver al estado previo al bloque de trabajo, no versionar
    cada paso.
    """
    registro = _read_registry(state_dir)
    previo = registro.get(conversation_id or "sin_id")
    ahora = datetime.now()

    # Una captura previa solo cuenta si es de ESTE proyecto y todavía existe. Sin estas
    # dos comprobaciones, el registro basta para afirmar que hay respaldo: un `state/`
    # copiado de otro proyecto —o una referencia borrada por una limpieza de git— haría
    # que el motor apruebe la edición prometiendo una reversibilidad que no existe.
    # Se observó al copiar `.agents/` completo a un proyecto nuevo.
    if previo and _mismo_proyecto(previo, root) and ref_exists(root, previo.get("ref", "")):
        try:
            transcurrido = (ahora - datetime.fromisoformat(previo["ts"])).total_seconds()
            if transcurrido < min_interval_seconds:
                return True, f"captura vigente {previo['sha'][:10]} ({int(transcurrido)}s)"
        except (KeyError, ValueError):
            pass

    ok, detalle = create_checkpoint(root, conversation_id, exclude_patterns)
    if not ok:
        return False, detalle

    registro[conversation_id or "sin_id"] = {
        "sha": detalle,
        "ts": ahora.isoformat(timespec="seconds"),
        "ref": _safe_ref(conversation_id),
        "root": str(root),
    }
    _write_registry(state_dir, registro)
    return True, f"captura {detalle[:10]}"


def restore_hint(conversation_id: str) -> str:
    """Orden de git para volver al estado capturado."""
    return f"git restore --source={_safe_ref(conversation_id)} -- ."
