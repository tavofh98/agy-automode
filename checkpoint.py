import json
import os
import pathlib
import re
import shutil
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


def _pesados(root: pathlib.Path, max_file_bytes: int) -> tuple[bool, list, list]:
    """Separa los archivos por tamaño sin leerlos. Devuelve (ok, a_capturar, omitidos)."""
    ok, listado = _git(["ls-files", "-z", "--cached", "--others", "--exclude-standard"], root)
    if not ok:
        return False, [], []
    a_capturar, omitidos = [], []
    for ruta in dict.fromkeys(r for r in listado.split("\0") if r):
        try:
            grande = (root / ruta).stat().st_size > max_file_bytes
        except OSError:  # ya no existe: la captura registra el borrado
            grande = False
        (omitidos if grande else a_capturar).append(ruta)
    return True, a_capturar, omitidos


def create_checkpoint(root: pathlib.Path, conversation_id: str,
                      exclude_patterns=(), max_file_bytes: int = 0) -> tuple[bool, str, list]:
    """Captura el proyecto en un commit sin padre. Devuelve (ok, sha o motivo, omitidos)."""
    if not is_repository(root):
        return False, "el proyecto no es un repositorio git", []

    # Copia del índice real: no toca el de la persona, y lo omitido conserva su versión en git.
    tmp_index = pathlib.Path(tempfile.gettempdir()) / f"automode_index_{os.getpid()}_{id(root)}"
    entorno = {"GIT_INDEX_FILE": str(tmp_index), "GIT_LITERAL_PATHSPECS": "1"}
    omitidos = []
    try:
        ok, indice = _git(["rev-parse", "--git-path", "index"], root)
        indice_real = root / indice if ok else None
        if indice_real and indice_real.is_file():
            shutil.copyfile(indice_real, tmp_index)

        if max_file_bytes:
            ok, a_capturar, omitidos = _pesados(root, max_file_bytes)
            if not ok:
                return False, "no se pudo listar el proyecto", []
            lista = tmp_index.with_suffix(".rutas")
            lista.write_bytes("\0".join(a_capturar).encode("utf-8"))
            try:
                ok, detalle = (True, "") if not a_capturar else _git(
                    ["add", "-A", f"--pathspec-from-file={lista}", "--pathspec-file-nul"],
                    root, entorno)
            finally:
                lista.unlink(missing_ok=True)
        else:
            ok, detalle = _git(["add", "-A"], root, entorno)
        if not ok:
            return False, f"no se pudo preparar el índice ({detalle[:120]})", []

        # Las credenciales salen de la captura aunque git las siga, y cuentan como omitidas.
        if exclude_patterns:
            ok, listado = _git(["ls-files", "-z"], root, entorno)
            if not ok:
                return False, f"no se pudo listar el índice ({listado[:120]})", []
            sensibles = [r for r in listado.split("\0") if r and _es_sensible(r, exclude_patterns)]
            if sensibles:
                ok, detalle = _git(["rm", "--cached", "-q", "--", *sensibles], root, entorno)
                if not ok:
                    return False, f"no se pudieron excluir las rutas sensibles ({detalle[:120]})", []
                omitidos += [r for r in sensibles if r not in omitidos]

        ok, tree = _git(["write-tree"], root, entorno)
        if not ok or not tree:
            return False, f"no se pudo escribir el árbol ({tree[:120]})", []

        marca = datetime.now().isoformat(timespec="seconds")
        mensaje = f"checkpoint automode {marca} (conversacion {conversation_id or 'sin_id'})"
        ok, sha = _git(["commit-tree", tree, "-m", mensaje], root, entorno)
        if not ok or not sha:
            return False, f"no se pudo crear el commit ({sha[:120]})", []

        ok, detalle = _git(["update-ref", _safe_ref(conversation_id), sha], root)
        if not ok:
            return False, f"no se pudo apuntar la referencia ({detalle[:120]})", []
        return True, sha, omitidos
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
    max_file_bytes: int = 0,
    keep_last: int = 0,
) -> tuple[bool, str]:
    """Captura el proyecto si no hay una captura reciente. Devuelve (hay_respaldo, detalle)."""
    registro = _read_registry(state_dir)
    previo = registro.get(conversation_id or "sin_id")
    ahora = datetime.now()

    # Una captura previa solo vale si es de este proyecto y su referencia sigue existiendo.
    if previo and _mismo_proyecto(previo, root) and ref_exists(root, previo.get("ref", "")):
        try:
            transcurrido = (ahora - datetime.fromisoformat(previo["ts"])).total_seconds()
            if transcurrido < min_interval_seconds:
                return True, f"captura vigente {previo['sha'][:10]} ({int(transcurrido)}s)"
        except (KeyError, ValueError):
            pass

    ok, detalle, omitidos = create_checkpoint(root, conversation_id, exclude_patterns,
                                              max_file_bytes)
    if not ok:
        return False, detalle

    registro[conversation_id or "sin_id"] = {
        "sha": detalle,
        "ts": ahora.isoformat(timespec="seconds"),
        "ref": _safe_ref(conversation_id),
        "root": str(root),
        "omitidos": omitidos,
    }
    _write_registry(state_dir, registro)
    if keep_last:
        _prune_refs(root, keep_last, _safe_ref(conversation_id))

    aviso = ""
    pesados = [r for r in omitidos if not _es_sensible(r, exclude_patterns)]
    if pesados:
        mb = max_file_bytes // (1024 * 1024)
        lista = ", ".join(pesados[:3]) + (f" y {len(pesados) - 3} más" if len(pesados) > 3 else "")
        aviso = f"; sin respaldo por pesar más de {mb} MB: {lista}"
    return True, f"captura {detalle[:10]}{aviso}"


def _prune_refs(root: pathlib.Path, keep_last: int, actual: str) -> None:
    """Borra las capturas antiguas y conserva las de las `keep_last` conversaciones más recientes."""
    ok, salida = _git(["for-each-ref", "--sort=-committerdate", "--format=%(refname)",
                       REF_PREFIX], root)
    if not ok:
        return
    for ref in [r for r in salida.splitlines() if r and r != actual][max(keep_last - 1, 0):]:
        _git(["update-ref", "-d", ref], root)


def omitted_paths(state_dir: pathlib.Path, conversation_id: str) -> list:
    """Rutas que la captura vigente de la conversación dejó fuera."""
    return _read_registry(state_dir).get(conversation_id or "sin_id", {}).get("omitidos", [])


def restore_hint(conversation_id: str, omitidos=()) -> str:
    """Orden para restaurar la captura, excluyendo lo que no se respaldó."""
    excluir = "".join(f" ':(exclude){r}'" for r in omitidos)
    return f"git restore --source={_safe_ref(conversation_id)} -- .{excluir}"
