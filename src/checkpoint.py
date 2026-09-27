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
    ok, output = _git(["rev-parse", "--is-inside-work-tree"], root)
    return ok and output.lower().startswith("true")


def _safe_ref(conversation_id: str) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_" else "_" for c in (conversation_id or "no_id"))
    return f"{REF_PREFIX}/{cleaned[:64]}"


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


def _is_sensitive(path: str, patterns) -> bool:
    for pattern in patterns:
        try:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def _split_by_size(root: pathlib.Path, max_file_bytes: int) -> tuple[bool, list, list]:
    """Separa los archivos por tamaño sin leerlos. Devuelve (ok, included, skipped)."""
    ok, listing = _git(["ls-files", "-z", "--cached", "--others", "--exclude-standard"], root)
    if not ok:
        return False, [], []
    included, skipped = [], []
    for path in dict.fromkeys(r for r in listing.split("\0") if r):
        try:
            too_large = (root / path).stat().st_size > max_file_bytes
        except OSError:  # ya no existe: la captura registra el borrado
            too_large = False
        (skipped if too_large else included).append(path)
    return True, included, skipped


def create_checkpoint(root: pathlib.Path, conversation_id: str,
                      exclude_patterns=(), max_file_bytes: int = 0) -> tuple[bool, str, list]:
    """Captura el proyecto en un commit sin padre. Devuelve (ok, sha o motivo, skipped)."""
    if not is_repository(root):
        return False, "el proyecto no es un repositorio git", []

    # Copia del índice real: no toca el de la persona, y lo omitido conserva su versión en git.
    tmp_index = pathlib.Path(tempfile.gettempdir()) / f"automode_index_{os.getpid()}_{id(root)}"
    env = {"GIT_INDEX_FILE": str(tmp_index), "GIT_LITERAL_PATHSPECS": "1"}
    skipped = []
    try:
        ok, index = _git(["rev-parse", "--git-path", "index"], root)
        real_index = root / index if ok else None
        if real_index and real_index.is_file():
            shutil.copyfile(real_index, tmp_index)

        if max_file_bytes:
            ok, included, skipped = _split_by_size(root, max_file_bytes)
            if not ok:
                return False, "no se pudo listar el proyecto", []
            pathspec_file = tmp_index.with_suffix(".paths")
            pathspec_file.write_bytes("\0".join(included).encode("utf-8"))
            try:
                ok, detail = (True, "") if not included else _git(
                    ["add", "-A", f"--pathspec-from-file={pathspec_file}", "--pathspec-file-nul"],
                    root, env)
            finally:
                pathspec_file.unlink(missing_ok=True)
        else:
            ok, detail = _git(["add", "-A"], root, env)
        if not ok:
            return False, f"no se pudo preparar el índice ({detail[:120]})", []

        # Las credenciales salen de la captura aunque git las siga, y cuentan como omitidas.
        if exclude_patterns:
            ok, listing = _git(["ls-files", "-z"], root, env)
            if not ok:
                return False, f"no se pudo listar el índice ({listing[:120]})", []
            sensitive = [r for r in listing.split("\0") if r and _is_sensitive(r, exclude_patterns)]
            if sensitive:
                ok, detail = _git(["rm", "--cached", "-q", "--", *sensitive], root, env)
                if not ok:
                    return False, f"no se pudieron excluir las rutas sensibles ({detail[:120]})", []
                skipped += [r for r in sensitive if r not in skipped]

        ok, tree = _git(["write-tree"], root, env)
        if not ok or not tree:
            return False, f"no se pudo escribir el árbol ({tree[:120]})", []

        timestamp = datetime.now().isoformat(timespec="seconds")
        message = f"checkpoint automode {timestamp} (conversacion {conversation_id or 'no_id'})"
        ok, sha = _git(["commit-tree", tree, "-m", message], root, env)
        if not ok or not sha:
            return False, f"no se pudo crear el commit ({sha[:120]})", []

        ok, detail = _git(["update-ref", _safe_ref(conversation_id), sha], root)
        if not ok:
            return False, f"no se pudo apuntar la referencia ({detail[:120]})", []
        return True, sha, skipped
    finally:
        try:
            tmp_index.unlink(missing_ok=True)
        except OSError:
            pass


def _same_project(previous: dict, root: pathlib.Path) -> bool:
    """¿La captura registrada se hizo sobre este mismo directorio?"""
    previous_root = previous.get("root")
    if not previous_root:
        return False
    try:
        return pathlib.Path(os.path.realpath(previous_root)) == pathlib.Path(os.path.realpath(root))
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
    registry = _read_registry(state_dir)
    previous = registry.get(conversation_id or "no_id")
    now = datetime.now()

    # Una captura previa solo vale si es de este proyecto y su referencia sigue existiendo.
    if previous and _same_project(previous, root) and ref_exists(root, previous.get("ref", "")):
        try:
            elapsed = (now - datetime.fromisoformat(previous["ts"])).total_seconds()
            if elapsed < min_interval_seconds:
                return True, f"captura vigente {previous['sha'][:10]} ({int(elapsed)}s)"
        except (KeyError, ValueError):
            pass

    ok, detail, skipped = create_checkpoint(root, conversation_id, exclude_patterns,
                                              max_file_bytes)
    if not ok:
        return False, detail

    registry[conversation_id or "no_id"] = {
        "sha": detail,
        "ts": now.isoformat(timespec="seconds"),
        "ref": _safe_ref(conversation_id),
        "root": str(root),
        "skipped": skipped,
    }
    _write_registry(state_dir, registry)
    if keep_last:
        _prune_refs(root, keep_last, _safe_ref(conversation_id))

    notice = ""
    heavy = [r for r in skipped if not _is_sensitive(r, exclude_patterns)]
    if heavy:
        mb = max_file_bytes // (1024 * 1024)
        heavy_names = ", ".join(heavy[:3]) + (f" y {len(heavy) - 3} más" if len(heavy) > 3 else "")
        notice = f"; sin respaldo por pesar más de {mb} MB: {heavy_names}"
    return True, f"captura {detail[:10]}{notice}"


def _prune_refs(root: pathlib.Path, keep_last: int, current_ref: str) -> None:
    """Borra las capturas antiguas y conserva las de las `keep_last` conversaciones más recientes."""
    ok, output = _git(["for-each-ref", "--sort=-committerdate", "--format=%(refname)",
                       REF_PREFIX], root)
    if not ok:
        return
    for ref in [r for r in output.splitlines() if r and r != current_ref][max(keep_last - 1, 0):]:
        _git(["update-ref", "-d", ref], root)


def omitted_paths(state_dir: pathlib.Path, conversation_id: str) -> list:
    """Rutas que la captura vigente de la conversación dejó fuera."""
    return _read_registry(state_dir).get(conversation_id or "no_id", {}).get("skipped", [])


def restore_hint(conversation_id: str, skipped=()) -> str:
    """Orden para restaurar la captura, excluyendo lo que no se respaldó."""
    excludes = "".join(f" ':(exclude){r}'" for r in skipped)
    return f"git restore --source={_safe_ref(conversation_id)} -- .{excludes}"
