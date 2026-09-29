import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

STATE_ROOT = pathlib.Path(os.path.expanduser("~/.gemini/automode"))
INFLIGHT_VAR = "AGY_AUTOMODE_INFLIGHT"

# Agente propio sin herramientas: sin él, agy añade ~10.000 tokens de su prompt a cada juicio.
AGENT = "automode-judge"
AGENT_MD = """---
name: automode-judge
description: Juez de seguridad del auto mode, sin herramientas.
tools: []
mainAgent: true
subagent: false
---

Sigue exactamente las instrucciones de cada mensaje.
"""


def state_dir(conversation: str) -> pathlib.Path:
    return STATE_ROOT / re.sub(r"[^A-Za-z0-9_-]", "_", conversation)[:64]


def write_agent(folder: str) -> list[str]:
    """Deja el agente del juez en la carpeta de trabajo y devuelve los argumentos para usarlo."""
    path = pathlib.Path(folder) / ".agents" / "agents"
    path.mkdir(parents=True, exist_ok=True)
    (path / f"{AGENT}.md").write_text(AGENT_MD, encoding="utf-8")
    return ["--agent", AGENT]


def resolve_binary() -> str:
    """Ruta de agy: el PATH del hook no siempre incluye `%LOCALAPPDATA%\\agy\\bin`."""
    found = shutil.which("agy")
    if found:
        return found
    candidate = pathlib.Path(os.environ.get("LOCALAPPDATA", "")) / "agy" / "bin" / "agy.exe"
    return str(candidate) if candidate.is_file() else "agy"


# ─────────────────────────────────────────────────────────────────────────────
# Cliente (lo usa el hook)
# ─────────────────────────────────────────────────────────────────────────────

def ask(conversation: str, prompt: str, timeout: float) -> dict | None:
    """Consulta al juez de la conversación. None si no hay uno que responda: se juzga en frío."""
    if not conversation:
        return None
    try:
        state = json.loads((state_dir(conversation) / "judge.json").read_text(encoding="utf-8"))
        request = {"token": state["token"], "prompt": prompt, "timeout": timeout}
        with socket.create_connection(("127.0.0.1", int(state["port"])), timeout=1.0) as sock:
            sock.settimeout(timeout + 5)
            sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
            data = b""
            while not data.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        envelope = json.loads(data.decode("utf-8")).get("envelope")
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    return envelope if isinstance(envelope, dict) else None


def ensure_server(conversation: str, model: str, idle_seconds: int) -> None:
    """Arranca el auxiliar de la conversación si no hay uno. No espera a que esté listo."""
    if not conversation:
        return
    folder = state_dir(conversation)
    lock_file = folder / "judge.lock"
    try:
        folder.mkdir(parents=True, exist_ok=True)
        # Un solo arranque a la vez: el candado caduca por si un arranque anterior murió.
        if lock_file.exists() and time.time() - lock_file.stat().st_mtime < 30:
            return
        lock_file.write_text(str(os.getpid()), encoding="utf-8")
        cmd = [sys.executable, str(pathlib.Path(__file__).resolve()), "serve",
               conversation, model, str(idle_seconds)]
        # Carpeta propia: con la del hook, Windows no deja borrar ni renombrar el proyecto.
        options = {"cwd": str(folder), "stdin": subprocess.DEVNULL,
                   "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                   "close_fds": True}
        if os.name == "nt":
            creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            # Salir del job de agy para que el auxiliar sobreviva a la llamada que lo lanzó.
            try:
                subprocess.Popen(cmd, creationflags=creation_flags | 0x01000000, **options)
            except OSError:
                subprocess.Popen(cmd, creationflags=creation_flags, **options)
        else:
            subprocess.Popen(cmd, start_new_session=True, **options)
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Servidor
# ─────────────────────────────────────────────────────────────────────────────

class Judge:
    """Un `agy` en modo stream-json, arrancado y a la espera de una acción que juzgar."""

    def __init__(self, model: str):
        env = dict(os.environ)
        env[INFLIGHT_VAR] = "1"  # sus propias herramientas las deniega el hook
        self.cwd = tempfile.mkdtemp(prefix="automode_judge_")  # fuera de todo workspace
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        self.proc = subprocess.Popen(
            [resolve_binary(), "--input-format", "stream-json", "--output-format", "stream-json",
             "--model", model, "--disable-slash-commands", "--print="] + write_agent(self.cwd),
            cwd=self.cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
            bufsize=1, **options)
        self.events = []
        threading.Thread(target=self._read_output, daemon=True).start()

    def _read_output(self):
        for line in self.proc.stdout:
            self.events.append(line)

    def is_alive(self) -> bool:
        return self.proc.poll() is None

    def query(self, prompt: str, timeout: float) -> dict | None:
        start = len(self.events)
        try:
            self.proc.stdin.write(json.dumps(
                {"event": "user", "message": {"content": prompt}}, ensure_ascii=False) + "\n")
            self.proc.stdin.flush()
        except OSError:
            return None
        deadline = time.time() + timeout
        while time.time() < deadline and self.is_alive():
            for line in self.events[start:]:
                if '"event":"result"' in line.replace(" ", ""):
                    try:
                        return json.loads(line).get("result")
                    except ValueError:
                        return None
            time.sleep(0.05)
        return None

    def close(self):
        try:
            self.proc.kill()
            self.proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        shutil.rmtree(self.cwd, ignore_errors=True)


class Pool:
    """El juez de repuesto de una conversación: cada acción usa uno y se arranca el siguiente."""

    def __init__(self, model: str):
        self.model = model
        self.lock = threading.Lock()
        self.spare = Judge(model)
        self.last_used = time.time()

    def acquire(self) -> Judge:
        with self.lock:
            self.last_used = time.time()
            judge, self.spare = self.spare, None
        return judge if judge and judge.is_alive() else Judge(self.model)

    def release(self, judge: Judge):
        judge.close()
        threading.Thread(target=self.replenish, daemon=True).start()

    def replenish(self):
        with self.lock:
            if self.spare is None or not self.spare.is_alive():
                self.spare = Judge(self.model)

    def close(self):
        with self.lock:
            if self.spare:
                self.spare.close()
            self.spare = None


def serve(conversation: str, model: str, idle_seconds: int) -> None:
    folder = state_dir(conversation)
    folder.mkdir(parents=True, exist_ok=True)
    state_file = folder / "judge.json"
    token = secrets.token_hex(32)
    pool = Pool(model)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                request = json.loads(self.rfile.readline().decode("utf-8"))
            except ValueError:
                return
            if request.get("token") != token:
                return
            judge = pool.acquire()
            envelope = judge.query(str(request.get("prompt", "")), float(request.get("timeout", 30)))
            pool.release(judge)
            if envelope is None:
                envelope = {"status": "ERROR", "response": "",
                            "error": "el juez precargado no respondió"}
            self.wfile.write((json.dumps({"envelope": envelope}, ensure_ascii=False) + "\n")
                             .encode("utf-8"))

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with Server(("127.0.0.1", 0), Handler) as srv:
        state = {"port": srv.server_address[1], "token": token, "pid": os.getpid()}
        tmp = state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, state_file)
        try:
            (folder / "judge.lock").unlink(missing_ok=True)
        except OSError:
            pass
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            while time.time() - pool.last_used < idle_seconds:
                time.sleep(5)
        finally:
            srv.shutdown()
            pool.close()
            try:
                if json.loads(state_file.read_text(encoding="utf-8")).get("pid") == os.getpid():
                    state_file.unlink()
                    shutil.rmtree(folder, ignore_errors=True)
            except (OSError, ValueError):
                pass


if __name__ == "__main__" and len(sys.argv) >= 5 and sys.argv[1] == "serve":
    serve(sys.argv[2], sys.argv[3], int(sys.argv[4]))
