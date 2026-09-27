import hashlib
import hmac
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


def _sign(token: str, nonce: str, text: str) -> str:
    return hmac.new(token.encode(), (nonce + text).encode("utf-8"), hashlib.sha256).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Cliente (lo usa el hook)
# ─────────────────────────────────────────────────────────────────────────────

def ask(conversation: str, prompt: str, model: str, timeout: float) -> dict | None:
    """Consulta al juez de la conversación. None si no hay uno que responda: se juzga en frío."""
    if not conversation:
        return None
    try:
        state = json.loads((state_dir(conversation) / "judge.json").read_text(encoding="utf-8"))
        token, port = state["token"], int(state["port"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    nonce = secrets.token_hex(16)
    request = {"token": token, "nonce": nonce, "model": model, "prompt": prompt,
                "timeout": timeout}
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0) as sock:
            sock.settimeout(timeout + 5)
            sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
            data = b""
            while not data.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        response = json.loads(data.decode("utf-8"))
    except (OSError, ValueError):
        return None
    envelope = response.get("envelope")
    text = json.dumps(envelope, sort_keys=True, ensure_ascii=False)
    if not isinstance(envelope, dict) or not hmac.compare_digest(
            str(response.get("mac", "")), _sign(token, nonce, text)):
        return None
    return envelope


def ensure_server(conversation: str, model: str, reuse_turns: int, idle_seconds: int) -> None:
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
               conversation, model, str(reuse_turns), str(idle_seconds)]
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
    """Un `agy` en modo stream-json, arrancado y a la espera de acciones que juzgar."""

    def __init__(self, model: str):
        self.model = model
        env = dict(os.environ)
        env[INFLIGHT_VAR] = "1"  # sus propias herramientas las deniega el hook
        self.cwd = tempfile.mkdtemp(prefix="automode_judge_")  # fuera de todo workspace
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        self.proc = subprocess.Popen(
            ["agy", "--input-format", "stream-json", "--output-format", "stream-json",
             "--model", model, "--disable-slash-commands", "--print="] + write_agent(self.cwd),
            cwd=self.cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
            bufsize=1, **options)
        self.events = []
        self.turns = 0
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
    """Los jueces de una conversación: uno precargado esperando, uno por acción."""

    def __init__(self, model: str, reuse_turns: int):
        self.model, self.reuse_turns = model, max(1, reuse_turns)
        self.lock = threading.Lock()
        self.ready: list[Judge] = []
        self.last_used = time.time()
        self.replenish()

    def replenish(self):
        with self.lock:
            self.ready = [judge for judge in self.ready if judge.is_alive()]
            if not self.ready:
                self.ready.append(Judge(self.model))

    def acquire(self, model: str) -> Judge:
        with self.lock:
            self.last_used = time.time()
            if model == self.model:
                self.ready = [judge for judge in self.ready if judge.is_alive()]
                if self.ready:
                    return self.ready.pop(0)
        return Judge(model)

    def release(self, judge: Judge):
        judge.turns += 1
        if judge.turns < self.reuse_turns and judge.is_alive() and judge.model == self.model:
            with self.lock:
                self.ready.append(judge)
        else:
            judge.close()
        threading.Thread(target=self.replenish, daemon=True).start()

    def close(self):
        with self.lock:
            for judge in self.ready:
                judge.close()
            self.ready = []


def serve(conversation: str, model: str, reuse_turns: int, idle_seconds: int) -> None:
    folder = state_dir(conversation)
    folder.mkdir(parents=True, exist_ok=True)
    state_file = folder / "judge.json"
    token = secrets.token_hex(32)
    pool = Pool(model, reuse_turns)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                request = json.loads(self.rfile.readline().decode("utf-8"))
            except ValueError:
                return
            if not hmac.compare_digest(str(request.get("token", "")), token):
                return
            judge = pool.acquire(str(request.get("model") or model))
            envelope = judge.query(str(request.get("prompt", "")), float(request.get("timeout", 30)))
            pool.release(judge)
            if envelope is None:
                envelope = {"status": "ERROR", "response": "",
                             "error": "el juez precargado no respondió"}
            text = json.dumps(envelope, sort_keys=True, ensure_ascii=False)
            payload = {"envelope": envelope, "mac": _sign(token, str(request.get("nonce", "")), text)}
            self.wfile.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = False

    with Server(("127.0.0.1", 0), Handler) as srv:
        state = {"port": srv.server_address[1], "token": token, "pid": os.getpid(),
                  "model": model, "conversation": conversation}
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


if __name__ == "__main__" and len(sys.argv) >= 6 and sys.argv[1] == "serve":
    serve(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
