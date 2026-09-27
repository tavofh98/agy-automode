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


def state_dir(conversation: str) -> pathlib.Path:
    return STATE_ROOT / re.sub(r"[^A-Za-z0-9_-]", "_", conversation)[:64]


def _firma(token: str, nonce: str, texto: str) -> str:
    return hmac.new(token.encode(), (nonce + texto).encode("utf-8"), hashlib.sha256).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Cliente (lo usa el hook)
# ─────────────────────────────────────────────────────────────────────────────

def ask(conversation: str, prompt: str, model: str, timeout: float) -> dict | None:
    """Consulta al juez de la conversación. Devuelve la envoltura de agy o None.

    None significa "juzga en frío": sin conversación, servidor ausente, caído, lento o no
    autenticado.
    """
    if not conversation:
        return None
    try:
        estado = json.loads((state_dir(conversation) / "judge.json").read_text(encoding="utf-8"))
        token, puerto = estado["token"], int(estado["port"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    nonce = secrets.token_hex(16)
    peticion = {"token": token, "nonce": nonce, "model": model, "prompt": prompt,
                "timeout": timeout}
    try:
        with socket.create_connection(("127.0.0.1", puerto), timeout=1.0) as s:
            s.settimeout(timeout + 5)
            s.sendall((json.dumps(peticion) + "\n").encode("utf-8"))
            datos = b""
            while not datos.endswith(b"\n"):
                trozo = s.recv(65536)
                if not trozo:
                    break
                datos += trozo
        respuesta = json.loads(datos.decode("utf-8"))
    except (OSError, ValueError):
        return None
    envoltura = respuesta.get("envelope")
    texto = json.dumps(envoltura, sort_keys=True, ensure_ascii=False)
    if not isinstance(envoltura, dict) or not hmac.compare_digest(
            str(respuesta.get("mac", "")), _firma(token, nonce, texto)):
        return None
    return envoltura


def ensure_server(conversation: str, model: str, reuse_turns: int, idle_seconds: int) -> None:
    """Arranca el auxiliar de la conversación si no hay uno. No espera a que esté listo."""
    if not conversation:
        return
    carpeta = state_dir(conversation)
    candado = carpeta / "judge.lock"
    try:
        carpeta.mkdir(parents=True, exist_ok=True)
        # Un solo arranque a la vez: el candado caduca por si un arranque anterior murió.
        if candado.exists() and time.time() - candado.stat().st_mtime < 30:
            return
        candado.write_text(str(os.getpid()), encoding="utf-8")
        cmd = [sys.executable, str(pathlib.Path(__file__).resolve()), "serve",
               conversation, model, str(reuse_turns), str(idle_seconds)]
        # Carpeta propia: heredar la del hook dejaría el proyecto bloqueado (en Windows no
        # se puede borrar ni renombrar una carpeta que un proceso vivo usa como cwd).
        opciones = {"cwd": str(carpeta), "stdin": subprocess.DEVNULL,
                    "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                    "close_fds": True}
        if os.name == "nt":
            base = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            # agy puede agrupar el hook en un job que se cierra con él: se intenta salir
            # del job para que el auxiliar sobreviva a la llamada que lo lanzó.
            try:
                subprocess.Popen(cmd, creationflags=base | 0x01000000, **opciones)
            except OSError:
                subprocess.Popen(cmd, creationflags=base, **opciones)
        else:
            subprocess.Popen(cmd, start_new_session=True, **opciones)
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Servidor
# ─────────────────────────────────────────────────────────────────────────────

class Juez:
    """Un `agy` en modo stream-json, arrancado y a la espera de acciones que juzgar."""

    def __init__(self, model: str):
        self.model = model
        entorno = dict(os.environ)
        entorno[INFLIGHT_VAR] = "1"  # sus propias herramientas las deniega el hook
        self.cwd = tempfile.mkdtemp(prefix="automode_juez_")  # fuera de todo workspace
        opciones = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
        self.proc = subprocess.Popen(
            ["agy", "--input-format", "stream-json", "--output-format", "stream-json",
             "--model", model, "--disable-slash-commands", "--print="],
            cwd=self.cwd, env=entorno, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
            bufsize=1, **opciones)
        self.eventos = []
        self.turnos = 0
        threading.Thread(target=self._leer, daemon=True).start()

    def _leer(self):
        for linea in self.proc.stdout:
            self.eventos.append(linea)

    def vivo(self) -> bool:
        return self.proc.poll() is None

    def consultar(self, prompt: str, timeout: float) -> dict | None:
        inicio = len(self.eventos)
        try:
            self.proc.stdin.write(json.dumps(
                {"event": "user", "message": {"content": prompt}}, ensure_ascii=False) + "\n")
            self.proc.stdin.flush()
        except OSError:
            return None
        limite = time.time() + timeout
        while time.time() < limite and self.vivo():
            for linea in self.eventos[inicio:]:
                if '"event":"result"' in linea.replace(" ", ""):
                    try:
                        return json.loads(linea).get("result")
                    except ValueError:
                        return None
            time.sleep(0.05)
        return None

    def cerrar(self):
        try:
            self.proc.kill()
            self.proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        shutil.rmtree(self.cwd, ignore_errors=True)


class Pool:
    """Los jueces de una conversación: uno de repuesto esperando, uno por acción."""

    def __init__(self, model: str, reuse_turns: int):
        self.model, self.reuse_turns = model, max(1, reuse_turns)
        self.lock = threading.Lock()
        self.libres: list[Juez] = []
        self.ultimo_uso = time.time()
        self.reponer()

    def reponer(self):
        with self.lock:
            self.libres = [j for j in self.libres if j.vivo()]
            if not self.libres:
                self.libres.append(Juez(self.model))

    def tomar(self, model: str) -> Juez:
        with self.lock:
            self.ultimo_uso = time.time()
            if model == self.model:
                self.libres = [j for j in self.libres if j.vivo()]
                if self.libres:
                    return self.libres.pop(0)
        return Juez(model)

    def devolver(self, juez: Juez):
        juez.turnos += 1
        if juez.turnos < self.reuse_turns and juez.vivo() and juez.model == self.model:
            with self.lock:
                self.libres.append(juez)
        else:
            juez.cerrar()
        threading.Thread(target=self.reponer, daemon=True).start()

    def cerrar(self):
        with self.lock:
            for j in self.libres:
                j.cerrar()
            self.libres = []


def serve(conversation: str, model: str, reuse_turns: int, idle_seconds: int) -> None:
    carpeta = state_dir(conversation)
    carpeta.mkdir(parents=True, exist_ok=True)
    archivo = carpeta / "judge.json"
    token = secrets.token_hex(32)
    pool = Pool(model, reuse_turns)

    class Manejador(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                pet = json.loads(self.rfile.readline().decode("utf-8"))
            except ValueError:
                return
            if not hmac.compare_digest(str(pet.get("token", "")), token):
                return
            juez = pool.tomar(str(pet.get("model") or model))
            envoltura = juez.consultar(str(pet.get("prompt", "")), float(pet.get("timeout", 30)))
            pool.devolver(juez)
            if envoltura is None:
                envoltura = {"status": "ERROR", "response": "",
                             "error": "el juez de repuesto no respondió"}
            texto = json.dumps(envoltura, sort_keys=True, ensure_ascii=False)
            salida = {"envelope": envoltura, "mac": _firma(token, str(pet.get("nonce", "")), texto)}
            self.wfile.write((json.dumps(salida, ensure_ascii=False) + "\n").encode("utf-8"))

    class Servidor(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = False

    with Servidor(("127.0.0.1", 0), Manejador) as srv:
        estado = {"port": srv.server_address[1], "token": token, "pid": os.getpid(),
                  "model": model, "conversation": conversation}
        tmp = archivo.with_suffix(".tmp")
        tmp.write_text(json.dumps(estado), encoding="utf-8")
        os.replace(tmp, archivo)
        try:
            (carpeta / "judge.lock").unlink(missing_ok=True)
        except OSError:
            pass
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            while time.time() - pool.ultimo_uso < idle_seconds:
                time.sleep(5)
        finally:
            srv.shutdown()
            pool.cerrar()
            try:
                if json.loads(archivo.read_text(encoding="utf-8")).get("pid") == os.getpid():
                    archivo.unlink()
                    shutil.rmtree(carpeta, ignore_errors=True)
            except (OSError, ValueError):
                pass


if __name__ == "__main__" and len(sys.argv) >= 6 and sys.argv[1] == "serve":
    serve(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
