"""Juez de repuesto: evita que cada consulta pague el arranque de `agy`.

Arrancar `agy` cuesta ~4 s de los ~6 que tarda una consulta en frío. Este proceso auxiliar
mantiene un `agy` en modo stream-json ya arrancado; cada consulta la atiende un juez
nuevo, que se descarta después, mientras en segundo plano se prepara el siguiente.

Un juez por consulta es deliberado: un `agy` que atiende varias consultas recuerda las
anteriores, incluidos los argumentos que redacta el agente, y un texto malicioso quedaría
en su contexto para las decisiones siguientes. `reuse_turns` lo permite a cambio de ese
riesgo; por defecto cada juicio empieza de cero.

Seguridad del canal:
- Escucha solo en 127.0.0.1.
- Un secreto aleatorio, en `~/.gemini/automode/`, autentica a las dos partes: el servidor
  rechaza peticiones sin él y el hook rechaza respuestas no firmadas. Un servidor falso
  que respondiera "allow" a todo no sabría firmar, y el hook volvería al método en frío.
- Si el auxiliar falla, `classifier_agy.py` juzga en frío: el auxiliar solo acelera.

Uso interno: `python judge_pool.py serve <modelo> <reuse_turns> <idle_seconds>`.
"""
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

STATE_DIR = pathlib.Path(os.path.expanduser("~/.gemini/automode"))
STATE_FILE = STATE_DIR / "judge.json"
LOCK_FILE = STATE_DIR / "judge.lock"
INFLIGHT_VAR = "AGY_AUTOMODE_INFLIGHT"


def _firma(token: str, nonce: str, texto: str) -> str:
    return hmac.new(token.encode(), (nonce + texto).encode("utf-8"), hashlib.sha256).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Cliente (lo usa el hook)
# ─────────────────────────────────────────────────────────────────────────────

def ask(prompt: str, model: str, timeout: float) -> dict | None:
    """Consulta al juez de repuesto. Devuelve la envoltura de agy o None si no hay servidor.

    None significa "juzga en frío": servidor ausente, caído, lento o no autenticado.
    """
    try:
        estado = json.loads(STATE_FILE.read_text(encoding="utf-8"))
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


def ensure_server(model: str, reuse_turns: int, idle_seconds: int) -> None:
    """Arranca el auxiliar en segundo plano si no hay uno. No espera a que esté listo."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        # Un solo arranque a la vez: el candado caduca por si un arranque anterior murió.
        if LOCK_FILE.exists() and time.time() - LOCK_FILE.stat().st_mtime < 30:
            return
        LOCK_FILE.write_text(str(os.getpid()), encoding="utf-8")
        cmd = [sys.executable, str(pathlib.Path(__file__).resolve()), "serve",
               model, str(reuse_turns), str(idle_seconds)]
        opciones = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
                    "stderr": subprocess.DEVNULL, "close_fds": True}
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
    """Un `agy` en modo stream-json, arrancado y a la espera de su consulta."""

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


def serve(model: str, reuse_turns: int, idle_seconds: int) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
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
                  "model": model}
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(estado), encoding="utf-8")
        os.replace(tmp, STATE_FILE)
        try:
            LOCK_FILE.unlink(missing_ok=True)
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
                if json.loads(STATE_FILE.read_text(encoding="utf-8")).get("pid") == os.getpid():
                    STATE_FILE.unlink()
            except (OSError, ValueError):
                pass


if __name__ == "__main__" and len(sys.argv) >= 5 and sys.argv[1] == "serve":
    serve(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
