"""Utilidad CLI para consultar y alternar entre los modos 'plan' y 'auto'.

Uso:
    python mode.py          # Muestra el estado actual
    python mode.py plan     # Conmuta a Modo Plan
    python mode.py auto     # Conmuta a Modo Auto
"""
import os
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
POLICY_FILE = HERE / "policy.toml"


def get_current_mode() -> str:
    env_mode = os.environ.get("AGY_MODE", "").strip().lower()
    if env_mode in ("plan", "auto"):
        return env_mode
    if POLICY_FILE.exists():
        try:
            txt = POLICY_FILE.read_text(encoding="utf-8")
            m = re.search(r'^\s*active\s*=\s*["\']([^"\']+)["\']', txt, re.MULTILINE)
            if m:
                return m.group(1).strip().lower()
        except OSError:
            pass
    return "auto"


def set_mode(new_mode: str) -> bool:
    new_mode = new_mode.lower()
    if new_mode not in ("plan", "auto"):
        print(f"Modo no válido: '{new_mode}'. Use 'plan' o 'auto'.")
        return False
    if not POLICY_FILE.exists():
        print(f"No se encontró el archivo de política: {POLICY_FILE}")
        return False
    try:
        content = POLICY_FILE.read_text(encoding="utf-8")
        if re.search(r'^\s*active\s*=', content, re.MULTILINE):
            updated = re.sub(
                r'(^\s*active\s*=\s*["\'])[^"\']+(["\'])',
                rf"\g<1>{new_mode}\g<2>",
                content,
                flags=re.MULTILINE,
            )
        else:
            # Añadir bajo [mode]
            updated = re.sub(
                r'(\[mode\][^\n]*\n)',
                rf'\g<1>active = "{new_mode}"\n',
                content,
            )
        POLICY_FILE.write_text(updated, encoding="utf-8")
        print(f"Modo actualizado con éxito a: '{new_mode}'")
        return True
    except OSError as exc:
        print(f"Error al escribir en {POLICY_FILE}: {exc}")
        return False


def print_status() -> None:
    mode = get_current_mode()
    env_override = os.environ.get("AGY_MODE")
    print("=" * 60)
    print("  ESTADO DE AUTO MODE (Antigravity CLI)")
    print("=" * 60)
    print(f"  Modo Activo      : {mode.upper()}")
    if env_override:
        print(f"  (Sobrescrito por AGY_MODE='{env_override}')")

    print("-" * 60)
    if mode == "plan":
        print("  Comportamiento MODO PLAN:")
        print("  - Lectura de archivos, búsquedas y git log/status: PERMITIDOS")
        print("  - Ejecución de código Python para exploración: PERMITIDO")
        print("  - Edición de código en proyecto o comandos con efectos: CONSULTA (ask)")
    else:
        print("  Comportamiento MODO AUTO:")
        print("  - Edición de código en el proyecto: PERMITIDA (autonomía total)")
        print("  - Comandos seguros y de desarrollo: PERMITIDOS")
        print("  - Comandos complejos: EVALUADOS POR CLASIFICADOR (o consulta)")
        print("  - Líneas rojas (destrucción, .env, hooks): BLOQUEADAS (deny)")
    print("=" * 60)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) > 1:
        arg = sys.argv[1].strip().lower()
        if arg in ("plan", "auto"):
            ok = set_mode(arg)
            return 0 if ok else 1
        elif arg in ("status", "--status", "-s"):
            print_status()
            return 0
        else:
            print(f"Uso: python {pathlib.Path(__file__).name} [plan|auto|status]")
            return 1
    print_status()
    return 0


if __name__ == "__main__":
    sys.exit(main())
