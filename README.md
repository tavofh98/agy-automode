# automode — auto mode para agy

Plugin para [Antigravity CLI](https://antigravity.google) (`agy`) que decide, antes de cada
llamada a herramienta, si el agente puede seguir solo. Pensado para trabajar con
`--dangerously-skip-permissions` sin quedar a ciegas:

- **Reglas fijas primero.** Lecturas dentro del proyecto, comandos de consulta y pruebas se
  aprueban al instante. Borrados masivos, `git push --force`, descargar y ejecutar código,
  leer credenciales o tocar el propio auto mode se deniegan siempre.
- **agy como juez de los casos dudosos.** Lo que las reglas no resuelven se consulta a
  `agy --print` con tu plan y tus últimos mensajes delante. Sin claves ni configuración
  aparte: usa la sesión de agy ya autenticada.
- **Juez de repuesto.** Cada conversación tiene un proceso auxiliar (`judge_pool.py`) que
  mantiene un agy ya arrancado, así que cada acción juzgada tarda ~2,5 s en vez de ~7. Cada
  juicio lo hace un agy nuevo, sin memoria de acciones anteriores, y ningún juez atiende a
  dos conversaciones. Escucha solo en `127.0.0.1`, sus respuestas van firmadas con un
  secreto en `~/.gemini/automode/<conversación>/` y se apaga tras 15 minutos sin acciones.
  Si no responde, la acción se juzga en frío como siempre.
- **Fase de planeación.** Tras escribir `/plan`, las ediciones de código pasan por el juez,
  que las deniega hasta que apruebes. Una frase de aprobación (ver más abajo) abre la fase de
  ejecución.
- **Respaldo antes de modificar.** Antes del primer cambio de cada bloque de trabajo guarda
  una captura git del proyecto en `refs/automode/<conversación>`, sin tocar tu índice ni tu
  rama. Las credenciales (`.env`, claves SSH…) quedan fuera de la captura, igual que los
  archivos de más de 10 MB: el motivo de la aprobación los nombra y la orden para deshacer
  los excluye. Se conservan las capturas de las últimas 20 conversaciones.
- **Instrucciones para el agente.** `rules/AGENTS.md` se suma a las reglas de agy mientras el
  plugin está activo: le pide preferir sus herramientas de lectura a la shell y agrupar las
  comprobaciones en un script, para que menos acciones tengan que esperar al juez.
- **Cortacircuitos.** Si el agente insiste en caminos prohibidos, mantiene la denegación y le
  pide que cambie de enfoque o se detenga a explicarte qué necesita.

## Requisitos

- `agy` instalado y autenticado.
- Python 3.11 o superior, disponible como `python`.
- git, y que el proyecto sea un repositorio. Si no lo es, el auto mode deniega las ediciones
  y le indica al agente que ejecute `git init`.

## Instalación

El mismo repositorio sirve para los dos ámbitos.

**En un proyecto** (para probarlo):

```bash
git clone <url-de-este-repo> .agents/plugins/automode
```

**Global** (para todos tus proyectos):

```bash
git clone <url-de-este-repo> agy-automode
agy plugin install agy-automode
```

Si está instalado en los dos ámbitos, en ese proyecto actúa solo la copia del proyecto: la
global no se ejecuta. Así puedes probar una versión nueva en un proyecto sin tocar la global.

**Pausarlo sin desinstalar:**

```bash
agy plugin disable automode
agy plugin enable automode
```

**Una sesión sin juez ni respaldo:** lanza agy con la variable `AGY_AUTOMODE=off`. Lo que
iría al juez se aprueba al instante y no se hace captura git; las líneas rojas se siguen
aplicando. También deja sin freno la fase de planeación, que depende del juez.

```powershell
$env:AGY_AUTOMODE = 'off'; agy
```

**Desinstalar:** `agy plugin uninstall automode`, o borra la carpeta `.agents/plugins/automode`.

> En Linux o macOS, si solo tienes `python3`, cambia `python` por `python3` en `hooks.json`.

## Uso

Lanza agy con `--dangerously-skip-permissions`:

```bash
agy --dangerously-skip-permissions
```

Sin esa opción el auto mode decide igual, pero agy te sigue pidiendo confirmación aunque el
hook apruebe la acción. Con ella, agy respeta las denegaciones del hook y deja de preguntar.
Si el propio hook falla (política ilegible, llamada que no puede leer, Python ausente o
anterior a 3.11), la acción se deniega y el motivo dice qué revisar.

**Atajo `agya`.** Para no escribir la opción cada vez, define un atajo que acepta los mismos
argumentos que `agy` (por ejemplo, `agya -c`).

En PowerShell, añade esta línea a tu perfil (`notepad $PROFILE`):

```powershell
function agya { agy --dangerously-skip-permissions @args }
```

Si al abrir PowerShell aparece «la ejecución de scripts está deshabilitada», permite tus
scripts locales una sola vez:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

En bash o zsh, añade a `~/.bashrc` o `~/.zshrc`:

```bash
alias agya='agy --dangerously-skip-permissions'
```

## Fases: planear y ejecutar

La fase se deduce de lo que escribes:

| Escribes | Fase |
|---|---|
| `/plan …` o «volvamos a planear» | Planeación: se lee y explora libremente; las ediciones pasan por el juez |
| `/auto`, «aprobado, ejecuta», «ejecútalo en modo automático» o «modo automático» | Ejecución: las ediciones dentro del proyecto se aprueban, con respaldo previo |

Las frases se configuran en `policy.toml` (`[mode].plan_triggers` y `auto_triggers`).

## Configuración

Todo el comportamiento vive en `policy.toml`: comandos seguros y bloqueados, rutas
sensibles, herramientas por nivel, el modelo y el tiempo límite del juez, el respaldo y el
cortacircuitos. Los comentarios del archivo explican cada sección.

`python mode.py` muestra el modo fijo de la política; `python mode.py plan|auto` lo cambia.

## Dónde guarda su estado

Cada conversación guarda su estado en la carpeta que agy crea para ella:
`~/.gemini/antigravity-cli/brain/<conversación>/.agents/automode/`. Contiene `audit.jsonl`
(una línea por decisión, con qué instalación actuó en el campo `hook`), los contadores del
cortacircuitos y la caché de veredictos. El agente no puede modificar esa carpeta.

## Pruebas

```bash
python selftest.py
```

Trabaja sobre un repositorio temporal y no llama a agy.
