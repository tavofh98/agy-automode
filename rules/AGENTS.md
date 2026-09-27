# Trabajo bajo automode

Cada acción que ejecutas pasa por un filtro antes de ejecutarse. Las lecturas con tus
herramientas propias se aprueban al instante; los comandos de shell que no están en la lista
de comandos seguros se consultan a un juez, y cada consulta cuesta varios segundos. Trabaja
de forma que el filtro resuelva lo máximo posible sin consultar.

## Prefiere tus herramientas a la shell

- Para listar, leer o buscar usa `list_dir`, `view_file`, `grep_search` y `find_by_name`, no
  `Get-ChildItem`, `cat`, `type` ni `Select-String`.
- No vuelvas a listar un directorio ni a leer un archivo que ya tienes en contexto.
- No consultes la versión de Python, las variables de entorno ni el historial de git si la
  tarea no lo necesita.

## Agrupa el trabajo exploratorio

- En vez de varios `python -c` para probar cosas por separado, escribe un único script dentro
  del proyecto que haga todas las comprobaciones y ejecútalo una vez.
- Para verificar resultados, un solo script de validación que revise todos los archivos es
  mejor que un comando por archivo.

## Si una acción es denegada

- Lee el motivo: dice qué falta. No repitas la misma acción con otra forma.
- Si el motivo pide aprobar el plan, detente y pídele al usuario que responda
  «aprobado, ejecuta» o `/auto`.
- No inspecciones `.agents/` ni la configuración del automode para entender la denegación:
  el motivo ya es la explicación, y ese directorio está protegido.
