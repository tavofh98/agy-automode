# Hallazgos y decisiones de diseño

Lo que no es código pero explica por qué el código es así.

## Contrato del hook con agy

- Entrada por stdin: `{"toolCall": {"name", "args"}, "stepIdx", "conversationId", "workspacePaths", "transcriptPath"}`.
- Salida por stdout, solo el JSON de decisión: `{"decision": "allow"|"deny", "reason"}`. Todo diagnóstico va al registro de auditoría.
- Con `--dangerously-skip-permissions`, agy respeta el `deny` del hook pero **ejecuta el `ask` sin preguntar**. Por eso no existe el veredicto `ask`, y cualquier error interno del hook deniega.
- Si el hook no puede ejecutarse (Python ausente, comando inexistente), agy bloquea la acción (medido con agy 1.2.11).

## Juez

- Solo ve la intención del usuario, el plan aprobado y la acción: nunca el razonamiento del agente, que es la defensa contra la persuasión.
- `--json-schema` no fuerza el formato en modo print: el JSON se sostiene con un prompt estricto y un extractor tolerante. Ante cualquier duda, `deny` marcado como fallo técnico, que no cuenta para el cortacircuitos.
- Recursión: el agy anidado corre con `AGY_AUTOMODE_INFLIGHT=1` y en un directorio temporal fuera de todo workspace. Hacen falta las dos defensas, porque agy también carga un `hooks.json` global de `~/.gemini/config/`.
- Latencia en Windows: ~4 s de arranque del binario y ~2 s de modelo. `gemini-3.8-flash-low` ya no gasta tokens de razonamiento, así que un juez en dos etapas no ahorra nada; lo que cuenta es el arranque.

## Capturas git

- Índice temporal (`GIT_INDEX_FILE`) que parte de una copia del índice de la persona: no toca su índice, rama, stash ni carpeta de trabajo. El commit no tiene padre y solo lo alcanza `refs/automode/<conversación>`.
- Respeta `.gitignore` y excluye siempre las rutas sensibles: se vio un `.env` copiado en todas las capturas de un repositorio que no lo ignoraba.
- Lo que la captura omite (credenciales, archivos de más de `max_file_mb`) queda excluido de la orden de restauración: una captura sin esa entrada haría que `git restore -- .` borrase el archivo.
- `/rewind` de agy solo deshace lo que agy edita con sus herramientas, no lo que borra un comando de shell: la captura es la única red para esos casos.

## Intención del usuario

- Se extraen solo los mensajes auténticos del usuario del transcript (`USER_EXPLICIT`, `USER_INPUT`); se descarta el razonamiento, las salidas de herramientas y las respuestas del modelo.
- Cuando hay un plan aprobado en `brain/<conversationId>/`, ese plan es la vara del trabajo, no los últimos mensajes sueltos.

## Juez de repuesto

- Cada acción la juzga un agy nuevo, ya arrancado, que se descarta al responder: ningún juicio ve los anteriores. Latencia ~2,5–3,9 s frente a ~7 s en frío.
- El formato de entrada de `agy --input-format stream-json` no está documentado: `{"event": "user", "message": {"content": "..."}}`, con `--print=` vacío y `--output-format stream-json`. `/clear` no existe en modo print, así que no hay forma de vaciar la memoria de un agy vivo.
- Un auxiliar por conversación, nunca compartido: la misma acción puede ser válida en una conversación y no en otra (`python simulador.py` se aprueba en la del simulador y se deniega en la de los correos).
- Canal: solo `127.0.0.1`, secreto por conversación en `~/.gemini/automode/<conversación>/` y respuestas firmadas con HMAC. Si el auxiliar falla, la acción se juzga en frío.
- Carpeta de trabajo propia: si hereda la del hook, Windows no deja borrar ni renombrar el proyecto mientras el auxiliar vive.
