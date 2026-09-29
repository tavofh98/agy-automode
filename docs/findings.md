# Findings and design decisions

What isn't code but explains why the code is the way it is.

## Hook contract with agy

- Input on stdin: `{"toolCall": {"name", "args"}, "stepIdx", "conversationId", "workspacePaths", "transcriptPath"}`.
- Output on stdout, only the decision JSON: `{"decision": "allow"|"deny", "reason"}`. All diagnostics go to the audit log.
- With `--dangerously-skip-permissions`, agy honors the hook's `deny` but **runs `ask` without asking**. That is why there is no `ask` verdict, and why any internal hook error denies.
- If the hook can't run (Python missing, command not found), agy blocks the action (measured with agy 1.2.11).
- `force_ask` also runs without asking.
- In agy's plan mode, an `allow` from the hook isn't always enough and agy asks again; `permissionOverrides: ["command(<exact command>)"]` prevents it without granting anything broader.
- agy runs the hook command from the folder that contains `hooks.json`, which is why `hooks.json` calls `python src/pretooluse.py`.

## Judge

- It only sees the user's intent, the approved plan and the action: never the agent's reasoning, which is the defense against persuasion.
- `--json-schema` doesn't enforce the format in print mode (re-measured: prose came back with `status: "SUCCESS"`): the JSON relies on a strict prompt and a tolerant extractor. When in doubt, `deny` marked as a technical failure (`[sin veredicto]`).
- Recursion: the nested agy runs with `AGY_AUTOMODE_INFLIGHT=1` in a temporary folder outside any workspace. Both defenses are needed, because agy also loads a global `hooks.json` from `~/.gemini/config/`.
- The judge runs as its own agent with no tools (`--agent automode-judge`, defined in `.agents/agents/` of its temporary folder). Without it, agy adds its own system prompt and tools: ~12,700 tokens per check versus ~2,700, with the same verdicts. `tools: []` must be written out: without the field, agy loads default tools (~5,500).
- If the agent can't be loaded (wrong name, missing `description`, invalid `model`), agy silently falls back to its default agent: exit code 0 and `status: "SUCCESS"`. Only its log says so (`Agent "<name>" not found, falling back to default`).
- Latency on Windows: ~4 s to start the binary and ~2 s for the model. Startup is what counts, not prompt size: with the custom agent, the cold judge's median only drops from 6.6 to 5.5 s.

## Git snapshots

- A temporary index (`GIT_INDEX_FILE`) that starts as a copy of the user's index: it doesn't touch their index, branch, stash or working folder. The commit has no parent and is only reachable from `refs/automode/<conversation>`.
- It honors `.gitignore` and always excludes sensitive paths: a `.env` was seen copied into every snapshot of a repository that didn't ignore it.
- Whatever the snapshot leaves out (credentials, files larger than `max_file_mb`) is excluded from the restore command: a snapshot without that entry would make `git restore -- .` delete the file.
- agy's `/rewind` only undoes what agy edits with its own tools, not what a shell command deletes: the snapshot is the only safety net for those cases.

## User intent and phase

- Only the user's own messages are taken from the transcript (`USER_EXPLICIT`, `USER_INPUT`); reasoning, tool outputs and model replies are discarded.
- When there is an approved plan in `brain/<conversationId>/`, that plan is the yardstick for the work, not the latest loose messages.
- The hook payload doesn't say which mode agy is in, and the `PLANNER_RESPONSE` step type shows up even without `/plan`: the phase is inferred from the last `/plan` or approval phrase the user typed.
- The phase must be known before deciding, because it changes the rule: in plan, editing project code goes to the judge; in execution, it is approved with a snapshot first.
- Approval works by fixed phrases (regular expressions in `policy.toml`, Spanish and English), a choice from the first version. A plain «yes» or «approved» doesn't count. Letting the judge interpret free-form approvals was considered and rejected (2026-09-28): asking inside the same check as an edit mixes in text written by the agent, and a false approval opens the whole execution phase; a separate check per message adds time and complexity for a small gain. `/auto` is the unambiguous way out.

## Pre-started judge

- Each action is judged by a new agy, already started, which is discarded after answering: no judgment sees the previous ones. Median latency ~2.3 s versus ~5.5 s cold.
- The input format of `agy --input-format stream-json` isn't documented: `{"event": "user", "message": {"content": "..."}}`, with an empty `--print=` and `--output-format stream-json`. `/clear` doesn't exist in print mode, so there is no way to empty the memory of a live agy.
- One helper per conversation, never shared: the same action can be valid in one conversation and not in another (`python simulador.py` is approved in the simulator's conversation and denied in the email one).
- Channel: `127.0.0.1` only, with a per-conversation token in `~/.gemini/automode/<conversation>/`. If the helper fails, the action is judged cold. Signed replies were dropped (2026-09-28): the client sent the token in clear, so the signature protected nothing.
- Its own working folder: if it inherits the hook's, Windows won't let you delete or rename the project while the helper is alive.
