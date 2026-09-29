# automode — auto mode for agy

A plugin for [Antigravity CLI](https://antigravity.google) (`agy`) that decides, before every
tool call, whether the agent can carry on by itself. It is meant for working with
`--dangerously-skip-permissions` without flying blind:

- **Fixed rules first.** Reads inside the project, query commands and tests are approved
  instantly. Mass deletions, `git push --force`, downloading and running code, reading
  credentials or touching the auto mode itself are always denied.
- **agy as the judge for unclear cases.** Whatever the rules don't settle is sent to
  `agy --print` together with your plan and your latest messages. No keys or extra setup: it
  uses your already authenticated agy session.
- **Pre-started judge.** Each conversation has a helper process (`src/judge_pool.py`) that
  keeps an agy already started: each judged action takes ~2.5 s instead of ~6, with no memory
  of the previous ones. The judge runs as an agent with no tools, so each check reads ~2,700
  tokens instead of ~12,700. The helper shuts down after 15 minutes without actions; if it
  doesn't answer, the action is judged cold.
- **Planning phase.** After you type `/plan`, code edits go through the judge, which denies
  them until you approve. An approval phrase (see below) opens the execution phase.
- **Backup before changes.** Before the first change of each block of work it stores a git
  snapshot of the project in `refs/automode/<conversation>`, without touching your index or
  your branch. Credentials (`.env`, SSH keys…) are left out of the snapshot, as are files
  larger than 10 MB: the approval reason names them and the undo command excludes them.
  Snapshots from the last 20 conversations are kept.
- **Instructions for the agent.** `rules/AGENTS.md` is added to agy's rules while the plugin
  is active: it asks the agent to prefer its own read tools over the shell and to group
  checks into a single script, so fewer actions have to wait for the judge.

## Requirements

- `agy` installed and authenticated.
- Python 3.11 or later, available as `python`.
- git, and the project must be a repository. If it isn't, the auto mode denies edits and
  tells the agent to run `git init`.

## Installation

The same repository works for both scopes.

**In a project** (to try it out):

```bash
git clone <this-repo-url> .agents/plugins/automode
```

**Global** (for all your projects):

```bash
git clone <this-repo-url> agy-automode
agy plugin install agy-automode
```

If it is installed in both scopes, only the project copy acts in that project: the global one
doesn't run. That way you can try a new version in one project without touching the global
one.

**Pause it without uninstalling** (for example, to run agy with
`--dangerously-skip-permissions` and no auto mode):

```bash
agy plugin disable automode
agy plugin enable automode
```

**Uninstall:** `agy plugin uninstall automode`, or delete the `.agents/plugins/automode`
folder.

> On Linux or macOS, if you only have `python3`, change `python` to `python3` in `hooks.json`.

## Usage

Launch agy with `--dangerously-skip-permissions`:

```bash
agy --dangerously-skip-permissions
```

Without that option the auto mode still decides, but agy keeps asking for confirmation even
when the hook approves the action. With it, agy honors the hook's denials and stops asking.
If the hook itself fails (unreadable policy, a call it can't read), the action is denied and
the reason says what to check.

**`agya` shortcut.** To avoid typing the option every time, define a shortcut that accepts the
same arguments as `agy` (for example, `agya -c`).

In PowerShell, add this line to your profile (`notepad $PROFILE`):

```powershell
function agya { agy --dangerously-skip-permissions @args }
```

If PowerShell says "running scripts is disabled on this system" when it opens, allow your
local scripts once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

In bash or zsh, add to `~/.bashrc` or `~/.zshrc`:

```bash
alias agya='agy --dangerously-skip-permissions'
```

## Phases: planning and execution

With no special message, the plugin works in the execution phase. The phase is inferred from
what you type:

| You type | Phase |
|---|---|
| `/plan …` or «volvamos a planear» | Planning: reading and exploring are free; edits go through the judge |
| `/auto`, «approved, go ahead», «plan approved», «run it in auto mode», «switch to auto mode», «aprobado, ejecuta», «ejecútalo en modo automático» or «modo automático» | Execution: edits inside the project are approved, with a backup first |

The phrases are set in `policy.toml` (`[mode].plan_triggers` and `auto_triggers`) as regular
expressions.

## Configuration

All behavior lives in `policy.toml`: safe and blocked commands, sensitive paths, tools by
level, the judge's model and time limit, and the backup. The comments in the file explain each
section. `[mode].active` sets the phase used when the conversation doesn't mark one.

## Where it keeps its state

Each conversation keeps its state in the folder agy creates for it:
`~/.gemini/antigravity-cli/brain/<conversation>/.agents/automode/`. It contains `audit.jsonl`
(one line per decision, with the installation that acted in the `hook` field) and the record
of git snapshots. The agent cannot modify that folder.

## Limitations

- **You still run agy with `--dangerously-skip-permissions`.** The hook is the only brake: if
  the plugin is disabled or not installed, agy runs with no checks at all.
- **Plan approval works by fixed phrases.** Only `/auto` and the phrases in the table above
  open the execution phase. A plain «yes», «ok» or «approved» doesn't count, and the phrases
  only exist in Spanish and English. When in doubt, use `/auto`.
- **Each judge check costs a little quota and time:** ~2–3 s with the pre-started judge,
  ~5–6 s when it has to start cold.
- **The judge never sees the agent's reasoning**, only your messages, the plan and the action.
  That is deliberate (the agent can't talk its way past it), but it also means a short reply
  like «yes» to a question from the agent carries no context for the judge.
- **The messages of the fixed rules and the code comments are in Spanish.** Code identifiers
  are in English.
- **Only tested on Windows**, with agy 1.2.12.

## Tests

```bash
python tests/selftest.py
```

It works on a temporary repository and doesn't call agy.
