# CLI Lane

[![Smoke](https://github.com/minglong51/clilane/actions/workflows/smoke.yml/badge.svg)](https://github.com/minglong51/clilane/actions/workflows/smoke.yml)

CLI Lane runs interactive CLI agents — Codex, Claude Code, Kimi, or any other
long-running command — in the background, each in its own lane with an identity
you can still trust days later. Reconnect through SSH, Mosh, or Termius to
inspect, attach, send input, press keys, stop, or remove a task, or read task
state across a fleet of hosts.

Plenty of tools keep a process alive; CLI Lane exists for what happens at the
edges. A task keeps its identity even after its pid is reused, so `stop` and
`rm` can never touch an innocent process. Logs survive the tmux server dying
and come back as recoverable orphans, not silent losses. `send` refuses input
an agent would receive as garbage bytes and `key` presses real keys instead.
Exit statuses distinguish signals from exit codes, and `--on-exit` reports a
finished task instead of making you poll. Every destructive path re-verifies
what it is about to touch before touching it.

CLI Lane is process-agnostic. It manages commands that you launch through
`clilane`; it does not depend on an agent framework or discover unrelated
processes.

```text
Laptop / Termius / another node
              │
          SSH or Mosh
              │
              ▼
        host running clilane
              │
      isolated tmux server
       ├── codex-project
       ├── kimi-research
       └── development-server
```

## Requirements

- macOS or Linux
- Python 3.10 or newer
- tmux 3.3 or newer
- `tail` for persistent log reading
- OpenSSH and key-based host access for `clilane fleet`

CLI Lane uses only the Python standard library. The lifecycle and fleet paths are
verified on macOS and Ubuntu in CI. tmux 3.3 is required because older releases
do not report the signal that ended a task, which would silently corrupt exit
statuses; `run` refuses to start on an older tmux.

## Install

### Homebrew

```bash
brew install minglong51/tap/clilane
clilane --version
```

### From the repository

```bash
git clone https://github.com/minglong51/clilane.git
cd clilane
mkdir -p "$HOME/.local/bin"
install -m 0755 bin/clilane "$HOME/.local/bin/clilane"
export PATH="$HOME/.local/bin:$PATH"
clilane --version
```

Persist the PATH change in your shell configuration if `~/.local/bin` is not
already available in new shells.

## Start and manage a task

Start a command. Everything after `--` is passed as exact arguments without an
extra shell:

```bash
clilane run demo -- python3 -u -c 'import time; print("hello"); time.sleep(300)'
```

You can immediately see and inspect it:

```bash
clilane ps
clilane status demo
clilane read demo
```

Attach to its terminal when you need full interaction. Press `Ctrl-Q` to detach
without stopping the command:

```bash
clilane attach demo
```

Stop and remove it when finished:

```bash
clilane stop demo
clilane rm demo
```

Agent CLIs use the same lifecycle:

```bash
clilane run codex-app -C ~/projects/sample-app -- codex
clilane run kimi-research -C ~/projects/research -- kimi
clilane run claude-api -C ~/projects/api -- claude
```

The named command must already be installed on that host.

## View tasks across hosts

`clilane fleet` reads a fixed set of hosts concurrently; `--watch` keeps the
table refreshing. `clilane fleet status HOST:TASK` and
`clilane fleet log HOST:TASK` read one task on one host. The fleet surface is
deliberately read-only: it cannot start, attach, send to, stop, or remove a
remote task.

Install CLI Lane on every host. The fleet commands consume the remote side's
existing `list --json`, `status --json`, and `log` output, so hosts on older
releases keep answering newer clients.

Configure SSH aliases, keys, users, ports, and jump hosts in `~/.ssh/config`.
Connect to each alias once so strict host-key checking succeeds:

```bash
ssh agent-host true
```

On the machine where you run `fleet`, mark that machine as `local` and add any
hosts it can reach as `ssh`. The names are display labels, and each destination
is an SSH alias. CLI Lane has no built-in knowledge of your machines, roles, or
network topology.

Create `~/.config/clilane/fleet.json`:

```json
{
  "schema_version": 1,
  "hosts": [
    {
      "name": "workstation",
      "transport": "local"
    },
    {
      "name": "agent-host",
      "transport": "ssh",
      "destination": "agent-host"
    }
  ]
}
```

The config must contain exactly one `local` entry. Each `ssh` destination must be
a plain SSH-config alias. Host names and destinations must begin with an ASCII
letter or number; their remaining characters may be letters, numbers, dots,
dashes, or underscores, up to 64 characters total. A config may contain at most
32 hosts; unknown fields and schema versions are rejected. CLI Lane never
enumerates your SSH config or probes hosts that are not listed.

Run the fleet snapshot:

```bash
clilane fleet
```

```text
HOST        NAME          STATE      AGE    PID      PROJECT    COMMAND
workstation kimi-research running    4m     8124     research   kimi
agent-host  codex-project running    15h    21686    sample-app codex
```

Override the config or per-host timeout when needed:

```bash
clilane fleet --config ~/fleet-lab.json --timeout 10
clilane fleet --json
```

An offline or invalid host does not hide healthy results. Human output reports
that host on stderr; JSON embeds the error. `fleet` exits `1` whenever the
snapshot is incomplete and `0` only when every configured host succeeds.
Queries use at most eight concurrent SSH connections. The default per-host SSH
transport timeout is 5 seconds and accepted values are greater than 0 and at
most 300. Each host may return at most 512 tasks and 256 KiB; with the 32-host
config limit, successful raw fleet data is capped at 8 MiB.

Fleet JSON has this top-level shape:

```json
{
  "schema_version": 1,
  "complete": false,
  "generated_at": "2026-08-19T12:00:00+00:00",
  "hosts": [
    {
      "name": "workstation",
      "status": "ok",
      "clilane_version": "0.4.0",
      "tasks": [],
      "error": null
    },
    {
      "name": "agent-host",
      "status": "error",
      "clilane_version": null,
      "tasks": [],
      "error": {
        "kind": "timeout",
        "message": "timed out after 5 seconds"
      }
    }
  ]
}
```

Fleet scope is explicit rather than inferred: “complete” means every host in this
config answered successfully. It does not mean every computer or process on your
network was discovered.

## One view for every agent

`clilane hub` attaches to a persistent `hub` session on CLI Lane's dedicated tmux
server: a shell for typing CLI Lane commands, plus prefix-less keys for reaching
every running agent.

```bash
clilane hub
```

| Key | Behavior |
| --- | --- |
| `M-n` | Open the menu: start a preset agent, or jump to a running one. |
| `M-h` | Return to the hub from whichever agent you are in. |
| `Ctrl-Q` | Detach and leave every agent running. |

The menu lists presets first, then every running task by name and state. Starting
one prompts for a task name; jumping switches straight to it.

`M-n` acts only while the hub is in front, so an attached agent keeps receiving it
as an ordinary key. `M-h` is deliberately global — a reliable way back matters more
than the one key it takes, and CLI Lane already reserves `Ctrl-Q` the same way.

Presets come from an optional file. Without one the hub is still a working
launcher: type `clilane run ...` in its shell, or press `M-n` to jump between
whatever is already running.

```json
{
  "schema_version": 1,
  "agents": [
    { "name": "claude", "command": ["claude"], "dir": "~/projects/app" },
    { "name": "codex", "command": ["codex"], "dir": "~/projects/app" },
    { "name": "kimi", "command": ["kimi"], "dir": "~/projects/web" },
    { "name": "hermes", "command": ["hermes"], "dir": "~" }
  ]
}
```

`dir` must be absolute after `~` expansion. A preset starts an ordinary task, so
`list`, `log`, `stop`, and the fleet commands all see it, and the task's tmux
window carries its name.

The hub runs on CLI Lane's own tmux server, so it nests safely inside your normal
tmux: your prefix, configuration, and other panes are untouched, and both survive a
dropped connection independently.

## SSH, Mosh, and tmux

Tasks live on the host, so disconnecting SSH, Mosh, or Termius does not stop them
while that host and CLI Lane's dedicated tmux server remain alive.

From an interactive remote login:

```bash
ssh agent-host
clilane ps
clilane attach codex-project
```

For a one-shot command whose non-login PATH does not include CLI Lane or Homebrew,
invoke a login shell:

```bash
ssh agent-host 'zsh -lc "clilane ps"'
```

`attach` removes inherited outer-tmux variables before connecting to CLI Lane's
isolated server. CLI Lane starts that server with `-f /dev/null`, so it does not
load or alter your normal tmux configuration. The default internal socket remains
named `agt` for compatibility with tasks created before the project was renamed.

## Command reference

| Command | Behavior |
|---|---|
| `run NAME [-C DIR] [--on-exit COMMAND] [--wait] -- COMMAND [ARG ...]` | Start a background task. `DIR` defaults to the current directory. `--wait` blocks and returns the command's exit status; `--timeout` returns 124. `--on-exit` runs a shell command after the task exits. |
| `list`, `ls`, `ps` | List tasks on the current host. `--json` emits an array. |
| `fleet` | Read the configured local and SSH hosts. Supports `--config`, `--timeout`, `--json`, and `--watch` (`--interval` defaults to 2 seconds). |
| `fleet status HOST:TASK` | Show one task on a fleet host as JSON. |
| `fleet log HOST:TASK` | Read a fleet task's persistent log. `--lines` defaults to 200. |
| `status TARGET` | Show one task by name or unique ID prefix. Supports `--json`. |
| `attach TARGET` | Attach interactively. `Ctrl-Q` detaches. |
| `hub` | Attach to the hub session: every agent in one view, with `M-n` for the start-or-jump menu, `M-h` to return, and `Ctrl-Q` to detach. `--config` overrides the presets file. |
| `read TARGET` | Print the last 200 terminal lines. `--all` prints retained scrollback. |
| `log TARGET` | Read persistent output. `--lines` defaults to 200; `--follow` follows rotation. |
| `send TARGET MESSAGE` | Paste text and press Enter. `--no-enter` only pastes. Control characters are rejected; use `key`. |
| `key TARGET KEY [KEY ...]` | Press named keys, such as `Enter`, `Escape`, `Up`, `Tab`, `BTab`, or `C-c`. `--list` prints supported names. |
| `wait TARGET` | Wait and return the task's exit status. `--timeout` returns 124 on timeout. |
| `stop TARGET` | Send TERM, then KILL after `--grace` seconds. The default grace is 3 seconds. |
| `rm`, `remove TARGET` | Remove a finished task and its logs. `--force` stops a running task first. |
| `clean` | Remove completed, stopped, incomplete, and lost tasks. Running tasks and orphaned logs remain. `--dry-run` reports only; `--orphans` also deletes orphaned logs. |
| `orphans` | List tasks whose tmux server died but whose logs survive. Supports `--json`. |
| `watch` | Refresh the current-host task list. `--interval` defaults to 1 second. |

The `--on-exit` hook runs through `/bin/sh -c` in the task's working directory
after the task process exits, with `CLILANE_TASK_NAME`, `CLILANE_TASK_ID`,
`CLILANE_LOG`, `CLILANE_EXIT_CODE`, and `CLILANE_SIGNAL` (the signal name, or
empty) in its environment. Hook output is captured in the task log. The hook
gets 30 seconds, then it is killed; its exit status never changes the task's.
With `--wait`, the wait returns after the hook finishes. Stopping or removing
the task while the hook runs delivers TERM to the hook first and kills it after
the grace period; the task's recorded exit status is unaffected either way.

Task names are unique per host. They are 1–64 characters, begin with an ASCII
letter or number, and otherwise contain ASCII letters, numbers, dots, dashes, or
underscores.

## States and local JSON

CLI Lane reports process lifecycle rather than semantic agent state:

- `initializing`
- `running`
- `stopped`
- `succeeded`
- `failed`

It cannot determine whether an agent is waiting for input, blocked on approval,
or idle at a prompt. Use `read`, `attach`, or `send` to inspect that condition.

`list --json` returns an array and `status --json` returns one object. A task has:

```text
id, name, state, command, cwd, created, log,
pid, attached, exit_code, signal
```

`pid` is null after exit. `exit_code` and `signal` are null while a task is
running.

## Configuration and storage

| Setting | Purpose |
|---|---|
| `~/.config/clilane/fleet.json` | Default versioned fleet inventory. |
| `~/.config/clilane/hub.json` | Optional hub launcher presets, up to nine agents. |
| `XDG_CONFIG_HOME` | Moves the default fleet and hub configs under `$XDG_CONFIG_HOME/clilane/`. |
| `CLILANE_TMUX_SOCKET` | Overrides the dedicated local tmux socket. |
| `CLILANE_STATE_HOME` | Overrides the local state root; it must be absolute. |
| `XDG_STATE_HOME` | Uses `$XDG_STATE_HOME/clilane` for state. |
| `AGT_TMUX_SOCKET`, `AGT_STATE_HOME` | Legacy compatibility settings. |

The default state root is `~/.local/state/clilane`. Each task also writes a small
JSON record under the state root's `registry/` directory so its log can be
identified and reclaimed after the tmux server or the machine restarts. Older
logs under `~/.local/state/agt` remain readable for compatibility.

## Security and logging

- Commands run as exact argument vectors through `execvpe`; CLI Lane does not
  insert a shell. Run `sh -lc` explicitly when you want pipelines or redirection.
- Tasks run with your user permissions. CLI Lane is not a sandbox.
- Each task receives a snapshot of its launching environment except transient
  tmux and terminal variables. Environment secrets remain available to the task.
- Logs contain raw terminal bytes, ANSI controls, and potentially sensitive
  program output.
- Local and fleet JSON include full command arguments, working directories, and
  log paths. Avoid putting secrets in command arguments.
- Control and log directories use mode `0700`; current logs use mode `0600`.
- Each task retains a 50 MiB current log and one previous rotated log.
- `stop` retains logs. `rm` and `clean` delete the current and previous logs.
- After a tmux server crash or reboot, logs survive and are listed by `orphans`;
  plain `clean` preserves them and `clean --orphans` deletes them.
- Fleet SSH runs without a PTY, stdin, agent forwarding, X11, or forwarding. It
  uses batch mode, strict known-host checking, one connection attempt, a
  transport timeout, a remote command limited to fixed read verbs with a pattern-validated task argument, and a 256 KiB per-host response
  limit.
- Fleet config cannot inject SSH flags or remote commands. Connection details
  belong in your normal SSH config. Treat that config as trusted: connection
  plumbing such as `ProxyCommand`, `KnownHostsCommand`, and `Match exec` can run
  local programs before CLI Lane connects.

## Troubleshooting

- `clilane: command not found`: add its install directory to `PATH`. For a
  one-shot SSH command, invoke a login shell as shown above.
- `clilane: tmux is required`: install tmux and ensure Homebrew's bin directory
  is available in that shell.
- `fleet config not found`: create the default file or pass `--config FILE`.
- SSH host-key failure: run `ssh ALIAS true` once and verify the key before
  retrying the fleet query.
- A remote reports that `clilane` is missing: install it there and confirm
  `ssh ALIAS 'zsh -lc "clilane --version"'` succeeds.
- A task is missing from `ps`: confirm it was started by the same Unix user with
  the same `CLILANE_TMUX_SOCKET` value.

## Limitations

- Only tasks started through CLI Lane are visible.
- Each host exposes one Unix user's selected CLI Lane tmux socket.
- No reboot or CLI Lane tmux-server-crash adoption of running tasks; their exit
  status is lost, though their logs survive and are listed by `orphans`.
- A descendant that creates a new POSIX session can escape lifecycle control.
- No queueing, by design: a task starts immediately or not at all. Sequential
  workflows compose from `run --wait` and `--on-exit`; anything beyond that
  belongs in a real scheduler running above CLI Lane, not inside it.
- No cross-host mutation, retries, dependency graphs, notifications beyond
  `--on-exit`, web UI, or automatic SSH-host discovery.
- Fleet snapshots are point-in-time; a task can change immediately afterward.
- Fleet ages assume host clocks are reasonably synchronized.
- Raw terminal logs are not structured or redacted.
- Windows is unsupported.

## License

[MIT](LICENSE)
