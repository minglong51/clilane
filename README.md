# CLI Lane

[![Smoke](https://github.com/minglong51/clilane/actions/workflows/smoke.yml/badge.svg)](https://github.com/minglong51/clilane/actions/workflows/smoke.yml)

CLI Lane keeps long-running terminal work alive without taking over your terminal.
Start Codex, Claude Code, Kimi, a development server, or any other command in the
background. Reconnect later through SSH, Mosh, or Termius to inspect, attach, send
input, stop, or remove it.

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

- macOS
- Python 3.10 or newer
- tmux
- `tail` for persistent log reading
- OpenSSH and key-based host access for `clilane fleet`

CLI Lane uses only the Python standard library. The lifecycle and fleet paths are
currently verified on macOS; Linux support has not been established.

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

`clilane fleet` reads a fixed set of hosts concurrently. It is deliberately
read-only: it cannot start, attach, send to, stop, or remove a remote task.

Install CLI Lane on every host. A machine running 0.2.0 can query a remote 0.1.0
installation because the fleet protocol consumes the existing `list --json`
shape.

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
      "clilane_version": "0.2.1",
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
| `run NAME [-C DIR] -- COMMAND [ARG ...]` | Start a background task. `DIR` defaults to the current directory. |
| `list`, `ls`, `ps` | List tasks on the current host. `--json` emits an array. |
| `fleet` | Read the configured local and SSH hosts. Supports `--config`, `--timeout`, and `--json`. |
| `status TARGET` | Show one task by name or unique ID prefix. Supports `--json`. |
| `attach TARGET` | Attach interactively. `Ctrl-Q` detaches. |
| `read TARGET` | Print the last 200 terminal lines. `--all` prints retained scrollback. |
| `log TARGET` | Read persistent output. `--lines` defaults to 200; `--follow` follows rotation. |
| `send TARGET MESSAGE` | Paste text and press Enter. `--no-enter` only pastes. |
| `wait TARGET` | Wait and return the task's exit status. `--timeout` returns 124 on timeout. |
| `stop TARGET` | Send TERM, then KILL after `--grace` seconds. The default grace is 3 seconds. |
| `rm`, `remove TARGET` | Remove a finished task and its logs. `--force` stops a running task first. |
| `clean` | Remove completed, stopped, and incomplete tasks. Running tasks remain. |
| `watch` | Refresh the current-host task list. `--interval` defaults to 1 second. |

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
| `XDG_CONFIG_HOME` | Moves the default fleet config to `$XDG_CONFIG_HOME/clilane/fleet.json`. |
| `CLILANE_TMUX_SOCKET` | Overrides the dedicated local tmux socket. |
| `CLILANE_STATE_HOME` | Overrides the local state root; it must be absolute. |
| `XDG_STATE_HOME` | Uses `$XDG_STATE_HOME/clilane` for state. |
| `AGT_TMUX_SOCKET`, `AGT_STATE_HOME` | Legacy compatibility settings. |

The default state root is `~/.local/state/clilane`. Older logs under
`~/.local/state/agt` remain readable for compatibility.

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
- Fleet SSH runs without a PTY, stdin, agent forwarding, X11, or forwarding. It
  uses batch mode, strict known-host checking, one connection attempt, a
  transport timeout, a fixed remote command, and a 256 KiB per-host response
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
- No reboot or CLI Lane tmux-server-crash adoption.
- A descendant that creates a new POSIX session can escape lifecycle control.
- No cross-host mutation, scheduling, retries, dependency graphs, notifications,
  web UI, or automatic SSH-host discovery.
- Fleet snapshots are point-in-time; a task can change immediately afterward.
- Fleet ages assume host clocks are reasonably synchronized.
- Raw terminal logs are not structured or redacted.
- Windows is unsupported, and Linux compatibility is not established.

## License

[MIT](LICENSE)
