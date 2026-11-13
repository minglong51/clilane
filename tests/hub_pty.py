#!/usr/bin/env python3

from __future__ import annotations

import errno
import fcntl
import json
import os
import pty
import runpy
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
CLILANE = ROOT / "bin" / "clilane"


class _Terminal:
    def __init__(
        self,
        arguments: Sequence[str],
        environment: dict[str, str],
        cwd: str | None = None,
        executable: Path = CLILANE,
    ) -> None:
        pid, descriptor = pty.fork()
        if pid == 0:
            try:
                if cwd is not None:
                    os.chdir(cwd)
                fcntl.ioctl(
                    sys.stdout.fileno(),
                    termios.TIOCSWINSZ,
                    struct.pack("HHHH", 24, 100, 0, 0),
                )
                os.execve(
                    str(executable),
                    [str(executable), *arguments],
                    environment,
                )
            except BaseException as error:
                print(error, file=sys.stderr)
                os._exit(127)
        self.pid = pid
        self.descriptor = descriptor
        self.output = bytearray()
        self.environment = dict(environment)
        self.exit_code: int | None = None
        fcntl.ioctl(
            descriptor,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", 24, 100, 0, 0),
        )
        os.kill(pid, signal.SIGWINCH)

    def mark(self) -> int:
        return len(self.output)

    def send(self, value: bytes) -> None:
        os.write(self.descriptor, value)

    def resize(self, columns: int, rows: int) -> None:
        fcntl.ioctl(
            self.descriptor, termios.TIOCSWINSZ,
            struct.pack("HHHH", rows, columns, 0, 0),
        )
        os.kill(self.pid, signal.SIGWINCH)

    def expect(self, value: str, since: int = 0, timeout: float = 15.0) -> None:
        expected = value.encode()
        deadline = time.monotonic() + timeout
        while expected not in self.output[since:]:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._read(min(remaining, 0.25)):
                if remaining > 0:
                    continue
                transcript = bytes(self.output[-6000:]).decode(errors="replace")
                raise AssertionError(f"terminal did not show {value!r}:\n{transcript}")

    def wait(self, timeout: float = 10.0) -> int:
        if self.exit_code is not None:
            return self.exit_code
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.exit_code = os.waitstatus_to_exitcode(status)
                return self.exit_code
            self._read(0.1)
        raise AssertionError("terminal client did not exit")

    def running(self) -> bool:
        if self.exit_code is not None:
            return False
        pid, status = os.waitpid(self.pid, os.WNOHANG)
        if not pid:
            return True
        self.exit_code = os.waitstatus_to_exitcode(status)
        return False

    def settle(self, quiet: float = 0.2, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = min(quiet, deadline - time.monotonic())
            readable, _, _ = select.select([self.descriptor], [], [], remaining)
            if not readable:
                return
            if not self._read(0):
                return

    def close(self) -> None:
        if self.exit_code is None:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.wait(3.0)
            except (AssertionError, ChildProcessError):
                try:
                    os.kill(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(self.pid, 0)
                except ChildProcessError:
                    pass
        try:
            os.close(self.descriptor)
        except OSError:
            pass

    def _read(self, timeout: float) -> bool:
        readable, _, _ = select.select([self.descriptor], [], [], timeout)
        if not readable:
            return True
        try:
            value = os.read(self.descriptor, 65536)
        except OSError as error:
            if error.errno == errno.EIO:
                return False
            raise
        if not value:
            return False
        self.output.extend(value)
        return True


def _run(
    environment: dict[str, str],
    arguments: Sequence[str],
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(CLILANE), *arguments],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"clilane {' '.join(arguments)} exited {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _tasks(environment: dict[str, str]) -> list[dict[str, object]]:
    result = _run(environment, ["list", "--json"])
    value = json.loads(result.stdout)
    assert isinstance(value, list)
    return value


def _tmux(
    environment: dict[str, str], arguments: Sequence[str]
) -> subprocess.CompletedProcess[bytes]:
    return _tmux_on_socket(
        environment, environment["CLILANE_TMUX_SOCKET"], arguments
    )


def _tmux_on_socket(
    environment: dict[str, str], socket: str, arguments: Sequence[str]
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "tmux",
            "-L",
            socket,
            "-f",
            "/dev/null",
            *arguments,
        ],
        env=environment,
        check=False,
        capture_output=True,
        timeout=10,
    )


def _hub_context_counts(environment: dict[str, str]) -> tuple[int, int]:
    result = _tmux(environment, ["show-options", "-g"])
    assert result.returncode == 0
    lines = result.stdout.splitlines()
    contexts = sum(line.startswith(b"@agt_hub_context_") for line in lines)
    clients = sum(line.startswith(b"@agt_hub_client_") for line in lines)
    return contexts, clients


def _hub_popup_count(environment: dict[str, str]) -> int:
    result = _tmux(environment, ["show-options", "-g"])
    assert result.returncode == 0
    return sum(
        line.startswith(b"@agt_hub_popup_") for line in result.stdout.splitlines()
    )


def _hub_popup_values(environment: dict[str, str]) -> list[str]:
    result = _tmux(environment, ["show-options", "-g"])
    assert result.returncode == 0
    return [
        line.decode().split(" ", 1)[1]
        for line in result.stdout.splitlines()
        if line.startswith(b"@agt_hub_popup_")
    ]


def _hub_pane_info(environment: dict[str, str], session: str) -> list[str]:
    result = _tmux(
        environment,
        ["display-message", "-p", "-t", session,
         "#{pane_id}|#{pane_pid}|#{pane_tty}|#{pane_width}|#{pane_height}|#{history_limit}|#{history_size}"],
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    values = result.stdout.decode().strip().split("|")
    assert len(values) == 7 and values[0].startswith("%"), (session, values)
    return values


def _hub_sessions(environment: dict[str, str]) -> set[str]:
    result = _tmux(environment, ["list-sessions", "-F", "#{session_name}"])
    return {name for name in result.stdout.decode().splitlines() if name.startswith("hub_")}


def _close_hub_pane(environment: dict[str, str], client: str) -> None:
    clients = _tmux(
        environment, ["list-clients", "-F", "#{client_name}|#{client_session}"]
    ).stdout.decode().splitlines()
    session = next(line.split("|", 1)[1] for line in clients if line.startswith(client + "|"))
    assert session.startswith("hub_"), session
    pane = _tmux(
        environment, ["show-options", "-qv", "-t", session, "@agt_hub_pane_id"]
    ).stdout.decode().strip()
    assert pane.startswith("%"), pane
    closed = _tmux(environment, ["kill-pane", "-t", pane])
    assert closed.returncode == 0, closed.stderr.decode(errors="replace")


def _call_clilane_function(
    environment: dict[str, str], name: str, arguments: Sequence[str]
) -> None:
    program = (
        "import runpy,sys; "
        "namespace=runpy.run_path(sys.argv[1],run_name='clilane_test'); "
        "namespace[sys.argv[2]](*sys.argv[3:])"
    )
    result = subprocess.run(
        [sys.executable, "-c", program, str(CLILANE), name, *arguments],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"{name} exited {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def _cleanup(environment: dict[str, str]) -> None:
    result = _run(environment, ["list", "--json"], check=False)
    if result.returncode == 0:
        try:
            tasks = json.loads(result.stdout)
        except json.JSONDecodeError:
            tasks = []
        for task in tasks:
            if isinstance(task, dict) and isinstance(task.get("id"), str):
                _run(
                    environment,
                    ["rm", task["id"], "--force", "--grace", "0"],
                    check=False,
                )
    _tmux(environment, ["kill-session", "-t", "hub"])


def _exercise_discovery_helpers(root: Path) -> None:
    namespace = runpy.run_path(str(CLILANE), run_name="clilane_test")
    discover = namespace["discover_hub_presets"]
    load = namespace["load_hub_presets"]
    notice = namespace["hub_no_presets_notice"]
    error_type = namespace["CliLaneError"]

    assert discover({}, str(root.resolve())) == []
    assert discover({"PATH": ""}, str(root.resolve())) == []

    helper_bin = root / "helper-agents"
    helper_bin.mkdir(mode=0o700)
    (helper_bin / "kimi").symlink_to("/bin/cat")
    assert discover(
        {"PATH": str(helper_bin.resolve())}, str(root.resolve())
    ) == [
        {
            "name": "kimi",
            "command": [str(root.resolve() / "helper-agents" / "kimi")],
            "dir": str(root.resolve()),
        }
    ]

    try:
        discover({"PATH": str(helper_bin)}, "relative")
    except Exception as error:
        assert type(error) is error_type
    else:
        raise AssertionError("relative discovery directory was accepted")

    try:
        load(str(root / "missing.json"), allow_missing=False)
    except Exception as error:
        assert type(error) is error_type
    else:
        raise AssertionError("missing explicit hub config was accepted")

    config = str(root / "config" / "clilane" / "hub.json")
    assert "Install Codex, Kimi, or Claude" in notice(
        config, config_present=False, config_required=False
    )
    default_notice = notice(config, config_present=True, config_required=False)
    assert "Config disables discovery" in default_notice
    assert "Remove it" in default_notice
    assert "Install Codex, Kimi, or Claude" not in default_notice
    explicit_notice = notice(config, config_present=True, config_required=True)
    assert "Add agent presets" in explicit_notice
    assert "Remove it" not in explicit_notice


def _exercise_hub_lifecycle(environment: dict[str, str]) -> None:
    terminal: _Terminal | None = None
    outer_terminal: _Terminal | None = None
    reopened: subprocess.Popen[bytes] | None = None
    outer_socket = f"outer-{os.getpid()}"
    escape_session = f"escape-{os.getpid()}"
    recursive_session = f"recursive-{os.getpid()}"
    try:
        terminal = _Terminal([], environment)
        terminal.expect("This clilane server")
        handshake_mark = terminal.mark()
        terminal.send(b"\x15")
        terminal.expect("> ▏", handshake_mark)
        clients = _tmux(
            environment,
            ["list-clients", "-F", "#{client_name}|#{client_pid}"],
        ).stdout.decode().splitlines()
        assert len(clients) == 1, clients
        client, _ = clients[0].split("|", 1)
        _close_hub_pane(environment, client)
        assert terminal.wait(5.0) == 0
        terminal.close()
        terminal = None

        deadline = time.monotonic() + 5.0
        while _hub_context_counts(environment) != (0, 0):
            if time.monotonic() >= deadline:
                raise AssertionError("pane-loss cleanup left a hub context behind")
            time.sleep(0.05)
        assert _hub_popup_count(environment) == 0
        assert _hub_sessions(environment) == set()

        terminal = _Terminal([], environment)
        terminal.expect("This clilane server")
        clients = _tmux(
            environment,
            ["list-clients", "-F", "#{client_name}|#{client_pid}"],
        ).stdout.decode().splitlines()
        assert len(clients) == 1, clients
        client, client_pid = clients[0].split("|", 1)
        original_values = _hub_popup_values(environment)
        assert len(original_values) == 1, original_values
        original_popup = original_values[0]
        old_pid, old_context, old_generation, backend = original_popup.split(":")
        assert old_pid == client_pid and backend == "pane"
        original_session = "hub_" + old_generation
        original_pane = _hub_pane_info(environment, original_session)
        repeated = _run(
            environment,
            ["__hub-open", client, original_session, client_pid, ""],
        )
        assert repeated.returncode == 0
        assert _hub_popup_values(environment) == original_values
        assert _hub_pane_info(environment, original_session)[:3] == original_pane[:3]
        redraw_mark = terminal.mark()
        reopened = subprocess.Popen(
            [str(CLILANE), "__hub-open", client, original_session, client_pid, old_context],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 5.0
        current_values = original_values
        while current_values == original_values:
            if reopened.poll() is not None:
                stdout, stderr = reopened.communicate()
                raise AssertionError(
                    "overlapping hub open exited before taking ownership\n"
                    + stdout.decode(errors="replace")
                    + stderr.decode(errors="replace")
                )
            if time.monotonic() >= deadline:
                raise AssertionError("overlapping hub open did not take ownership")
            time.sleep(0.05)
            current_values = _hub_popup_values(environment)
        assert len(current_values) == 1, current_values
        current_popup = current_values[0]
        terminal.expect("This clilane server", redraw_mark)
        handshake_mark = terminal.mark()
        terminal.send(b"\x15")
        terminal.expect("> ▏", handshake_mark)
        for callback in ("finish_hub_popup", "finish_hub_pane"):
            _call_clilane_function(
                environment, callback,
                [client, client_pid, old_context, old_generation],
            )
        assert _hub_popup_values(environment) == [current_popup]
        assert _hub_context_counts(environment) == (1, 1)
        assert terminal.running()
        current_pid, current_context, current_generation, backend = current_popup.split(":")
        assert current_pid == client_pid
        assert backend == "pane" and current_generation != old_generation
        assert current_context == old_context

        created = _tmux(
            environment,
            ["new-session", "-d", "-s", escape_session, "--", "/bin/cat"],
        )
        assert created.returncode == 0, created.stderr.decode(errors="replace")
        switched = _tmux(
            environment,
            ["switch-client", "-E", "-c", client, "-t", escape_session],
        )
        assert switched.returncode == 0, switched.stderr.decode(errors="replace")
        stdout, stderr = reopened.communicate(timeout=5)
        assert reopened.returncode == 0, stderr.decode(errors="replace")
        reopened = None
        attached = _tmux(
            environment,
            ["list-clients", "-F", "#{client_name}|#{client_session}"],
        ).stdout.decode().splitlines()
        assert attached == [f"{client}|{escape_session}"], attached
        assert terminal.running()
        assert _hub_popup_count(environment) == 0
        assert _hub_sessions(environment) == set()
        assert _hub_context_counts(environment) == (1, 1)
        detached = _tmux(environment, ["detach-client", "-t", client])
        assert detached.returncode == 0, detached.stderr.decode(errors="replace")
        assert terminal.wait() == 0
        terminal.close()
        terminal = None
        deadline = time.monotonic() + 5.0
        while _hub_context_counts(environment) != (0, 0):
            if time.monotonic() >= deadline:
                raise AssertionError("switched client context was not removed")
            time.sleep(0.05)
        _tmux(environment, ["kill-session", "-t", escape_session])

        terminal = _Terminal([], environment)
        terminal.expect("This clilane server")
        deadline = time.monotonic() + 5.0
        standby = b""
        while b"Switcher inactive" not in standby:
            captured = _tmux(environment, ["capture-pane", "-p", "-t", "hub"])
            assert captured.returncode == 0, captured.stderr.decode(errors="replace")
            standby = captured.stdout
            if time.monotonic() >= deadline:
                raise AssertionError(
                    "hub backing pane did not show the standby surface:\n"
                    + standby.decode(errors="replace")
                )
            time.sleep(0.05)
        assert b"Ctrl-B to reopen" in standby
        pane = _tmux(
            environment,
            [
                "display-message",
                "-p",
                "-t",
                "hub",
                "#{pane_current_command}|#{pane_start_command}",
            ],
        ).stdout.decode().strip()
        current_command, start_command = pane.split("|", 1)
        assert current_command not in {
            "bash",
            "dash",
            "fish",
            "sh",
            "zsh",
        }, pane
        assert "__hub-standby" in start_command, pane
        handshake_mark = terminal.mark()
        terminal.send(b"\x15")
        terminal.expect("> ▏", handshake_mark)
        terminal.send(b"\x11")
        assert terminal.wait() == 0
        terminal.close()
        terminal = None

        target_path = _tmux(
            environment,
            ["display-message", "-p", "-t", "hub", "#{socket_path}"],
        ).stdout.decode().strip()
        assert target_path
        shell_executable = shutil.which("sh")
        tmux_executable = shutil.which("tmux")
        assert shell_executable is not None
        assert tmux_executable is not None
        before = _hub_context_counts(environment)
        recursive_output = (
            Path(environment["CLILANE_STATE_HOME"]) / "recursive-output.txt"
        )
        recursive_code = (
            Path(environment["CLILANE_STATE_HOME"]) / "recursive-code.txt"
        )
        recursive_command = (
            f"{shlex.quote(str(CLILANE))} hub >"
            f" {shlex.quote(str(recursive_output))} 2>&1; "
            f"printf '%s' $? > {shlex.quote(str(recursive_code))}; exec /bin/cat"
        )
        created = _tmux(
            environment,
            [
                "new-session",
                "-d",
                "-s",
                recursive_session,
                "-e",
                f"CLILANE_TMUX_SOCKET={environment['CLILANE_TMUX_SOCKET']}",
                "-e",
                f"CLILANE_STATE_HOME={environment['CLILANE_STATE_HOME']}",
                "-e",
                f"TMUX_TMPDIR={environment['TMUX_TMPDIR']}",
                "--",
                shell_executable,
                "-c",
                recursive_command,
            ],
        )
        assert created.returncode == 0, created.stderr.decode(errors="replace")
        deadline = time.monotonic() + 5.0
        recursive_result = ""
        while not recursive_result:
            if recursive_code.exists():
                recursive_result = recursive_code.read_text(encoding="utf-8")
                if recursive_result:
                    break
            if time.monotonic() >= deadline:
                captured = _tmux(
                    environment,
                    ["capture-pane", "-p", "-S", "-100", "-t", recursive_session],
                )
                panes = _tmux(
                    environment,
                    [
                        "list-panes",
                        "-a",
                        "-F",
                        "#{session_name}|#{pane_current_command}|#{pane_start_command}",
                    ],
                )
                raise AssertionError(
                    "same-socket recursive hub command did not finish\n"
                    + panes.stdout.decode(errors="replace")
                    + captured.stdout.decode(errors="replace")
                    + captured.stderr.decode(errors="replace")
                )
            time.sleep(0.05)
        assert recursive_result == "1"
        assert "already inside CLI Lane" in recursive_output.read_text(
            encoding="utf-8"
        )
        assert _hub_context_counts(environment) == before
        _tmux(environment, ["kill-session", "-t", recursive_session])

        outer_marker = f"outer tmux resumed {os.getpid()}"
        outer_command = (
            f"{shlex.quote(str(CLILANE))} hub; "
            f"printf '%s\\n' {shlex.quote(outer_marker)}; exec /bin/cat"
        )
        created = _tmux_on_socket(
            environment,
            outer_socket,
            [
                "new-session",
                "-d",
                "-s",
                "outer",
                shlex.join([shell_executable, "-c", outer_command]),
            ],
        )
        assert created.returncode == 0, created.stderr.decode(errors="replace")
        outer_path = _tmux_on_socket(
            environment,
            outer_socket,
            ["display-message", "-p", "-t", "outer", "#{socket_path}"],
        ).stdout.decode().strip()
        assert outer_path and outer_path != target_path
        outer_terminal = _Terminal(
            [
                "-L",
                outer_socket,
                "-f",
                "/dev/null",
                "attach-session",
                "-t",
                "outer",
            ],
            environment,
            executable=Path(tmux_executable),
        )
        outer_terminal.expect("This clilane server")
        handshake_mark = outer_terminal.mark()
        outer_terminal.send(b"\x15")
        outer_terminal.expect("> ▏", handshake_mark)
        clients = _tmux(
            environment,
            ["list-clients", "-F", "#{client_name}|#{client_pid}"],
        ).stdout.decode().splitlines()
        assert len(clients) == 1, clients
        client, _ = clients[0].split("|", 1)
        resume_mark = outer_terminal.mark()
        _close_hub_pane(environment, client)
        outer_terminal.expect(outer_marker, resume_mark)
        deadline = time.monotonic() + 5.0
        while _hub_context_counts(environment) != (0, 0):
            if time.monotonic() >= deadline:
                raise AssertionError("nested pane-loss cleanup left a context behind")
            time.sleep(0.05)
        assert _hub_popup_count(environment) == 0
        assert _hub_sessions(environment) == set()
        outer_terminal.send(b"\x02d")
        assert outer_terminal.wait() == 0
        outer_terminal.close()
        outer_terminal = None
    finally:
        if reopened is not None and reopened.poll() is None:
            reopened.terminate()
            reopened.wait(timeout=3)
        if terminal is not None:
            terminal.close()
        if outer_terminal is not None:
            outer_terminal.close()
        _tmux_on_socket(environment, outer_socket, ["kill-session", "-t", "outer"])
        _tmux(environment, ["kill-session", "-t", escape_session])
        _tmux(environment, ["kill-session", "-t", recursive_session])
        _cleanup(environment)


def _exercise_hub_launch_loss(environment: dict[str, str]) -> None:
    root = Path(environment["CLILANE_STATE_HOME"])
    for submitted in (False, True):
        mode = "submitted" if submitted else "unsubmitted"
        marker = root / f"{mode}-held.json"
        lost = root / f"{mode}-ownership-lost"
        release = root / f"{mode}-release"
        delivery = root / f"{mode}-delivery.txt"
        wrapper = root / f"{mode}-clilane"
        config = root / f"{mode}-hub.json"
        receiver = (
            "import sys\nfrom pathlib import Path\n"
            "for line in sys.stdin:\n"
            f"    with Path({str(delivery)!r}).open('a') as stream: stream.write(line)\n"
            "    print(line,end='',flush=True)\n"
        )
        config.write_text(json.dumps({
            "schema_version": 1,
            "agents": [{"name": f"held-{mode}", "command": [sys.executable, "-u", "-c", receiver], "dir": str(root)}],
        }))
        wrapper.write_text(
            f"#!{sys.executable}\n"
            "import json,runpy,time\n"
            "from pathlib import Path\n"
            f"namespace=runpy.run_path({str(CLILANE)!r},run_name='held_clilane')\n"
            "scope=namespace['main'].__globals__\n"
            "scope['__file__']=__file__\n"
            "owned=scope['hub_popup_owned']\n"
            "def observed_owned(*args):\n"
            "    result=owned(*args)\n"
            "    if not result and args[-1].endswith(':pane:launch'):\n"
            f"        Path({str(lost)!r}).touch()\n"
            "    return result\n"
            "scope['hub_popup_owned']=observed_owned\n"
            "send=scope['send_hub_prompt']\n"
            "def held_send(preset,task,prompt):\n"
            f"    if {submitted!r}: send(preset,task,prompt)\n"
            f"    marker=Path({str(marker)!r})\n"
            "    marker.with_suffix('.tmp').write_text(json.dumps({'id':task.id,'name':task.name}))\n"
            "    marker.with_suffix('.tmp').replace(marker)\n"
            "    deadline=time.monotonic()+30\n"
            f"    while not Path({str(release)!r}).exists():\n"
            "        scope['hub_launch_checkpoint']()\n"
            "        if time.monotonic()>=deadline: raise scope['CliLaneError']('held worker timed out')\n"
            "        time.sleep(0.02)\n"
            f"    if not {submitted!r}: send(preset,task,prompt)\n"
            "scope['send_hub_prompt']=held_send\n"
            "raise SystemExit(scope['main']())\n"
        )
        wrapper.chmod(0o700)
        terminal: _Terminal | None = None
        escape = f"held-escape-{mode}"
        prompt = f"owned launch {mode} {os.getpid()}"
        try:
            terminal = _Terminal(["hub", "--config", str(config)], environment, executable=wrapper)
            terminal.expect("This clilane server")
            terminal.send(prompt.encode() + b"\r")
            deadline = time.monotonic() + 10.0
            while not marker.exists():
                assert time.monotonic() < deadline, bytes(terminal.output).decode(errors="replace")
                terminal.settle(quiet=0.05, timeout=0.1)
            task = json.loads(marker.read_text())
            claim = _hub_popup_values(environment)
            assert len(claim) == 1 and claim[0].endswith(":pane:launch"), claim
            client, client_pid, source = _tmux(
                environment, ["list-clients", "-F", "#{client_name}|#{client_pid}|#{client_session}"]
            ).stdout.decode().strip().split("|")
            assert source.startswith("hub_"), source
            assert claim[0].startswith(client_pid + ":"), claim
            created = _tmux(environment, ["new-session", "-d", "-s", escape, "--", "/bin/cat"])
            assert created.returncode == 0, created.stderr
            switched = _tmux(environment, ["switch-client", "-E", "-c", client, "-t", escape])
            assert switched.returncode == 0, switched.stderr
            if submitted:
                deadline = time.monotonic() + 5.0
                while not lost.exists():
                    assert time.monotonic() < deadline, "UI did not observe ownership loss"
                    terminal.settle(quiet=0.05, timeout=0.1)
                assert source in _hub_sessions(environment), "UI exited before its submitted worker unwound"
                _wait_for_state(environment, task["name"], "running")
                logged = _run(environment, ["log", task["id"], "--lines", "50"]).stdout
                assert prompt in logged, logged
                deadline = time.monotonic() + 5.0
                while not delivery.exists() or delivery.read_text() != prompt + "\n":
                    assert time.monotonic() < deadline, "submitted prompt was not delivered exactly once"
                    time.sleep(0.05)
                release.touch()
            else:
                _wait_for_state(environment, task["name"], "stopped")
                logged = _run(environment, ["log", task["id"], "--lines", "50"]).stdout
                assert prompt not in logged, logged
                assert not delivery.exists() or delivery.read_text() == ""
            deadline = time.monotonic() + 10.0
            while _hub_sessions(environment):
                assert time.monotonic() < deadline, _hub_sessions(environment)
                terminal.settle(quiet=0.05, timeout=0.1)
            assert _hub_popup_count(environment) == 0
            assert _hub_context_counts(environment) == (1, 1)
            assert _tmux(
                environment, ["list-clients", "-F", "#{client_name}|#{client_session}"]
            ).stdout.decode().splitlines() == [f"{client}|{escape}"]
            assert terminal.running()
            if submitted:
                _wait_for_state(environment, task["name"], "running")
                assert delivery.read_text() == prompt + "\n"
            detached = _tmux(environment, ["detach-client", "-t", client])
            assert detached.returncode == 0, detached.stderr
            assert terminal.wait() == 0
            deadline = time.monotonic() + 5.0
            while _hub_context_counts(environment) != (0, 0):
                assert time.monotonic() < deadline, _hub_context_counts(environment)
                time.sleep(0.05)
        finally:
            release.touch()
            if terminal is not None:
                terminal.close()
            _tmux(environment, ["kill-session", "-t", "=" + escape])
            _cleanup(environment)


def _last_frame(terminal: _Terminal, since: int) -> str:
    sessions = _client_sessions(terminal.environment)
    assert len(sessions) == 1, sessions
    return _tmux(
        terminal.environment, ["capture-pane", "-p", "-t", sessions[0]]
    ).stdout.decode(errors="replace")


def _client_sessions(environment: dict[str, str]) -> list[str]:
    return _tmux(
        environment, ["list-clients", "-F", "#{client_session}"]
    ).stdout.decode().split()


def _wait_for_client_session(
    environment: dict[str, str], terminal: _Terminal, session: str
) -> None:
    deadline = time.monotonic() + 10.0
    while _client_sessions(environment) != [session]:
        assert time.monotonic() < deadline, _client_sessions(environment)
        terminal.settle(quiet=0.1, timeout=0.5)


def _wait_for_attached_task(
    environment: dict[str, str], terminal: _Terminal, name: str
) -> None:
    deadline = time.monotonic() + 10.0
    while True:
        tasks = _tasks(environment)
        matching = [task for task in tasks if task["name"] == name]
        if (
            len(matching) == 1
            and matching[0]["state"] == "running"
            and matching[0]["attached"]
        ):
            return
        assert time.monotonic() < deadline, tasks
        terminal.settle(quiet=0.1, timeout=0.5)


def _exercise_switcher_keys(environment: dict[str, str]) -> None:
    terminal: _Terminal | None = None
    try:
        terminal = _Terminal([], environment)
        terminal.expect("This clilane server")
        mark = terminal.mark()
        terminal.send(b"\x15")
        terminal.expect("> ▏", mark)
        terminal.send(b"\x1b[D")
        terminal.settle()
        assert terminal.running(), "Left on an empty composer detached the client"
        for keys, expected in (
            (b"alpha beta", "alpha beta▏"),
            (b"\x01X", "X▏alpha beta"),
            (b"\x05\x17", "Xalpha ▏"),
            (b"\x19", "Xalpha beta▏"),
            (b"\x1b[H\x1b[3~", "▏alpha beta"),
            (b"\x1b[F\x1bb", "alpha ▏beta"),
            (b"\x1bf\x1b[1;5D", "alpha ▏beta"),
            (b"\x1b[1;5C\x04", "alpha beta▏"),
            (b"\x1bOH\x04", "▏lpha beta"),
            (b"\x1bOF\x01\x0b", "> ▏"),
            (b"\x19", "lpha beta▏"),
        ):
            mark = terminal.mark()
            terminal.send(keys)
            terminal.expect(expected, mark)
        mark = terminal.mark()
        terminal.send(b"\x03")
        terminal.expect("Leave and discard drafts?", mark)
        mark = terminal.mark()
        terminal.send(b"\x1b\x1bOP")
        terminal.expect("KEYBOARD HELP", mark)
        assert terminal.running()
        terminal.resize(40, 10)
        terminal.send(b"\x1b[B" * 100)
        terminal.expect("Windows clients need WSL or SSH")
        mark = terminal.mark()
        terminal.send(b"\x1b")
        terminal.expect("lpha beta", mark)
        terminal.resize(100, 24)
        mark = terminal.mark()
        terminal.send(b"\x15")
        terminal.expect("> ▏", mark)
        terminal.send(b"\x04")
        assert terminal.wait() == 0
        terminal.close()

        _run(environment, ["run", "keys-job", "--", "/bin/cat"])
        job = _tasks(environment)[0]
        job_session = next(session for session in _tmux(environment, ["list-sessions", "-F", "#{session_name}"]).stdout.decode().split() if session.startswith("agt_"))
        terminal = _Terminal(["attach", "keys-job"], environment)
        _wait_for_client_session(environment, terminal, job_session)
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        mark = terminal.mark()
        terminal.send(b"keep this draft")
        terminal.expect("keep this draft", mark)
        terminal.send(b"\x1b")
        _wait_for_client_session(environment, terminal, job_session)
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("keep this draft", mark)
        assert _tasks(environment)[0]["id"] == job["id"]
        terminal.send(b"\x03")
        _wait_for_client_session(environment, terminal, job_session)
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("keep this draft", mark)
        mark = terminal.mark()
        terminal.send(b"\x11")
        terminal.expect("Leave and discard drafts?", mark)
        time.sleep(2.5)
        terminal.send(b"\r")
        assert terminal.wait() == 0
        terminal.close()
        assert _tasks(environment)[0]["state"] == "running"
        assert b"@agt_hub_drafts_" not in _tmux(environment, ["show-options", "-g"]).stdout

        terminal = _Terminal(["attach", "keys-job"], environment)
        _wait_for_client_session(environment, terminal, job_session)
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        terminal.settle()
        assert "keep this draft" not in _last_frame(terminal, mark)
        _run(environment, ["rm", "keys-job", "--force", "--grace", "0"])
        terminal.send(b"\x1b")
        assert terminal.wait() == 0
        terminal.close()
        terminal = None
    finally:
        if terminal is not None:
            terminal.close()
        _cleanup(environment)


def _wait_for_state(
    environment: dict[str, str], name: str, state: str, timeout: float = 10.0
) -> None:
    deadline = time.monotonic() + timeout
    while True:
        states = {task["name"]: task["state"] for task in _tasks(environment)}
        if states.get(name) == state:
            return
        assert time.monotonic() < deadline, states
        time.sleep(0.1)


def _exercise_switcher_actions(environment: dict[str, str]) -> None:
    terminal: _Terminal | None = None
    try:
        _run(environment, ["run", "act-job", "--", "/bin/cat"])
        _wait_for_state(environment, "act-job", "running")
        terminal = _Terminal([], environment)
        terminal.expect("This clilane server")
        mark = terminal.mark()
        terminal.send(b"\x15")
        terminal.expect("> ▏", mark)

        mark = terminal.mark()
        terminal.send(b" ")
        terminal.expect("reply · act-job", mark)
        terminal.settle()
        frame = _last_frame(terminal, mark)
        assert "act-job · open · latest output" in frame, frame
        assert "Enter open · type to reply" in frame, frame

        terminal.send(b"ping-from-switcher")
        mark = terminal.mark()
        terminal.send(b"\r")
        terminal.expect("Sent to act-job", mark)
        deadline = time.monotonic() + 10.0
        while "ping-from-switcher" not in _run(environment, ["read", "act-job"]).stdout:
            assert time.monotonic() < deadline, "reply never reached the job"
            time.sleep(0.2)
        deadline = time.monotonic() + 10.0
        while True:
            terminal.settle()
            frame = _last_frame(terminal, mark)
            if "ping-from-switcher" in frame and "> ▏" in frame:
                break
            assert time.monotonic() < deadline, frame
        assert "reply · act-job" in frame, frame

        terminal.send(b"draft")
        mark = terminal.mark()
        terminal.send(b"\x1b[B")
        terminal.expect("Reply kept with its job", mark)
        terminal.settle()
        frame = _last_frame(terminal, mark)
        assert "reply · act-job" not in frame and "draft" not in frame, frame
        terminal.send(b"\x1b[A")
        terminal.settle()
        mark = terminal.mark()
        terminal.send(b" ")
        terminal.expect("reply · act-job", mark)
        terminal.expect("draft", mark)
        terminal.send(b"\x15")

        mark = terminal.mark()
        terminal.send(b"\x1b")
        terminal.expect("Space preview", mark, timeout=5.0)
        terminal.settle()
        frame = _last_frame(terminal, mark)
        assert "reply · act-job" not in frame, frame
        assert terminal.running(), "Esc with an open peek detached the client"

        mark = terminal.mark()
        terminal.send(b"\x18")
        terminal.expect("Stop act-job?", mark)
        terminal.send(b"z")
        terminal.settle()
        mark = terminal.mark()
        terminal.send(b"\x15\x1b[A")
        terminal.settle()
        assert "Stop act-job?" not in _last_frame(terminal, mark), "typing did not disarm Ctrl-X"
        assert _tasks(environment)[0]["state"] == "running"

        mark = terminal.mark()
        terminal.send(b"\x18")
        terminal.expect("Stop act-job?", mark)
        time.sleep(2.5)
        mark = terminal.mark()
        terminal.send(b"\r")
        terminal.expect("Stopped act-job", mark, timeout=20.0)
        _wait_for_state(environment, "act-job", "stopped")

        mark = terminal.mark()
        terminal.send(b"\x18")
        terminal.expect("Remove act-job?", mark)
        mark = terminal.mark()
        terminal.send(b"\r")
        terminal.expect("Removed act-job", mark, timeout=20.0)
        assert _tasks(environment) == [], _tasks(environment)

        mark = terminal.mark()
        terminal.send(b"\x18")
        terminal.expect("Select a job to stop or remove", mark)
        mark = terminal.mark()
        terminal.send(b" ")
        terminal.expect("Select a job to peek", mark)
        terminal.send(b"\x11")
        assert terminal.wait() == 0
        terminal.close()
        terminal = None
    finally:
        if terminal is not None:
            terminal.close()
        _cleanup(environment)


def _exercise_switcher_resume(environment: dict[str, str]) -> None:
    terminal: _Terminal | None = None
    try:
        _run(
            environment,
            ["run", "res-job", "--", "/bin/sh", "-c", "echo first-run-output; exit 0"],
        )
        _wait_for_state(environment, "res-job", "succeeded")
        first_id = _tasks(environment)[0]["id"]
        terminal = _Terminal([], environment)
        terminal.expect("This clilane server")
        mark = terminal.mark()
        terminal.send(b"\x15")
        terminal.expect("> ▏", mark)

        mark = terminal.mark()
        terminal.send(b" ")
        terminal.expect("res-job · succeeded · last output", mark)
        terminal.expect("first-run-output", mark)
        terminal.settle()
        frame = _last_frame(terminal, mark)
        assert "Ctrl-R rerun" in frame, frame
        assert "Enter send" not in frame, frame
        assert terminal.running(), "Space on a finished job left the switcher"

        mark = terminal.mark()
        terminal.send(b"\x12")
        deadline = time.monotonic() + 15.0
        while True:
            tasks = _tasks(environment)
            if len(tasks) == 2 and any(task["id"] != first_id for task in tasks):
                break
            assert time.monotonic() < deadline, tasks
            time.sleep(0.2)
        resumed = next(task for task in tasks if task["id"] != first_id)
        assert resumed["name"] == "res-job-2", resumed
        assert resumed["command"] == ["/bin/sh", "-c", "echo first-run-output; exit 0"], resumed
        _wait_for_state(environment, resumed["name"], "succeeded")
        original_log = _run(environment, ["log", first_id, "--lines", "50"]).stdout
        resumed_log = _run(environment, ["log", resumed["id"], "--lines", "50"]).stdout
        assert original_log.count("first-run-output") == 1, original_log
        assert resumed_log.count("first-run-output") == 1, resumed_log
        history = json.loads(_run(environment, ["history", "--json"]).stdout)
        assert next(task for task in history if task["id"] == resumed["id"])["resumed_from"] == first_id
        terminal.close()
        terminal = None

        _run(environment, ["run", "live-job", "--", "/bin/cat"])
        _wait_for_state(environment, "live-job", "running")
        terminal = _Terminal([], environment)
        terminal.expect("This clilane server")
        mark = terminal.mark()
        terminal.send(b"\x15")
        terminal.expect("> ▏", mark)
        mark = terminal.mark()
        terminal.send(b"\x12")
        terminal.expect("live-job is still running", mark)
        terminal.send(b"\x11")
        assert terminal.wait() == 0
        terminal.close()
        terminal = None
    finally:
        if terminal is not None:
            terminal.close()
        _cleanup(environment)


def _exercise_shell_access(environment: dict[str, str], root: Path) -> None:
    environment = dict(environment, SHELL="/bin/sh")
    tool_dir = root / "shell-agent"
    tool_dir.mkdir()
    provider = tool_dir / "codex"
    subprocess.run(
        ["cc", "-x", "c", "-o", str(provider), "-"],
        input="#include <unistd.h>\nint main(void) { for (;;) pause(); }\n",
        text=True, check=True, capture_output=True,
    )
    terminal: _Terminal | None = None
    try:
        _run(environment, ["run", "busy-shell", "-C", str(root), "--", "/bin/sh", "-i"])
        original = _tasks(environment)[0]
        original_session = "agt_" + str(original["id"]).replace("-", "")[:12]
        _run(environment, ["rename", str(original["id"]), "Pinned shell"])
        terminal = _Terminal(["attach", str(original["id"])], environment)
        terminal.expect("LOCAL · Pinned shell")
        mark = terminal.mark()
        terminal.send(shlex.quote(str(provider)).encode() + b"\r")
        terminal.expect("codex*", mark)
        terminal.expect("codex* · open", mark)
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        terminal.expect("New shell", mark)
        terminal.send(b"\x1b[A\r")
        terminal.expect("LOCAL · Shell ·", mark)
        tasks = _tasks(environment)
        assert len(tasks) == 2, tasks
        fresh = next(task for task in tasks if task["id"] != original["id"])
        assert fresh["cwd"] == str(root.resolve()), fresh
        assert next(task for task in tasks if task["id"] == original["id"])["pid"] == original["pid"]
        foreground = _tmux(environment, ["display-message", "-p", "-t", original_session, "#{pane_current_command}"]).stdout.decode().strip()
        assert foreground == "codex", foreground
        mark = terminal.mark()
        terminal.send(b"printf 'fresh-shell-marker\\n'\r")
        terminal.expect("fresh-shell-marker", mark)
        old_output = _tmux(environment, ["capture-pane", "-p", "-t", original_session]).stdout.decode()
        assert "fresh-shell-marker" not in old_output, old_output
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        terminal.send(b"\x1b[A\r")
        deadline = time.monotonic() + 10
        while len(_tasks(environment)) != 3:
            assert time.monotonic() < deadline
            time.sleep(0.1)
        terminal.settle()
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        terminal.send(b"\x1b[B\x1b[B\r")
        terminal.expect("LOCAL · Pinned shell", mark)
        terminal.expect("codex*", mark)
        terminal.send(b"\x03")
        deadline = time.monotonic() + 5
        while _tmux(environment, ["display-message", "-p", "-t", original_session, "#{pane_current_command}"]).stdout.decode().strip() == "codex":
            assert time.monotonic() < deadline
            time.sleep(0.1)
        socket = _tmux(environment, ["display-message", "-p", "#{socket_path}"]).stdout.decode().strip()
        status = _run(environment, ["__hub-status", str(Path(shutil.which("tmux")).resolve()), socket, original_session, "180"]).stdout
        assert "Pinned shell" in status and "codex*" not in status, status
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        terminal.send(b"\x11")
        assert terminal.wait() == 0
    finally:
        if terminal is not None:
            terminal.close()
        _cleanup(environment)


def _exercise_saved_history(environment: dict[str, str]) -> None:
    terminal: _Terminal | None = None
    original_id = ""
    try:
        _run(environment, ["run", "saved-job", "--wait", "--", "/bin/echo", "saved-output-preview"])
        original_id = str(_tasks(environment)[0]["id"])
        session = "agt_" + original_id.replace("-", "")[:12]
        _tmux(environment, ["kill-session", "-t", session])
        terminal = _Terminal([], environment)
        terminal.expect("This clilane server")
        terminal.expect(original_id[:8])
        clients = _tmux(environment, ["list-clients", "-F", "#{client_session}"]).stdout
        mark = terminal.mark()
        terminal.send(b"\r")
        terminal.expect("saved-output-preview", mark)
        terminal.expect("saved log", mark)
        assert _tmux(environment, ["list-clients", "-F", "#{client_session}"]).stdout == clients
        mark = terminal.mark()
        terminal.send(b"\x12")
        terminal.expect("saved-output-preview", mark)
        deadline = time.monotonic() + 10
        while True:
            history = json.loads(_run(environment, ["history", "--json"]).stdout)
            resumed = next((task for task in history if task["resumed_from"] == original_id), None)
            if resumed is not None and resumed["terminal_available"] and resumed["state"] == "succeeded" and any(
                task["id"] == resumed["id"] and task["attached"] for task in _tasks(environment)
            ):
                break
            assert time.monotonic() < deadline, (
                history, _last_frame(terminal, mark),
                json.loads((Path(environment["CLILANE_STATE_HOME"]) / "history" / f"{original_id}.json").read_text()),
            )
            terminal.settle(quiet=0.1, timeout=0.5)
        assert any(task["id"] == original_id and not task["terminal_available"] for task in history), history
        terminal.close()
        terminal = None
        _cleanup(environment)
        (Path(environment["CLILANE_STATE_HOME"]) / "history" / f"{original_id}.json").unlink()
        terminal = _Terminal([], environment)
        terminal.expect("This clilane server")
        terminal.expect("unknown")
        mark = terminal.mark()
        terminal.send(b"\x12")
        terminal.expect("Recovery unavailable: job outcome or cleanup unknown", mark)
        terminal.settle()
        assert not _tasks(environment)
        mark = terminal.mark()
        terminal.send(b"\r")
        terminal.expect("saved-output-preview", mark)
        terminal.send(b"\x11")
        assert terminal.wait() == 0
    finally:
        if terminal is not None:
            terminal.close()
        _cleanup(environment)
        if original_id:
            _run(environment, ["rm", original_id], check=False)


def _exercise_switcher_sections(environment: dict[str, str], tool_bin: Path) -> None:
    terminal: _Terminal | None = None
    fake_claude = tool_bin / "claude"
    fake_claude.write_text("#!/bin/sh\nprintf 'fake-claude args:%s\\n' \"$*\"\nexit 0\n")
    fake_claude.chmod(0o700)
    environment = dict(environment)
    environment["CLILANE_HUB_HISTORY"] = "2"
    try:
        for name in ("hist-1", "hist-2", "hist-3"):
            _run(environment, ["run", name, "--", "/bin/sh", "-c", f"echo {name}; exit 0"])
            _wait_for_state(environment, name, "succeeded")
        _run(environment, ["run", "agent-job", "--", str(fake_claude)])
        _wait_for_state(environment, "agent-job", "succeeded")
        _run(environment, ["run", "live-1", "--", "/bin/cat"])
        _wait_for_state(environment, "live-1", "running")

        terminal = _Terminal([], environment)
        terminal.expect("This clilane server")
        mark = terminal.mark()
        terminal.send(b"\x15")
        terminal.expect("> ▏", mark)
        terminal.settle()
        frame = _last_frame(terminal, mark)
        assert "ONGOING (1)" in frame, frame
        assert "HISTORY (showing 2 of 4)" in frame, frame
        assert "… 2 more · ↓ to reveal" in frame, frame
        assert "agent-job" in frame and "hist-3" in frame, frame
        assert "hist-2" not in frame and "hist-1" not in frame, frame

        terminal.send(b"\x1b[B\x1b[B")
        terminal.settle()
        mark = terminal.mark()
        terminal.send(b"\x1b[B")
        terminal.expect("HISTORY (4)", mark)
        terminal.settle()
        frame = _last_frame(terminal, mark)
        assert "hist-2" in frame and "hist-1" in frame, frame
        assert "more · ↓ to reveal" not in frame, frame

        terminal.send(b"\x1b[B")
        terminal.settle()
        sessions = _tmux(
            environment, ["list-sessions", "-F", "#{session_name}"]
        ).stdout.decode().split()
        before = {session for session in sessions if session.startswith("agt_")}
        mark = terminal.mark()
        terminal.send(b"\r")
        terminal.expect("Pane is dead", mark)
        assert terminal.running(), "Enter on a finished plain job left the client"
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        assert {
            session for session in
            _tmux(environment, ["list-sessions", "-F", "#{session_name}"])
            .stdout.decode().split()
            if session.startswith("agt_")
        } == before, "opening a finished plain job changed the task session set"

        mark = terminal.mark()
        terminal.send(b"\x15")
        terminal.expect("> ▏", mark)
        terminal.send(b"\x1b[A\x1b[A\x1b[A")
        terminal.settle()
        mark = terminal.mark()
        terminal.send(b" ")
        terminal.expect("agent-job · succeeded · last output", mark)
        terminal.expect("Ctrl-R resume", mark)
        terminal.resize(40, 10)
        terminal.expect("Ctrl-R latest (project)", mark)
        terminal.resize(100, 24)
        terminal.settle()
        agent_id = next(task["id"] for task in _tasks(environment) if task["name"] == "agent-job")
        mark = terminal.mark()
        terminal.send(b"\r")
        terminal.expect("LOCAL · agent-job", mark)
        terminal.settle()
        assert next(task["id"] for task in _tasks(environment) if task["name"] == "agent-job") == agent_id
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        terminal.send(b"\x12")
        deadline = time.monotonic() + 15.0
        while True:
            entries = {task["name"]: task for task in _tasks(environment)}
            resumed = entries.get("agent-job-2")
            if resumed is not None and entries["agent-job"]["id"] == agent_id:
                break
            assert time.monotonic() < deadline, entries
            time.sleep(0.2)
        assert resumed["command"] == [str(fake_claude), "--continue"], resumed
        _wait_for_state(environment, resumed["name"], "succeeded")
        logged = _run(environment, ["log", resumed["id"], "--lines", "50"]).stdout
        assert "fake-claude args:--continue" in logged, logged
        terminal.close()
        terminal = None
    finally:
        if terminal is not None:
            terminal.close()
        _cleanup(environment)


def _exercise_keyboard_portability(environment: dict[str, str], root: Path) -> None:
    tool_bin = root / "keyboard-tools"
    tool_bin.mkdir(mode=0o700)
    raw_agent = tool_bin / "omp"
    received = tool_bin / "received"
    raw_agent.write_text(
        f"#!{sys.executable}\nimport os,tty\ntty.setraw(0)\nprint('READY',flush=True)\n"
        f"with open({str(received)!r},'ab',buffering=0) as f:\n"
        " while True: f.write(os.read(0,1024))\n"
    )
    raw_agent.chmod(0o700)
    terminal: _Terminal | None = None
    try:
        _run(environment, ["run", "portable-omp", "--", str(raw_agent)])
        _run(environment, ["run", "portable-other", "--", "/bin/cat"])
        terminal = _Terminal(["attach", "portable-omp"], environment)
        terminal.expect("READY")
        native = b"\x11\x03\x04\x18\x12\x1b[D"
        terminal.send(native)
        deadline = time.monotonic() + 5.0
        expected = native
        while not received.exists() or received.read_bytes() != expected:
            assert time.monotonic() < deadline, received.read_bytes() if received.exists() else b""
            terminal.settle()
        for key in ("C-q", "C-Tab", "C-BTab", "C-PPage", "C-NPage"):
            assert not _tmux(environment, ["list-keys", "-T", "root", key]).stdout.strip()
        assert _tmux(environment, ["show-options", "-gv", "prefix"]).stdout.strip() == b"None"
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        terminal.send(b"\x02")
        _wait_for_attached_task(environment, terminal, "portable-omp")
        deadline = time.monotonic() + 5.0
        while received.read_bytes() != native + b"\x02":
            assert time.monotonic() < deadline, received.read_bytes()
            terminal.settle()
        terminal.settle()
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        mark = terminal.mark()
        terminal.send(b"\x1b[A\r")
        terminal.expect("LOCAL · portable-other", mark)
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        mark = terminal.mark()
        terminal.send(b"\x1b[B\r")
        terminal.expect("LOCAL · portable-omp", mark)
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        terminal.resize(24, 8)
        mark = terminal.mark()
        terminal.send(b"\x1b[B\x1b[B\r")
        terminal.expect("KEYBOARD HELP", mark)
        mark = terminal.mark()
        terminal.send(b"\x1b")
        terminal.expect("CLI LANE", mark)
        terminal.resize(100, 24)
        mark = terminal.mark()
        terminal.send(b"\x1b[A\x1b[A\x1b[A\r")
        terminal.expect("LOCAL · portable-other", mark)
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        mark = terminal.mark()
        terminal.send(b"saved while reading help\x1b[B\r")
        terminal.expect("KEYBOARD HELP", mark)
        mark = terminal.mark()
        terminal.send(b"\x1b")
        terminal.expect("This clilane server", mark)
        mark = terminal.mark()
        terminal.send(b"\x1b[B\r")
        terminal.expect("Leave and discard drafts?", mark)
        terminal.resize(20, 4)
        mark = terminal.mark()
        terminal.send(b"\x11")
        terminal.expect("Enter yes", mark)
        terminal.send(b"\r")
        assert terminal.wait() == 0
        assert all(task["state"] == "running" for task in _tasks(environment))
        terminal.close()
        terminal = None

        terminal = _Terminal(["attach", "portable-other"], environment)
        _wait_for_attached_task(environment, terminal, "portable-other")
        terminal.resize(20, 4)
        terminal.send(b"\x02")
        terminal.expect("Ctrl-Q leave")
        terminal.send(b"\x11")
        assert terminal.wait() == 0
        terminal.close()

        terminal = _Terminal(["attach", "portable-other"], environment)
        _wait_for_attached_task(environment, terminal, "portable-other")
        terminal.send(b"\x02")
        terminal.expect("This clilane server")
        for label, expected in (("?  Help", "KEYBOARD HELP"), ("Leave CliLane ·", None)):
            session = _client_sessions(environment)[0]
            frame = _tmux(environment, ["capture-pane", "-p", "-t", session]).stdout.decode().splitlines()
            row = next(index + 1 for index, line in enumerate(frame) if label in line)
            mark = terminal.mark()
            terminal.send(f"\x1b[<0;3;{row}M\x1b[<0;3;{row}m".encode())
            if expected is not None:
                terminal.expect(expected, mark)
                mark = terminal.mark()
                terminal.send(b"\x1b")
                terminal.expect("This clilane server", mark)
            else:
                assert terminal.wait() == 0
        terminal.close()
        terminal = None
        assert all(task["state"] == "running" for task in _tasks(environment))
    finally:
        if terminal is not None:
            terminal.close()
        _cleanup(environment)


def _exercise_agent_ux(environment: dict[str, str], root: Path) -> None:
    tool_dir = root / "agent-ux-tools"
    tool_dir.mkdir(mode=0o700)
    agent = tool_dir / "kiro-cli"
    received = tool_dir / "argv.json"
    submitted = tool_dir / "submitted.json"
    blocked = tool_dir / "blocked"
    unexpected = tool_dir / "unexpected-input"
    agent.write_text(
        f"#!{sys.executable}\nimport json,os,select,signal,sys,tty\n"
        f"open({str(received)!r},'w').write(json.dumps(sys.argv[1:]))\n"
        "tty.setraw(0)\npasted=False\n"
        f"while os.path.exists({str(blocked)!r}):\n"
        " ready,_,_=select.select([0],[],[],0.05)\n"
        f" if ready: open({str(unexpected)!r},'ab').write(os.read(0,1024))\n"
        "def draw(*_):\n"
        " if pasted: return\n"
        " screen='\\x1b[0m\\x1b[H\\x1b[2J'+'─'*os.get_terminal_size().columns\n"
        " screen+='\\r\\nkiro_default · model · ◔ 3%\\r\\n\\r\\n'\n"
        " screen+='›  \\x1b[38;5;247mask a question or describe a task ↵\\r\\n'\n"
        " screen+='/copy to clipboard\\x1b[0m\\x1b[4;3H\\x1b[?25h\\x1b[?2004h'\n"
        " os.write(1,screen.encode())\n"
        "signal.signal(signal.SIGWINCH,draw)\ndraw()\n"
        "data=b''\n"
        "while not data.endswith(b'\\x1b[201~'): data+=os.read(0,1)\n"
        "assert data.startswith(b'\\x1b[200~')\npasted=True\n"
        "prompt=data[6:-6].decode().replace('\\r','\\n')\n"
        "os.write(1,('\\x1b[0m\\x1b[H\\x1b[2J› '+prompt.replace('\\n','\\r\\n')).encode())\n"
        "count=0\n"
        "while True:\n"
        " key=os.read(0,1)\n"
        " if key==b'\\r':\n"
        "  count+=1\n"
        f"  open({str(submitted)!r},'w').write(json.dumps({{'prompt':prompt,'count':count}}))\n"
        "  os.write(1,b'\\r\\nAGENT-UX-SUBMITTED')\n"
    )
    agent.chmod(0o700)
    command = [str(agent), "chat", "--model", "auto"]
    config = tool_dir / "hub.json"
    config.write_text(json.dumps({"schema_version": 1, "agents": [
        {"name": "kiro-cli", "command": command, "dir": str(tool_dir)}
    ]}))
    terminal: _Terminal | None = None
    try:
        blocked.touch()
        terminal = _Terminal(["hub", "--config", str(config)], environment)
        terminal.expect("This clilane server")
        terminal.send(b"keep this draft\r")
        deadline = time.monotonic() + 5
        while not received.exists():
            assert time.monotonic() < deadline, "blocked launch did not start"
            terminal.settle(quiet=0.05, timeout=0.1)
        terminal.settle(quiet=0.3, timeout=0.5)
        assert not unexpected.exists(), "initial message reached an unrecognized editor"
        mark = terminal.mark()
        terminal.send(b"\x03")
        terminal.expect("Launch cancelled", mark)
        terminal.expect("keep this draft", mark)
        assert not unexpected.exists() and not submitted.exists()
        assert all(task["state"] != "running" for task in _tasks(environment))
        for task in _tasks(environment):
            _run(environment, ["rm", task["id"]])
        blocked.unlink()
        received.unlink()
        terminal.send(b"\x15")
        prompt = '--literal "quoted" $value `text`\nsecond line'
        terminal.send(b"\x1b[200~" + prompt.encode() + b"\x1b[201~\r")
        terminal.expect("AGENT-UX-SUBMITTED")
        assert json.loads(received.read_text()) == command[1:]
        assert json.loads(submitted.read_text()) == {"prompt": prompt, "count": 1}
        task = _tasks(environment)[0]
        assert task["command"] == command
        assert prompt not in json.dumps(task)
        pane = _tmux(environment, ["list-panes", "-a", "-F", "#{pane_id}|#{@agt_ready}"]).stdout.decode()
        target = next(line.split("|")[0] for line in pane.splitlines() if line.endswith("|" + task["id"]))
        launched = _tmux(environment, ["display-message", "-p", "-t", target, "#{pane_start_command}"]).stdout.decode()
        assert prompt not in launched
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("Leave CliLane", mark)
        terminal.send(b"\x11")
        assert terminal.wait() == 0
        terminal.close()
        terminal = None
        _run(environment, ["stop", task["id"], "--grace", "0"])
        received.unlink()
        submitted.unlink()
        _run(environment, ["run", "fresh-start", "--", *command])
        deadline = time.monotonic() + 5
        while not received.exists():
            assert time.monotonic() < deadline, "fresh launch did not start"
            time.sleep(0.05)
        assert json.loads(received.read_text()) == command[1:]
        time.sleep(0.3)
        assert not submitted.exists(), "initial question was replayed on a fresh launch"
    finally:
        if terminal is not None:
            terminal.close()
        _cleanup(environment)

    cases = json.loads((ROOT / "tests/fixtures/navigation/native-prompts.json").read_text())
    for case in cases:
        if case["state"] not in {"empty", "startup", "model-picker", "multiline"}:
            continue
        for hidden in ([False, True] if case["expected"] else [False]):
            frame = tool_dir / "frame.json"
            keys = tool_dir / "keys"
            keys.write_bytes(b"")
            frame.write_text(json.dumps(case))
            agent = tool_dir / case["agent"]
            cursor_sequence = "\x1b[?25l" if hidden else "\x1b[?25h"
            agent.write_text(
                f"#!{sys.executable}\nimport json,os,signal,tty\ntty.setraw(0)\n"
                f"v=json.load(open({str(frame)!r}))\n"
                "screen='\\x1b[0m\\x1b[H\\x1b[2J'+'\\r\\n'.join(v['rows'])\n"
                "screen+=f\"\\x1b[{v['row']+1};{v['cursor']+1}H\"\n"
                f"screen+={cursor_sequence!r}\n"
                "signal.signal(signal.SIGWINCH,lambda *_: os.write(1,screen.encode()))\n"
                "os.write(1,screen.encode())\n"
                f"with open({str(keys)!r},'ab',buffering=0) as out:\n"
                " while True: out.write(os.read(0,1024))\n"
            )
            agent.chmod(0o700)
            terminal = None
            try:
                _run(environment, ["run", "arrow-source", "--", str(agent)])
                _run(environment, ["run", "arrow-target", "--", "/bin/cat"])
                terminal = _Terminal(["attach", "arrow-source"], environment)
                _wait_for_attached_task(environment, terminal, "arrow-source")
                terminal.settle(quiet=0.3, timeout=1)
                terminal.send(b"\x1b[D")
                if case["expected"] and not hidden:
                    _wait_for_attached_task(environment, terminal, "arrow-target")
                    assert not keys.read_bytes()
                else:
                    deadline = time.monotonic() + 5
                    while not keys.read_bytes():
                        assert time.monotonic() < deadline, (case["agent"], case["state"], hidden)
                        terminal.settle(quiet=0.05, timeout=0.1)
                    assert keys.read_bytes() == b"\x1b[D"
                    _wait_for_attached_task(environment, terminal, "arrow-source")
            finally:
                if terminal is not None:
                    terminal.close()
                _cleanup(environment)


def _exercise_terminfo(environment: dict[str, str], terminfo_dir: Path) -> None:
    terminal: _Terminal | None = None
    source = subprocess.run(
        ["infocmp", "-x", "xterm-256color"], capture_output=True, text=True, check=True
    ).stdout
    name = "xterm-clilanetest"
    entry = source.replace("xterm-256color|", f"{name}|", 1)
    compiled = subprocess.run(
        ["tic", "-x", "-o", str(terminfo_dir), "-"],
        input=entry,
        capture_output=True,
        text=True,
    )
    assert compiled.returncode == 0, compiled.stderr
    exotic = {**environment, "TERM": name, "TERMINFO": str(terminfo_dir)}
    unresolved = {
        **environment,
        "TERM": name,
        "CLILANE_TMUX_SOCKET": environment["CLILANE_TMUX_SOCKET"] + "-none",
    }
    _exercise_terminfo_case(exotic, name, expect_notice=False)
    _exercise_terminfo_case(unresolved, name, expect_notice=True)


def _exercise_terminfo_case(
    environment: dict[str, str], name: str, *, expect_notice: bool
) -> None:
    terminal: _Terminal | None = None
    notice = f"cannot find terminfo for {name}"
    try:
        terminal = _Terminal(["run", "ti-job", "--", "/bin/cat"], environment)
        assert terminal.wait() == 0, "run from an interactive terminal failed"
        terminal.close()
        terminal = _Terminal(["ps"], environment)
        terminal.expect("ti-job")
        assert terminal.wait() == 0, "ps from an interactive terminal failed"
        terminal.close()
        _wait_for_state(environment, "ti-job", "running")

        job_session = next(
            session
            for session in _tmux(environment, ["list-sessions", "-F", "#{session_name}"])
            .stdout.decode()
            .split()
            if session.startswith("agt_")
        )
        terminal = _Terminal(["attach", "ti-job"], environment)
        if expect_notice:
            terminal.expect(notice)
        _wait_for_client_session(environment, terminal, job_session)
        mark = terminal.mark()
        terminal.send(b"\x02")
        terminal.expect("This clilane server", mark)
        terminal.send(b"\x11")
        assert terminal.wait() == 0
        terminal.close()

        terminal = _Terminal([], environment)
        if expect_notice:
            terminal.expect(notice)
        terminal.expect("This clilane server")
        transcript = bytes(terminal.output).decode(errors="replace")
        assert (notice in transcript) == expect_notice, transcript[-600:]
        terminal.send(b"\x11")
        assert terminal.wait() == 0
        terminal.close()
        terminal = None
    finally:
        if terminal is not None:
            terminal.close()
        _cleanup(environment)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="clp-", dir="/tmp") as temporary:
        root = Path(temporary)
        config_dir = root / "config" / "clilane"
        state_dir = root / "state"
        tmux_dir = root / "tmux"
        for directory in (config_dir, state_dir, tmux_dir):
            directory.mkdir(parents=True, mode=0o700)
        environment = {
            key: value
            for key, value in os.environ.items()
            if key
            in {
                "HOME",
                "LANG",
                "LC_ALL",
                "LOGNAME",
                "PATH",
                "SHELL",
                "TMPDIR",
                "USER",
            }
        }
        environment.update(
            {
                "CI_HUB_ENV": "adopted",
                "CLILANE_STATE_HOME": str(state_dir),
                "CLILANE_TMUX_SOCKET": f"clp-{os.getpid()}",
                "TERM": "xterm-256color",
                "TMUX_TMPDIR": str(tmux_dir),
                "XDG_CONFIG_HOME": str(root / "config"),
            }
        )
        _exercise_discovery_helpers(root)
        lifecycle_environment = dict(environment)
        lifecycle_state = root / "lifecycle-state"
        lifecycle_state.mkdir(mode=0o700)
        lifecycle_environment["CLILANE_STATE_HOME"] = str(lifecycle_state)
        lifecycle_environment["CLILANE_TMUX_SOCKET"] = f"clp-life-{os.getpid()}"
        _exercise_hub_lifecycle(lifecycle_environment)
        _exercise_hub_launch_loss(lifecycle_environment)
        keys_environment = dict(environment)
        keys_state = root / "keys-state"
        keys_state.mkdir(mode=0o700)
        keys_environment["CLILANE_STATE_HOME"] = str(keys_state)
        keys_environment["CLILANE_TMUX_SOCKET"] = f"clp-keys-{os.getpid()}"
        _exercise_switcher_keys(keys_environment)
        _exercise_keyboard_portability(keys_environment, root)
        _exercise_agent_ux(keys_environment, root)
        actions_environment = dict(environment)
        actions_state = root / "actions-state"
        actions_state.mkdir(mode=0o700)
        actions_environment["CLILANE_STATE_HOME"] = str(actions_state)
        actions_environment["CLILANE_TMUX_SOCKET"] = f"clp-actions-{os.getpid()}"
        _exercise_switcher_actions(actions_environment)
        resume_environment = dict(environment)
        resume_state = root / "resume-state"
        resume_state.mkdir(mode=0o700)
        resume_environment["CLILANE_STATE_HOME"] = str(resume_state)
        resume_environment["CLILANE_TMUX_SOCKET"] = f"clp-resume-{os.getpid()}"
        _exercise_switcher_resume(resume_environment)
        shell_environment = dict(environment)
        shell_environment["CLILANE_STATE_HOME"] = str(root / "shell-state")
        shell_environment["CLILANE_TMUX_SOCKET"] = f"clp-shell-{os.getpid()}"
        _exercise_shell_access(shell_environment, root)
        history_environment = dict(environment)
        history_environment["CLILANE_STATE_HOME"] = str(root / "saved-history-state")
        history_environment["CLILANE_TMUX_SOCKET"] = f"clp-saved-history-{os.getpid()}"
        _exercise_saved_history(history_environment)
        sections_environment = dict(environment)
        sections_state = root / "sections-state"
        sections_state.mkdir(mode=0o700)
        sections_tools = root / "sections-tools"
        sections_tools.mkdir(mode=0o700)
        sections_environment["CLILANE_STATE_HOME"] = str(sections_state)
        sections_environment["CLILANE_TMUX_SOCKET"] = f"clp-sections-{os.getpid()}"
        _exercise_switcher_sections(sections_environment, sections_tools)
        terminfo_environment = dict(environment)
        terminfo_state = root / "terminfo-state"
        terminfo_state.mkdir(mode=0o700)
        terminfo_dir = root / "terminfo"
        terminfo_dir.mkdir(mode=0o700)
        terminfo_environment["CLILANE_STATE_HOME"] = str(terminfo_state)
        terminfo_environment["CLILANE_TMUX_SOCKET"] = f"clp-terminfo-{os.getpid()}"
        _exercise_terminfo(terminfo_environment, terminfo_dir)

        tool_bin = root / "tools"
        tool_bin.mkdir(mode=0o700)
        tmux_executable = shutil.which("tmux")
        sleep_executable = shutil.which("sleep")
        assert tmux_executable is not None
        assert sleep_executable is not None
        (tool_bin / "tmux").symlink_to(tmux_executable)
        (tool_bin / "sleep").symlink_to(sleep_executable)
        (tool_bin / "python3").symlink_to(sys.executable)
        cat_executable = tool_bin / "cat"
        cat_executable.write_text("#!/bin/sh\nexec /bin/cat\n")
        cat_executable.chmod(0o700)

        launch_project = root / "launch-project"
        source_project = root / "source-project"
        for project, agents in (
            (launch_project, ("codex", "kimi", "claude")),
            (source_project, ("kimi",)),
        ):
            agent_bin = project / "agent-bin"
            agent_bin.mkdir(parents=True, mode=0o700)
            for agent in agents:
                (agent_bin / agent).symlink_to(cat_executable)

        discovery_environment = dict(environment)
        discovery_environment["PATH"] = os.pathsep.join(
            ["agent-bin", str(tool_bin.resolve())]
        )
        discovery_environment["SHELL"] = "/bin/sh"
        discovery_terminal: _Terminal | None = None
        try:
            discovery_terminal = _Terminal(
                [], discovery_environment, cwd=str(launch_project)
            )
            discovery_terminal.expect("[codex ·")
            for label, key in (("kimi", b"\t"), ("claude", b"\t"), ("kimi", b"\x1b[Z"), ("codex", b"\x1b[Z")):
                agent_mark = discovery_terminal.mark()
                discovery_terminal.send(key)
                discovery_terminal.expect(f"[{label} ·", agent_mark)
            discovery_terminal.expect("[codex · launch-project]")
            launch_prompt = f"zero config {os.getpid()}"
            mark = discovery_terminal.mark()
            discovery_terminal.send(launch_prompt.encode() + b"\r")
            discovery_terminal.expect("Starting codex-launch-project", mark)
            discovery_terminal.expect(launch_prompt, mark)
            _wait_for_attached_task(
                discovery_environment, discovery_terminal, "codex-launch-project"
            )
            discovery_terminal.expect(f"LOCAL · zero config {os.getpid()}", mark)
            mark = discovery_terminal.mark()
            discovery_terminal.send(b"\x02")
            discovery_terminal.expect("This clilane server", mark)
            discovery_terminal.expect(launch_prompt, mark)
            discovery_terminal.expect("Enter open · Space preview", mark)
            handshake_mark = discovery_terminal.mark()
            discovery_terminal.send(b"\x15")
            discovery_terminal.expect("> ▏", handshake_mark)
            discovery_terminal.send(b"\x11")
            assert discovery_terminal.wait() == 0
            discovery_terminal.close()
            discovery_terminal = None

            tasks = _tasks(discovery_environment)
            launched = [
                task
                for task in tasks
                if task["name"] == "codex-launch-project"
            ]
            assert len(launched) == 1, tasks
            assert launched[0]["command"] == [
                str(launch_project.resolve() / "agent-bin" / "codex")
            ]
            assert launched[0]["cwd"] == str(launch_project.resolve())

            _run(
                discovery_environment,
                [
                    "run",
                    "source-ui",
                    "-C",
                    str(source_project),
                    "--",
                    "/bin/cat",
                ],
            )
            discovery_terminal = _Terminal(
                ["attach", "source-ui"],
                discovery_environment,
                cwd=str(launch_project),
            )
            discovery_terminal.expect("LOCAL · source-ui")
            mark = discovery_terminal.mark()
            discovery_terminal.send(b"\x02")
            discovery_terminal.expect("This clilane server", mark)
            discovery_terminal.expect("[kimi · source-project]", mark)
            source_prompt = f"source project {os.getpid()}"
            mark = discovery_terminal.mark()
            discovery_terminal.send(source_prompt.encode() + b"\r")
            discovery_terminal.expect("Starting kimi-source-project", mark)
            discovery_terminal.expect(source_prompt, mark)
            _wait_for_attached_task(
                discovery_environment, discovery_terminal, "kimi-source-project"
            )
            discovery_terminal.expect(f"LOCAL · {source_prompt}", mark)
            mark = discovery_terminal.mark()
            discovery_terminal.send(b"\x02")
            discovery_terminal.expect("This clilane server", mark)
            discovery_terminal.expect(source_prompt, mark)
            discovery_terminal.expect("Enter open · Space preview", mark)
            handshake_mark = discovery_terminal.mark()
            discovery_terminal.send(b"\x15")
            discovery_terminal.expect("> ▏", handshake_mark)
            discovery_terminal.send(b"\x11")
            assert discovery_terminal.wait() == 0
            discovery_terminal.close()
            discovery_terminal = None

            tasks = _tasks(discovery_environment)
            launched = [
                task
                for task in tasks
                if task["name"] == "kimi-source-project"
            ]
            assert len(launched) == 1, tasks
            assert launched[0]["command"] == [
                str(source_project.resolve() / "agent-bin" / "kimi")
            ]
            assert launched[0]["cwd"] == str(source_project.resolve())

            (config_dir / "hub.json").write_text(
                json.dumps({"schema_version": 1, "agents": []}),
                encoding="utf-8",
            )
            before = len(tasks)
            discovery_terminal = _Terminal(
                [], discovery_environment, cwd=str(launch_project)
            )
            discovery_terminal.expect("[no-agent]")
            discovery_terminal.expect("[no-agent]")
            mark = discovery_terminal.mark()
            discovery_terminal.send(b"suppressed discovery\r")
            discovery_terminal.expect("Config disables discovery", mark)
            assert len(_tasks(discovery_environment)) == before
            discovery_terminal.close()
            discovery_terminal = None
        finally:
            if discovery_terminal is not None:
                discovery_terminal.close()
            _cleanup(discovery_environment)

        command = [
            "/bin/sh",
            "-c",
            'printf "adopted=%s\\n" "$CI_HUB_ENV"; exec /bin/cat',
        ]
        config = json.dumps(
            {
                "schema_version": 1,
                "agents": [
                    {"name": "codex", "command": command, "dir": temporary},
                    {"name": "kimi", "command": command, "dir": temporary},
                    {"name": "claude", "command": command, "dir": temporary},
                    {"name": "hermes", "command": command, "dir": temporary},
                ],
            }
        )
        (config_dir / "hub.json").write_text(config, encoding="utf-8")
        unusual_config = root / "#{session_name} $quote's" / 'hub "config".json'
        unusual_config.parent.mkdir()
        unusual_config.write_text(config, encoding="utf-8")
        other_config = root / "other-hub.json"
        other_config.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "agents": [
                        {"name": "other", "command": command, "dir": temporary}
                    ],
                }
            ),
            encoding="utf-8",
        )
        empty_config = root / "empty-hub.json"
        empty_config.write_text(
            json.dumps({"schema_version": 1, "agents": []}), encoding="utf-8"
        )
        terminal: _Terminal | None = None
        other_terminal: _Terminal | None = None
        try:
            _run(environment, ["run", "local-ui", "-C", temporary, "--", "/bin/cat"])
            bot_environment = dict(environment)
            bot_environment["OPENCLAW_SESSION"] = "telegram-ci"
            _run(bot_environment, ["run", "bot-ui", "-C", temporary, "--", "/bin/cat"])

            terminal = _Terminal(["attach", "local-ui"], environment)
            terminal.expect("LOCAL · local-ui")
            terminal.settle()
            assert not _tmux(
                environment, ["list-keys", "-T", "root", "M-h"]
            ).stdout
            assert not _tmux(
                environment, ["list-keys", "-T", "root", "M-n"]
            ).stdout

            mark = terminal.mark()
            terminal.send(b"\x02")
            terminal.expect("This clilane server", mark)
            terminal.expect("ORIGIN", mark)
            terminal.expect("BOT", mark)
            terminal.expect("[codex ·", mark)
            terminal.expect("bot-ui", mark)
            terminal.expect("local-ui", mark)
            terminal.expect("Enter open · Space preview", mark)
            time.sleep(0.25)

            mark = terminal.mark()
            terminal.send(b"\x1b[C")
            terminal.expect("LOCAL · local-ui", mark)

            terminal.settle()
            mark = terminal.mark()
            terminal.send(b"\x02")
            terminal.expect("This clilane server", mark)
            terminal.expect("Enter open · Space preview", mark)
            time.sleep(0.25)
            ordered = sorted(
                _tasks(environment),
                key=lambda task: str(task["created"]),
                reverse=True,
            )
            local_index = next(
                index for index, task in enumerate(ordered) if task["name"] == "local-ui"
            )
            bot_index = next(
                index for index, task in enumerate(ordered) if task["name"] == "bot-ui"
            )
            direction = b"\x1b[A" if bot_index < local_index else b"\x1b[B"
            terminal.send(direction + b"\x1b[C")
            terminal.expect("BOT · bot-ui", mark)

            other_environment = dict(environment)
            other_environment["CI_HUB_ENV"] = "other"
            other_terminal = _Terminal(
                ["hub", "--config", str(other_config)], other_environment
            )
            other_terminal.expect("This clilane server")
            other_terminal.expect("[other ·")
            other_mark = other_terminal.mark()
            other_terminal.send(b"\x1b[B\x1b[C")
            other_terminal.expect("LOCAL · local-ui", other_mark)

            terminal.settle()
            mark = terminal.mark()
            terminal.send(b"\x02")
            terminal.expect("This clilane server", mark)
            terminal.expect("Enter open · Space preview", mark)
            time.sleep(0.25)
            terminal.expect("[codex ·", mark)
            main_sessions = _hub_sessions(environment)
            assert len(main_sessions) == 1, main_sessions
            main_session = next(iter(main_sessions))
            main_pane = _hub_pane_info(environment, main_session)
            other_mark = other_terminal.mark()
            other_terminal.send(b"\x02")
            other_terminal.expect("This clilane server", other_mark)
            other_terminal.expect("[other ·", other_mark)
            peer_sessions = _hub_sessions(environment) - main_sessions
            assert len(peer_sessions) == 1, peer_sessions
            peer_session = next(iter(peer_sessions))
            peer_pane = _hub_pane_info(environment, peer_session)
            other_terminal.resize(80, 18)
            terminal.send(b"resize-main")
            other_terminal.send(b"resize-peer")
            for columns, rows in ((32, 8), (18, 5), (160, 48), (100, 24)):
                terminal.resize(columns, rows)
                deadline = time.monotonic() + 5.0
                while (
                    _hub_pane_info(environment, main_session)[3:5] != [str(columns), str(rows)]
                    or _hub_pane_info(environment, peer_session)[3:5] != ["80", "18"]
                ):
                    assert time.monotonic() < deadline, (
                        (columns, rows), _hub_pane_info(environment, main_session),
                        _hub_pane_info(environment, peer_session),
                    )
                    terminal.settle(quiet=0.05, timeout=0.1)
                    other_terminal.settle(quiet=0.05, timeout=0.1)
                assert _hub_pane_info(environment, main_session)[:3] == main_pane[:3]
                assert _hub_pane_info(environment, peer_session)[:3] == peer_pane[:3]
            for session, draft in ((main_session, b"resize-main"), (peer_session, b"resize-peer")):
                deadline = time.monotonic() + 5.0
                while draft not in _tmux(environment, ["capture-pane", "-p", "-t", session]).stdout:
                    assert time.monotonic() < deadline, f"draft lost in {session}"
                    terminal.settle(quiet=0.05, timeout=0.1)
                    other_terminal.settle(quiet=0.05, timeout=0.1)
                assert _hub_pane_info(environment, session)[-2:] == ["0", "0"]
            edit_mark = terminal.mark()
            terminal.send(b"\x15")
            terminal.expect("> ▏", edit_mark)
            agent_mark = terminal.mark()
            terminal.send(b"\x1b[Z")
            terminal.expect("[hermes ·", agent_mark)
            agent_mark = terminal.mark()
            terminal.send(b"\t")
            terminal.expect("[codex ·", agent_mark)
            edit_mark = terminal.mark()
            terminal.send(b"ac\x1b[Db")
            terminal.expect("ab▏c", edit_mark)
            edit_mark = terminal.mark()
            terminal.send(b"\x7f")
            terminal.expect("a▏c", edit_mark)
            edit_mark = terminal.mark()
            terminal.send(b"\x15")
            terminal.expect("> ▏", edit_mark)
            agent_mark = terminal.mark()
            terminal.send(b"\t")
            terminal.expect("[kimi ·", agent_mark)
            prompt = f"hub message {os.getpid()}\nsecond line"
            terminal.send(b"\x1b[200~")
            for index in range(0, len(prompt), 5):
                terminal.send(prompt[index:index + 5].encode())
                terminal.resize(80 + 10 * (index % 3), 20 + index % 4)
                time.sleep(0.025)
            terminal.send(b"\x1b[201~")
            terminal.resize(100, 24)
            terminal.expect(prompt.replace("\n", " "), mark)
            assert _hub_pane_info(environment, main_session)[:3] == main_pane[:3]
            assert _hub_pane_info(environment, main_session)[-2:] == ["0", "0"]
            assert len(_tasks(environment)) == 2

            mark = terminal.mark()
            terminal.send(b"\r")
            terminal.expect("Starting kimi-", mark)
            terminal.expect("adopted=adopted", mark)
            terminal.expect("second line", mark)

            other_prompt = f"other client {os.getpid()}"
            other_terminal.settle()
            other_mark = other_terminal.mark()
            assert b"resize-peer" in _tmux(
                environment, ["capture-pane", "-p", "-t", peer_session]
            ).stdout
            other_terminal.send(b"\x15")
            other_terminal.expect("> ▏", other_mark)
            other_terminal.resize(100, 24)
            other_mark = other_terminal.mark()
            other_terminal.send(other_prompt.encode() + b"\r")
            other_terminal.expect("Starting other-", other_mark)
            other_terminal.expect("adopted=other", other_mark)
            other_terminal.expect(other_prompt, other_mark)
            other_terminal.settle()
            other_mark = other_terminal.mark()
            other_terminal.send(b"\x02")
            other_terminal.expect("This clilane server", other_mark)
            other_terminal.expect("[other ·", other_mark)
            other_terminal.send(b"\x11")
            assert other_terminal.wait() == 0

            terminal.settle()
            mark = terminal.mark()
            terminal.send(b"\x02")
            terminal.expect("This clilane server", mark)
            terminal.expect(prompt.replace("\n", " "), mark)
            terminal.expect("[kimi ·", mark)
            terminal.expect("Enter open · Space preview", mark)
            time.sleep(0.25)
            terminal.send(b"\x11")
            assert terminal.wait() == 0

            tasks = _tasks(environment)
            assert len(tasks) == 4, tasks
            created = [task for task in tasks if str(task["name"]).startswith("kimi-")]
            assert len(created) == 1, tasks
            assert created[0]["command"] == command
            other_created = [
                task for task in tasks if str(task["name"]).startswith("other-")
            ]
            assert len(other_created) == 1, tasks
            assert "origin" not in created[0]
            serialized_tasks = json.dumps(tasks)
            assert prompt not in serialized_tasks
            assert other_prompt not in serialized_tasks

            terminal.close()
            terminal = _Terminal([], environment)
            terminal.expect("This clilane server")
            terminal.expect("[codex ·")
            mark = terminal.mark()
            terminal.send(b"\x1b[B" * len(tasks) + b"\r")
            terminal.expect("adopted=adopted", mark)
            assert len(_tasks(environment)) == len(tasks) + 1
            mark = terminal.mark()
            terminal.send(b"\x02")
            terminal.expect("This clilane server", mark)
            terminal.send(b"\x11")
            assert terminal.wait() == 0

            terminal.close()
            terminal = _Terminal(
                ["hub", "--config", str(unusual_config)], environment
            )
            terminal.expect("This clilane server")
            terminal.expect("[codex ·")
            terminal.send(b"\x11")
            assert terminal.wait() == 0

            terminal.close()
            before = len(_tasks(environment))
            terminal = _Terminal(["hub", "--config", str(empty_config)], environment)
            terminal.expect("[no-agent]")
            empty_prompt = f"no preset {os.getpid()}"
            terminal.send(empty_prompt.encode() + b"\r")
            terminal.expect("Add agent presets to")
            assert len(_tasks(environment)) == before
            terminal.send(b"\x15\x11")
            assert terminal.wait() == 0

            terminal.close()
            terminal = _Terminal(["attach", "local-ui"], environment)
            terminal.expect("LOCAL · local-ui")
            deadline = time.monotonic() + 5
            context_counts = _hub_context_counts(environment)
            while context_counts != (1, 1) and time.monotonic() < deadline:
                time.sleep(0.05)
                context_counts = _hub_context_counts(environment)
            assert context_counts == (1, 1), context_counts
            clients = _tmux(
                environment,
                ["list-clients", "-F", "#{client_name}|#{client_pid}"],
            ).stdout.decode().splitlines()
            assert len(clients) == 1, clients
            client, client_pid = clients[0].split("|", 1)
            _run(
                environment,
                ["__hub-forget", client, client, client_pid, "0" * 32],
            )
            assert _hub_context_counts(environment) == (1, 1)
            os.kill(terminal.pid, signal.SIGKILL)
            assert terminal.wait() == -signal.SIGKILL
            deadline = time.monotonic() + 5
            while _hub_context_counts(environment) != (0, 0):
                if time.monotonic() >= deadline:
                    raise AssertionError("detached client context was not removed")
                time.sleep(0.05)

            terminal.close()
            large_environment = dict(environment)
            for index in range(70):
                large_environment[f"CI_LARGE_{index:02d}"] = "x" * 3072
            terminal = _Terminal(["attach", "local-ui"], large_environment)
            terminal.expect("LOCAL · local-ui")
            mark = terminal.mark()
            terminal.send(b"\x02")
            terminal.expect("environment is too large", mark)
            blocked_prompt = f"blocked launch {os.getpid()}"
            mark = terminal.mark()
            terminal.send(blocked_prompt.encode() + b"\r")
            terminal.expect("environment is too large", mark)
            assert len(_tasks(environment)) == before
            terminal.send(b"\x15\x11")
            assert terminal.wait() == 0

            finished = _run(
                environment,
                [
                    "run",
                    "finished-ui",
                    "-C",
                    temporary,
                    "--wait",
                    "--",
                    "/usr/bin/true",
                ],
                check=False,
            )
            assert finished.returncode == 0, finished.stderr
            terminal.close()
            terminal = _Terminal([], environment)
            terminal.expect("finished-ui")
            terminal.expect("succeeded")
            terminal.send(b"\x11")
            assert terminal.wait() == 0

            _run(environment, ["clean"])
            hub = _tmux(environment, ["has-session", "-t", "hub"])
            assert hub.returncode == 0, hub.stderr.decode(errors="replace")
        finally:
            if terminal is not None:
                terminal.close()
            if other_terminal is not None:
                other_terminal.close()
            _cleanup(environment)
    print("hub PTY smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
