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
        closed = _tmux(environment, ["display-popup", "-c", client, "-C"])
        assert closed.returncode == 0, closed.stderr.decode(errors="replace")
        assert terminal.wait(5.0) == 0
        terminal.close()
        terminal = None

        deadline = time.monotonic() + 5.0
        while _hub_context_counts(environment) != (0, 0):
            if time.monotonic() >= deadline:
                raise AssertionError("popup-loss cleanup left a hub context behind")
            time.sleep(0.05)
        assert _hub_popup_count(environment) == 0

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
        redraw_mark = terminal.mark()
        reopened = subprocess.Popen(
            [str(CLILANE), "__hub-open", client, "hub", client_pid, ""],
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
        old_pid, old_context, old_generation = original_popup.split(":", 2)
        assert old_pid == client_pid
        _call_clilane_function(
            environment,
            "finish_hub_popup",
            [client, client_pid, old_context, old_generation],
        )
        assert _hub_popup_values(environment) == [current_popup]
        assert _hub_context_counts(environment) == (1, 1)
        assert terminal.running()
        current_pid, current_context, _ = current_popup.split(":", 2)
        assert current_pid == client_pid
        launch_popup = f"{current_popup}:launch"
        _call_clilane_function(
            environment,
            "replace_hub_popup",
            [client, client_pid, current_context, current_popup, launch_popup],
        )
        assert _hub_popup_values(environment) == [launch_popup]

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
        closed = _tmux(environment, ["display-popup", "-c", client, "-C"])
        assert closed.returncode == 0, closed.stderr.decode(errors="replace")
        stdout, stderr = reopened.communicate(timeout=5)
        assert reopened.returncode == 1, stdout.decode(errors="replace")
        assert b"could not open the session switcher" in stderr, stderr
        reopened = None
        attached = _tmux(
            environment,
            ["list-clients", "-F", "#{client_name}|#{client_session}"],
        ).stdout.decode().splitlines()
        assert attached == [f"{client}|{escape_session}"], attached
        assert terminal.running()
        assert _hub_popup_count(environment) == 0
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
        assert b"Ctrl-b w to reopen" in standby
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
        closed = _tmux(environment, ["display-popup", "-c", client, "-C"])
        assert closed.returncode == 0, closed.stderr.decode(errors="replace")
        outer_terminal.expect(outer_marker, resume_mark)
        deadline = time.monotonic() + 5.0
        while _hub_context_counts(environment) != (0, 0):
            if time.monotonic() >= deadline:
                raise AssertionError("nested popup-loss cleanup left a context behind")
            time.sleep(0.05)
        assert _hub_popup_count(environment) == 0
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

        tool_bin = root / "tools"
        tool_bin.mkdir(mode=0o700)
        tmux_executable = shutil.which("tmux")
        sleep_executable = shutil.which("sleep")
        assert tmux_executable is not None
        assert sleep_executable is not None
        (tool_bin / "tmux").symlink_to(tmux_executable)
        (tool_bin / "sleep").symlink_to(sleep_executable)
        (tool_bin / "python3").symlink_to(sys.executable)

        launch_project = root / "launch-project"
        source_project = root / "source-project"
        for project, agents in (
            (launch_project, ("codex", "kimi", "claude")),
            (source_project, ("kimi",)),
        ):
            agent_bin = project / "agent-bin"
            agent_bin.mkdir(parents=True, mode=0o700)
            for agent in agents:
                (agent_bin / agent).symlink_to("/bin/cat")

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
            discovery_terminal.expect("codex / kimi / claude")
            discovery_terminal.expect("[codex · launch-project]")
            launch_prompt = f"zero config {os.getpid()}"
            mark = discovery_terminal.mark()
            discovery_terminal.send(launch_prompt.encode() + b"\r")
            discovery_terminal.expect("Starting codex-launch-project", mark)
            discovery_terminal.expect(launch_prompt, mark)
            discovery_terminal.settle()
            mark = discovery_terminal.mark()
            discovery_terminal.send(b"\x11")
            discovery_terminal.expect("This clilane server", mark)
            discovery_terminal.expect("codex-launch-project", mark)
            discovery_terminal.expect("empty message: →/Enter view", mark)
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
            discovery_terminal.send(b"\x11")
            discovery_terminal.expect("This clilane server", mark)
            discovery_terminal.expect("[kimi · source-project]", mark)
            source_prompt = f"source project {os.getpid()}"
            mark = discovery_terminal.mark()
            discovery_terminal.send(source_prompt.encode() + b"\r")
            discovery_terminal.expect("Starting kimi-source-project", mark)
            discovery_terminal.expect(source_prompt, mark)
            discovery_terminal.settle()
            mark = discovery_terminal.mark()
            discovery_terminal.send(b"\x11")
            discovery_terminal.expect("This clilane server", mark)
            discovery_terminal.expect("kimi-source-project", mark)
            discovery_terminal.expect("empty message: →/Enter view", mark)
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
            discovery_terminal.expect("no presets")
            discovery_terminal.expect("Config disables discovery")
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
            terminal.send(b"\x02w")
            terminal.expect("This clilane server", mark)
            terminal.expect("ORIGIN", mark)
            terminal.expect("BOT OpenClaw/automation", mark)
            terminal.expect("codex / kimi / claude / hermes", mark)
            terminal.expect("bot-ui", mark)
            terminal.expect("local-ui", mark)
            terminal.expect("empty message: →/Enter view", mark)
            time.sleep(0.25)

            mark = terminal.mark()
            terminal.send(b"\x1b[C")
            terminal.expect("LOCAL · local-ui", mark)

            terminal.settle()
            mark = terminal.mark()
            terminal.send(b"\x11")
            terminal.expect("This clilane server", mark)
            terminal.expect("empty message: →/Enter view", mark)
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
            terminal.send(b"\x11")
            terminal.expect("This clilane server", mark)
            terminal.expect("empty message: →/Enter view", mark)
            time.sleep(0.25)
            terminal.expect("[codex ·", mark)
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
            terminal.send(b"\x1b[200~" + prompt.encode() + b"\x1b[201~")
            terminal.expect(prompt.replace("\n", " "), mark)
            assert len(_tasks(environment)) == 2

            mark = terminal.mark()
            terminal.send(b"\r")
            terminal.expect("Starting kimi-", mark)
            terminal.expect("adopted=adopted", mark)
            terminal.expect("second line", mark)

            other_prompt = f"other client {os.getpid()}"
            other_terminal.settle()
            other_mark = other_terminal.mark()
            other_terminal.send(b"\x11")
            other_terminal.expect("This clilane server", other_mark)
            other_terminal.expect("[other ·", other_mark)
            other_mark = other_terminal.mark()
            other_terminal.send(other_prompt.encode() + b"\r")
            other_terminal.expect("Starting other-", other_mark)
            other_terminal.expect("adopted=other", other_mark)
            other_terminal.expect(other_prompt, other_mark)
            other_terminal.settle()
            other_mark = other_terminal.mark()
            other_terminal.send(b"\x11")
            other_terminal.expect("This clilane server", other_mark)
            other_terminal.expect("[other ·", other_mark)
            other_terminal.send(b"\x11")
            assert other_terminal.wait() == 0

            terminal.settle()
            mark = terminal.mark()
            terminal.send(b"\x11")
            terminal.expect("This clilane server", mark)
            terminal.expect("kimi-", mark)
            terminal.expect("[kimi ·", mark)
            terminal.expect("empty message: →/Enter view", mark)
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
            terminal.expect("Type a message to start a new session", mark)
            assert len(_tasks(environment)) == len(tasks)
            terminal.send(b"\x11")
            assert terminal.wait() == 0

            terminal.close()
            terminal = _Terminal(
                ["hub", "--config", str(unusual_config)], environment
            )
            terminal.expect("This clilane server")
            terminal.expect("codex / kimi / claude / hermes")
            terminal.send(b"\x11")
            assert terminal.wait() == 0

            terminal.close()
            before = len(_tasks(environment))
            terminal = _Terminal(["hub", "--config", str(empty_config)], environment)
            terminal.expect("no presets")
            terminal.expect("[no-agent]")
            empty_prompt = f"no preset {os.getpid()}"
            terminal.send(empty_prompt.encode() + b"\r")
            terminal.expect("Add agent presets to")
            assert len(_tasks(environment)) == before
            terminal.send(b"\x11")
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
            terminal.send(b"\x02w")
            terminal.expect("environment is too large", mark)
            blocked_prompt = f"blocked launch {os.getpid()}"
            mark = terminal.mark()
            terminal.send(blocked_prompt.encode() + b"\r")
            terminal.expect("environment is too large", mark)
            assert len(_tasks(environment)) == before
            terminal.send(b"\x11")
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
