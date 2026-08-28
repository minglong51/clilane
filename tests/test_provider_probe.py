from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts/provider_probe.py"
SPEC = importlib.util.spec_from_file_location("provider_probe", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT_PATH}")
provider_probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = provider_probe
SPEC.loader.exec_module(provider_probe)


def write_executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return path


def fake_codex(
    path: Path,
    workspace: Path,
    *,
    reverse_request: bool = False,
    post_terminal: bool = False,
) -> Path:
    workspace = workspace.resolve()
    source = f'''#!/usr/bin/env python3
import json
import os
import sys

def fail(code):
    raise SystemExit(code)

def receive():
    raw = sys.stdin.buffer.readline()
    if not raw:
        fail(80)
    return json.loads(raw)

def emit(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\\n")
    sys.stdout.flush()

if sys.argv[1:] == ["--version"]:
    sys.stdout.write("codex-cli 0.149.1\\n")
    fail(0)
if sys.argv[1:] != ["app-server", "--stdio", "--strict-config"]:
    fail(81)
if "CLILANE_PRIVACY_CANARY" in os.environ or "OPENAI_API_KEY" in os.environ:
    fail(82)
message = receive()
if message != {{"id":"clilane-init-1","method":"initialize","params":{{"clientInfo":{{"name":"clilane_provider_evidence","title":"CLILane Provider Evidence","version":"0.9.0"}}}}}}:
    fail(83)
emit({{"id":"clilane-init-1","result":{{}}}})
if receive() != {{"method":"initialized"}}:
    fail(84)
message = receive()
params = message.get("params", {{}})
if message.get("id") != "clilane-thread-1" or message.get("method") != "thread/start":
    fail(85)
if params.get("cwd") != {str(workspace)!r} or params.get("ephemeral") is not True:
    fail(86)
if params.get("approvalPolicy") != "never" or params.get("sandbox") != "read-only":
    fail(87)
if params.get("config") != {{"features.hooks":False,"features.plugins":False,"web_search":"disabled"}}:
    fail(88)
emit({{"id":"clilane-thread-1","result":{{"thread":{{"id":"dynamic-thread","sessionId":"dynamic-session"}}}}}})
message = receive()
params = message.get("params", {{}})
if message.get("id") != "clilane-turn-1" or message.get("method") != "turn/start":
    fail(89)
if params.get("threadId") != "dynamic-thread" or params.get("input") != [{{"type":"text","text":{provider_probe.PROBE_PROMPT!r}}}]:
    fail(90)
if params.get("approvalPolicy") != "never" or params.get("sandboxPolicy") != {{"networkAccess":False,"type":"readOnly"}}:
    fail(91)
emit({{"id":"clilane-turn-1","result":{{"turn":{{"id":"dynamic-turn","items":[],"status":"inProgress"}}}}}})
if {reverse_request!r}:
    emit({{"id":"dynamic-approval","method":"item/commandExecution/requestApproval","params":{{"threadId":"dynamic-thread","turnId":"dynamic-turn"}}}})
    if receive() != {{"id":"dynamic-approval","result":{{"decision":"cancel"}}}}:
        fail(92)
    if receive() != {{"id":"clilane-interrupt-1","method":"turn/interrupt","params":{{"threadId":"dynamic-thread","turnId":"dynamic-turn"}}}}:
        fail(93)
else:
    emit({{"method":"item/agentMessage/delta","params":{{"delta":"CLILANE_","itemId":"dynamic-item","threadId":"dynamic-thread","turnId":"dynamic-turn"}}}})
    emit({{"method":"item/agentMessage/delta","params":{{"delta":"PROBE_OK","itemId":"dynamic-item","threadId":"dynamic-thread","turnId":"dynamic-turn"}}}})
    emit({{"method":"turn/completed","params":{{"threadId":"dynamic-thread","turn":{{"id":"dynamic-turn","items":[],"status":"completed"}}}}}})
    if {post_terminal!r}:
        emit({{"method":"thread/status/changed","params":{{"threadId":"dynamic-thread"}}}})
if sys.stdin.buffer.readline() != b"":
    fail(94)
'''
    return write_executable(path, source)


def fake_kimi(path: Path, workspace: Path, *, reverse_request: bool = False) -> Path:
    workspace = workspace.resolve()
    source = f'''#!/usr/bin/env python3
import json
import os
import sys

def fail(code):
    raise SystemExit(code)

def receive():
    raw = sys.stdin.buffer.readline()
    if not raw:
        fail(80)
    return json.loads(raw)

def emit(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\\n")
    sys.stdout.flush()

if sys.argv[1:] == ["--version"]:
    sys.stdout.write("0.38.0\\n")
    fail(0)
if sys.argv[1:] != ["acp"]:
    fail(81)
if "CLILANE_PRIVACY_CANARY" in os.environ or "MOONSHOT_API_KEY" in os.environ:
    fail(82)
message = receive()
if message.get("jsonrpc") != "2.0" or message.get("id") != 1 or message.get("method") != "initialize":
    fail(83)
capabilities = message.get("params", {{}}).get("clientCapabilities")
if capabilities != {{"fs":{{"readTextFile":False,"writeTextFile":False}},"terminal":False}}:
    fail(84)
emit({{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":1}}}})
message = receive()
if message != {{"jsonrpc":"2.0","id":2,"method":"session/new","params":{{"cwd":{str(workspace)!r},"mcpServers":[]}}}}:
    fail(85)
emit({{"jsonrpc":"2.0","id":2,"result":{{"sessionId":"dynamic-session"}}}})
message = receive()
if message.get("jsonrpc") != "2.0" or message.get("id") != 3 or message.get("method") != "session/prompt":
    fail(86)
if message.get("params") != {{"prompt":[{{"type":"text","text":{provider_probe.PROBE_PROMPT!r}}}],"sessionId":"dynamic-session"}}:
    fail(87)
if {reverse_request!r}:
    emit({{"jsonrpc":"2.0","id":"dynamic-permission","method":"session/request_permission","params":{{"sessionId":"dynamic-session","toolCall":{{}}}}}})
    if receive() != {{"jsonrpc":"2.0","id":"dynamic-permission","result":{{"outcome":{{"outcome":"cancelled"}}}}}}:
        fail(88)
    if receive() != {{"jsonrpc":"2.0","method":"session/cancel","params":{{"sessionId":"dynamic-session"}}}}:
        fail(89)
else:
    emit({{"jsonrpc":"2.0","method":"session/update","params":{{"sessionId":"dynamic-session","update":{{"sessionUpdate":"agent_message_chunk","content":{{"type":"text","text":"CLILANE_"}}}}}}}})
    emit({{"jsonrpc":"2.0","method":"session/update","params":{{"sessionId":"dynamic-session","update":{{"sessionUpdate":"agent_message_chunk","content":{{"type":"text","text":"PROBE_OK"}}}}}}}})
    emit({{"jsonrpc":"2.0","id":3,"result":{{"stopReason":"end_turn"}}}})
if sys.stdin.buffer.readline() != b"":
    fail(90)
'''
    return write_executable(path, source)


def fake_claude(path: Path, workspace: Path, config_dir: Path) -> Path:
    workspace = workspace.resolve()
    config_dir = config_dir.resolve()
    expected_arguments = [
        "-p",
        "--input-format",
        "text",
        "--output-format",
        "text",
        "--no-session-persistence",
        "--setting-sources",
        "user",
        "--settings",
        str(config_dir / "probe-settings.json"),
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--disable-slash-commands",
        "--no-chrome",
        "--tools",
        "",
        "--permission-mode",
        "dontAsk",
        "--model",
        provider_probe.CLAUDE_MODEL,
        "--max-budget-usd",
        provider_probe.CLAUDE_MAX_BUDGET_USD,
        "--prompt-suggestions",
        "false",
        "--session-id",
        provider_probe.CLAUDE_SESSION_ID,
    ]
    source = f'''#!/usr/bin/env python3
import json
import os
import subprocess
import sys

def fail(code):
    raise SystemExit(code)

def option(arguments, name):
    if arguments.count(name) != 1:
        fail(81)
    index = arguments.index(name)
    if index + 1 >= len(arguments):
        fail(82)
    return arguments[index + 1]

def run_hook(settings, event_name, value):
    groups = settings.get("hooks", {{}}).get(event_name)
    if type(groups) is not list or len(groups) != 1:
        fail(83)
    if event_name == "SessionStart" and groups[0].get("matcher") != "startup":
        fail(84)
    hooks = groups[0].get("hooks")
    if type(hooks) is not list or len(hooks) != 1:
        fail(85)
    hook = hooks[0]
    if hook.get("type") != "command" or type(hook.get("args")) is not list or hook.get("timeout") != 10:
        fail(86)
    completed = subprocess.run(
        [hook["command"], *hook["args"]],
        input=json.dumps(value, separators=(",", ":")).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd={str(workspace)!r},
        env=os.environ.copy(),
        check=False,
        timeout=10,
    )
    if completed.returncode != 0 or completed.stdout or completed.stderr:
        fail(87)

if sys.argv[1:] == ["--version"]:
    sys.stdout.write("2.1.245 (Claude Code)\\n")
    fail(0)
arguments = sys.argv[1:]
if arguments != {expected_arguments!r}:
    fail(88)
if os.environ.get("CLAUDE_CONFIG_DIR") != {str(config_dir)!r}:
    fail(93)
for name in (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_USE_MANTLE",
    "CLILANE_PRIVACY_CANARY",
):
    if name in os.environ:
        fail(94)
for name in ("OTEL_LOGS_EXPORTER", "OTEL_METRICS_EXPORTER", "OTEL_TRACES_EXPORTER"):
    if os.environ.get(name) != "none":
        fail(94)
settings_path = option(arguments, "--settings")
with open(settings_path, encoding="utf-8") as source_file:
    settings = json.load(source_file)
common = {{
    "session_id": {provider_probe.CLAUDE_SESSION_ID!r},
    "transcript_path": {str(config_dir / 'transcript.jsonl')!r},
    "cwd": {str(workspace)!r},
    "permission_mode": "dontAsk",
}}
run_hook(settings, "SessionStart", {{**common, "hook_event_name":"SessionStart", "source":"startup", "model":{provider_probe.CLAUDE_MODEL!r}}})
prompt = sys.stdin.buffer.read()
if prompt != {provider_probe.PROBE_PROMPT!r}.encode("ascii"):
    fail(95)
run_hook(settings, "UserPromptSubmit", {{**common, "hook_event_name":"UserPromptSubmit", "prompt":{provider_probe.PROBE_PROMPT!r}}})
run_hook(settings, "Stop", {{**common, "hook_event_name":"Stop", "stop_hook_active":False, "last_assistant_message":{provider_probe.EXPECTED_RESPONSE!r}}})
sys.stdout.write({provider_probe.EXPECTED_RESPONSE!r} + "\\n")
'''
    return write_executable(path, source)


def fake_claude_with_descendant(path: Path, process_group_path: Path) -> Path:
    source = f'''#!/usr/bin/env python3
import os
import signal
import subprocess
import sys
import time

if sys.argv[1:] == ["--version"]:
    sys.stdout.write("2.1.245 (Claude Code)\\n")
    raise SystemExit(0)
child = subprocess.Popen(
    [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"],
    close_fds=True,
)
with open({str(process_group_path)!r}, "w", encoding="ascii") as destination:
    destination.write(str(os.getpgrp()))
os.chmod({str(process_group_path)!r}, 0o600)
sys.stdout.write({provider_probe.EXPECTED_RESPONSE!r} + "\\n")
'''
    return write_executable(path, source)


def fake_stubborn_provider(path: Path) -> Path:
    source = '''#!/usr/bin/env python3
import signal
import sys
import time

if sys.argv[1:] != ["--linger"]:
    raise SystemExit(81)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(60)
'''
    return write_executable(path, source)


def fake_stubborn_collector(path: Path, process_group_path: Path) -> Path:
    source = f'''#!/usr/bin/env python3
import os
import signal
import subprocess
import sys
import time

def option(name):
    index = sys.argv.index(name)
    return sys.argv[index + 1]

control_fd = int(option("--provider-control-fd"))
os.set_inheritable(control_fd, False)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
provider = subprocess.Popen(
    [option("--provider-executable"), "--linger"],
    start_new_session=True,
    close_fds=True,
)
with open({str(process_group_path)!r}, "w", encoding="ascii") as destination:
    destination.write(str(provider.pid))
os.chmod({str(process_group_path)!r}, 0o600)
os.write(control_fd, f"S {{provider.pid}}\\n".encode("ascii"))
while True:
    time.sleep(60)
'''
    return write_executable(path, source)


def fake_oversized_codex(path: Path) -> Path:
    source = f'''#!/usr/bin/env python3
import json
import sys

if sys.argv[1:] == ["--version"]:
    sys.stdout.write("codex-cli 0.149.1\\n")
    raise SystemExit(0)
if sys.argv[1:] != ["app-server", "--stdio", "--strict-config"]:
    raise SystemExit(81)
json.loads(sys.stdin.buffer.readline())
sys.stdout.write("X" * {provider_probe.MAX_LINE_BYTES + 1})
sys.stdout.flush()
sys.stdin.buffer.read()
'''
    return write_executable(path, source)


class ProbeDirectoryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.capture_root = self.base / "captures"
        self.workspace = self.base / "workspace"
        self.config_dir = self.base / "config"
        self.capture_root.mkdir(mode=0o700)
        self.workspace.mkdir(mode=0o700)
        self.config_dir.mkdir(mode=0o700)
        self.capture_root.chmod(0o700)
        self.workspace.chmod(0o700)
        self.config_dir.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def config(self, provider: str, executable: Path, capture_id: str) -> object:
        return provider_probe.ProbeConfig(
            provider=provider,
            capture_root=self.capture_root,
            capture_id=capture_id,
            provider_executable=executable,
            workspace=self.workspace,
            config_dir=self.config_dir if provider == "claude" else None,
        )

    def receipt(self, capture_id: str) -> dict[str, object]:
        return json.loads(
            (self.capture_root / f"{capture_id}.receipt.json").read_text(
                encoding="utf-8"
            )
        )

    @contextlib.contextmanager
    def pinned_manifest(self, provider: str, executable: Path):
        digests = {
            name: hashlib.sha256(name.encode("ascii")).hexdigest()
            for name in ("claude", "codex", "kimi")
        }
        digests[provider] = hashlib.sha256(executable.read_bytes()).hexdigest()
        manifest = {
            "platform": provider_probe.current_platform(),
            "providers": [
                {
                    "executable_sha256": digests[name],
                    "provider": name,
                    "provider_version": provider_probe.SOURCE_INTERFACES[name][0],
                    "source_interface": provider_probe.SOURCE_INTERFACES[name][1],
                }
                for name in ("claude", "codex", "kimi")
            ],
            "schema_version": 1,
        }
        path = self.base / f"{provider}-executables.json"
        path.write_bytes(
            (
                json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True)
                + "\n"
            ).encode("utf-8")
        )
        path.chmod(0o644)
        with mock.patch.object(provider_probe, "EXECUTABLE_MANIFEST_PATH", path):
            yield


class SuccessfulProtocolTests(ProbeDirectoryTestCase):
    def test_claude_uses_exact_bounded_cli_and_three_private_hooks(self) -> None:
        executable = fake_claude(
            self.base / "fake-claude", self.workspace, self.config_dir
        )
        with self.pinned_manifest("claude", executable), mock.patch.dict(
            os.environ,
            {
                "ANTHROPIC_API_KEY": "must-not-cross",
                "ANTHROPIC_AUTH_TOKEN": "must-not-cross",
                "CLAUDE_CODE_OAUTH_TOKEN": "must-not-cross",
                "CLILANE_PRIVACY_CANARY": "must-not-cross",
                "OTEL_TRACES_EXPORTER": "must-not-cross",
            },
        ):
            result = provider_probe.run_probe(
                self.config("claude", executable, "capture-claude-success")
            )
        self.assertEqual(result.provider, "claude")
        self.assertEqual(result.provider_version, "2.1.245")
        self.assertEqual(result.message_count, 3)
        for suffix in provider_probe.CLAUDE_CAPTURE_SUFFIXES:
            receipt = self.receipt(f"capture-claude-success-{suffix}")
            self.assertEqual(receipt["capture_status"], "complete")
            self.assertEqual(receipt["termination"]["reason"], "hook_eof")
        expected_files = {
            "probe-prompt.txt": provider_probe.PROBE_PROMPT.encode("ascii"),
            "probe-stdout.bin": (provider_probe.EXPECTED_RESPONSE + "\n").encode(
                "ascii"
            ),
            "probe-stderr.bin": b"",
        }
        for name, expected in expected_files.items():
            path = self.config_dir / name
            self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        settings_path = self.config_dir / "probe-settings.json"
        self.assertEqual(stat.S_IMODE(settings_path.stat().st_mode), 0o600)

    def test_codex_uses_dynamic_ids_exactly_once_with_sanitized_environment(self) -> None:
        executable = fake_codex(self.base / "fake-codex", self.workspace)
        with self.pinned_manifest("codex", executable), mock.patch.dict(
            os.environ,
            {
                "CLILANE_PRIVACY_CANARY": "must-not-cross",
                "OPENAI_API_KEY": "must-not-cross",
            },
        ):
            result = provider_probe.run_probe(
                self.config("codex", executable, "capture-codex-success")
            )
        self.assertEqual(result.provider, "codex")
        self.assertEqual(result.provider_version, "0.149.1")
        receipt = self.receipt("capture-codex-success")
        self.assertEqual(receipt["capture_status"], "complete")
        self.assertEqual(receipt["termination"]["exit_code"], 0)

    def test_kimi_uses_dynamic_session_for_exactly_one_prompt(self) -> None:
        executable = fake_kimi(self.base / "fake-kimi", self.workspace)
        with self.pinned_manifest("kimi", executable), mock.patch.dict(
            os.environ,
            {
                "CLILANE_PRIVACY_CANARY": "must-not-cross",
                "MOONSHOT_API_KEY": "must-not-cross",
            },
        ):
            result = provider_probe.run_probe(
                self.config("kimi", executable, "capture-kimi-success")
            )
        self.assertEqual(result.provider, "kimi")
        self.assertEqual(result.provider_version, "0.38.0")
        receipt = self.receipt("capture-kimi-success")
        self.assertEqual(receipt["capture_status"], "complete")
        self.assertEqual(receipt["termination"]["exit_code"], 0)


class AbortProtocolTests(ProbeDirectoryTestCase):
    def test_codex_cancels_approval_and_interrupts_turn(self) -> None:
        executable = fake_codex(
            self.base / "fake-codex", self.workspace, reverse_request=True
        )
        with self.pinned_manifest("codex", executable):
            with self.assertRaisesRegex(
                provider_probe.ProbeError, "^unexpected-provider-request$"
            ):
                provider_probe.run_probe(
                    self.config("codex", executable, "capture-codex-cancel")
                )
        receipt = self.receipt("capture-codex-cancel")
        self.assertEqual(receipt["termination"]["exit_code"], 0)

    def test_kimi_cancels_permission_and_aborts_session(self) -> None:
        executable = fake_kimi(
            self.base / "fake-kimi", self.workspace, reverse_request=True
        )
        with self.pinned_manifest("kimi", executable):
            with self.assertRaisesRegex(
                provider_probe.ProbeError, "^unexpected-provider-request$"
            ):
                provider_probe.run_probe(
                    self.config("kimi", executable, "capture-kimi-cancel")
                )
        receipt = self.receipt("capture-kimi-cancel")
        self.assertEqual(receipt["termination"]["exit_code"], 0)


class PrivacyAndBoundaryTests(ProbeDirectoryTestCase):
    def test_environment_is_an_explicit_non_secret_allowlist(self) -> None:
        environment = provider_probe.sanitized_environment(
            {
                "HOME": "/private/home",
                "PATH": "/usr/bin:/bin",
                "TMPDIR": "/private/tmp",
                "CODEX_HOME": "/private/codex",
                "OPENAI_API_KEY": "secret",
                "ANTHROPIC_API_KEY": "secret",
                "AWS_SECRET_ACCESS_KEY": "secret",
                "CLILANE_PRIVACY_CANARY": "secret",
            }
        )
        self.assertEqual(environment["HOME"], "/private/home")
        self.assertEqual(environment["CODEX_HOME"], "/private/codex")
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("ANTHROPIC_API_KEY", environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
        self.assertNotIn("CLILANE_PRIVACY_CANARY", environment)

    def test_oversized_raw_provider_line_is_not_printed(self) -> None:
        executable = fake_oversized_codex(self.base / "fake-codex")
        stderr = io.StringIO()
        stdout = io.StringIO()
        arguments = (
            "--provider",
            "codex",
            "--capture-root",
            str(self.capture_root),
            "--capture-id",
            "capture-codex-oversized",
            "--provider-executable",
            str(executable),
            "--workspace",
            str(self.workspace),
        )
        with self.pinned_manifest("codex", executable):
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                return_code = provider_probe.main(arguments)
        self.assertEqual(return_code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "provider_probe.py: protocol-line-budget-exceeded\n",
        )
        self.assertNotIn("X" * 32, stderr.getvalue())

    def test_executable_hash_mismatch_fails_before_collector_spawn(self) -> None:
        executable = fake_codex(self.base / "fake-codex", self.workspace)
        with self.pinned_manifest("codex", executable):
            executable.write_text(
                executable.read_text(encoding="utf-8") + "\n# lookalike\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            with mock.patch.object(provider_probe.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(
                    provider_probe.ProbeError,
                    "^provider-executable-hash-mismatch$",
                ):
                    provider_probe.run_probe(
                        self.config("codex", executable, "capture-codex-lookalike")
                    )
        popen.assert_not_called()

    def test_post_terminal_provider_output_fails_closed(self) -> None:
        executable = fake_codex(
            self.base / "fake-codex", self.workspace, post_terminal=True
        )
        with self.pinned_manifest("codex", executable):
            with self.assertRaisesRegex(
                provider_probe.ProbeError, "^post-terminal-provider-output$"
            ):
                provider_probe.run_probe(
                    self.config("codex", executable, "capture-codex-post-terminal")
                )
        receipt = self.receipt("capture-codex-post-terminal")
        self.assertEqual(receipt["termination"]["exit_code"], 0)

    def test_claude_timeout_terminates_the_entire_provider_group(self) -> None:
        process_group_path = self.base / "claude-process-group"
        executable = fake_claude_with_descendant(
            self.base / "fake-claude", process_group_path
        )
        with self.pinned_manifest("claude", executable), mock.patch.object(
            provider_probe, "TURN_TIMEOUT_SECONDS", 1.0
        ), mock.patch.object(
            provider_probe, "COLLECTOR_SIGNAL_TIMEOUT_SECONDS", 0.5
        ):
            with self.assertRaisesRegex(
                provider_probe.ProbeError, "^provider-timeout$"
            ):
                provider_probe.run_probe(
                    self.config(
                        "claude", executable, "capture-claude-descendant"
                    )
                )
        process_group_id = int(process_group_path.read_text(encoding="ascii"))
        with self.assertRaises(ProcessLookupError):
            os.killpg(process_group_id, 0)

    def test_forced_collector_cleanup_kills_reported_provider_group(self) -> None:
        process_group_path = self.base / "collector-provider-group"
        provider = fake_stubborn_provider(self.base / "fake-provider")
        collector = fake_stubborn_collector(
            self.base / "fake-collector", process_group_path
        )
        transport = None
        with self.pinned_manifest("codex", provider):
            expected = provider_probe.load_executable_manifest(
                provider_probe.EXECUTABLE_MANIFEST_PATH
            )
            pinned = provider_probe.pin_executable("codex", provider, expected)
            with mock.patch.dict(
                provider_probe.COLLECTORS, {"codex": collector}
            ), mock.patch.object(
                provider_probe, "ABORT_TIMEOUT_SECONDS", 0.1
            ), mock.patch.object(
                provider_probe, "COLLECTOR_SIGNAL_TIMEOUT_SECONDS", 0.5
            ), mock.patch.object(
                provider_probe, "COLLECTOR_TIMEOUT_SECONDS", 0.1
            ):
                transport = provider_probe.JsonLineTransport(
                    self.config(
                        "codex", provider, "capture-codex-stubborn-collector"
                    ),
                    pinned,
                )
                try:
                    with self.assertRaisesRegex(
                        provider_probe.ProbeError,
                        "^collector-termination-forced$",
                    ):
                        transport.abort()
                finally:
                    transport.close()
        self.assertIsNotNone(transport)
        process_group_id = int(process_group_path.read_text(encoding="ascii"))
        with self.assertRaises(ProcessLookupError):
            os.killpg(process_group_id, 0)

    def test_constructor_failure_still_kills_reported_provider_group(self) -> None:
        process_group_path = self.base / "constructor-provider-group"
        provider = fake_stubborn_provider(self.base / "fake-provider")
        collector = fake_stubborn_collector(
            self.base / "fake-collector", process_group_path
        )

        class FailingSelector:
            def register(self, *_args, **_kwargs):
                deadline = time.monotonic() + 2.0
                while not process_group_path.exists():
                    if time.monotonic() >= deadline:
                        raise RuntimeError("fake collector did not start")
                    time.sleep(0.01)
                raise OSError("fault injection")

            def get_map(self):
                return {}

            def close(self):
                return None

        with self.pinned_manifest("codex", provider):
            expected = provider_probe.load_executable_manifest(
                provider_probe.EXECUTABLE_MANIFEST_PATH
            )
            pinned = provider_probe.pin_executable("codex", provider, expected)
            with mock.patch.dict(
                provider_probe.COLLECTORS, {"codex": collector}
            ), mock.patch.object(
                provider_probe.selectors,
                "DefaultSelector",
                FailingSelector,
            ), mock.patch.object(
                provider_probe, "COLLECTOR_SIGNAL_TIMEOUT_SECONDS", 0.5
            ), mock.patch.object(
                provider_probe, "COLLECTOR_TIMEOUT_SECONDS", 0.1
            ):
                with self.assertRaisesRegex(
                    provider_probe.ProbeError,
                    "^collector-termination-forced$",
                ):
                    provider_probe.JsonLineTransport(
                        self.config(
                            "codex",
                            provider,
                            "capture-codex-constructor-failure",
                        ),
                        pinned,
                    )
        process_group_id = int(process_group_path.read_text(encoding="ascii"))
        with self.assertRaises(ProcessLookupError):
            os.killpg(process_group_id, 0)

    def test_codex_launcher_resolution_matches_t8_package_layout(self) -> None:
        package = self.base / "package"
        launcher = package / "bin/codex.js"
        native = (
            package
            / "node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex"
        )
        launcher.parent.mkdir(parents=True)
        native.parent.mkdir(parents=True)
        launcher.write_text("launcher", encoding="utf-8")
        native.write_text("native", encoding="utf-8")
        with mock.patch.object(provider_probe.platform, "system", return_value="Darwin"):
            with mock.patch.object(
                provider_probe.platform, "machine", return_value="arm64"
            ):
                self.assertEqual(
                    provider_probe._codex_native_path(launcher), native.resolve()
                )

    def test_claude_without_private_config_is_rejected_before_any_spawn(self) -> None:
        with mock.patch.object(provider_probe.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(
                provider_probe.ProbeError, "^config-directory-required$"
            ):
                provider_probe.run_probe(
                    provider_probe.ProbeConfig(
                        provider="claude",
                        capture_root=self.capture_root,
                        capture_id="capture-claude-no-config",
                        provider_executable=Path("/does/not/exist"),
                        workspace=self.workspace,
                    )
                )
        popen.assert_not_called()

    def test_config_directory_is_rejected_for_non_claude_providers(self) -> None:
        for provider in ("codex", "kimi"):
            with self.subTest(provider=provider):
                with mock.patch.object(provider_probe.subprocess, "Popen") as popen:
                    with self.assertRaisesRegex(
                        provider_probe.ProbeError,
                        "^config-directory-not-applicable$",
                    ):
                        provider_probe.validate_config(
                            provider_probe.ProbeConfig(
                                provider=provider,
                                capture_root=self.capture_root,
                                capture_id=f"capture-{provider}-config",
                                provider_executable=Path("/does/not/exist"),
                                workspace=self.workspace,
                                config_dir=self.config_dir,
                            )
                        )
                popen.assert_not_called()

    def test_strict_json_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        for raw in (b'{"id":1,"id":2}', b'{"value":NaN}'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(
                    provider_probe.ProbeError, "^protocol-json-invalid$"
                ):
                    provider_probe.strict_message(raw)

    def test_workspace_must_be_empty_private_and_separate(self) -> None:
        executable = self.base / "unused"
        (self.workspace / "private.txt").write_text("private", encoding="utf-8")
        with self.assertRaisesRegex(provider_probe.ProbeError, "^workspace-not-empty$"):
            provider_probe.validate_config(
                self.config("codex", executable, "capture-workspace-not-empty")
            )
        self.workspace.joinpath("private.txt").unlink()
        self.workspace.chmod(0o755)
        with self.assertRaisesRegex(
            provider_probe.ProbeError, "^private-directory-invalid$"
        ):
            provider_probe.validate_config(
                self.config("codex", executable, "capture-workspace-mode")
            )

    def test_new_script_has_only_standard_library_imports(self) -> None:
        import ast

        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module != "__future__"
        )
        self.assertTrue(imports <= set(sys.stdlib_module_names), imports)


if __name__ == "__main__":
    unittest.main()
