from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from dataclasses import replace
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
    sys.stdout.write("codex-cli 0.162.1\\n")
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


def fake_claude(
    path: Path,
    workspace: Path,
    config_dir: Path,
    *,
    oauth_payload_sha256: str | None = None,
    unrelated_descriptor: int | None = None,
    outcome: str = "complete",
    hook_permission_mode: str = "default",
    session_start_fields: dict[str, object] | None = None,
) -> Path:
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
        "default",
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
import hashlib
import json
import os
import subprocess
import sys
import time

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
    sys.stdout.write("2.1.283 (Claude Code)\\n")
    fail(0)
oauth_fd = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR")
expected_oauth_sha256 = {oauth_payload_sha256!r}
if expected_oauth_sha256 is None:
    if oauth_fd is not None:
        fail(96)
else:
    if oauth_fd is None or not oauth_fd.isascii() or not oauth_fd.isdecimal() or int(oauth_fd) < 3:
        fail(96)
    payload = bytearray()
    while True:
        chunk = os.read(int(oauth_fd), 4096)
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > 4096:
            fail(97)
    os.close(int(oauth_fd))
    if hashlib.sha256(payload).hexdigest() != expected_oauth_sha256:
        fail(97)
    if any(payload.decode("ascii") in value for value in (*sys.argv, *os.environ.values())):
        fail(97)
unrelated_descriptor = {unrelated_descriptor!r}
if unrelated_descriptor is not None:
    try:
        os.fstat(unrelated_descriptor)
    except OSError:
        pass
    else:
        fail(98)
if {outcome!r} == "fail":
    sys.stdin.buffer.read()
    fail(99)
if {outcome!r} == "timeout":
    sys.stdin.buffer.read()
    time.sleep(60)
arguments = sys.argv[1:]
if arguments != {expected_arguments!r}:
    fail(88)
if os.environ.get("CLAUDE_CONFIG_DIR") != {str(config_dir)!r}:
    fail(93)
if os.environ.get("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB") != "1":
    fail(94)
for name in (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_USE_MANTLE",
    "CLAUDE_CODE_REMOTE",
    "CLAUDE_SECURESTORAGE_CONFIG_DIR",
    "CLAUDE_CODE_IS_COWORK",
    "CLAUDE_AGENT_SDK_VERSION",
    "CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD",
    "CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING",
    "CLAUDE_CODE_BACKGROUND_SESSION_ID",
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
}}
run_hook(settings, "SessionStart", {{**common, "hook_event_name":"SessionStart", "source":"startup", **{(session_start_fields or {})!r}}})
common["permission_mode"] = {hook_permission_mode!r}
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
    sys.stdout.write("2.1.283 (Claude Code)\\n")
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


def fake_cancellable_provider(
    path: Path,
    process_group_path: Path,
    ready_path: Path,
    cleanup_path: Path,
    *,
    provider: str,
    oauth_payload_sha256: str | None,
) -> Path:
    source = f'''#!/usr/bin/env python3
import hashlib
import os
import signal
import subprocess
import sys
import time

def publish(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as destination:
        destination.write(value)

def cancel(_number, _frame):
    if not os.path.exists({str(cleanup_path)!r}):
        publish({str(cleanup_path)!r}, "cleanup")

if sys.argv[1:] == ["--version"]:
    sys.stdout.write({('2.1.283 (Claude Code)' if provider == 'claude' else 'codex-cli 0.162.1')!r} + "\\n")
    raise SystemExit(0)
publish({str(process_group_path)!r}, str(os.getpgrp()))
signal.signal(signal.SIGTERM, cancel)
if {oauth_payload_sha256!r} is not None:
    descriptor = int(os.environ["CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR"])
    payload = bytearray()
    while not payload.endswith(b"\\n"):
        chunk = os.read(descriptor, 4096)
        if not chunk or len(payload) + len(chunk) > 4096:
            raise SystemExit(81)
        payload.extend(chunk)
    os.close(descriptor)
    if hashlib.sha256(payload[:-1]).hexdigest() != {oauth_payload_sha256!r}:
        raise SystemExit(82)
elif "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR" in os.environ:
    raise SystemExit(83)
child = subprocess.Popen(
    [sys.executable, "-B", "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready', flush=True); time.sleep(60)"],
    stdout=subprocess.PIPE,
    close_fds=True,
)
if child.stdout.readline() != b"ready\\n":
    raise SystemExit(84)
publish({str(ready_path)!r}, str(child.pid))
while True:
    time.sleep(60)
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
    sys.stdout.write("codex-cli 0.162.1\\n")
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
        self.assertEqual(result.provider_version, "2.1.283")
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
        self.assertEqual(result.provider_version, "0.162.1")
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


class ClaudeHookValidationTests(ProbeDirectoryTestCase):
    def test_probe_rejects_hook_permission_mode_drift(self) -> None:
        executable = fake_claude(
            self.base / "fake-claude", self.workspace, self.config_dir,
            hook_permission_mode="dontAsk",
        )
        with self.pinned_manifest("claude", executable):
            with self.assertRaisesRegex(provider_probe.ProbeError, "^capture-event-invalid$"):
                provider_probe.run_probe(
                    self.config("claude", executable, "capture-claude-mode-drift")
                )

    def test_accepts_matching_optional_start_metadata(self) -> None:
        executable = fake_claude(
            self.base / "fake-claude", self.workspace, self.config_dir,
            session_start_fields={"model": provider_probe.CLAUDE_MODEL, "permission_mode": "default"},
        )
        with self.pinned_manifest("claude", executable):
            result = provider_probe.run_probe(
                self.config("claude", executable, "capture-claude-start-metadata")
            )
        self.assertEqual(result.message_count, 3)

    def assert_start_metadata_rejected(self, fields: dict[str, object]) -> None:
        executable = fake_claude(
            self.base / "fake-claude", self.workspace, self.config_dir,
            session_start_fields=fields,
        )
        with self.pinned_manifest("claude", executable):
            with self.assertRaisesRegex(provider_probe.ProbeError, "^capture-event-invalid$"):
                provider_probe.run_probe(
                    self.config("claude", executable, "capture-claude-start-invalid")
                )

    def test_rejects_conflicting_start_model(self) -> None:
        self.assert_start_metadata_rejected({"model": "unexpected-model"})

    def test_rejects_explicit_null_start_model(self) -> None:
        self.assert_start_metadata_rejected({"model": None})

    def test_rejects_conflicting_start_permission_mode(self) -> None:
        self.assert_start_metadata_rejected({"permission_mode": "dontAsk"})


class OAuthDescriptorTests(ProbeDirectoryTestCase):
    payload = b"synthetic-socket-only-oauth-sentinel"

    def oauth_config(self, executable: Path, descriptor: int) -> object:
        return replace(
            self.config("claude", executable, "capture-claude-oauth"),
            oauth_fd=descriptor,
        )

    def arguments(self, descriptor: str) -> tuple[str, ...]:
        return (
            "--provider", "claude",
            "--capture-root", str(self.capture_root),
            "--capture-id", "capture-claude-oauth",
            "--provider-executable", str(self.base / "fake-claude"),
            "--workspace", str(self.workspace),
            "--config-dir", str(self.config_dir),
            "--oauth-fd", descriptor,
        )

    def assert_closed(self, descriptor: int) -> None:
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def assert_no_persisted_payload(self) -> None:
        for path in self.base.rglob("*"):
            if path.is_file():
                self.assertNotIn(self.payload, path.read_bytes(), str(path))

    def open_descriptors(self) -> set[int]:
        result = set()
        for name in os.listdir("/dev/fd"):
            if name.isdecimal():
                descriptor = int(name)
                try:
                    os.fstat(descriptor)
                except OSError:
                    continue
                result.add(descriptor)
        return result

    def test_child_reads_only_owned_socket_without_persisting_payload(self) -> None:
        with contextlib.ExitStack() as stack:
            source, destination = socket.socketpair()
            unrelated, unrelated_peer = socket.socketpair()
            for connection in (source, destination, unrelated, unrelated_peer):
                stack.enter_context(connection)
            source.sendall(self.payload)
            source.shutdown(socket.SHUT_WR)
            os.set_inheritable(unrelated.fileno(), True)
            executable = fake_claude(
                self.base / "fake-claude", self.workspace, self.config_dir,
                oauth_payload_sha256=hashlib.sha256(self.payload).hexdigest(),
                unrelated_descriptor=unrelated.fileno(),
            )
            inherited = []
            popen = provider_probe.subprocess.Popen
            matches = provider_probe._executable_matches
            prompt_closure_checks = []

            def spawn(*args, **kwargs):
                passed = kwargs.get("pass_fds", ())
                self.assertEqual(len(passed), 1)
                self.assertIs(kwargs["close_fds"], True)
                self.assertNotEqual(passed[0], destination.fileno())
                self.assertEqual(
                    kwargs["env"]["CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR"],
                    str(passed[0]),
                )
                self.assertNotIn(self.payload.decode("ascii"), repr(args))
                self.assertNotIn(self.payload.decode("ascii"), repr(kwargs["env"]))
                os.fstat(passed[0])
                inherited.append(passed[0])
                return popen(*args, **kwargs)

            def verify_closed_after_spawn(pinned):
                if inherited:
                    self.assert_closed(inherited[0])
                    prompt_closure_checks.append(True)
                return matches(pinned)

            forbidden = {
                "ANTHROPIC_API_KEY": "host-value",
                "ANTHROPIC_AUTH_TOKEN": "host-value",
                "CLAUDE_CODE_OAUTH_TOKEN": "host-value",
                "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR": "999999",
                "CLAUDE_CODE_REMOTE": "host-value",
                "CLAUDE_SECURESTORAGE_CONFIG_DIR": "host-value",
                "CLAUDE_CODE_IS_COWORK": "host-value",
                "CLAUDE_AGENT_SDK_VERSION": "host-value",
                "CLAUDE_CODE_ADDITIONAL_DIRECTORIES_CLAUDE_MD": "host-value",
                "CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING": "host-value",
                "CLAUDE_CODE_BACKGROUND_SESSION_ID": "host-value",
            }
            with self.pinned_manifest("claude", executable), mock.patch.dict(
                os.environ, forbidden
            ), mock.patch.object(
                provider_probe.subprocess, "Popen", side_effect=spawn
            ), mock.patch.object(
                provider_probe, "_executable_matches", side_effect=verify_closed_after_spawn
            ):
                result = provider_probe.run_probe(
                    self.oauth_config(executable, destination.fileno())
                )
                self.assertEqual(
                    os.environ["CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR"], "999999"
                )
            self.assertEqual(result.message_count, 3)
            self.assertEqual(len(inherited), 1)
            self.assertTrue(prompt_closure_checks)
            self.assert_closed(inherited[0])
            os.fstat(destination.fileno())
            for suffix in provider_probe.CLAUDE_CAPTURE_SUFFIXES:
                receipt = self.receipt(f"capture-claude-oauth-{suffix}")
                self.assertEqual(receipt["capture_status"], "complete")
            self.assert_no_persisted_payload()

    def test_default_does_not_inherit_host_oauth_descriptor_or_open_socket(self) -> None:
        unrelated, unrelated_peer = socket.socketpair()
        with unrelated, unrelated_peer:
            os.set_inheritable(unrelated.fileno(), True)
            executable = fake_claude(
                self.base / "fake-claude", self.workspace, self.config_dir,
                unrelated_descriptor=unrelated.fileno(),
            )
            popen = provider_probe.subprocess.Popen

            def spawn(*args, **kwargs):
                self.assertEqual(kwargs.get("pass_fds", ()), ())
                self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", kwargs["env"])
                self.assertIs(kwargs["close_fds"], True)
                return popen(*args, **kwargs)

            with self.pinned_manifest("claude", executable), mock.patch.dict(
                os.environ,
                {"CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR": str(unrelated.fileno())},
            ), mock.patch.object(provider_probe.subprocess, "Popen", side_effect=spawn):
                result = provider_probe.run_probe(
                    self.config("claude", executable, "capture-claude-no-oauth")
                )
            self.assertEqual(result.message_count, 3)
            os.fstat(unrelated.fileno())

    def test_api_rejects_non_integer_and_stdio_descriptors_before_spawn(self) -> None:
        for value in (True, False, -1, 0, 1, 2, 3.0, "3", [], {}):
            with self.subTest(value=value), mock.patch.object(
                provider_probe.subprocess, "Popen"
            ) as popen:
                with self.assertRaisesRegex(provider_probe.ProbeError, "^oauth-fd-invalid$"):
                    provider_probe.run_probe(
                        self.oauth_config(self.base / "unused", value)
                    )
                popen.assert_not_called()

    def test_api_rejects_other_providers_without_closing_caller_socket(self) -> None:
        source, destination = socket.socketpair()
        with source, destination:
            for provider in ("codex", "kimi"):
                with self.subTest(provider=provider), mock.patch.object(
                    provider_probe.subprocess, "Popen"
                ) as popen:
                    config = replace(
                        self.config(provider, self.base / "unused", "capture-other-oauth"),
                        oauth_fd=destination.fileno(),
                    )
                    with self.assertRaisesRegex(
                        provider_probe.ProbeError, "^oauth-fd-not-applicable$"
                    ):
                        provider_probe.run_probe(config)
                    popen.assert_not_called()
                    os.fstat(destination.fileno())

    def test_api_rejects_regular_file_and_pipe_without_consuming_them(self) -> None:
        with tempfile.TemporaryFile(dir=self.base) as regular:
            regular.write(self.payload)
            regular.seek(0)
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, self.payload)
                for descriptor in (regular.fileno(), read_fd, write_fd):
                    with self.subTest(descriptor=descriptor), mock.patch.object(
                        provider_probe.subprocess, "Popen"
                    ) as popen:
                        with self.assertRaisesRegex(
                            provider_probe.ProbeError, "^oauth-fd-invalid$"
                        ):
                            provider_probe.run_probe(
                                self.oauth_config(self.base / "unused", descriptor)
                            )
                        popen.assert_not_called()
                        os.fstat(descriptor)
                self.assertEqual(regular.read(), self.payload)
                self.assertEqual(os.read(read_fd, len(self.payload)), self.payload)
            finally:
                os.close(read_fd)
                os.close(write_fd)

    def test_api_rejects_closed_descriptor(self) -> None:
        source, destination = socket.socketpair()
        with source:
            descriptor = destination.fileno()
            destination.close()
            with mock.patch.object(provider_probe.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(provider_probe.ProbeError, "^oauth-fd-invalid$"):
                    provider_probe.run_probe(self.oauth_config(self.base / "unused", descriptor))
                popen.assert_not_called()
            self.assert_closed(descriptor)

    def test_api_rejects_unconnected_and_listening_unix_sockets(self) -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            for listening in (False, True):
                if listening:
                    connection.bind(str(self.base / "listener"))
                    connection.listen(1)
                with self.subTest(listening=listening), mock.patch.object(
                    provider_probe.subprocess, "Popen"
                ) as popen:
                    with self.assertRaisesRegex(provider_probe.ProbeError, "^oauth-fd-invalid$"):
                        provider_probe.run_probe(
                            self.oauth_config(self.base / "unused", connection.fileno())
                        )
                    popen.assert_not_called()
                    os.fstat(connection.fileno())

    def test_api_rejects_connected_unix_datagram_socket(self) -> None:
        source, destination = socket.socketpair(type=socket.SOCK_DGRAM)
        with source, destination, mock.patch.object(provider_probe.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(provider_probe.ProbeError, "^oauth-fd-invalid$"):
                provider_probe.run_probe(
                    self.oauth_config(self.base / "unused", destination.fileno())
                )
            popen.assert_not_called()
            os.fstat(destination.fileno())

    def test_api_rejects_connected_inet_socket(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            with socket.create_connection(listener.getsockname(), timeout=1) as source:
                destination, _address = listener.accept()
                with destination, mock.patch.object(provider_probe.subprocess, "Popen") as popen:
                    with self.assertRaisesRegex(provider_probe.ProbeError, "^oauth-fd-invalid$"):
                        provider_probe.run_probe(
                            self.oauth_config(self.base / "unused", destination.fileno())
                        )
                    popen.assert_not_called()
                    os.fstat(destination.fileno())

    def assert_failed_provider_closes_duplicate(self, outcome: str, reason: str) -> None:
        source, destination = socket.socketpair()
        with source, destination:
            source.sendall(self.payload)
            source.shutdown(socket.SHUT_WR)
            executable = fake_claude(
                self.base / "fake-claude", self.workspace, self.config_dir,
                oauth_payload_sha256=hashlib.sha256(self.payload).hexdigest(),
                outcome=outcome,
            )
            inherited = []
            popen = provider_probe.subprocess.Popen

            def spawn(*args, **kwargs):
                inherited.extend(kwargs["pass_fds"])
                return popen(*args, **kwargs)

            with self.pinned_manifest("claude", executable), mock.patch.object(
                provider_probe, "TURN_TIMEOUT_SECONDS", 0.5
            ), mock.patch.object(provider_probe.subprocess, "Popen", side_effect=spawn):
                with self.assertRaisesRegex(provider_probe.ProbeError, f"^{reason}$"):
                    provider_probe.run_probe(self.oauth_config(executable, destination.fileno()))
            self.assertEqual(len(inherited), 1)
            self.assert_closed(inherited[0])
            os.fstat(destination.fileno())
            self.assert_no_persisted_payload()

    def test_provider_failure_closes_owned_duplicate_and_preserves_caller_socket(self) -> None:
        self.assert_failed_provider_closes_duplicate("fail", "provider-failed")

    def test_provider_timeout_closes_owned_duplicate_and_preserves_caller_socket(self) -> None:
        self.assert_failed_provider_closes_duplicate("timeout", "provider-timeout")

    def test_spawn_failure_closes_owned_duplicate_and_preserves_caller_socket(self) -> None:
        source, destination = socket.socketpair()
        with source, destination:
            executable = fake_claude(self.base / "fake-claude", self.workspace, self.config_dir)
            inherited = []

            def fail_spawn(*_args, **kwargs):
                inherited.extend(kwargs["pass_fds"])
                os.fstat(inherited[0])
                raise OSError("synthetic private spawn detail")

            with self.pinned_manifest("claude", executable), mock.patch.object(
                provider_probe.subprocess, "Popen", side_effect=fail_spawn
            ):
                with self.assertRaisesRegex(provider_probe.ProbeError, "^provider-spawn-failed$"):
                    provider_probe.run_probe(self.oauth_config(executable, destination.fileno()))
            self.assertEqual(len(inherited), 1)
            self.assert_closed(inherited[0])
            os.fstat(destination.fileno())

    def test_pre_spawn_failure_does_not_leak_duplicate_or_consume_payload(self) -> None:
        source, destination = socket.socketpair()
        with source, destination:
            source.sendall(self.payload)
            before = self.open_descriptors()
            with mock.patch.object(
                provider_probe, "load_executable_manifest",
                side_effect=provider_probe.ProbeError("executable-manifest-invalid"),
            ), mock.patch.object(provider_probe.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(provider_probe.ProbeError, "^executable-manifest-invalid$"):
                    provider_probe.run_probe(self.oauth_config(self.base / "unused", destination.fileno()))
            popen.assert_not_called()
            self.assertEqual(self.open_descriptors(), before)
            self.assertEqual(destination.recv(len(self.payload)), self.payload)

    def test_cli_closes_inherited_descriptor_on_success(self) -> None:
        source, destination = socket.socketpair()
        with source, destination:
            descriptor = destination.detach()
            try:
                with mock.patch.object(provider_probe, "run_probe") as run_probe:
                    self.assertEqual(provider_probe.main(self.arguments(str(descriptor))), 0)
                self.assertEqual(run_probe.call_args.args[0].oauth_fd, descriptor)
                self.assert_closed(descriptor)
            finally:
                with contextlib.suppress(OSError):
                    os.close(descriptor)

    def test_cli_closes_inherited_descriptor_and_redacts_failures(self) -> None:
        for error, expected in (
            (provider_probe.ProbeError("provider-failed"), "provider-failed"),
            (RuntimeError(self.payload.decode("ascii")), "internal-error"),
        ):
            source, destination = socket.socketpair()
            with self.subTest(error=type(error).__name__), source, destination:
                descriptor = destination.detach()
                try:
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with mock.patch.object(provider_probe, "run_probe", side_effect=error):
                        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                            self.assertEqual(provider_probe.main(self.arguments(str(descriptor))), 1)
                    self.assert_closed(descriptor)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertEqual(stderr.getvalue(), f"provider_probe.py: {expected}\n")
                    self.assertNotIn(self.payload.decode("ascii"), stderr.getvalue())
                finally:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)

    def test_cli_rejects_non_decimal_descriptor_without_echoing_argument(self) -> None:
        for value in ("synthetic-private-token", "3.0", "+3", " 3", "٣", "-1"):
            with self.subTest(value=value), mock.patch.object(provider_probe, "run_probe") as run_probe:
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                    provider_probe.main(self.arguments(value))
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("error: invalid arguments", stderr.getvalue())
                self.assertNotIn(value, stderr.getvalue())
                run_probe.assert_not_called()

    def test_cli_parse_failure_closes_already_recognized_inherited_descriptor(self) -> None:
        source, destination = socket.socketpair()
        with source, destination:
            descriptor = destination.detach()
            try:
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                    provider_probe.main((*self.arguments(str(descriptor)), "--synthetic-private-argument"))
                self.assertEqual(raised.exception.code, 2)
                self.assertNotIn("synthetic-private-argument", stderr.getvalue())
                self.assert_closed(descriptor)
            finally:
                with contextlib.suppress(OSError):
                    os.close(descriptor)

    def test_cli_never_closes_stdio(self) -> None:
        for descriptor in (0, 1, 2):
            with self.subTest(descriptor=descriptor):
                before = os.fstat(descriptor)
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    try:
                        code = provider_probe.main(self.arguments(str(descriptor)))
                    except SystemExit as error:
                        code = error.code
                self.assertIn(code, (1, 2))
                self.assertEqual(os.fstat(descriptor), before)


class CliCancellationTests(ProbeDirectoryTestCase):
    def assert_cli_cancellation(
        self,
        number: int,
        *,
        repeated: bool = False,
        during_spawn: bool = False,
        provider: str = "claude",
    ) -> None:
        payload = b"synthetic-cancellation-socket-only-sentinel"
        process_group_path = self.base / "provider-group"
        ready_path = self.base / "provider-ready"
        cleanup_path = self.base / "provider-cleanup"
        result_path = self.base / "cli-result.json"
        executable = fake_cancellable_provider(
            self.base / "fake-provider",
            process_group_path,
            ready_path,
            cleanup_path,
            provider=provider,
            oauth_payload_sha256=(
                hashlib.sha256(payload).hexdigest() if provider == "claude" else None
            ),
        )
        source, destination = socket.socketpair()
        descriptor = destination.fileno()
        arguments = [
            "--provider", provider,
            "--capture-root", str(self.capture_root),
            "--capture-id", "capture-cancellation",
            "--provider-executable", str(executable),
            "--workspace", str(self.workspace),
        ]
        if provider == "claude":
            arguments.extend((
                "--config-dir", str(self.config_dir),
                "--oauth-fd", str(descriptor),
            ))
        process = None
        try:
            with self.pinned_manifest(provider, executable):
                manifest_path = provider_probe.EXECUTABLE_MANIFEST_PATH
                driver = self.base / "run-cli.py"
                driver.write_text(f'''
import importlib.util
import json
import os
import signal
import sys
import time
from pathlib import Path

spec = importlib.util.spec_from_file_location("provider_probe", {str(SCRIPT_PATH)!r})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.EXECUTABLE_MANIFEST_PATH = Path({str(manifest_path)!r})
module.COLLECTOR_SIGNAL_TIMEOUT_SECONDS = 0.4
module.COLLECTOR_TIMEOUT_SECONDS = 1
module.ABORT_TIMEOUT_SECONDS = 0.05
handled = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
def previous(_number, _frame):
    return None
for signum in handled:
    signal.signal(signum, previous)
original_popen = module.subprocess.Popen
def spawning(*args, **kwargs):
    child = original_popen(*args, **kwargs)
    deadline = time.monotonic() + 4.0
    while not Path({str(ready_path)!r}).exists() and child.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    os.kill(os.getpid(), {int(number)!r})
    return child
if {during_spawn!r}:
    module.subprocess.Popen = spawning
code = module.main({arguments!r})
closed = True
if {provider!r} == "claude":
    try:
        os.fstat({descriptor!r})
        closed = False
    except OSError:
        pass
result = {{"code": code, "descriptor_closed": closed,
          "handlers_restored": all(signal.getsignal(signum) is previous for signum in handled)}}
output = os.open({str(result_path)!r}, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(output, "w", encoding="ascii") as destination:
    json.dump(result, destination)
raise SystemExit(code)
''', encoding="utf-8")
                driver.chmod(0o600)
                source.sendall(payload + b"\n")
                source.shutdown(socket.SHUT_WR)
                process = subprocess.Popen(
                    [sys.executable, "-B", str(driver)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    pass_fds=(descriptor,) if provider == "claude" else (),
                    start_new_session=True,
                    env={
                        "HOME": str(self.base),
                        "PATH": os.environ.get("PATH", os.defpath),
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                )
                destination.close()
                deadline = time.monotonic() + 5.0
                while not ready_path.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not ready_path.exists() and process.poll() is not None:
                    _stdout, failure = process.communicate(timeout=1.0)
                    self.fail(f"fake provider did not become ready: {failure!r}")
                self.assertTrue(ready_path.exists(), "fake provider did not become ready")
                if not during_spawn:
                    os.kill(process.pid, number)
                if repeated:
                    deadline = time.monotonic() + 2.0
                    while not cleanup_path.exists() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(cleanup_path.exists(), "provider cleanup did not start")
                    for repeated_number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM) * 3:
                        if process.poll() is not None:
                            break
                        os.kill(process.pid, repeated_number)
                        time.sleep(0.01)
                stdout, stderr = process.communicate(timeout=8.0)
            self.assertEqual(process.returncode, 1)
            self.assertEqual(stdout, b"")
            self.assertEqual(stderr, b"provider_probe.py: probe-cancelled\n")
            self.assertEqual(
                json.loads(result_path.read_text(encoding="ascii")),
                {"code": 1, "descriptor_closed": True, "handlers_restored": True},
            )
            process_group_id = int(process_group_path.read_text(encoding="ascii"))
            with self.assertRaises(ProcessLookupError):
                os.killpg(process_group_id, 0)
            self.assertEqual(list(self.config_dir.glob(".clilane-provider-stage-*")), [])
            source.settimeout(0.5)
            if provider == "claude":
                self.assertEqual(source.recv(1), b"")
            for directory in (self.config_dir, self.capture_root):
                for path in directory.rglob("*"):
                    if path.is_file():
                        self.assertNotIn(payload, path.read_bytes())
        finally:
            destination.close()
            source.close()
            if process_group_path.exists():
                process_group_id = int(process_group_path.read_text(encoding="ascii"))
                try:
                    os.killpg(process_group_id, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=3.0)

    def test_sigterm_cleans_provider_descendant_socket_and_staged_executable(self) -> None:
        self.assert_cli_cancellation(signal.SIGTERM)

    def test_sighup_cleans_provider_descendant_socket_and_staged_executable(self) -> None:
        self.assert_cli_cancellation(signal.SIGHUP)

    def test_sigint_cleans_provider_descendant_socket_and_staged_executable(self) -> None:
        self.assert_cli_cancellation(signal.SIGINT)

    def test_repeated_signals_do_not_interrupt_process_group_cleanup(self) -> None:
        self.assert_cli_cancellation(signal.SIGTERM, repeated=True)

    def test_signal_before_spawn_returns_preserves_child_ownership(self) -> None:
        self.assert_cli_cancellation(signal.SIGHUP, during_spawn=True)

    def test_auth_free_codex_cancellation_cleans_collector_and_provider(self) -> None:
        self.assert_cli_cancellation(signal.SIGTERM, provider="codex")


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
