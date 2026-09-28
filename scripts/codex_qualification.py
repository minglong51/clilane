from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import select
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from codex_analysis import valid_account_update
from codex_observer import (
    FRESHNESS_NS, Journal, ObserverError, TaskBinding, _encode, _read_private,
)
from provider_evidence import EvidenceError, analyze_codex_capture
from provider_probe import (
    MAX_LINE_BYTES, PER_CAPTURE_BYTES, ProbeConfig, ProbeError, SafeArgumentParser,
    JsonLineTransport, PinnedExecutable, _private_directory, _write_private_bytes,
    load_executable_manifest, pin_executable, sanitized_environment, strict_message,
)
from provider_capture import iter_capture_frames, repository_paths, validate_capture_root


CAPTURE_ID = "capture-codex-input-recovery"
INPUT_METHOD = "item/tool/requestUserInput"
PERMISSIONS_METHOD = "item/permissions/requestApproval"
COMMAND_METHOD = "item/commandExecution/requestApproval"
FILE_METHOD = "item/fileChange/requestApproval"
SCENARIOS = {
    "input": INPUT_METHOD, "permissions": PERMISSIONS_METHOD,
    "command": COMMAND_METHOD, "file": FILE_METHOD,
}
PROMPT = (
    "This is a synthetic protocol probe. Call request_user_input exactly once, "
    "with one question asking whether to choose Alpha or Beta and those two options. "
    "Do not call any other tool. After the response, reply with exactly "
    "CLILANE_PROBE_OK and end the turn."
)
PERMISSIONS_PROMPT = (
    "This is a synthetic protocol probe. Call request_permissions exactly once, "
    "asking only for network access. Do not access the network, run a command, "
    "read or write a file, or call any other tool. The permission request will be denied. "
    "After the response, reply with exactly CLILANE_PROBE_OK and end the turn."
)
DISABLED_FEATURES = (
    "hooks", "plugins", "apps", "browser_use", "browser_use_external",
    "browser_use_full_cdp_access", "computer_use", "in_app_browser", "image_generation",
    "multi_agent", "multi_agent_v2", "shell_tool", "shell_snapshot", "skill_search",
    "skill_mcp_dependency_install", "memories", "goals", "sleep_tool", "view_image",
    "remote_plugin", "external_migration", "external_agent_memory_import", "tool_suggest",
    "auth_elicitation", "enable_mcp_apps", "workspace_dependencies",
)
CONFIG = (
    'project_doc_max_bytes = 0\ncli_auth_credentials_store = "file"\n'
    'sandbox_mode = "read-only"\napproval_policy = "never"\nweb_search = "disabled"\n'
    'history.persistence = "none"\nskills.include_instructions = false\n'
    'skills.bundled.enabled = false\n[features]\ncode_mode_host = true\n'
    + "".join(f"{feature} = false\n" for feature in DISABLED_FEATURES)
)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ProbeError(code)


class Cancellation:
    def __init__(self) -> None:
        self.cleanup: Callable[[], None] | None = None
        self.previous: dict[int, Any] = {}
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            self.previous[number] = signal.signal(number, self.handle)

    def handle(self, _number: int, _frame: Any) -> None:
        for number in self.previous:
            signal.signal(number, signal.SIG_IGN)
        if self.cleanup is not None:
            self.cleanup()
        raise ProbeError("qualification-cancelled")

    def close(self) -> None:
        for number, previous in self.previous.items():
            signal.signal(number, previous)


def remove_credentials(path: Path, identity: os.stat_result) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    require((current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino),
            "credential-copy-replaced")
    path.unlink()


def environment(config: Path, temporary: Path) -> dict[str, str]:
    result = {
        key: os.environ[key] for key in ("HOME", "PATH", "USER", "LOGNAME", "LANG")
        if key in os.environ
    }
    result.update(CODEX_HOME=str(config), TMPDIR=str(temporary))
    return sanitized_environment(result)


def initialize(transport: Any) -> None:
    transport.send({
        "id": "probe-init", "method": "initialize",
        "params": {
            "clientInfo": {"name": "clilane_qualification", "version": "1"},
            "capabilities": {"experimentalApi": True},
        },
    })
    response(transport, "probe-init")
    transport.send({"method": "initialized"})


def response(transport: Any, identity: str) -> dict[str, Any]:
    deadline = time.monotonic() + 20
    while True:
        message = transport.receive(deadline)
        require("jsonrpc" not in message, "protocol-envelope-invalid")
        if "method" in message:
            require("id" not in message, "unexpected-provider-request")
            method = message["method"]
            params = message.get("params")
            require(type(params) is dict, "protocol-params-invalid")
            require(method in {
                "remoteControl/status/changed", "account/rateLimits/updated", "account/updated",
                "thread/started", "thread/status/changed", "thread/settings/updated", "turn/started",
            }, "unexpected-provider-notification")
            if method == "remoteControl/status/changed":
                require(params.get("status") == "disabled", "remote-control-enabled")
            if method == "account/updated":
                require(valid_account_update(params), "invalid-account-update")
            continue
        require(message.get("id") == identity and "error" not in message,
                "protocol-response-mismatch")
        result = message.get("result")
        require(type(result) is dict, "protocol-response-invalid")
        return result


def skills(transport: Any, workspace: Path, *, isolated: bool) -> list[str]:
    transport.send({
        "id": "probe-skills", "method": "skills/list",
        "params": {"cwds": [str(workspace)], "forceReload": True},
    })
    data = response(transport, "probe-skills").get("data")
    require(type(data) is list and len(data) == 1 and type(data[0]) is dict,
            "skills-preflight-invalid")
    entry = data[0]
    entries = entry.get("skills")
    require(entry.get("cwd") == str(workspace) and entry.get("errors") == []
            and type(entries) is list and len(entries) <= 256, "skills-preflight-invalid")
    paths = []
    for skill in entries:
        require(type(skill) is dict and type(skill.get("enabled")) is bool,
                "skills-preflight-invalid")
        path = skill.get("path")
        require(type(path) is str and path.startswith("/") and "\0" not in path
                and len(path) <= 4096, "skills-preflight-invalid")
        require(not isolated or skill["enabled"] is False, "host-skills-enabled")
        paths.append(path)
    return sorted(set(paths))


def preflight(
    root: Path, pinned: PinnedExecutable, config: Path, capture_id: str, *, isolated: bool,
) -> list[str]:
    spec = ProbeConfig("codex", root / "preflight-captures", capture_id, pinned.path,
                       root / "workspace")
    transport = JsonLineTransport(spec, pinned, environment=environment(config, root / "tmp"))
    try:
        initialize(transport)
        paths = skills(transport, spec.workspace, isolated=isolated)
        transport.finish()
        return paths
    except BaseException:
        transport.abort()
        raise
    finally:
        transport.close()


class ObserverClient:
    def __init__(self, binding: TaskBinding, path: Path, digest: str) -> None:
        self.binding = binding
        self.buffer = bytearray()
        child_environment = sanitized_environment({
            key: os.environ[key] for key in ("HOME", "PATH", "USER", "LOGNAME", "LANG")
            if key in os.environ
        })
        child_environment.update({
            key: os.environ[key]
            for key in ("CLILANE_STATE_HOME", "CLILANE_TMUX_SOCKET", "CLILANE_TASK_ID")
        })
        self.process = subprocess.Popen(
            [sys.executable, "-B", str(Path(__file__).with_name("codex_observer.py")),
             "--journal", str(path), "--journal-sha256", digest],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=child_environment, cwd="/", close_fds=True, start_new_session=True, bufsize=0,
        )
        try:
            os.set_blocking(self.process.stdin.fileno(), False)
            startup = self.read()
            require(startup.get("task_generation") == binding.generation
                    and type(startup.get("instance")) is str
                    and type(startup.get("report")) is dict, "observer-startup-invalid")
            self.instance = startup["instance"]
            self.initial = startup["report"]
        except BaseException:
            self.close()
            raise

    def read(self) -> dict[str, Any]:
        require(self.process.stdout is not None, "observer-pipe-invalid")
        deadline = time.monotonic() + 5
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            require(remaining > 0 and bool(select.select(
                [self.process.stdout], [], [], max(remaining, 0)
            )[0]), "observer-timeout")
            chunk = os.read(self.process.stdout.fileno(), 4096)
            require(bool(chunk), "observer-exited")
            self.buffer.extend(chunk)
            require(len(self.buffer) <= MAX_LINE_BYTES, "observer-output-limit")
        end = self.buffer.index(b"\n")
        raw = bytes(self.buffer[:end])
        del self.buffer[:end + 1]
        return strict_message(raw)

    def command(self, operation: str, **fields: Any) -> dict[str, Any]:
        require(self.process.stdin is not None and self.process.poll() is None,
                "observer-not-running")
        raw = _encode({"op": operation, "task_generation": self.binding.generation,
                       "instance": self.instance, **fields})
        require(len(raw) <= 128 * 1024, "observer-input-limit")
        deadline = time.monotonic() + 5
        pending = memoryview(raw)
        while pending:
            remaining = deadline - time.monotonic()
            require(remaining > 0 and bool(select.select(
                [], [self.process.stdin], [], max(remaining, 0)
            )[1]), "observer-input-timeout")
            written = os.write(self.process.stdin.fileno(), pending)
            require(written > 0, "observer-input-failed")
            pending = pending[written:]
        return self.read()

    def ok(self, operation: str, **fields: Any) -> dict[str, Any]:
        reply = self.command(operation, **fields)
        require(reply.get("ok") is True and type(reply.get("report")) is dict,
                "observer-command-rejected")
        return reply["report"]

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        for pipe in (self.process.stdin, self.process.stdout):
            if pipe is not None:
                pipe.close()


class Broker:
    def __init__(
        self, transport: JsonLineTransport, binding: TaskBinding, path: Path,
        *, scenario_name: str = "input", workspace: Path | None = None,
    ) -> None:
        require(scenario_name in SCENARIOS, "scenario-invalid")
        require(scenario_name not in {"command", "file"} or workspace is not None,
                "scenario-workspace-required")
        self.scenario_name = scenario_name
        self.request_method = SCENARIOS[scenario_name]
        self.workspace = workspace
        self.tool_item_id: str | None = None
        self.tool_request_id: str | int | None = None
        self.denial_sent = False
        self.tool_declined = False
        self.transport = transport
        self.binding = binding
        self.path = path
        self.started_ns = time.monotonic_ns()
        self.journal = Journal(path, binding)
        self.observer: ObserverClient | None = None
        try:
            self.observer = ObserverClient(binding, path, self.journal.digest.hexdigest())
        except BaseException:
            self.journal.close()
            raise

    def observe(self, stream: str, message: dict[str, Any]) -> None:
        observed_ns = time.monotonic_ns() - self.started_ns
        self.journal.append(stream, observed_ns, message)
        self.observer.ok("observe", stream=stream, observed_ns=observed_ns, message=message)

    def send(self, message: dict[str, Any]) -> None:
        if self.tool_request_id is not None and message.get("id") == self.tool_request_id:
            require(message == {"id": self.tool_request_id, "result": {"decision": "decline"}}
                    and not self.denial_sent, "invalid-denial-response")
            self.denial_sent = True
        self.transport.send(message)
        self.observe("I", message)

    def receive(self, deadline: float) -> dict[str, Any]:
        message = self.transport.receive(deadline)
        params = message.get("params", {})
        require("jsonrpc" not in message and type(params) is dict, "protocol-envelope-invalid")
        if "method" in message and "id" in message:
            require(message["method"] == self.request_method, "unexpected-provider-request")
            if self.scenario_name in {"command", "file"}:
                require(self.tool_request_id is None, "duplicate-approval-request")
                action_request(params, self.workspace, self.scenario_name, self.tool_item_id)
                self.tool_request_id = message["id"]
        if message.get("method") in {"item/started", "item/completed"}:
            item = params.get("item")
            require(type(item) is dict, "provider-item-invalid")
            if item.get("type") not in {"userMessage", "agentMessage", "reasoning", "plan"}:
                require(self.scenario_name in {"command", "file"}, "provider-side-effect-attempt")
                action_item(item, self.workspace, self.scenario_name)
                if message["method"] == "item/started":
                    require(self.tool_item_id is None and item.get("status") == "inProgress",
                            "unexpected-action-start")
                    self.tool_item_id = item["id"]
                else:
                    require(item["id"] == self.tool_item_id and self.denial_sent
                            and not self.tool_declined and item.get("status") == "declined",
                            "action-not-declined")
                    self.tool_declined = True
        require(message.get("method") != "item/commandExecution/outputDelta",
                "unexpected-command-output")
        require(message.get("method") != "warning", "provider-warning")
        self.observe("O", message)
        return message

    def read_thread(self, thread_id: str, identity: str) -> None:
        self.send({"id": identity, "method": "thread/read",
                   "params": {"threadId": thread_id, "includeTurns": False}})
        response(self, identity)

    def restart(self) -> None:
        self.observer.close()
        self.observer = None
        self.observer = ObserverClient(self.binding, self.path, self.journal.digest.hexdigest())

    def close(self) -> None:
        try:
            if self.observer is not None:
                self.observer.close()
        finally:
            self.journal.close()


def recovery(broker: Broker, thread_id: str, request: dict[str, Any]) -> dict[str, bool]:
    observer = broker.observer
    broker.read_thread(thread_id, "probe-read-before")
    ready = observer.ok("ready", recovered_count=1)
    require(ready["health"] == "healthy" and len(ready["unresolved_requests"]) == 1,
            "observer-not-ready")
    for fields, expected in (
        ({"task_generation": "0" * 64}, "stale-task-generation"),
        ({"instance": "stale-instance"}, "stale-observer-instance"),
    ):
        rejected = observer.command("status", **fields)
        require(rejected == {"ok": False, "error": expected}, "stale-delivery-accepted")
        require(observer.ok("status") == ready, "stale-delivery-mutated-state")
    duplicate = observer.ok("observe", stream="O",
                            observed_ns=time.monotonic_ns() - broker.started_ns, message=request)
    require(duplicate["unresolved_requests"] == ready["unresolved_requests"]
            and duplicate["duplicate_count"] == ready["duplicate_count"] + 1
            and duplicate["fresh_until_monotonic_ns"] == ready["fresh_until_monotonic_ns"],
            "duplicate-delivery-mutated-state")
    delay = (ready["fresh_until_monotonic_ns"] - time.monotonic_ns()) / 1_000_000_000
    if delay > 0:
        time.sleep(delay + 0.02)
    expired = observer.ok("status")
    require(expired["health"] == "unknown" and expired["state"] == "expired",
            "observer-did-not-expire")
    transport = broker.transport
    transport._read_control_available(fail_closed=True)
    provider = transport.active_provider_pgid
    require(provider is not None and transport.control_event_count == 3,
            "provider-lifetime-invalid")
    old_pid, old_instance = observer.process.pid, observer.instance
    broker.restart()
    replacement = broker.observer
    initial = replacement.initial
    require(replacement.process.pid != old_pid and replacement.instance != old_instance,
            "observer-not-restarted")
    require(initial["health"] == "unknown" and initial["state"] == "recovering"
            and initial["unresolved_requests"] == ready["unresolved_requests"]
            and initial["replayed_message_count"] == broker.journal.count,
            "request-not-recovered")
    require(replacement.command("ready", recovered_count=1) == {
        "ok": False, "error": "fresh-source-proof-required",
    }, "replay-renewed-freshness")
    broker.read_thread(thread_id, "probe-read-after")
    renewed = replacement.ok("ready", recovered_count=1)
    require(renewed["health"] == "healthy" and renewed["thread_read_count"] == 2,
            "recovered-observer-not-ready")
    transport._read_control_available(fail_closed=True)
    require(transport.active_provider_pgid == provider and transport.control_event_count == 3
            and transport.process.poll() is None, "provider-restarted")
    return {key: True for key in (
        "stale_delivery_rejected", "duplicate_delivery_noop", "freshness_expired",
        "observer_process_restarted",
        {INPUT_METHOD: "pending_input_recovered", PERMISSIONS_METHOD: "pending_permission_approval_recovered",
         COMMAND_METHOD: "pending_command_approval_recovered", FILE_METHOD: "pending_file_approval_recovered"}[
            broker.request_method],
        "replay_stayed_unknown",
        "fresh_source_read_required", "provider_process_unchanged",
    )}


def permission_request(params: dict[str, Any], workspace: Path) -> None:
    require(set(params) <= {
        "cwd", "environmentId", "itemId", "permissions", "reason", "startedAtMs",
        "threadId", "turnId",
    } and params.get("cwd") == str(workspace)
            and (params.get("environmentId") is None or params["environmentId"] == "local"),
            "permission-request-invalid")
    permissions = params.get("permissions")
    require(type(permissions) is dict and set(permissions) <= {"network", "fileSystem"}
            and permissions.get("fileSystem") is None
            and permissions.get("network") == {"enabled": True}
            and type(permissions["network"]["enabled"]) is bool,
            "unexpected-permissions")
    require(type(params.get("startedAtMs")) is int and 0 < params["startedAtMs"] < 1 << 63
            and (params.get("reason") is None or (
                type(params["reason"]) is str and len(params["reason"]) <= 4096
            )), "permission-request-invalid")


def action_target(workspace: Path, scenario_name: str) -> Path:
    return workspace.parent / ("denied-command" if scenario_name == "command" else "denied-file.txt")


def command_matches(command: Any, target: Path) -> bool:
    if type(command) is not str or len(command) > 4096:
        return False
    try:
        words = shlex.split(command)
        if len(words) == 3 and words[0] in {"/bin/sh", "/bin/bash", "/bin/zsh"} and words[1] in {"-c", "-lc"}:
            words = shlex.split(words[2])
    except ValueError:
        return False
    return words == ["/usr/bin/touch", str(target)]


def action_item(item: dict[str, Any], workspace: Path, scenario_name: str) -> None:
    target = action_target(workspace, scenario_name)
    require(type(item.get("id")) is str and 0 < len(item["id"]) <= 256, "action-identity-invalid")
    if scenario_name == "command":
        require(item.get("type") == "commandExecution" and item.get("cwd") == str(workspace)
                and command_matches(item.get("command"), target)
                and all(item.get(field) is None for field in (
                    "exitCode", "processId", "pluginId", "scriptPath",
                )) and (item.get("durationMs") is None or type(item["durationMs"]) is int and item["durationMs"] == 0),
                "unexpected-command-execution")
        require(item.get("aggregatedOutput") is None or item.get("aggregatedOutput") == "",
                "unexpected-command-output")
    else:
        changes = item.get("changes")
        require(item.get("type") == "fileChange" and type(changes) is list and len(changes) == 1,
                "unexpected-file-change")
        change = changes[0]
        require(type(change) is dict and set(change) == {"path", "kind", "diff"}
                and change["path"] == str(target) and change["kind"] == {"type": "add"}
                and type(change["diff"]) is str
                and change["diff"] in {"CLILANE_PROBE_SENTINEL\n", "+CLILANE_PROBE_SENTINEL\n"},
                "unexpected-file-change")
    require(not os.path.lexists(target), "denied-action-created-target")


def action_request(
    params: dict[str, Any], workspace: Path, scenario_name: str, item_id: str | None,
) -> None:
    require(item_id is not None and params.get("itemId") == item_id
            and type(params.get("startedAtMs")) is int and 0 < params["startedAtMs"] < 1 << 63,
            "action-request-invalid")
    target = action_target(workspace, scenario_name)
    if scenario_name == "command":
        require(set(params) <= {
            "additionalPermissions", "approvalId", "availableDecisions", "command", "commandActions",
            "cwd", "environmentId", "itemId", "kind", "networkApprovalContext",
            "proposedExecpolicyAmendment", "proposedNetworkPolicyAmendments", "reason", "startedAtMs",
            "threadId", "turnId",
        } and params.get("cwd") == str(workspace) and command_matches(params.get("command"), target)
                and params.get("kind", "command") == "command"
                and (params.get("environmentId") is None or params["environmentId"] == "local")
                and params.get("networkApprovalContext") is None,
                "unexpected-command-request")
    else:
        require(set(params) <= {"grantRoot", "itemId", "reason", "startedAtMs", "threadId", "turnId"}
                and (params.get("grantRoot") is None or params["grantRoot"] == str(target.parent)),
                "unexpected-file-request")
    require(not os.path.lexists(target), "denied-action-created-target")


def scenario(broker: Broker, workspace: Path) -> dict[str, bool]:
    permissions = broker.request_method == PERMISSIONS_METHOD
    action = broker.request_method in {COMMAND_METHOD, FILE_METHOD}
    prompt = PERMISSIONS_PROMPT if permissions else PROMPT
    if action:
        target = action_target(workspace, broker.scenario_name)
        require(not os.path.lexists(target), "action-target-exists")
        operation = (
            f"Call exec_command exactly once with cmd={json.dumps('/usr/bin/touch ' + shlex.quote(str(target)))}, "
            "sandbox_permissions=require_escalated and a short justification. "
            if broker.scenario_name == "command" else
            f"Call apply_patch exactly once to add the absolute path {target} containing exactly "
            "CLILANE_PROBE_SENTINEL followed by one newline. "
        )
        prompt = "This is a synthetic approval protocol probe. " + operation + (
            "Request approval; it will be denied. Do not use another tool, run a preliminary command, "
            "or retry after denial. After the denial, reply exactly CLILANE_PROBE_OK and end the turn."
        )
    policy: str | dict[str, Any] = {"granular": {
        "mcp_elicitations": False, "rules": False, "sandbox_approval": action,
        "skill_approval": False, "request_permissions": permissions,
    }} if permissions or action else "never"
    initialize(broker)
    skills(broker, workspace, isolated=True)
    broker.send({"id": "probe-thread", "method": "thread/start", "params": {
        "approvalPolicy": policy, "approvalsReviewer": "user",
        "cwd": str(workspace), "ephemeral": True,
        "sandbox": "read-only", "personality": "none", "developerInstructions": prompt,
    }})
    started = response(broker, "probe-thread")
    thread = started.get("thread")
    model = started.get("model")
    require(type(thread) is dict and type(thread.get("id")) is str and type(model) is str,
            "thread-start-invalid")
    thread_id = thread["id"]
    broker.send({"id": "probe-turn", "method": "turn/start", "params": {
        "threadId": thread_id, "input": [{"type": "text", "text": prompt}],
        "approvalPolicy": policy, "approvalsReviewer": "user",
        "sandboxPolicy": {"type": "readOnly", "networkAccess": False},
        "collaborationMode": {"mode": "default" if permissions or action else "plan", "settings": {
            "model": model, "reasoning_effort": "low", "developer_instructions": prompt,
        }},
    }})
    response(broker, "probe-turn")
    deadline = time.monotonic() + 60
    recovered: dict[str, bool] | None = None
    completed = False
    idle = False
    read_id: str | None = None
    read_sequence = 0
    next_read = deadline
    while not (completed and idle and read_id is None):
        require(time.monotonic() < deadline, "protocol-timeout")
        if recovered is not None and time.monotonic() >= next_read:
            if read_id is None and not (completed and idle):
                read_sequence += 1
                read_id = f"probe-read-live-{read_sequence}"
                broker.send({"id": read_id, "method": "thread/read",
                             "params": {"threadId": thread_id, "includeTurns": False}})
            next_read = time.monotonic() + 1
        try:
            message = broker.receive(min(deadline, next_read))
        except ProbeError as error:
            if recovered is None or str(error) != "protocol-timeout" or time.monotonic() >= deadline:
                raise
            require(broker.observer.ok("status")["health"] == "healthy", "source-freshness-expired")
            continue
        method = message.get("method")
        params = message.get("params", {})
        if "id" in message:
            if method is None:
                require(read_id is not None and message["id"] == read_id
                        and "error" not in message, "protocol-response-mismatch")
                read_id = None
                next_read = time.monotonic() + 1
                continue
            require(method == broker.request_method and recovered is None,
                    "unexpected-provider-request")
            if permissions:
                permission_request(params, workspace)
            elif not action:
                require(params.get("isBlocking") is True
                        and type(params.get("questions")) is list and len(params["questions"]) == 1,
                        "unexpected-input-request")
            recovered = recovery(broker, thread_id, message)
            broker.send({"id": message["id"], "result": {"decision": "decline"} if action else {
                "permissions": {}, "scope": "turn",
            } if permissions else {"answers": {}}})
            next_read = time.monotonic() + 1
        if method == "turn/completed":
            require(params.get("turn", {}).get("status") == "completed", "turn-not-completed")
            completed = True
        if method == "thread/status/changed":
            idle = params.get("status", {}).get("type") == "idle"
    require(recovered is not None, "request-not-observed")
    final = broker.observer.ok("status")
    require(final["unresolved_requests"] == [] and final["unhandled_message_count"] == 0,
            "request-not-resolved")
    recovered["permission_approval_resolved" if permissions else "input_request_resolved"] = True
    if permissions:
        recovered["permission_grant_empty"] = True
    if action:
        require(broker.tool_declined and not os.path.lexists(action_target(workspace, broker.scenario_name)),
                "action-denial-not-proven")
        recovered.pop("input_request_resolved")
        recovered[f"{broker.scenario_name}_approval_resolved"] = True
        recovered["action_declined_without_target_creation"] = True
    return recovered


def verify_diagnostics(stderr: bytes, scenario_name: str) -> None:
    if not stderr:
        return
    expected = {
        "command": b'error=exec_command failed: CreateProcess { message: "Rejected(\\"rejected by user\\")" }',
        "file": b"error=patch rejected by user",
    }.get(scenario_name)
    require(expected is not None and re.fullmatch(
        rb"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z ERROR codex_core::tools::router: "
        + re.escape(expected) + rb"\n", stderr,
    ) is not None, "provider-stderr-output")


def verify_journal(
    root: Path, binding: TaskBinding, report: dict[str, Any], *, scenario_name: str = "input",
) -> None:
    capture = _read_private(root / "captures" / f"{CAPTURE_ID}.capture", PER_CAPTURE_BYTES)
    require(hashlib.sha256(capture).hexdigest() == report["source_capture_sha256"],
            "capture-changed")
    buffers = {"I": bytearray(), "O": bytearray()}
    source: dict[str, list[dict[str, Any]]] = {"I": [], "O": []}
    observed: list[tuple[str, int, dict[str, Any]]] = []
    stderr = bytearray()
    stderr_times: list[int] = []
    for stream, observed_ns, payload in iter_capture_frames(io.BytesIO(capture)):
        if stream == "E":
            stderr.extend(payload)
            if payload:
                stderr_times.append(observed_ns)
            continue
        buffer = buffers[stream]
        buffer.extend(payload)
        while b"\n" in buffer:
            end = buffer.index(b"\n")
            message = strict_message(bytes(buffer[:end]))
            source[stream].append(message)
            observed.append((stream, observed_ns, message))
            del buffer[:end + 1]
    require(not any(buffers.values()), "capture-message-truncated")
    verify_diagnostics(bytes(stderr), scenario_name)
    if stderr:
        requests = [message for stream, _, message in observed
                    if stream == "O" and message.get("method") == SCENARIOS[scenario_name]
                    and "id" in message]
        require(len(requests) == 1, "denial-diagnostic-unbound")
        request_id = requests[0]["id"]
        declines = [observed_ns for stream, observed_ns, message in observed
                    if stream == "I" and type(message.get("id")) is type(request_id)
                    and message == {"id": request_id, "result": {"decision": "decline"}}]
        completed = [observed_ns for stream, observed_ns, message in observed
                     if stream == "O" and message.get("method") == "turn/completed"]
        require(len(declines) == len(completed) == 1
                and all(declines[0] <= moment < completed[0] for moment in stderr_times),
                "denial-diagnostic-outside-turn")
    rows = _read_private(root / "journal" / "source.jsonl", 256 * 1024).splitlines()
    require(strict_message(rows[0]) == {"schema_version": 1, "task_generation": binding.generation},
            "journal-binding-mismatch")
    journal: dict[str, list[dict[str, Any]]] = {"I": [], "O": []}
    for row in rows[1:]:
        frame = strict_message(row)
        journal[frame["stream"]].append(frame["message"])
    require(source == journal, "journal-source-mismatch")


def task_binding() -> TaskBinding:
    deadline = time.monotonic() + 5
    while True:
        try:
            return TaskBinding.from_environment(os.environ)
        except ObserverError as error:
            if str(error) not in {"task-record-mismatch", "task-record-not-found-for-absolute-socket"}:
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def run(
    root: Path, executable: Path, auth_file: Path, cancellation: Cancellation | None = None,
    *, scenario_name: str = "input",
) -> dict[str, Any]:
    require(scenario_name in SCENARIOS, "scenario-invalid")
    binding = task_binding()
    require(root.is_absolute() and root.resolve() == root, "run-root-not-canonical")
    _private_directory(root, empty=True)
    validated_root = validate_capture_root(root, repository_paths(Path(__file__)))
    validated_root.close()
    pinned = pin_executable("codex", executable, load_executable_manifest())
    for name in ("discovery-config", "config", "workspace", "tmp", "captures",
                 "preflight-captures", "journal"):
        (root / name).mkdir(mode=0o700)
    isolated_config = (
        "suppress_unstable_features_warning = true\n" if scenario_name == "permissions" else ""
    ) + CONFIG + (
        "request_permissions_tool = " + ("true" if scenario_name == "permissions" else "false") + "\n"
    )
    if scenario_name in {"command", "file"}:
        isolated_config = isolated_config.replace("shell_tool = false\n", "shell_tool = true\n")
    _write_private_bytes(root / "discovery-config" / "config.toml", isolated_config.encode())
    paths = preflight(root, pinned, root / "discovery-config", "capture-discovery", isolated=False)
    config = isolated_config + "".join(
        "[[skills.config]]\npath = " + json.dumps(path, ensure_ascii=True) + "\nenabled = false\n"
        for path in paths
    )
    _write_private_bytes(root / "config" / "config.toml", config.encode())
    preflight(root, pinned, root / "config", "capture-isolation", isolated=True)
    auth = _read_private(auth_file, 128 * 1024)
    credentials = strict_message(auth)
    tokens = credentials.get("tokens")
    require(type(tokens) is dict and type(tokens.get("access_token")) is str,
            "subscription-credentials-required")
    parts = tokens["access_token"].split(".")
    require(len(parts) == 3, "credential-expiry-invalid")
    claims = strict_message(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    require(type(claims.get("exp")) is int and claims["exp"] > time.time() + 180,
            "credential-expiry-too-soon")
    auth_copy = root / "config" / "auth.json"
    descriptor = os.open(auth_copy, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    identity = os.fstat(descriptor)
    transport: JsonLineTransport | None = None
    broker: Broker | None = None
    finished = False
    try:
        if cancellation is not None:
            cancellation.cleanup = lambda: remove_credentials(auth_copy, identity)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(auth)
            stream.flush()
            os.fsync(stream.fileno())
        del auth, credentials, tokens, parts, claims
        spec = ProbeConfig("codex", root / "captures", CAPTURE_ID, pinned.path, root / "workspace")
        transport = JsonLineTransport(spec, pinned, environment=environment(root / "config", root / "tmp"))
        broker = Broker(transport, binding, root / "journal" / "source.jsonl",
                        scenario_name=scenario_name, workspace=spec.workspace)
        checks = scenario(broker, spec.workspace)
        transport.finish()
        finished = True
        broker.close()
        broker = None
        report = analyze_codex_capture(spec.capture_root, CAPTURE_ID)
        require(report["analysis_complete"] and report["provider_warning_count"] == 0
                and report["turn_count"] == 1 and report["thread_read_count"] >= 2,
                "capture-analysis-incomplete")
        if scenario_name != "input":
            require(any(event["event"] == "thread_state" and "waitingOnApproval" in event["flags"]
                        for event in report["events"]), "approval-state-not-observed")
        verify_journal(root, binding, report, scenario_name=scenario_name)
        checks["journal_matches_source"] = True
        if scenario_name in {"command", "file"}:
            checks["provider_diagnostics_match_denial"] = True
        return {
            "schema_version": 1, "scope": f"phase0-{scenario_name}-observer-restart",
            "qualification": "unqualified", "provider": "codex", "provider_version": "0.157.1",
            "source_capture_sha256": report["source_capture_sha256"],
            "executable_sha256": pinned.sha256, "checks": checks,
            "message_count": report["message_count"], "thread_read_count": report["thread_read_count"],
            "freshness_seconds": FRESHNESS_NS // 1_000_000_000,
        }
    finally:
        try:
            remove_credentials(auth_copy, identity)
        finally:
            if cancellation is not None:
                cancellation.cleanup = None
            try:
                if transport is not None and not finished:
                    transport.abort()
            finally:
                try:
                    if broker is not None:
                        broker.close()
                finally:
                    if transport is not None:
                        transport.close()


def main(argv: Sequence[str] | None = None) -> int:
    cancellation: Cancellation | None = None
    try:
        cancellation = Cancellation()
        parser = SafeArgumentParser(
            prog="codex_qualification.py", allow_abbrev=False,
            description="Bounded Phase0 request and observer-restart probe. Run inside an isolated "
            "clilane task with an absolute socket, private state directories, and a fresh private "
            "run root outside the repository. Private provider captures are retained there.",
        )
        parser.add_argument("--run-root", required=True)
        parser.add_argument("--provider-executable", required=True)
        parser.add_argument("--scenario", choices=tuple(SCENARIOS), default="input",
                            help="Input cancellation (default), empty permission grant, "
                            "or a declined synthetic command/file approval.")
        parser.add_argument("--auth-file", required=True,
                            help="Private Codex subscription credentials valid for at least three minutes; "
                            "the probe removes its isolated copy after the run.")
        arguments = parser.parse_args(argv)
        result = run(Path(arguments.run_root), Path(arguments.provider_executable),
                     Path(arguments.auth_file), cancellation, scenario_name=arguments.scenario)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ProbeError, ObserverError, EvidenceError) as error:
        print(f"codex_qualification.py: {error}", file=sys.stderr)
    except Exception:
        print("codex_qualification.py: qualification-failed", file=sys.stderr)
    finally:
        if cancellation is not None:
            cancellation.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
