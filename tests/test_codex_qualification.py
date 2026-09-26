from __future__ import annotations

import copy
import base64
import hashlib
import json
import os
import shlex
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
try:
    import codex_qualification as qualification
finally:
    sys.path.pop(0)


class SyntheticTransport:
    def __init__(self, messages: list[dict[str, Any]] | None = None) -> None:
        self.messages = copy.deepcopy(messages or [])
        self.sent: list[dict[str, Any]] = []

    def send(self, message: dict[str, Any]) -> None:
        self.sent.append(copy.deepcopy(message))

    def receive(self, deadline: float) -> dict[str, Any]:
        if not self.messages:
            raise qualification.ProbeError("synthetic-messages-exhausted")
        return self.messages.pop(0)


class QualificationFixture(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="codex-qualification-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.binding = qualification.TaskBinding("a" * 64)
        self.broker_count = 0

    def target(self, scenario_name: str) -> Path:
        return self.root / ("denied-command" if scenario_name == "command" else "denied-file.txt")

    def item(self, scenario_name: str, status: str = "inProgress") -> dict[str, Any]:
        if scenario_name == "command":
            return {"id": "synthetic-item", "type": "commandExecution", "cwd": str(self.workspace), "command": "/usr/bin/touch " + shlex.quote(str(self.target(scenario_name))), "status": status, "aggregatedOutput": None, "exitCode": None, "processId": None, "durationMs": None}
        return {"id": "synthetic-item", "type": "fileChange", "status": status, "changes": [{"path": str(self.target(scenario_name)), "kind": {"type": "add"}, "diff": "CLILANE_PROBE_SENTINEL\n"}]}

    def request(self, scenario_name: str) -> dict[str, Any]:
        params: dict[str, Any] = {"threadId": "synthetic-thread", "turnId": "synthetic-turn", "itemId": "synthetic-item", "startedAtMs": 1}
        if scenario_name == "command":
            params.update(cwd=str(self.workspace), command=self.item(scenario_name)["command"])
        elif scenario_name == "file":
            params["grantRoot"] = str(self.root)
        elif scenario_name == "permissions":
            params.update(cwd=str(self.workspace), permissions={"network": {"enabled": True}})
        else:
            params.update(isBlocking=True, questions=[{"id": "choice", "question": "Alpha or Beta?", "options": [{"label": "Alpha"}, {"label": "Beta"}]}])
        return {"id": "synthetic-request", "method": qualification.SCENARIOS[scenario_name], "params": params}

    def notification(self, method: str, item: dict[str, Any]) -> dict[str, Any]:
        return {"method": method, "params": {"threadId": "synthetic-thread", "turnId": "synthetic-turn", "item": item}}

    def broker(self, scenario_name: str, messages: list[dict[str, Any]] | None = None) -> tuple[qualification.Broker, SyntheticTransport]:
        self.broker_count += 1
        transport = SyntheticTransport(messages)
        observer = mock.Mock()
        observer.ok.return_value = {"unresolved_requests": [], "unhandled_message_count": 0}
        with mock.patch.object(qualification, "ObserverClient", return_value=observer):
            broker = qualification.Broker(transport, self.binding, self.root / f"journal-{self.broker_count}.jsonl", scenario_name=scenario_name, workspace=self.workspace)
        self.addCleanup(broker.close)
        return broker, transport

    def lifecycle(self, scenario_name: str) -> list[dict[str, Any]]:
        result = [{"id": "probe-init", "result": {}}, {"id": "probe-skills", "result": {"data": [{"cwd": str(self.workspace), "errors": [], "skills": []}]}}, {"id": "probe-thread", "result": {"thread": {"id": "synthetic-thread", "sessionId": "synthetic-session"}, "model": "synthetic-model"}}, {"id": "probe-turn", "result": {"turn": {"id": "synthetic-turn", "status": "inProgress"}}}]
        if scenario_name in {"command", "file"}:
            result.append(self.notification("item/started", self.item(scenario_name)))
        result.append(self.request(scenario_name))
        if scenario_name in {"command", "file"}:
            result.append(self.notification("item/completed", self.item(scenario_name, "declined")))
        result.extend([{"method": "serverRequest/resolved", "params": {"threadId": "synthetic-thread", "requestId": "synthetic-request"}}, {"method": "turn/completed", "params": {"threadId": "synthetic-thread", "turn": {"id": "synthetic-turn", "status": "completed"}}}, {"method": "thread/status/changed", "params": {"threadId": "synthetic-thread", "status": {"type": "idle"}}}])
        return result


class ActionValidationTests(QualificationFixture):
    def test_only_exact_touch_command_and_allowed_shell_wrappers_match(self) -> None:
        target = self.target("command")
        command = "/usr/bin/touch " + shlex.quote(str(target))
        for value in (command, *[f"{shell} {flag} {shlex.quote(command)}" for shell in ("/bin/sh", "/bin/bash", "/bin/zsh") for flag in ("-c", "-lc")]):
            with self.subTest(command=value):
                self.assertTrue(qualification.command_matches(value, target))
        for value in (None, [], "x" * 4097, "'unterminated", command + " && /usr/bin/true", command + "; /usr/bin/true", command + "\n/usr/bin/true", command + " | /usr/bin/true", command + " > /tmp/other", command + " /tmp/other", command.replace("/usr/bin/touch", "touch"), "/usr/bin/touch /tmp/other", f"/bin/zsh -c {shlex.quote(command)} ignored", f"/usr/bin/env /bin/sh -c {shlex.quote(command)}"):
            with self.subTest(command=value):
                self.assertFalse(qualification.command_matches(value, target))

    def test_command_item_rejects_wrong_cwd_execution_metadata_and_output(self) -> None:
        for changes, error in (({"cwd": str(self.root)}, "unexpected-command-execution"), ({"command": "/usr/bin/true"}, "unexpected-command-execution"), ({"type": "fileChange"}, "unexpected-command-execution"), ({"exitCode": 0}, "unexpected-command-execution"), ({"processId": "123"}, "unexpected-command-execution"), ({"pluginId": "plugin"}, "unexpected-command-execution"), ({"scriptPath": "/tmp/script"}, "unexpected-command-execution"), ({"durationMs": True}, "unexpected-command-execution"), ({"durationMs": 1}, "unexpected-command-execution"), ({"aggregatedOutput": "executed output"}, "unexpected-command-output")):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(qualification.ProbeError, f"^{error}$"):
                    qualification.action_item({**self.item("command"), **changes}, self.workspace, "command")
        with self.assertRaisesRegex(qualification.ProbeError, "^unexpected-command-output$"):
            qualification.action_item({**self.item("command", "declined"), "aggregatedOutput": "executed output"}, self.workspace, "command")

    def test_file_item_requires_one_exact_addition(self) -> None:
        valid = self.item("file")
        qualification.action_item(valid, self.workspace, "file")
        for changes in ([], valid["changes"] * 2, [{**valid["changes"][0], "path": str(self.root / "other")}], [{**valid["changes"][0], "kind": {"type": "update"}}], [{**valid["changes"][0], "diff": "different contents\n"}], [{**valid["changes"][0], "extra": True}], [None]):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(qualification.ProbeError, "^unexpected-file-change$"):
                    qualification.action_item({**valid, "changes": changes}, self.workspace, "file")
        for identity in (None, "", "x" * 257, True):
            with self.subTest(identity=identity):
                with self.assertRaisesRegex(qualification.ProbeError, "^action-identity-invalid$"):
                    qualification.action_item({**valid, "id": identity}, self.workspace, "file")

    def test_existing_or_dangling_symlink_target_rejected_before_action(self) -> None:
        for scenario_name in ("command", "file"):
            for symlink in (False, True):
                with self.subTest(scenario=scenario_name, symlink=symlink):
                    target = self.target(scenario_name)
                    if symlink:
                        target.symlink_to(self.root / "missing-target")
                    else:
                        target.write_text("existing sentinel", encoding="utf-8")
                    try:
                        with self.assertRaisesRegex(qualification.ProbeError, "^denied-action-created-target$"):
                            qualification.action_item(self.item(scenario_name), self.workspace, scenario_name)
                        with self.assertRaisesRegex(qualification.ProbeError, "^denied-action-created-target$"):
                            qualification.action_request(self.request(scenario_name)["params"], self.workspace, scenario_name, "synthetic-item")
                        broker, transport = self.broker(scenario_name)
                        with self.assertRaisesRegex(qualification.ProbeError, "^action-target-exists$"):
                            qualification.scenario(broker, self.workspace)
                        self.assertEqual(transport.sent, [])
                    finally:
                        target.unlink()

    def test_approval_request_requires_matching_item_valid_time_and_local_scope(self) -> None:
        for scenario_name in ("command", "file"):
            params = self.request(scenario_name)["params"]
            qualification.action_request(params, self.workspace, scenario_name, "synthetic-item")
            for changes in ({"itemId": "other"}, {"startedAtMs": True}, {"startedAtMs": 0}, {"startedAtMs": 1 << 63}):
                with self.subTest(scenario=scenario_name, changes=changes):
                    with self.assertRaisesRegex(qualification.ProbeError, "^action-request-invalid$"):
                        qualification.action_request({**params, **changes}, self.workspace, scenario_name, "synthetic-item")
            with self.assertRaisesRegex(qualification.ProbeError, "^action-request-invalid$"):
                qualification.action_request(params, self.workspace, scenario_name, None)
        for changes in ({"cwd": str(self.root)}, {"command": "/usr/bin/true"}, {"environmentId": "remote"}, {"networkApprovalContext": {}}, {"kind": "network"}, {"unexpected": True}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(qualification.ProbeError, "^unexpected-command-request$"):
                    qualification.action_request({**self.request("command")["params"], **changes}, self.workspace, "command", "synthetic-item")
        for changes in ({"grantRoot": "/"}, {"path": "/other"}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(qualification.ProbeError, "^unexpected-file-request$"):
                    qualification.action_request({**self.request("file")["params"], **changes}, self.workspace, "file", "synthetic-item")


class BrokerDenialTests(QualificationFixture):
    def test_command_prompt_quotes_target_in_root_with_spaces_and_shell_metacharacters(self) -> None:
        self.root = self.root / "private run;literal"
        self.root.mkdir(mode=0o700)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        broker, transport = self.broker("command", self.lifecycle("command"))
        with mock.patch.object(qualification, "recovery", return_value={}):
            result = qualification.scenario(broker, self.workspace)
        turn = next(message for message in transport.sent if message.get("method") == "turn/start")
        prompt = turn["params"]["input"][0]["text"]
        command, _end = json.JSONDecoder().raw_decode(prompt.split("cmd=", 1)[1])
        self.assertEqual(shlex.split(command), ["/usr/bin/touch", str(self.target("command"))])
        self.assertEqual([message for message in transport.sent if "result" in message], [{"id": "synthetic-request", "result": {"decision": "decline"}}])
        self.assertTrue(result["action_declined_without_target_creation"])
        self.assertFalse(os.path.lexists(self.target("command")))

    def test_command_and_file_scenarios_send_exactly_one_decline_and_never_grant(self) -> None:
        for scenario_name in ("command", "file"):
            with self.subTest(scenario=scenario_name):
                broker, transport = self.broker(scenario_name, self.lifecycle(scenario_name))
                with mock.patch.object(qualification, "recovery", return_value={"synthetic_recovery": True}):
                    result = qualification.scenario(broker, self.workspace)
                self.assertEqual([message for message in transport.sent if "result" in message], [{"id": "synthetic-request", "result": {"decision": "decline"}}])
                self.assertTrue(result[scenario_name + "_approval_resolved"])
                self.assertTrue(result["action_declined_without_target_creation"])
                self.assertTrue(broker.tool_declined)
                self.assertFalse(os.path.lexists(self.target(scenario_name)))
                thread = next(message for message in transport.sent if message.get("method") == "thread/start")
                self.assertEqual(thread["params"]["sandbox"], "read-only")
                self.assertEqual(thread["params"]["approvalPolicy"]["granular"], {"mcp_elicitations": False, "rules": False, "sandbox_approval": True, "skill_approval": False, "request_permissions": False})

    def test_broker_blocks_grant_mutation_and_repeated_denial_before_transport(self) -> None:
        broker, transport = self.broker("command", [self.notification("item/started", self.item("command")), self.request("command")])
        broker.receive(0)
        broker.receive(0)
        for result in ({"decision": "accept"}, {"decision": "acceptForSession"}, {"decision": "decline", "extra": True}, {"permissions": {"network": {"enabled": True}}}):
            with self.subTest(result=result):
                with self.assertRaisesRegex(qualification.ProbeError, "^invalid-denial-response$"):
                    broker.send({"id": "synthetic-request", "result": result})
                self.assertEqual(transport.sent, [])
        decline = {"id": "synthetic-request", "result": {"decision": "decline"}}
        broker.send(decline)
        with self.assertRaisesRegex(qualification.ProbeError, "^invalid-denial-response$"):
            broker.send(decline)
        self.assertEqual(transport.sent, [decline])

    def test_duplicate_or_differently_bound_approval_rejected(self) -> None:
        for scenario_name in ("command", "file"):
            with self.subTest(scenario=scenario_name):
                start = self.notification("item/started", self.item(scenario_name))
                request = self.request(scenario_name)
                broker, _transport = self.broker(scenario_name, [start, request, request])
                broker.receive(0)
                broker.receive(0)
                with self.assertRaisesRegex(qualification.ProbeError, "^duplicate-approval-request$"):
                    broker.receive(0)
                wrong = copy.deepcopy(request)
                wrong["params"]["itemId"] = "other-item"
                broker, _transport = self.broker(scenario_name, [start, wrong])
                broker.receive(0)
                with self.assertRaisesRegex(qualification.ProbeError, "^action-request-invalid$"):
                    broker.receive(0)

    def test_terminal_action_requires_prior_denial_exact_item_and_declined_status(self) -> None:
        for scenario_name in ("command", "file"):
            for status, identity, denial in (("declined", "synthetic-item", False), ("completed", "synthetic-item", True), ("failed", "synthetic-item", True), ("declined", "other-item", True)):
                with self.subTest(scenario=scenario_name, status=status, identity=identity, denial=denial):
                    item = {**self.item(scenario_name, status), "id": identity}
                    broker, _transport = self.broker(scenario_name, [self.notification("item/started", self.item(scenario_name)), self.request(scenario_name), self.notification("item/completed", item)])
                    broker.receive(0)
                    broker.receive(0)
                    if denial:
                        broker.send({"id": "synthetic-request", "result": {"decision": "decline"}})
                    with self.assertRaisesRegex(qualification.ProbeError, "^action-not-declined$"):
                        broker.receive(0)

    def test_extra_action_start_output_delta_and_provider_warning_are_rejected(self) -> None:
        cases = [(self.notification("item/started", self.item("command")), "unexpected-action-start"), ({"method": "item/commandExecution/outputDelta", "params": {"delta": "private-output"}}, "unexpected-command-output"), ({"method": "warning", "params": {"message": "private-warning"}}, "provider-warning")]
        for message, error in cases:
            with self.subTest(error=error):
                broker, _transport = self.broker("command", [self.notification("item/started", self.item("command")), message])
                broker.receive(0)
                with self.assertRaisesRegex(qualification.ProbeError, f"^{error}$"):
                    broker.receive(0)

    def test_input_and_permission_scenarios_cannot_execute_actions(self) -> None:
        for scenario_name in ("input", "permissions"):
            with self.subTest(scenario=scenario_name):
                broker, _transport = self.broker(scenario_name, [self.notification("item/started", self.item("command"))])
                with self.assertRaisesRegex(qualification.ProbeError, "^provider-side-effect-attempt$"):
                    broker.receive(0)

    def test_action_scenario_requires_completed_turn_after_decline(self) -> None:
        for status in ("failed", "interrupted", "inProgress"):
            with self.subTest(status=status):
                messages = self.lifecycle("command")
                next(message for message in messages if message.get("method") == "turn/completed")["params"]["turn"]["status"] = status
                broker, _transport = self.broker("command", messages)
                with mock.patch.object(qualification, "recovery", return_value={}):
                    with self.assertRaisesRegex(qualification.ProbeError, "^turn-not-completed$"):
                        qualification.scenario(broker, self.workspace)

    def test_existing_input_and_permission_scenarios_send_empty_responses(self) -> None:
        for scenario_name, expected in (("input", {"answers": {}}), ("permissions", {"permissions": {}, "scope": "turn"})):
            with self.subTest(scenario=scenario_name):
                broker, transport = self.broker(scenario_name, self.lifecycle(scenario_name))
                with mock.patch.object(qualification, "recovery", return_value={"synthetic_recovery": True}):
                    result = qualification.scenario(broker, self.workspace)
                self.assertEqual([message for message in transport.sent if "result" in message], [{"id": "synthetic-request", "result": expected}])
                self.assertTrue(result["input_request_resolved" if scenario_name == "input" else "permission_approval_resolved"])

    def test_input_rejects_nonblocking_or_multiple_questions_before_response(self) -> None:
        for changes in ({"isBlocking": False}, {"isBlocking": 1}, {"questions": []}, {"questions": [{}, {}]}, {"questions": None}):
            with self.subTest(changes=changes):
                messages = self.lifecycle("input")
                messages[4]["params"].update(changes)
                broker, transport = self.broker("input", messages)
                with mock.patch.object(qualification, "recovery") as recover:
                    with self.assertRaisesRegex(qualification.ProbeError, "^unexpected-input-request$"):
                        qualification.scenario(broker, self.workspace)
                recover.assert_not_called()
                self.assertFalse(any("result" in message for message in transport.sent))

    def test_permission_scope_is_network_only_and_strictly_typed(self) -> None:
        params = self.request("permissions")["params"]
        qualification.permission_request(params, self.workspace)
        for value in ({}, {"network": {"enabled": 1}}, {"network": {"enabled": False}}, {"network": {"enabled": True, "extra": True}}, {"network": {"enabled": True}, "fileSystem": {}}, {"network": {"enabled": True}, "other": True}):
            with self.subTest(permissions=value):
                with self.assertRaisesRegex(qualification.ProbeError, "^unexpected-permissions$"):
                    qualification.permission_request({**params, "permissions": value}, self.workspace)
        for changes in ({"cwd": "/other"}, {"environmentId": "remote"}, {"startedAtMs": True}, {"reason": "x" * 4097}, {"extra": True}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(qualification.ProbeError, "^permission-request-invalid$"):
                    qualification.permission_request({**params, **changes}, self.workspace)


class DiagnosticAndJournalTests(QualificationFixture):
    def diagnostic(self, scenario_name: str) -> bytes:
        suffix = b'error=exec_command failed: CreateProcess { message: "Rejected(\\"rejected by user\\")" }' if scenario_name == "command" else b"error=patch rejected by user"
        return b"2026-09-26T12:34:56.123456Z ERROR codex_core::tools::router: " + suffix + b"\n"

    def test_only_one_exact_diagnostic_for_matching_action_scenario_is_allowed(self) -> None:
        for scenario_name in qualification.SCENARIOS:
            qualification.verify_diagnostics(b"", scenario_name)
        for scenario_name in ("command", "file"):
            diagnostic = self.diagnostic(scenario_name)
            qualification.verify_diagnostics(diagnostic, scenario_name)
            for value in (diagnostic * 2, diagnostic + b"extra private output\n", b"extra private output\n" + diagnostic, diagnostic.rstrip(b"\n"), diagnostic.replace(b" ERROR ", b" WARN "), diagnostic.replace(b"codex_core::tools::router", b"other::router"), diagnostic.replace(b"rejected by user", b"execution failed"), self.diagnostic("file" if scenario_name == "command" else "command")):
                with self.subTest(scenario=scenario_name, stderr=value):
                    with self.assertRaisesRegex(qualification.ProbeError, "^provider-stderr-output$"):
                        qualification.verify_diagnostics(value, scenario_name)
        for scenario_name in ("input", "permissions"):
            with self.subTest(scenario=scenario_name):
                with self.assertRaisesRegex(qualification.ProbeError, "^provider-stderr-output$"):
                    qualification.verify_diagnostics(self.diagnostic("command"), scenario_name)

    def journal_inputs(self, scenario_name: str) -> tuple[bytes, bytes, list[tuple[str, int, bytes]], dict[str, Any]]:
        messages = [("I", {"method": "initialized"}), ("O", {"method": "thread/status/changed", "params": {"threadId": "synthetic-thread", "status": {"type": "idle"}}})]
        capture = b"synthetic-capture-bytes"
        frames = [(stream, number, (json.dumps(message) + "\n").encode()) for number, (stream, message) in enumerate(messages)]
        rows = [{"schema_version": 1, "task_generation": self.binding.generation}] + [{"stream": stream, "observed_ns": number, "message": message} for number, (stream, message) in enumerate(messages)]
        journal = b"".join((json.dumps(row) + "\n").encode() for row in rows)
        return capture, journal, frames, {"source_capture_sha256": hashlib.sha256(capture).hexdigest()}

    def verify_frames(self, frames: list[tuple[str, int, bytes]], scenario_name: str) -> None:
        capture = b"synthetic ordered capture"
        rows = [{"schema_version": 1, "task_generation": self.binding.generation}]
        rows.extend({"stream": stream, "observed_ns": moment, "message": json.loads(raw)} for stream, moment, raw in frames if stream != "E")
        journal = b"".join((json.dumps(row) + "\n").encode() for row in rows)
        with mock.patch.object(qualification, "_read_private", side_effect=[capture, journal]), mock.patch.object(qualification, "iter_capture_frames", return_value=iter(sorted(frames, key=lambda frame: frame[1]))):
            qualification.verify_journal(self.root, self.binding, {"source_capture_sha256": hashlib.sha256(capture).hexdigest()}, scenario_name=scenario_name)

    def denial_frames(self, scenario_name: str) -> list[tuple[str, int, bytes]]:
        messages = [("O", 1, self.request(scenario_name)), ("I", 3, {"id": "synthetic-request", "result": {"decision": "decline"}}), ("O", 7, {"method": "turn/completed", "params": {"threadId": "synthetic-thread", "turn": {"id": "synthetic-turn", "status": "completed"}}})]
        return [(stream, moment, (json.dumps(message) + "\n").encode()) for stream, moment, message in messages]

    def test_denial_diagnostic_must_be_within_exact_decline_completion_window(self) -> None:
        for scenario_name in ("command", "file"):
            frames = self.denial_frames(scenario_name)
            diagnostic = self.diagnostic(scenario_name)
            for moment in (3, 6):
                with self.subTest(scenario=scenario_name, accepted=moment):
                    self.verify_frames(frames + [("E", moment, diagnostic)], scenario_name)
            for moment in (0, 2, 7, 8):
                with self.subTest(scenario=scenario_name, rejected=moment):
                    with self.assertRaisesRegex(qualification.ProbeError, "^denial-diagnostic-outside-turn$"):
                        self.verify_frames(frames + [("E", moment, diagnostic)], scenario_name)
            midpoint = len(diagnostic) // 2
            self.verify_frames(frames + [("E", 3, diagnostic[:midpoint]), ("E", 6, diagnostic[midpoint:]), ("E", 8, b"")], scenario_name)
            with self.assertRaisesRegex(qualification.ProbeError, "^denial-diagnostic-outside-turn$"):
                self.verify_frames(frames + [("E", 3, diagnostic[:midpoint]), ("E", 7, diagnostic[midpoint:])], scenario_name)

    def test_denial_diagnostic_requires_one_matching_request_decline_and_completion(self) -> None:
        frames = self.denial_frames("command")
        diagnostic = ("E", 4, self.diagnostic("command"))
        for changed, error in ((frames[1:], "denial-diagnostic-unbound"), (frames + [frames[0]], "denial-diagnostic-unbound"), ([frames[0], frames[2]], "denial-diagnostic-outside-turn"), (frames + [frames[1]], "denial-diagnostic-outside-turn"), (frames[:2], "denial-diagnostic-outside-turn"), (frames + [frames[2]], "denial-diagnostic-outside-turn")):
            with self.subTest(error=error, frame_count=len(changed)):
                with self.assertRaisesRegex(qualification.ProbeError, f"^{error}$"):
                    self.verify_frames(changed + [diagnostic], "command")
        for identity in ("wrong-request", 7, True):
            with self.subTest(identity=identity):
                changed = list(frames)
                changed[1] = ("I", 3, (json.dumps({"id": identity, "result": {"decision": "decline"}}) + "\n").encode())
                with self.assertRaisesRegex(qualification.ProbeError, "^denial-diagnostic-outside-turn$"):
                    self.verify_frames(changed + [diagnostic], "command")
        changed = list(frames)
        request = self.request("command")
        request["id"] = 1
        changed[0] = ("O", 1, (json.dumps(request) + "\n").encode())
        changed[1] = ("I", 3, b'{"id":true,"result":{"decision":"decline"}}\n')
        with self.assertRaisesRegex(qualification.ProbeError, "^denial-diagnostic-outside-turn$"):
            self.verify_frames(changed + [diagnostic], "command")

    def test_journal_verification_binds_capture_hash_task_messages_and_scenario(self) -> None:
        capture, journal, frames, report = self.journal_inputs("input")
        with mock.patch.object(qualification, "_read_private", side_effect=[capture, journal]), mock.patch.object(qualification, "iter_capture_frames", return_value=iter(frames)):
            qualification.verify_journal(self.root, self.binding, report)
        with mock.patch.object(qualification, "_read_private", return_value=capture):
            with self.assertRaisesRegex(qualification.ProbeError, "^capture-changed$"):
                qualification.verify_journal(self.root, self.binding, {"source_capture_sha256": "0" * 64})
        wrong = journal.replace(self.binding.generation.encode(), b"b" * 64)
        with mock.patch.object(qualification, "_read_private", side_effect=[capture, wrong]), mock.patch.object(qualification, "iter_capture_frames", return_value=iter(frames)):
            with self.assertRaisesRegex(qualification.ProbeError, "^journal-binding-mismatch$"):
                qualification.verify_journal(self.root, self.binding, report)
        wrong = journal.replace(b"initialized", b"different")
        with mock.patch.object(qualification, "_read_private", side_effect=[capture, wrong]), mock.patch.object(qualification, "iter_capture_frames", return_value=iter(frames)):
            with self.assertRaisesRegex(qualification.ProbeError, "^journal-source-mismatch$"):
                qualification.verify_journal(self.root, self.binding, report)
        with mock.patch.object(qualification, "_read_private", side_effect=[capture, journal]), mock.patch.object(qualification, "iter_capture_frames", return_value=iter(frames + [("E", 2, self.diagnostic("file"))])):
            with self.assertRaisesRegex(qualification.ProbeError, "^provider-stderr-output$"):
                qualification.verify_journal(self.root, self.binding, report, scenario_name="command")

    def test_journal_rejects_truncated_protocol_line(self) -> None:
        capture, journal, frames, report = self.journal_inputs("input")
        frames[-1] = (frames[-1][0], frames[-1][1], frames[-1][2].rstrip(b"\n"))
        with mock.patch.object(qualification, "_read_private", side_effect=[capture, journal]), mock.patch.object(qualification, "iter_capture_frames", return_value=iter(frames)):
            with self.assertRaisesRegex(qualification.ProbeError, "^capture-message-truncated$"):
                qualification.verify_journal(self.root, self.binding, report)


class CleanupAndIsolationTests(QualificationFixture):
    def test_run_failure_cleans_credential_copy_and_preserves_replacement_inode(self) -> None:
        claims = base64.urlsafe_b64encode(b'{"exp":4102444800}').decode().rstrip("=")
        synthetic = json.dumps({"tokens": {"access_token": "synthetic." + claims + ".synthetic"}}).encode()
        pinned = qualification.PinnedExecutable(Path("/synthetic/executable"), "b" * 64, (1, 1, 1, 1))
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                root = self.root / ("replacement-run" if replacement else "failed-run")
                root.mkdir(mode=0o700)

                def fail_transport(*args: Any, **kwargs: Any) -> None:
                    path = root / "config/auth.json"
                    self.assertEqual(path.read_bytes(), synthetic)
                    if replacement:
                        path.rename(root / "displaced-copy")
                        path.write_bytes(b"synthetic replacement")
                    raise qualification.ProbeError("synthetic-spawn-failed")

                with mock.patch.object(qualification, "task_binding", return_value=self.binding), mock.patch.object(qualification, "load_executable_manifest", return_value={}), mock.patch.object(qualification, "pin_executable", return_value=pinned), mock.patch.object(qualification, "preflight", return_value=[]), mock.patch.object(qualification, "_read_private", return_value=synthetic), mock.patch.object(qualification, "JsonLineTransport", side_effect=fail_transport):
                    with self.assertRaisesRegex(qualification.ProbeError, "^credential-copy-replaced$" if replacement else "^synthetic-spawn-failed$"):
                        qualification.run(root, pinned.path, Path("/synthetic/input"))
                if replacement:
                    self.assertEqual((root / "config/auth.json").read_bytes(), b"synthetic replacement")
                else:
                    self.assertFalse((root / "config/auth.json").exists())

    def test_credential_cleanup_removes_only_original_inode_and_is_idempotent(self) -> None:
        path = self.root / "synthetic-credential-copy"
        path.write_bytes(b"synthetic contents")
        identity = path.stat()
        qualification.remove_credentials(path, identity)
        self.assertFalse(path.exists())
        qualification.remove_credentials(path, identity)
        path.write_bytes(b"first")
        identity = path.stat()
        displaced = self.root / "displaced"
        path.rename(displaced)
        path.write_bytes(b"replacement")
        with self.assertRaisesRegex(qualification.ProbeError, "^credential-copy-replaced$"):
            qualification.remove_credentials(path, identity)
        self.assertEqual(path.read_bytes(), b"replacement")
        self.assertEqual(displaced.read_bytes(), b"first")

    def test_cancellation_cleans_copy_and_restores_handlers_without_real_signals(self) -> None:
        with mock.patch.object(qualification.signal, "signal", return_value="previous") as install:
            cancellation = qualification.Cancellation()
            cleanup = mock.Mock()
            cancellation.cleanup = cleanup
            with self.assertRaisesRegex(qualification.ProbeError, "^qualification-cancelled$"):
                cancellation.handle(signal.SIGTERM, None)
            cleanup.assert_called_once_with()
            cancellation.close()
        self.assertEqual(install.call_count, 9)
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            self.assertIn(mock.call(number, signal.SIG_IGN), install.call_args_list)
            self.assertIn(mock.call(number, "previous"), install.call_args_list)

    def test_environment_drops_unlisted_values_without_mutating_parent(self) -> None:
        environment = {"HOME": "/synthetic/home", "PATH": "/usr/bin:/bin", "LANG": "C", "OPENAI_API_KEY": "synthetic-denied", "CLILANE_PRIVATE_VALUE": "synthetic-denied"}
        with mock.patch.dict(os.environ, environment, clear=True):
            before = dict(os.environ)
            actual = qualification.environment(self.root / "config", self.root / "tmp")
            self.assertEqual(dict(os.environ), before)
        self.assertEqual(actual["CODEX_HOME"], str(self.root / "config"))
        self.assertEqual(actual["TMPDIR"], str(self.root / "tmp"))
        self.assertNotIn("OPENAI_API_KEY", actual)
        self.assertNotIn("CLILANE_PRIVATE_VALUE", actual)

    def test_skills_preflight_refuses_enabled_skills_in_isolation(self) -> None:
        valid = {"id": "probe-skills", "result": {"data": [{"cwd": str(self.workspace), "errors": [], "skills": [{"enabled": False, "path": "/synthetic/skill"}]}]}}
        transport = SyntheticTransport([valid])
        self.assertEqual(qualification.skills(transport, self.workspace, isolated=True), ["/synthetic/skill"])
        valid["result"]["data"][0]["skills"][0]["enabled"] = True
        with self.assertRaisesRegex(qualification.ProbeError, "^host-skills-enabled$"):
            qualification.skills(SyntheticTransport([valid]), self.workspace, isolated=True)


if __name__ == "__main__":
    unittest.main()
