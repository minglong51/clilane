from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("codex_analysis", ROOT / "scripts/codex_analysis.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load codex_analysis")
codex_analysis = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = codex_analysis
SPEC.loader.exec_module(codex_analysis)


class CodexAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.analysis = codex_analysis.CodexAnalysis()
        self.thread = {"id": "private-thread-sentinel", "sessionId": "private-session-sentinel"}
        self.observed_ns = 0

    def feed(self, stream: str, message: dict[str, Any]) -> None:
        self.observed_ns += 1_000_000
        self.analysis.feed(stream, self.observed_ns, (json.dumps(message) + "\n").encode())

    def bind_thread(self) -> None:
        self.feed("I", {"id": "thread-start", "method": "thread/start", "params": {}})
        self.feed("O", {"id": "thread-start", "result": {"thread": self.thread}})
        self.feed("O", {"method": "thread/started", "params": {"thread": self.thread}})

    def start_turn(self, turn_id: str = "private-turn-sentinel", *, notification_first: bool = False) -> None:
        self.feed("I", {"id": "start-" + turn_id, "method": "turn/start", "params": {"threadId": self.thread["id"]}})
        turn = {"id": turn_id, "status": "inProgress"}
        response = {"id": "start-" + turn_id, "result": {"turn": turn}}
        notification = {"method": "turn/started", "params": {"threadId": self.thread["id"], "turn": turn}}
        for message in ([notification, response] if notification_first else [response, notification]):
            self.feed("O", message)

    def complete_turn(self, turn_id: str = "private-turn-sentinel", status: str = "completed") -> None:
        self.feed("O", {"method": "turn/completed", "params": {"threadId": self.thread["id"], "turn": {"id": turn_id, "status": status}}})

    def request(self, request_id: str | int = "private-request-sentinel", method: str = "item/tool/requestUserInput", **extra: Any) -> dict[str, Any]:
        params = {"threadId": self.thread["id"], "turnId": "private-turn-sentinel", "itemId": "private-item-sentinel", **extra}
        if method == "item/tool/requestUserInput":
            params.setdefault("isBlocking", True)
        return {"id": request_id, "method": method, "params": params}

    def resolve(self, request_id: str | int = "private-request-sentinel") -> None:
        self.feed("O", {"method": "serverRequest/resolved", "params": {"threadId": self.thread["id"], "requestId": request_id}})

    def test_completed_turns_accept_both_start_response_orders(self) -> None:
        self.bind_thread()
        for number, status in enumerate(("completed", "interrupted", "failed")):
            turn_id = f"turn-{number}"
            self.start_turn(turn_id, notification_first=number % 2 == 0)
            self.complete_turn(turn_id, status)
        result = self.analysis.finish()
        self.assertTrue(result["analysis_complete"])
        self.assertEqual(result["turn_count"], 3)
        self.assertEqual([event["state"] for event in result["events"]], ["inProgress", "completed", "inProgress", "interrupted", "inProgress", "failed"])
        self.assertEqual(result["qualification"], "unqualified")
        self.assertEqual(result["task_binding"], "unknown")
        self.assertEqual(result["source_health"], "unknown")

    def test_input_and_approval_lifecycles_require_server_resolution(self) -> None:
        cases = [("item/tool/requestUserInput", True), ("item/tool/requestUserInput", False), ("item/commandExecution/requestApproval", True), ("item/fileChange/requestApproval", True), ("item/permissions/requestApproval", True)]
        for method, blocking in cases:
            with self.subTest(method=method, blocking=blocking):
                self.setUp()
                self.bind_thread()
                self.start_turn()
                self.feed("O", self.request(method=method, isBlocking=blocking, prompt="private-prompt-sentinel"))
                self.feed("I", {"id": "private-request-sentinel", "result": {"answer": "private-answer-sentinel"}})
                self.complete_turn()
                self.assertFalse(self.analysis.finish()["analysis_complete"])
                self.assertEqual(self.analysis.finish()["unresolved_request_count"], 1)
                self.resolve()
                result = self.analysis.finish()
                self.assertTrue(result["analysis_complete"])
                opened, resolved = [event for event in result["events"] if event["request_id"]]
                self.assertEqual(opened["request_id"], resolved["request_id"])
                self.assertEqual((opened["request_method"], resolved["request_method"]), (method, method))
                self.assertEqual(opened["blocking"], blocking)
                self.assertEqual(opened["request_kind"], "input" if "requestUserInput" in method else "approval")
                self.assertNotIn("private-", json.dumps(result))

    def test_string_and_integer_request_ids_are_distinct(self) -> None:
        self.bind_thread()
        self.start_turn()
        self.feed("O", self.request(7))
        self.feed("O", self.request("7"))
        self.resolve(7)
        self.assertEqual(self.analysis.finish()["unresolved_request_count"], 1)
        self.resolve("7")
        self.complete_turn()
        self.assertTrue(self.analysis.finish()["analysis_complete"])
        self.assertEqual({event["request_id"] for event in self.analysis.events if event["request_id"]}, {"synthetic-codex-request-1", "synthetic-codex-request-2"})

    def test_exact_duplicates_are_idempotent_across_lifecycle(self) -> None:
        self.bind_thread()
        self.start_turn()
        request = self.request()
        self.feed("O", request)
        self.feed("O", copy.deepcopy(request))
        self.feed("I", {"id": "thread-start", "method": "thread/start", "params": {}})
        self.feed("O", {"id": "thread-start", "result": {"thread": self.thread}})
        self.resolve()
        self.resolve()
        self.complete_turn()
        self.complete_turn()
        result = self.analysis.finish()
        self.assertTrue(result["analysis_complete"])
        self.assertEqual(result["duplicate_count"], 5)
        self.assertEqual(len(result["events"]), 4)

    def test_conflicting_duplicate_identities_fail_closed(self) -> None:
        cases = [
            ("I", {"id": "thread-start", "method": "initialize", "params": {}}, "conflicting-client-request"),
            ("O", {"id": "thread-start", "result": {"thread": {"id": "other", "sessionId": "other"}}}, "conflicting-response"),
            ("O", self.request(prompt="changed"), "conflicting-server-request"),
        ]
        for stream, message, error in cases:
            with self.subTest(error=error):
                self.setUp()
                self.bind_thread()
                self.start_turn()
                self.feed("O", self.request())
                with self.assertRaisesRegex(codex_analysis.AnalysisError, f"^{error}$"):
                    self.feed(stream, message)

    def test_stale_or_unbound_thread_turn_and_request_are_rejected(self) -> None:
        cases = [
            ("O", self.request(threadId="old-thread"), "thread-binding-mismatch"),
            ("O", self.request(turnId="old-turn"), "turn-binding-mismatch"),
            ("O", {"id": "unknown", "result": {}}, "unbound-response"),
            ("I", {"id": "unknown", "result": {}}, "unbound-request-response"),
            ("O", {"method": "serverRequest/resolved", "params": {"threadId": self.thread["id"], "requestId": "unknown"}}, "unbound-request-resolution"),
            ("O", {"method": "thread/started", "params": {"thread": {**self.thread, "sessionId": "old-session"}}}, "thread-binding-mismatch"),
        ]
        for stream, message, error in cases:
            with self.subTest(error=error):
                self.setUp()
                self.bind_thread()
                self.start_turn()
                with self.assertRaisesRegex(codex_analysis.AnalysisError, f"^{error}$"):
                    self.feed(stream, message)

    def test_overlapping_and_reused_turns_are_rejected(self) -> None:
        self.bind_thread()
        self.start_turn()
        with self.assertRaisesRegex(codex_analysis.AnalysisError, "^overlapping-turns$"):
            self.start_turn("other-turn")
        self.complete_turn()
        with self.assertRaisesRegex(codex_analysis.AnalysisError, "^turn-binding-mismatch$"):
            self.feed("O", self.request())
        self.feed("I", {"id": "new-start", "method": "turn/start", "params": {"threadId": self.thread["id"]}})
        with self.assertRaisesRegex(codex_analysis.AnalysisError, "^reused-turn-identity$"):
            self.feed("O", {"id": "new-start", "result": {"turn": {"id": "private-turn-sentinel", "status": "inProgress"}}})

    def test_completion_before_start_and_conflicting_terminal_status_fail(self) -> None:
        self.bind_thread()
        self.feed("I", {"id": "start", "method": "turn/start", "params": {"threadId": self.thread["id"]}})
        with self.assertRaisesRegex(codex_analysis.AnalysisError, "^turn-order-mismatch$"):
            self.complete_turn()
        self.setUp()
        self.bind_thread()
        self.start_turn()
        self.complete_turn()
        with self.assertRaisesRegex(codex_analysis.AnalysisError, "^conflicting-turn-completion$"):
            self.complete_turn(status="failed")

    def test_thread_reads_are_correlated_and_cannot_change_binding(self) -> None:
        self.bind_thread()
        self.start_turn()
        self.complete_turn()
        request = {"id": "read", "method": "thread/read", "params": {"threadId": self.thread["id"], "includeTurns": False}}
        self.feed("I", request)
        self.assertFalse(self.analysis.finish()["analysis_complete"])
        self.feed("O", {"id": "read", "result": {"thread": self.thread}})
        self.assertEqual(self.analysis.finish()["thread_read_count"], 1)
        self.assertTrue(self.analysis.finish()["analysis_complete"])
        self.feed("I", {**request, "id": "read-2"})
        with self.assertRaisesRegex(codex_analysis.AnalysisError, "^thread-binding-mismatch$"):
            self.feed("O", {"id": "read-2", "result": {"thread": {**self.thread, "sessionId": "stale"}}})

    def test_thread_read_parameters_are_strict(self) -> None:
        for extras in ({"includeTurns": 1}, {"includeTurns": None}, {"extra": True}):
            with self.subTest(extras=extras):
                self.setUp()
                self.bind_thread()
                with self.assertRaisesRegex(codex_analysis.AnalysisError, "^invalid-thread-read$"):
                    self.feed("I", {"id": "read", "method": "thread/read", "params": {"threadId": self.thread["id"], **extras}})

    def test_strict_json_envelope_and_number_boundaries(self) -> None:
        cases = [(b'{"id":1,"id":2,"result":{}}\n', "duplicate-json-key"), (b'{"id":1,"result":{"x":0,"x":1}}\n', "duplicate-json-key"), (b'{"id":1,"result":{"x":NaN}}\n', "invalid-json-number"), (b'{"id":1,"result":{"x":1e999}}\n', "invalid-json-number"), (b'\xff\n', "invalid-json"), (b'[]\n', "invalid-object"), (b'{"id":1,"result":{},"error":{}}\n', "invalid-envelope"), (b'{"jsonrpc":"2.0","id":1,"result":{}}\n', "invalid-envelope"), (b'{"method":"initialize","result":{}}\n', "invalid-envelope")]
        for raw, error in cases:
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(codex_analysis.AnalysisError, f"^{error}$"):
                    codex_analysis.CodexAnalysis().feed("I", 0, raw)

    def test_request_identity_types_and_lengths_are_strict(self) -> None:
        for identity in (None, True, False, [], {}, 1.5, "", "x" * 257, 1 << 63, -(1 << 63) - 1):
            with self.subTest(identity=identity):
                self.setUp()
                with self.assertRaisesRegex(codex_analysis.AnalysisError, "^invalid-identity$"):
                    self.feed("I", {"id": identity, "method": "initialize", "params": {}})

    def test_input_blocking_marker_must_be_boolean(self) -> None:
        for value in (None, 0, 1, "true", []):
            with self.subTest(value=value):
                self.setUp()
                self.bind_thread()
                self.start_turn()
                with self.assertRaisesRegex(codex_analysis.AnalysisError, "^invalid-request-blocking$"):
                    self.feed("O", self.request(isBlocking=value))

    def test_thread_flags_are_bounded_and_order_independent(self) -> None:
        self.bind_thread()
        flags = ["waitingOnUserInput", "waitingOnApproval"]
        for value in (flags, list(reversed(flags))):
            self.feed("O", {"method": "thread/status/changed", "params": {"threadId": self.thread["id"], "status": {"type": "active", "activeFlags": value}}})
        self.assertEqual(self.analysis.finish()["duplicate_count"], 1)
        self.assertEqual(self.analysis.events[0]["flags"], sorted(flags))
        for status in ({"type": "active"}, {"type": "idle", "activeFlags": flags}, {"type": "active", "activeFlags": ["unknown"]}, {"type": "active", "activeFlags": [flags[0], flags[0]]}):
            with self.subTest(status=status):
                with self.assertRaisesRegex(codex_analysis.AnalysisError, "^invalid-thread-flags$"):
                    self.feed("O", {"method": "thread/status/changed", "params": {"threadId": self.thread["id"], "status": status}})

    def test_partial_lines_stderr_and_payloads_do_not_leak(self) -> None:
        self.bind_thread()
        self.start_turn()
        raw = (json.dumps({"method": "item/agentMessage/delta", "params": {"threadId": self.thread["id"], "turnId": "private-turn-sentinel", "delta": "private-content-\u2603"}}, ensure_ascii=False) + "\n").encode()
        split = raw.index("\u2603".encode()) + 1
        self.analysis.feed("O", 9_000_000, raw[:split])
        with self.assertRaisesRegex(codex_analysis.AnalysisError, "^truncated-json-line$"):
            self.analysis.finish()
        self.analysis.feed("O", 10_000_000, raw[split:])
        self.analysis.feed("E", 11_000_000, b"private-stderr-sentinel\xff")
        self.complete_turn()
        result = self.analysis.finish()
        self.assertTrue(result["analysis_complete"])
        self.assertEqual(result["ignored_notification_count"], 1)
        self.assertNotIn("private-", json.dumps(result))

    def test_unhandled_messages_prevent_complete_analysis(self) -> None:
        self.bind_thread()
        self.start_turn()
        self.complete_turn()
        self.feed("O", {"method": "unknown/newFeature", "params": {}})
        self.assertFalse(self.analysis.finish()["analysis_complete"])
        self.assertEqual(self.analysis.finish()["unhandled_message_count"], 1)

    def test_account_updates_are_validated_and_omitted_from_replay(self) -> None:
        self.bind_thread()
        self.start_turn()
        for params in ({}, {"authMode": None, "planType": None}, {"authMode": "chatgpt", "planType": "pro"}, {"authMode": "apikey"}):
            self.feed("O", {"method": "account/updated", "params": params})
        self.complete_turn()
        report = self.analysis.finish()
        self.assertTrue(report["analysis_complete"])
        self.assertEqual(report["ignored_notification_count"], 4)
        self.assertEqual(report["unhandled_message_count"], 0)
        self.assertEqual(report["source_health"], "unknown")
        self.assertEqual([event["event"] for event in report["events"]], ["turn_started", "turn_completed"])
        self.assertNotIn("authMode", json.dumps(report))
        self.assertNotIn("planType", json.dumps(report))

    def test_malformed_account_update_fails_without_disclosing_payload(self) -> None:
        for params in ({"authMode": True}, {"authMode": []}, {"authMode": "private-mode-sentinel"}, {"planType": 1}, {"planType": {}}, {"planType": "private-plan-sentinel"}, {"account": "private-account-sentinel"}):
            with self.subTest(params=params):
                with self.assertRaisesRegex(codex_analysis.AnalysisError, "^invalid-account-update$"):
                    self.feed("O", {"method": "account/updated", "params": params})
                self.assertEqual(self.analysis.ignored, 0)
                self.assertEqual(self.analysis.events, [])

    def test_protocol_limits_reject_excess_before_unbounded_growth(self) -> None:
        with self.assertRaisesRegex(codex_analysis.AnalysisError, "^line-limit$"):
            self.analysis.feed("O", 0, b"x" * (codex_analysis.MAX_LINE_BYTES + 1))
        self.setUp()
        with mock.patch.object(codex_analysis, "MAX_MESSAGES", 1):
            self.feed("I", {"method": "initialized"})
            with self.assertRaisesRegex(codex_analysis.AnalysisError, "^message-limit$"):
                self.feed("I", {"method": "initialized"})
        self.setUp()
        with mock.patch.object(codex_analysis, "MAX_IDENTITIES", 1):
            self.feed("I", {"id": "one", "method": "initialize"})
            with self.assertRaisesRegex(codex_analysis.AnalysisError, "^identity-limit$"):
                self.feed("I", {"id": "two", "method": "initialize"})
        self.setUp()
        self.bind_thread()
        with mock.patch.object(codex_analysis, "MAX_EVENTS", 1):
            self.start_turn()
            with self.assertRaisesRegex(codex_analysis.AnalysisError, "^event-limit$"):
                self.complete_turn()


if __name__ == "__main__":
    unittest.main()
