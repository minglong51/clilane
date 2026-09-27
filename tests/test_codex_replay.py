from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


codex_analysis = load_script("codex_analysis")
codex_replay = load_script("codex_replay")
METHODS = (
    "item/tool/requestUserInput",
    "item/commandExecution/requestApproval",
    "item/fileChange/requestApproval",
    "item/permissions/requestApproval",
)
PINNED_EXECUTABLE = "8eaf1ad12fe6bf89b1710330f58900014322c7c5af677e43be116d8ac5fc0a9e"


def synthetic_report(method: str = METHODS[0], *, idle_before_completion: bool = False, blocking: bool = True, waiting_flag: bool = True) -> dict[str, Any]:
    analysis = codex_analysis.CodexAnalysis()
    thread = {"id": "private-thread-sentinel", "sessionId": "private-session-sentinel"}
    turn = {"id": "private-turn-sentinel", "status": "inProgress"}
    observed_ns = 0

    def feed(stream: str, message: dict[str, Any]) -> None:
        nonlocal observed_ns
        observed_ns += 1_000_000
        analysis.feed(stream, observed_ns, (json.dumps(message) + "\n").encode())

    feed("I", {"id": "private-start-rpc", "method": "thread/start", "params": {}})
    feed("O", {"id": "private-start-rpc", "result": {"thread": thread}})
    feed("O", {"method": "thread/started", "params": {"thread": thread}})
    feed("I", {"id": "private-turn-rpc", "method": "turn/start", "params": {"threadId": thread["id"]}})
    feed("O", {"id": "private-turn-rpc", "result": {"turn": turn}})
    feed("O", {"method": "turn/started", "params": {"threadId": thread["id"], "turn": turn}})
    flag = "waitingOnUserInput" if method == METHODS[0] else "waitingOnApproval"
    feed("O", {"method": "thread/status/changed", "params": {"threadId": thread["id"], "status": {"type": "active", "activeFlags": [flag] if waiting_flag else []}}})
    feed("O", {"id": "private-request-sentinel", "method": method, "params": {"threadId": thread["id"], "turnId": turn["id"], "itemId": "private-item-sentinel", "isBlocking": blocking, "prompt": "private-prompt-sentinel", "cwd": "/private/source-sentinel"}})
    feed("I", {"id": "private-read-rpc", "method": "thread/read", "params": {"threadId": thread["id"], "includeTurns": False}})
    feed("O", {"id": "private-read-rpc", "result": {"thread": thread}})
    feed("I", {"id": "private-request-sentinel", "result": {"answer": "private-answer-sentinel"}})
    feed("O", {"method": "serverRequest/resolved", "params": {"threadId": thread["id"], "requestId": "private-request-sentinel"}})
    feed("O", {"method": "thread/status/changed", "params": {"threadId": thread["id"], "status": {"type": "active", "activeFlags": []}}})
    completed = {"method": "turn/completed", "params": {"threadId": thread["id"], "turn": {**turn, "status": "completed"}}}
    idle = {"method": "thread/status/changed", "params": {"threadId": thread["id"], "status": {"type": "idle"}}}
    for message in ((idle, completed) if idle_before_completion else (completed, idle)):
        feed("O", message)
    analysis.feed("E", observed_ns, b"private-stderr-sentinel")
    report = analysis.finish()
    report.update(
        provider="codex",
        provider_version="0.155.1",
        source_interface="codex-app-server",
        source_capture_sha256=hashlib.sha256(("synthetic-test-source:" + method).encode()).hexdigest(),
        executable_sha256=PINNED_EXECUTABLE,
        capture_status="complete",
    )
    return report


def encoded(records: list[dict[str, Any]]) -> bytes:
    return b"".join((json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode() for record in records)


def reindex(report: dict[str, Any]) -> None:
    for index, event in enumerate(report["events"], 1):
        event["sequence"] = index
        event["observed_ms"] = index


class CodexReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = synthetic_report()

    def assert_rejected(self, report: dict[str, Any]) -> None:
        with self.assertRaises(codex_replay.ReplayError) as caught:
            codex_replay.validate_replay_bytes(encoded([report]))
        self.assertNotIn("private-", str(caught.exception))
        self.assertNotIn("/Users/", str(caught.exception))

    def event(self, name: str, report: dict[str, Any] | None = None) -> dict[str, Any]:
        return next(event for event in (report or self.report)["events"] if event["event"] == name)

    def test_all_request_methods_replay_without_qualifying_provider(self) -> None:
        for method in METHODS:
            with self.subTest(method=method):
                report = synthetic_report(method)
                raw = codex_replay.canonical_replay_bytes([report])
                self.assertEqual(codex_replay.validate_replay_bytes(raw), [report])
                self.assertEqual(report["qualification"], "unqualified")
                self.assertEqual((report["task_binding"], report["source_health"]), ("unknown", "unknown"))
                self.assertTrue(report["analysis_complete"])
                self.assertEqual([event["request_method"] for event in report["events"] if event["request_id"]], [method, method])
                self.assertTrue(all(event["request_method"] is None for event in report["events"] if event["request_id"] is None))
                self.assertNotIn(b"private-", raw)
                self.assertNotIn(b"/private/", raw)

    def test_committed_fixture_preserves_all_four_unqualified_scenarios(self) -> None:
        fixture = ROOT / "tests/fixtures/provider-evidence/codex-replay.jsonl"
        records = codex_replay.validate_replay_bytes(fixture.read_bytes())
        self.assertCountEqual(
            [self.event("request_opened", record)["request_method"] for record in records],
            METHODS,
        )
        for record in records:
            self.assertEqual(record["qualification"], "unqualified")
            self.assertEqual((record["task_binding"], record["source_health"]), ("unknown", "unknown"))

    def test_request_method_allowlists_stay_in_sync(self) -> None:
        self.assertEqual(codex_replay.REQUEST_METHODS, codex_analysis.REQUEST_METHODS)

    def test_blocking_requests_require_observed_waiting_state(self) -> None:
        for method in METHODS:
            with self.subTest(method=method):
                report = synthetic_report(method, waiting_flag=False)
                with self.assertRaisesRegex(codex_replay.ReplayError, "^missing-blocking-wait-state$"):
                    codex_replay.validate_replay_bytes(encoded([report]))

    def test_nonblocking_input_without_waiting_flag_replays(self) -> None:
        report = synthetic_report(blocking=False, waiting_flag=False)
        self.assertTrue(report["analysis_complete"])
        self.assertTrue(all(not event["flags"] for event in report["events"]))
        self.assertFalse(self.event("request_opened", report)["blocking"])
        raw = codex_replay.canonical_replay_bytes([report])
        self.assertEqual(codex_replay.validate_replay_bytes(raw), [report])

    def test_source_analyzer_accepts_both_terminal_notification_orders(self) -> None:
        for method in METHODS:
            for idle_first in (True, False):
                with self.subTest(method=method, idle_before_completion=idle_first):
                    report = synthetic_report(method, idle_before_completion=idle_first)
                    terminal = [(event["event"], event["state"]) for event in report["events"][-2:]]
                    expected = [("thread_state", "idle"), ("turn_completed", "completed")]
                    self.assertEqual(terminal, expected if idle_first else list(reversed(expected)))
                    self.assertTrue(report["analysis_complete"])
                    raw = codex_replay.canonical_replay_bytes([report])
                    self.assertEqual(codex_replay.validate_replay_bytes(raw), [report])
                    self.assertEqual(report["qualification"], "unqualified")

    def test_canonical_bytes_are_deterministic_across_record_and_key_order(self) -> None:
        reports = [synthetic_report(method) for method in METHODS]
        original = copy.deepcopy(reports)
        shuffled = [dict(reversed(list(report.items()))) for report in reversed(reports)]
        first = codex_replay.canonical_replay_bytes(reports)
        self.assertEqual(first, codex_replay.canonical_replay_bytes(shuffled))
        validated = codex_replay.validate_replay_bytes(first)
        self.assertEqual([row["source_capture_sha256"] for row in validated], sorted(row["source_capture_sha256"] for row in reports))
        self.assertEqual(reports, original)
        self.assertTrue(first.endswith(b"\n"))

    def test_duplicate_capture_hashes_are_rejected(self) -> None:
        duplicate = synthetic_report(METHODS[1])
        duplicate["source_capture_sha256"] = self.report["source_capture_sha256"]
        for records in ([self.report, copy.deepcopy(self.report)], [self.report, duplicate]):
            with self.subTest(distinct_records=records[0] != records[1]):
                with self.assertRaises(codex_replay.ReplayError):
                    codex_replay.canonical_replay_bytes(records)
                with self.assertRaises(codex_replay.ReplayError):
                    codex_replay.validate_replay_bytes(encoded(records))

    def test_noncanonical_jsonl_is_rejected(self) -> None:
        raw = encoded([self.report])
        reports = sorted([self.report, synthetic_report(METHODS[1])], key=lambda report: report["source_capture_sha256"])
        for candidate in (raw.rstrip(b"\n"), b" " + raw, raw + b"\n", json.dumps(self.report, indent=2).encode() + b"\n", encoded(list(reversed(reports)))):
            with self.subTest(candidate=candidate[:20]):
                with self.assertRaises(codex_replay.ReplayError):
                    codex_replay.validate_replay_bytes(candidate)

    def test_malformed_envelopes_and_duplicate_keys_are_rejected(self) -> None:
        raw = encoded([self.report])
        candidates = [b"", b"\n", b"[]\n", b"null\n", b"true\n", b"{\n", b"\xff\n", raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'), raw.replace(b'"sequence":1', b'"sequence":1,"sequence":1', 1), raw.replace(b'"message_count":15', b'"message_count":NaN'), raw.replace(b'"message_count":15', b'"message_count":1e999')]
        for candidate in candidates:
            with self.subTest(candidate=candidate[:35]):
                with self.assertRaises(codex_replay.ReplayError):
                    codex_replay.validate_replay_bytes(candidate)

    def test_top_level_keys_are_exact(self) -> None:
        for key in self.report:
            with self.subTest(missing=key):
                report = copy.deepcopy(self.report)
                del report[key]
                self.assert_rejected(report)
        for key in ("prompt", "source_path", "transcript", "private-extra-sentinel"):
            with self.subTest(extra=key):
                report = copy.deepcopy(self.report)
                report[key] = "private-content-sentinel"
                self.assert_rejected(report)

    def test_event_keys_are_exact(self) -> None:
        for key in self.event("request_opened"):
            with self.subTest(missing=key):
                report = copy.deepcopy(self.report)
                del self.event("request_opened", report)[key]
                self.assert_rejected(report)
        report = copy.deepcopy(self.report)
        self.event("request_opened", report)["prompt"] = "private-content-sentinel"
        self.assert_rejected(report)

    def test_private_strings_are_rejected_in_every_text_field(self) -> None:
        for key, value in self.report.items():
            if isinstance(value, str):
                with self.subTest(top_level=key):
                    report = copy.deepcopy(self.report)
                    report[key] = "/Users/private-content-sentinel"
                    self.assert_rejected(report)
        for index, event in enumerate(self.report["events"]):
            for key, value in event.items():
                if isinstance(value, str) or value is None:
                    with self.subTest(event=index, field=key):
                        report = copy.deepcopy(self.report)
                        report["events"][index][key] = "private-content-sentinel"
                        self.assert_rejected(report)
        report = copy.deepcopy(self.report)
        report["events"][0]["flags"] = ["private-content-sentinel"]
        self.assert_rejected(report)

    def test_qualification_binding_and_capture_constants_cannot_be_promoted(self) -> None:
        mutations = {"schema_version": [2, True, 1.0], "analyzer": ["codex-app-server-v2"], "analysis_complete": [False, 1, "true"], "qualification": ["qualified", "authoritative"], "task_binding": ["exact"], "source_health": ["fresh"], "session_binding": ["unknown"], "provider": ["claude"], "provider_version": ["0.155.2"], "source_interface": ["native_hook"], "capture_status": ["partial", "synthetic"]}
        for key, values in mutations.items():
            for value in values:
                with self.subTest(field=key, value=value):
                    report = copy.deepcopy(self.report)
                    report[key] = value
                    self.assert_rejected(report)

    def test_provenance_hashes_are_strict_and_executable_must_match_pin(self) -> None:
        for key in ("source_capture_sha256", "executable_sha256"):
            for value in ("a" * 63, "a" * 65, "A" * 64, "g" * 64, None, True, [], {}):
                with self.subTest(field=key, value=value):
                    report = copy.deepcopy(self.report)
                    report[key] = value
                    self.assert_rejected(report)
        report = copy.deepcopy(self.report)
        report["executable_sha256"] = "a" * 64
        self.assert_rejected(report)

    def test_manifest_drift_invalidates_previously_pinned_records(self) -> None:
        evidence = codex_replay.provider_evidence
        manifest = evidence.load_executable_manifest(ROOT / evidence.EXECUTABLE_MANIFEST_PATH)
        changed = {**manifest, "codex": hashlib.sha256(b"different-synthetic-executable").hexdigest()}
        with mock.patch.object(evidence, "load_executable_manifest", return_value=changed) as load:
            self.assert_rejected(self.report)
        load.assert_called_once_with(ROOT / evidence.EXECUTABLE_MANIFEST_PATH)
        with mock.patch.object(evidence, "load_executable_manifest", side_effect=evidence.EvidenceError("private-manifest-sentinel")):
            self.assert_rejected(self.report)

    def test_exporter_requires_provenance_analysis_and_validates_its_result(self) -> None:
        root = Path("/private/synthetic-test-root")
        capture_id = "capture-codex-synthetic-test"
        evidence = codex_replay.provider_evidence
        with mock.patch.object(evidence, "analyze_codex_capture", return_value=copy.deepcopy(self.report)) as analyze:
            raw = codex_replay.export_capture(root, capture_id)
        analyze.assert_called_once_with(root, capture_id)
        self.assertEqual(codex_replay.validate_replay_bytes(raw), [self.report])
        self.assertNotIn(b"private-", raw)
        for invalid in ({**self.report, "analysis_complete": False}, {**self.report, "prompt": "private-prompt-sentinel"}, {**self.report, "qualification": "authoritative"}):
            with mock.patch.object(evidence, "analyze_codex_capture", return_value=invalid):
                with self.assertRaises(codex_replay.ReplayError) as caught:
                    codex_replay.export_capture(root, capture_id)
                self.assertNotIn("private-", str(caught.exception))

    def test_exporter_does_not_bypass_provenance_failure(self) -> None:
        evidence = codex_replay.provider_evidence
        for error in (evidence.EvidenceError("private-capture-sentinel"), OSError("private-source-sentinel")):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(evidence, "analyze_codex_capture", side_effect=error) as analyze:
                    with self.assertRaises(codex_replay.ReplayError) as caught:
                        codex_replay.export_capture(Path("/private/synthetic-test-root"), "capture-codex-synthetic-test")
                analyze.assert_called_once()
                self.assertNotIn("private-", str(caught.exception))

    def test_export_arguments_are_typed_before_accessing_source(self) -> None:
        with mock.patch.object(codex_replay.provider_evidence, "analyze_codex_capture") as analyze:
            for root, capture_id in (("/private/synthetic-test-root", "capture-test"), (None, "capture-test"), (Path("/private/synthetic-test-root"), None), (Path("/private/synthetic-test-root"), True)):
                with self.assertRaises(codex_replay.ReplayError):
                    codex_replay.export_capture(root, capture_id)
        analyze.assert_not_called()

    def test_input_can_be_nonblocking_but_approval_cannot(self) -> None:
        for method in METHODS:
            with self.subTest(method=method):
                report = synthetic_report(method)
                for event in report["events"]:
                    if event["request_id"]:
                        event["blocking"] = False
                if method == METHODS[0]:
                    self.assertEqual(codex_replay.validate_replay_bytes(encoded([report])), [report])
                else:
                    self.assert_rejected(report)

    def test_counter_types_and_bounds_are_strict(self) -> None:
        counters = [key for key in self.report if key.endswith("_count")]
        for key in counters:
            for value in (True, False, 0.5, "1", None, -1, 1 << 63):
                with self.subTest(field=key, value=value):
                    report = copy.deepcopy(self.report)
                    report[key] = value
                    self.assert_rejected(report)

    def test_incomplete_or_inconsistent_counts_are_rejected(self) -> None:
        for key, value in (("provider_warning_count", 1), ("unhandled_message_count", 1), ("unresolved_request_count", 1), ("turn_count", 0), ("turn_count", 2), ("message_count", 0), ("message_count", 4097), ("duplicate_count", 16), ("ignored_notification_count", 16), ("thread_read_count", 16)):
            with self.subTest(field=key, value=value):
                report = copy.deepcopy(self.report)
                report[key] = value
                self.assert_rejected(report)

    def test_synthetic_binding_mismatches_are_rejected(self) -> None:
        for key, value in (("session_id", "synthetic-codex-session-2"), ("session_id", None)):
            report = copy.deepcopy(self.report)
            report[key] = value
            self.assert_rejected(report)
        for key, value in (("thread_id", "synthetic-codex-thread-2"), ("turn_id", "synthetic-codex-turn-2"), ("request_id", "synthetic-codex-request-2")):
            for name in ("request_opened", "request_resolved"):
                with self.subTest(field=key, event=name):
                    report = copy.deepcopy(self.report)
                    self.event(name, report)[key] = value
                    self.assert_rejected(report)

    def test_sequence_and_observation_times_are_bounded_and_ordered(self) -> None:
        for key in ("sequence", "observed_ms"):
            for value in (True, False, -1, 1.5, "1", None, 1 << 63):
                with self.subTest(field=key, value=value):
                    report = copy.deepcopy(self.report)
                    report["events"][1][key] = value
                    self.assert_rejected(report)
        for key, value in (("sequence", 1), ("sequence", 3), ("observed_ms", self.report["events"][0]["observed_ms"] - 1)):
            report = copy.deepcopy(self.report)
            report["events"][1][key] = value
            self.assert_rejected(report)

    def test_equal_observation_milliseconds_are_allowed(self) -> None:
        report = copy.deepcopy(self.report)
        for event in report["events"]:
            event["observed_ms"] = 10
        self.assertEqual(codex_replay.validate_replay_bytes(encoded([report])), [report])

    def test_explicit_resource_limits_fail_closed(self) -> None:
        for raw in (b"x" * (4 * 1024 * 1024 + 1), b"x" * (512 * 1024 + 1) + b"\n", b"[" * 2000 + b"]" * 2000 + b"\n", encoded([self.report]) * 33):
            with self.subTest(size=len(raw)):
                with self.assertRaises(codex_replay.ReplayError):
                    codex_replay.validate_replay_bytes(raw)
        report = copy.deepcopy(self.report)
        report["events"] = [copy.deepcopy(report["events"][0]) for _ in range(1025)]
        reindex(report)
        self.assert_rejected(report)
        report = copy.deepcopy(self.report)
        report["events"][-1]["observed_ms"] = 86_400_000
        self.assertEqual(codex_replay.validate_replay_bytes(encoded([report])), [report])
        report["events"][-1]["observed_ms"] += 1
        self.assert_rejected(report)

    def test_public_container_arguments_are_strict(self) -> None:
        for raw in (None, "{}\n", bytearray(encoded([self.report])), memoryview(encoded([self.report]))):
            with self.assertRaises(codex_replay.ReplayError):
                codex_replay.validate_replay_bytes(raw)
        for records in (None, {}, (), [], (self.report,), [None], [self.report] * 33):
            with self.assertRaises(codex_replay.ReplayError):
                codex_replay.canonical_replay_bytes(records)

    def test_request_method_and_kind_must_agree(self) -> None:
        for key, value in (("request_method", None), ("request_method", "item/new/requestApproval"), ("request_method", METHODS[1]), ("request_kind", "approval"), ("blocking", "true"), ("blocking", 1), ("blocking", None)):
            with self.subTest(field=key, value=value):
                report = copy.deepcopy(self.report)
                self.event("request_opened", report)[key] = value
                self.assert_rejected(report)
        report = copy.deepcopy(self.report)
        self.event("turn_started", report)["request_method"] = METHODS[0]
        self.assert_rejected(report)

    def test_resolution_must_match_open_request(self) -> None:
        for key, value in (("request_id", "synthetic-codex-request-2"), ("turn_id", "synthetic-codex-turn-2"), ("request_method", METHODS[3]), ("request_kind", "approval"), ("blocking", False)):
            with self.subTest(field=key, value=value):
                report = copy.deepcopy(self.report)
                self.event("request_resolved", report)[key] = value
                self.assert_rejected(report)
        report = synthetic_report(METHODS[1])
        self.event("request_resolved", report)["request_method"] = METHODS[3]
        self.assert_rejected(report)

    def test_nonrequest_events_cannot_contain_request_identity(self) -> None:
        for key, value in (("request_id", "synthetic-codex-request-1"), ("request_method", METHODS[0]), ("request_kind", "input"), ("blocking", True)):
            report = copy.deepcopy(self.report)
            self.event("turn_completed", report)[key] = value
            self.assert_rejected(report)

    def test_missing_lifecycle_events_are_rejected(self) -> None:
        for name in ("turn_started", "request_opened", "request_resolved", "turn_completed"):
            with self.subTest(event=name):
                report = copy.deepcopy(self.report)
                report["events"] = [event for event in report["events"] if event["event"] != name]
                reindex(report)
                self.assert_rejected(report)
        report = copy.deepcopy(self.report)
        report["events"].pop()
        self.assert_rejected(report)

    def test_duplicate_lifecycle_events_are_rejected(self) -> None:
        for name in ("turn_started", "request_opened", "request_resolved", "turn_completed"):
            with self.subTest(event=name):
                report = copy.deepcopy(self.report)
                event = self.event(name, report)
                index = report["events"].index(event)
                report["events"].insert(index + 1, copy.deepcopy(event))
                reindex(report)
                self.assert_rejected(report)

    def test_early_resolution_completion_and_idle_are_rejected(self) -> None:
        for first, second in (("request_opened", "request_resolved"), ("request_resolved", "turn_completed"), ("turn_started", "request_opened")):
            with self.subTest(events=(first, second)):
                report = copy.deepcopy(self.report)
                i = report["events"].index(self.event(first, report))
                j = report["events"].index(self.event(second, report))
                report["events"][i], report["events"][j] = report["events"][j], report["events"][i]
                reindex(report)
                self.assert_rejected(report)
        report = copy.deepcopy(self.report)
        idle = report["events"].pop()
        report["events"].insert(report["events"].index(self.event("request_resolved", report)), idle)
        reindex(report)
        self.assert_rejected(report)

    def test_idle_before_resolution_is_rejected_even_with_valid_terminal_idle(self) -> None:
        for idle_first in (True, False):
            with self.subTest(idle_before_completion=idle_first):
                report = synthetic_report(idle_before_completion=idle_first)
                idle = next(event for event in report["events"] if event["state"] == "idle")
                index = report["events"].index(self.event("request_resolved", report))
                report["events"].insert(index, copy.deepcopy(idle))
                report["message_count"] += 1
                reindex(report)
                self.assert_rejected(report)

    def test_idle_before_turn_cannot_substitute_for_terminal_idle(self) -> None:
        report = copy.deepcopy(self.report)
        idle = report["events"][-1]
        report["events"] = [idle, *(event for event in report["events"] if event["event"] != "thread_state")]
        reindex(report)
        self.assert_rejected(report)

    def test_failed_or_interrupted_turns_and_nonidle_terminal_states_are_rejected(self) -> None:
        for state in ("failed", "interrupted", "inProgress", None):
            report = copy.deepcopy(self.report)
            self.event("turn_completed", report)["state"] = state
            self.assert_rejected(report)
        for state in ("active", "notLoaded", "systemError", None):
            report = copy.deepcopy(self.report)
            report["events"][-1]["state"] = state
            self.assert_rejected(report)

    def test_flags_are_bounded_and_appropriate_for_event(self) -> None:
        for flags in (None, "waitingOnUserInput", ["waitingOnUserInput", "waitingOnUserInput"], ["unknown"], [True]):
            report = copy.deepcopy(self.report)
            self.event("thread_state", report)["flags"] = flags
            self.assert_rejected(report)
        for name in ("turn_started", "request_opened", "request_resolved", "turn_completed"):
            report = copy.deepcopy(self.report)
            self.event(name, report)["flags"] = ["waitingOnUserInput"]
            self.assert_rejected(report)
        report = copy.deepcopy(self.report)
        report["events"][-1]["flags"] = ["waitingOnApproval"]
        self.assert_rejected(report)
        report = copy.deepcopy(self.report)
        self.event("thread_state", report)["flags"] = ["waitingOnApproval"]
        self.assert_rejected(report)

    def test_container_types_are_strict(self) -> None:
        for value in (None, {}, "events", 1, []):
            report = copy.deepcopy(self.report)
            report["events"] = value
            self.assert_rejected(report)
        for value in (None, [], "event", 1, True):
            report = copy.deepcopy(self.report)
            report["events"][0] = value
            self.assert_rejected(report)

    def test_offline_check_accepts_valid_bytes_and_rejects_private_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "synthetic-replay.jsonl"
            fixture.write_bytes(codex_replay.canonical_replay_bytes([self.report]))
            command = [sys.executable, "-B", str(ROOT / "scripts/codex_replay.py"), "--check", "--fixture", str(fixture)]
            environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            result = subprocess.run(command, capture_output=True, timeout=10, env=environment)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            fixture.write_bytes(encoded([{**self.report, "prompt": "private-content-sentinel"}]))
            result = subprocess.run(command, capture_output=True, timeout=10, env=environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b"private-content-sentinel", result.stdout + result.stderr)

    def test_cli_argument_errors_do_not_echo_private_arguments(self) -> None:
        command = [sys.executable, "-B", str(ROOT / "scripts/codex_replay.py"), "--check", "--capture-root", "/private/private-source-sentinel"]
        result = subprocess.run(command, capture_output=True, timeout=10, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"private-source-sentinel", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
