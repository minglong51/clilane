from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
try:
    import codex_observer
finally:
    sys.path.pop(0)


class ObserverFixture(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="codex-observer-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.binding = codex_observer.TaskBinding("a" * 64)
        self.now = 10_000_000_000
        self.observed_ns = 0
        self.observer = codex_observer.Observer(self.binding, clock=lambda: self.now)
        self.thread = {"id": "private-thread-sentinel", "sessionId": "private-session-sentinel"}

    def command(self, op: str, **values: Any) -> dict[str, Any]:
        return {"op": op, "task_generation": self.binding.generation, "instance": self.observer.instance, **values}

    def observe(self, stream: str, message: dict[str, Any]) -> dict[str, Any]:
        self.observed_ns += 1_000_000
        return self.observer.handle(self.command("observe", stream=stream, observed_ns=self.observed_ns, message=message))

    def bind_thread(self) -> None:
        self.observe("I", {"id": "thread-start", "method": "thread/start", "params": {}})
        self.observe("O", {"id": "thread-start", "result": {"thread": self.thread}})

    def read_thread(self, request_id: str = "read-live") -> None:
        self.observe("I", {"id": request_id, "method": "thread/read", "params": {"threadId": self.thread["id"], "includeTurns": False}})
        self.observe("O", {"id": request_id, "result": {"thread": self.thread}})

    def make_ready(self) -> dict[str, Any]:
        self.bind_thread()
        self.read_thread()
        return self.observer.handle(self.command("ready", recovered_count=0))

    def frames(self, *, read: bool = False, request: bool = False) -> list[tuple[str, dict[str, Any]]]:
        result = [("I", {"id": "thread-start", "method": "thread/start", "params": {}}), ("O", {"id": "thread-start", "result": {"thread": self.thread}})]
        if request:
            turn = {"id": "private-turn-sentinel", "status": "inProgress"}
            result.extend([("I", {"id": "turn-start", "method": "turn/start", "params": {"threadId": self.thread["id"]}}), ("O", {"id": "turn-start", "result": {"turn": turn}}), ("O", {"method": "turn/started", "params": {"threadId": self.thread["id"], "turn": turn}}), ("O", {"id": "private-request-sentinel", "method": "item/permissions/requestApproval", "params": {"threadId": self.thread["id"], "turnId": turn["id"], "itemId": "private-item-sentinel", "reason": "private-prompt-sentinel"}})])
        if read:
            result.extend([("I", {"id": "read-replayed", "method": "thread/read", "params": {"threadId": self.thread["id"], "includeTurns": False}}), ("O", {"id": "read-replayed", "result": {"thread": self.thread}})])
        return result

    def journal(self, frames: list[tuple[str, dict[str, Any]]], name: str = "journal.jsonl") -> tuple[Path, str]:
        path = self.root / name
        journal = codex_observer.Journal(path, self.binding)
        try:
            for number, (stream, message) in enumerate(frames, 1):
                journal.append(stream, number * 1_000_000, message)
            digest = journal.digest.hexdigest()
        finally:
            journal.close()
        return path, digest

    def replay(self, frames: list[tuple[str, dict[str, Any]]]) -> None:
        path, digest = self.journal(frames)
        self.observer.replay(path, digest)
        self.observed_ns = len(frames) * 1_000_000

    def private_file(self, raw: bytes, name: str = "fixture.jsonl") -> Path:
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return path


class ObserverFreshnessTests(ObserverFixture):
    def test_account_update_cannot_establish_or_renew_source_freshness(self) -> None:
        message = {"method": "account/updated", "params": {"authMode": "chatgpt", "planType": "pro"}}
        self.bind_thread()
        report = self.observe("O", message)
        self.assertEqual(report["health"], "unknown")
        with self.assertRaisesRegex(codex_observer.ObserverError, "^fresh-source-proof-required$"):
            self.observer.handle(self.command("ready", recovered_count=0))
        self.read_thread()
        ready = self.observer.handle(self.command("ready", recovered_count=0))
        self.now += 1_000_000_000
        self.assertEqual(self.observe("O", message)["fresh_until_monotonic_ns"], ready["fresh_until_monotonic_ns"])
        self.now = ready["fresh_until_monotonic_ns"]
        with self.assertRaisesRegex(codex_observer.ObserverError, "^observer-expired$"):
            self.observe("O", message)
        expired = self.observer.report()
        self.assertEqual((expired["health"], expired["state"]), ("unknown", "expired"))
        self.assertIsNone(expired["fresh_until_monotonic_ns"])

    def test_bound_live_thread_read_is_required_before_ready(self) -> None:
        self.bind_thread()
        with self.assertRaisesRegex(codex_observer.ObserverError, "^fresh-source-proof-required$"):
            self.observer.handle(self.command("ready", recovered_count=0))
        self.observe("I", {"id": "read-live", "method": "thread/read", "params": {"threadId": self.thread["id"]}})
        with self.assertRaisesRegex(codex_observer.ObserverError, "^fresh-source-proof-required$"):
            self.observer.handle(self.command("ready", recovered_count=0))
        self.observe("O", {"id": "read-live", "result": {"thread": self.thread}})
        report = self.observer.handle(self.command("ready", recovered_count=0))
        self.assertEqual((report["health"], report["state"]), ("healthy", "ready"))
        self.assertEqual(report["fresh_until_monotonic_ns"], self.now + codex_observer.FRESHNESS_NS)
        self.assertEqual(report["qualification"], "unqualified")

    def test_replay_and_duplicate_read_cannot_supply_new_live_proof(self) -> None:
        self.replay(self.frames(read=True))
        report = self.observer.report()
        self.assertEqual((report["health"], report["state"]), ("unknown", "recovering"))
        self.assertEqual(report["thread_read_count"], 1)
        self.assertEqual(report["replayed_message_count"], 4)
        self.assertIsNone(report["fresh_until_monotonic_ns"])
        self.read_thread("read-replayed")
        self.assertEqual(self.observer.report()["duplicate_count"], 2)
        with self.assertRaisesRegex(codex_observer.ObserverError, "^fresh-source-proof-required$"):
            self.observer.handle(self.command("ready", recovered_count=0))
        self.read_thread("read-new")
        report = self.observer.handle(self.command("ready", recovered_count=0))
        self.assertEqual(report["health"], "healthy")
        self.assertEqual(report["thread_read_count"], 2)

    def test_live_response_to_a_replayed_request_is_not_live_proof(self) -> None:
        self.replay(self.frames(read=True)[:-1])
        self.observe("O", {"id": "read-replayed", "result": {"thread": self.thread}})
        self.assertEqual(self.observer.report()["thread_read_count"], 1)
        with self.assertRaisesRegex(codex_observer.ObserverError, "^fresh-source-proof-required$"):
            self.observer.handle(self.command("ready", recovered_count=0))

    def test_recovered_requests_require_exact_count_and_stay_sanitized(self) -> None:
        self.replay(self.frames(request=True))
        self.read_thread()
        for count in (0, 2, True, "1"):
            with self.subTest(count=count):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^recovery-count-mismatch$"):
                    self.observer.handle(self.command("ready", recovered_count=count))
        report = self.observer.handle(self.command("ready", recovered_count=1))
        self.assertEqual(report["unresolved_requests"], ["synthetic-codex-request-1"])
        self.assertNotIn("private-", json.dumps(report))
        self.observe("I", {"id": "private-request-sentinel", "result": {"permissions": {}}})
        self.assertEqual(self.observer.report()["unresolved_requests"], ["synthetic-codex-request-1"])
        report = self.observe("O", {"method": "serverRequest/resolved", "params": {"threadId": self.thread["id"], "requestId": "private-request-sentinel"}})
        self.assertEqual(report["unresolved_requests"], [])

    def test_invalid_response_and_out_of_order_observation_are_atomic(self) -> None:
        self.bind_thread()
        self.observe("I", {"id": "read-live", "method": "thread/read", "params": {"threadId": self.thread["id"]}})
        before = self.observer.report()
        with self.assertRaisesRegex(codex_observer.AnalysisError, "^thread-binding-mismatch$"):
            self.observe("O", {"id": "read-live", "result": {"thread": {**self.thread, "sessionId": "stale-session"}}})
        self.assertEqual(self.observer.report(), before)
        with self.assertRaisesRegex(codex_observer.ObserverError, "^observation-order-mismatch$"):
            self.observer.handle(self.command("observe", stream="O", observed_ns=0, message={"id": "read-live", "result": {"thread": self.thread}}))
        self.assertEqual(self.observer.report(), before)
        self.observe("O", {"id": "read-live", "result": {"thread": self.thread}})
        self.assertEqual(self.observer.handle(self.command("ready", recovered_count=0))["health"], "healthy")

    def test_health_expires_at_exact_deadline_and_cannot_be_revived(self) -> None:
        ready = self.make_ready()
        deadline = ready["fresh_until_monotonic_ns"]
        self.now = deadline - 1
        self.assertEqual(self.observer.report()["health"], "healthy")
        self.now = deadline
        report = self.observer.handle(self.command("status"))
        self.assertEqual((report["health"], report["state"]), ("unknown", "expired"))
        self.assertIsNone(report["fresh_until_monotonic_ns"])
        for command in (self.command("ready", recovered_count=0), self.command("observe", stream="I", observed_ns=20_000_000, message={"method": "initialized"})):
            with self.subTest(op=command["op"]):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^observer-expired$"):
                    self.observer.handle(command)
        self.now -= 1
        self.assertEqual(self.observer.report()["state"], "expired")

    def test_only_a_new_correlated_read_refreshes_ready_health(self) -> None:
        deadline = self.make_ready()["fresh_until_monotonic_ns"]
        self.now += 1_000_000_000
        self.read_thread("read-live")
        self.assertEqual(self.observer.report()["fresh_until_monotonic_ns"], deadline)
        self.observe("O", {"method": "thread/status/changed", "params": {"threadId": self.thread["id"], "status": {"type": "idle"}}})
        self.assertEqual(self.observer.report()["fresh_until_monotonic_ns"], deadline)
        self.read_thread("read-fresh")
        self.assertEqual(self.observer.report()["fresh_until_monotonic_ns"], self.now + codex_observer.FRESHNESS_NS)

    def test_stale_proof_and_unhandled_source_cannot_mark_ready(self) -> None:
        self.bind_thread()
        self.read_thread()
        self.now += codex_observer.FRESHNESS_NS
        with self.assertRaisesRegex(codex_observer.ObserverError, "^fresh-source-proof-required$"):
            self.observer.handle(self.command("ready", recovered_count=0))
        self.read_thread("read-fresh")
        self.observe("O", {"method": "unknown/newFeature", "params": {}})
        with self.assertRaisesRegex(codex_observer.ObserverError, "^fresh-source-proof-required$"):
            self.observer.handle(self.command("ready", recovered_count=0))

    def test_stale_task_and_observer_commands_do_not_mutate_state(self) -> None:
        self.bind_thread()
        before = self.observer.report()
        for field, value, error in (("task_generation", "b" * 64, "stale-task-generation"), ("instance", "old-instance", "stale-observer-instance")):
            with self.subTest(field=field):
                command = self.command("observe", stream="I", observed_ns=3_000_000, message={"method": "initialized"})
                command[field] = value
                with self.assertRaisesRegex(codex_observer.ObserverError, f"^{error}$"):
                    self.observer.handle(command)
                self.assertEqual(self.observer.report(), before)
        replacement = codex_observer.Observer(self.binding, clock=lambda: self.now)
        self.assertNotEqual(replacement.instance, self.observer.instance)
        with self.assertRaisesRegex(codex_observer.ObserverError, "^stale-observer-instance$"):
            replacement.handle(self.command("status"))

    def test_commands_and_observation_frames_reject_invalid_shapes(self) -> None:
        for command in (self.command("status", extra=True), self.command("unknown"), self.command("ready"), self.command("observe", stream="I", observed_ns=0)):
            with self.subTest(command=command):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^invalid-command$"):
                    self.observer.handle(command)
        for stream, observed, message in (("E", 0, {}), (None, 0, {}), ("O", True, {}), ("O", -1, {}), ("O", 1 << 63, {}), ("O", 0, []), ("O", 0, {"payload": "x" * 65536})):
            with self.subTest(stream=stream, observed=observed):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^invalid-observation$"):
                    self.observer.handle(self.command("observe", stream=stream, observed_ns=observed, message=message))
        self.assertEqual(self.observer.report()["message_count"], 0)


class JournalBoundaryTests(ObserverFixture):
    def test_journal_is_private_exclusive_and_digest_binds_all_bytes(self) -> None:
        path, digest = self.journal(self.frames())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
        original = path.read_bytes()
        with self.assertRaises(FileExistsError):
            codex_observer.Journal(path, self.binding)
        self.assertEqual(path.read_bytes(), original)
        self.observer.replay(path, digest)
        self.assertEqual(self.observer.report()["replayed_message_count"], 2)
        self.assertEqual(self.observer.report()["health"], "unknown")

    def test_journal_integrity_and_task_binding_fail_before_replay(self) -> None:
        path, digest = self.journal(self.frames())
        with self.assertRaisesRegex(codex_observer.ObserverError, "^journal-integrity-mismatch$"):
            self.observer.replay(path, "0" * 64)
        self.assertEqual(self.observer.report()["message_count"], 0)
        other = codex_observer.Observer(codex_observer.TaskBinding("b" * 64))
        with self.assertRaisesRegex(codex_observer.ObserverError, "^journal-binding-mismatch$"):
            other.replay(path, digest)
        self.assertEqual(other.report()["message_count"], 0)
        raw = path.read_bytes().rstrip(b"\n")
        path.write_bytes(raw)
        with self.assertRaisesRegex(codex_observer.ObserverError, "^journal-integrity-mismatch$"):
            self.observer.replay(path, hashlib.sha256(raw).hexdigest())

    def test_failed_replay_is_atomic_and_valid_replay_can_follow(self) -> None:
        path, _digest = self.journal(self.frames())
        valid = path.read_bytes()
        malformed = valid + json.dumps({"stream": "O", "observed_ns": 3_000_000, "message": {"id": "unbound", "result": {}}}).encode() + b"\n"
        path.write_bytes(malformed)
        with self.assertRaisesRegex(codex_observer.AnalysisError, "^unbound-response$"):
            self.observer.replay(path, hashlib.sha256(malformed).hexdigest())
        self.assertEqual(self.observer.report()["message_count"], 0)
        self.assertEqual(self.observer.report()["replayed_message_count"], 0)
        path.write_bytes(valid)
        self.observer.replay(path, hashlib.sha256(valid).hexdigest())
        self.assertEqual(self.observer.report()["message_count"], 2)
        with self.assertRaisesRegex(codex_observer.ObserverError, "^replay-order-mismatch$"):
            self.observer.replay(path, hashlib.sha256(valid).hexdigest())

    def test_journal_headers_and_frame_fields_are_exact(self) -> None:
        header = {"schema_version": 1, "task_generation": self.binding.generation}
        cases = [(dict(header, schema_version=True), "journal-binding-mismatch"), (dict(header, extra=True), "journal-binding-mismatch"), (header, "journal-frame-invalid")]
        for number, (value, error) in enumerate(cases):
            with self.subTest(error=error, number=number):
                raw = json.dumps(value).encode() + b"\n"
                if error == "journal-frame-invalid":
                    raw += b'{"stream":"I","observed_ns":0,"message":{},"extra":true}\n'
                path = self.private_file(raw, f"invalid-{number}.jsonl")
                with self.assertRaisesRegex(codex_observer.ObserverError, f"^{error}$"):
                    self.observer.replay(path, hashlib.sha256(raw).hexdigest())
                self.assertEqual(self.observer.report()["message_count"], 0)

    def test_private_reader_rejects_modes_links_empty_and_oversized_files(self) -> None:
        path = self.private_file(b"synthetic private contents")
        for mode in (0o644, 0o400, 0o666):
            with self.subTest(mode=mode):
                path.chmod(mode)
                with self.assertRaisesRegex(codex_observer.ObserverError, "^private-file-invalid$"):
                    codex_observer._read_private(path, 100)
        path.chmod(0o600)
        hardlink = self.root / "hardlink"
        os.link(path, hardlink)
        with self.assertRaisesRegex(codex_observer.ObserverError, "^private-file-invalid$"):
            codex_observer._read_private(path, 100)
        hardlink.unlink()
        symlink = self.root / "symlink"
        symlink.symlink_to(path)
        with self.assertRaises(OSError):
            codex_observer._read_private(symlink, 100)
        with self.assertRaisesRegex(codex_observer.ObserverError, "^private-file-invalid$"):
            codex_observer._read_private(path, 2)
        path.write_bytes(b"")
        with self.assertRaisesRegex(codex_observer.ObserverError, "^private-file-invalid$"):
            codex_observer._read_private(path, 100)

    def test_private_reader_rejects_nonregular_files_without_blocking(self) -> None:
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(codex_observer.ObserverError, "^private-file-invalid$"):
            codex_observer._read_private(fifo, 100)

    def test_private_reader_rejects_mutation_during_read(self) -> None:
        path = self.private_file(b"original")
        original_read = os.read
        changed = False

        def mutate(descriptor: int, count: int) -> bytes:
            nonlocal changed
            result = original_read(descriptor, count)
            if not changed:
                changed = True
                path.write_bytes(b"replacement contents")
            return result

        with mock.patch.object(codex_observer.os, "read", side_effect=mutate):
            with self.assertRaisesRegex(codex_observer.ObserverError, "^private-file-changed$"):
                codex_observer._read_private(path, 100)

    def test_private_directory_requires_canonical_path_mode_and_owner(self) -> None:
        path = self.private_file(b"synthetic")
        self.root.chmod(0o755)
        with self.assertRaisesRegex(codex_observer.ObserverError, "^private-directory-required$"):
            codex_observer._read_private(path, 100)
        self.root.chmod(0o700)
        link = self.root / "directory-link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(codex_observer.ObserverError, "^private-directory-required$"):
            codex_observer._read_private(link / path.name, 100)
        with mock.patch.object(codex_observer.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(codex_observer.ObserverError, "^private-directory-required$"):
                codex_observer._read_private(path, 100)

    def test_journal_budgets_and_failed_creation_do_not_leave_partial_files(self) -> None:
        path = self.root / "journal.jsonl"
        with mock.patch.object(codex_observer, "MAX_JOURNAL_BYTES", 1):
            with self.assertRaisesRegex(codex_observer.ObserverError, "^journal-byte-limit$"):
                codex_observer.Journal(path, self.binding)
        self.assertFalse(path.exists())
        journal = codex_observer.Journal(path, self.binding)
        try:
            with mock.patch.object(codex_observer, "MAX_COMMANDS", 1):
                journal.append("I", 0, {"method": "initialized"})
                with self.assertRaisesRegex(codex_observer.ObserverError, "^journal-message-limit$"):
                    journal.append("I", 1, {"method": "initialized"})
            before = path.read_bytes()
            with mock.patch.object(codex_observer, "MAX_JOURNAL_BYTES", len(before)):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^journal-byte-limit$"):
                    journal.append("I", 2, {"method": "initialized"})
            self.assertEqual(path.read_bytes(), before)
        finally:
            journal.close()
        with mock.patch.object(codex_observer, "MAX_COMMANDS", 0):
            with self.assertRaisesRegex(codex_observer.ObserverError, "^journal-message-limit$"):
                self.observer.replay(path, hashlib.sha256(path.read_bytes()).hexdigest())


class TaskBindingTests(ObserverFixture):
    def environment_and_record(self) -> tuple[dict[str, str], Path, dict[str, Any]]:
        state = self.root / "state"
        state.mkdir(mode=0o700)
        registry = state / "registry"
        registry.mkdir(mode=0o700)
        socket = str(self.root / "synthetic.sock")
        task = "01234567-89ab-cdef-0123-456789abcdef"
        bucket = registry / hashlib.sha256(socket.encode()).hexdigest()[:16]
        bucket.mkdir(mode=0o700)
        path = bucket / (task + ".json")
        record = {"schema_version": 1, "phase": "live", "socket": socket, "id": task, "session": "agt_" + task.replace("-", "")[:12], "created": "synthetic-generation-one"}
        path.write_text(json.dumps(record), encoding="utf-8")
        path.chmod(0o600)
        return {"CLILANE_STATE_HOME": str(state), "CLILANE_TMUX_SOCKET": socket, "CLILANE_TASK_ID": task}, path, record

    def live_output(self, record: dict[str, Any], **changes: str) -> bytes:
        values = {
            "session": record["session"], "session_id": "$1", "created": "12345",
            "pane": "%2", "dead": "0", "pid": "10",
            "encoded": base64.urlsafe_b64encode(json.dumps(record).encode()).decode(),
            "committed": "1", "started": "synthetic-start", "ready": record["id"],
            "stopped": "0", "result": "",
        }
        values.update(changes)
        return ("|".join(values.values()) + "\n").encode()

    @contextmanager
    def live_proof(self, path: Path) -> Iterator[None]:
        identities = {
            30: codex_observer._ProcessIdentity(30, 20, os.getuid(), "observer-start"),
            20: codex_observer._ProcessIdentity(20, 10, os.getuid(), "task-start"),
            10: codex_observer._ProcessIdentity(10, 1, os.getuid(), "synthetic-start"),
        }
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(codex_observer.shutil, "which", return_value="/synthetic/tmux"))
            stack.enter_context(mock.patch.object(codex_observer, "_socket_identity", return_value=(1, 2)))
            stack.enter_context(mock.patch.object(codex_observer, "_task_query", side_effect=lambda *_args: self.live_output(json.loads(path.read_bytes()))))
            stack.enter_context(mock.patch.object(codex_observer, "_process_identity", side_effect=lambda pid, _deadline: identities[pid]))
            stack.enter_context(mock.patch.object(codex_observer.os, "getpid", return_value=30))
            yield

    def test_generation_is_stable_for_exact_record_and_changes_with_new_task_lifetime(self) -> None:
        environment, path, record = self.environment_and_record()
        with self.live_proof(path):
            binding = codex_observer.TaskBinding.from_environment(environment)
            self.assertEqual(binding, codex_observer.TaskBinding.from_environment(environment))
            expected = hashlib.sha256("\0".join(record[key] for key in ("socket", "id", "created", "session")).encode()).hexdigest()
            self.assertEqual(binding.generation, expected)
            record["created"] = "synthetic-generation-two"
            path.write_text(json.dumps(record), encoding="utf-8")
            self.assertNotEqual(binding, codex_observer.TaskBinding.from_environment(environment))
            self.assertNotIn(environment["CLILANE_TASK_ID"], binding.generation)

    def test_registry_record_without_live_socket_is_insufficient(self) -> None:
        environment, _path, _record = self.environment_and_record()
        with mock.patch.object(codex_observer.shutil, "which", return_value="/synthetic/tmux"):
            with self.assertRaisesRegex(codex_observer.ObserverError, "^task-proof-unavailable$"):
                codex_observer.TaskBinding.from_environment(environment)

    def test_live_query_targets_exact_socket_and_session_without_environment_pane(self) -> None:
        environment, path, record = self.environment_and_record()
        with self.live_proof(path):
            with mock.patch.object(codex_observer, "_task_query", return_value=self.live_output(record)) as query:
                codex_observer.TaskBinding.from_environment({**environment, "TMUX_PANE": "%unrelated"})
        self.assertEqual(query.call_count, 2)
        arguments = query.call_args.args[0]
        self.assertEqual(arguments[:10], ["/synthetic/tmux", "-N", "-S", record["socket"], "-f", "/dev/null", "list-panes", "-s", "-t", "=" + record["session"]])

    def test_live_pane_lifecycle_and_identifiers_fail_closed(self) -> None:
        environment, path, record = self.environment_and_record()
        cases = (
            {"session": "agt_other"}, {"session_id": "1"}, {"created": "0"},
            {"pane": "bad"}, {"dead": "1"}, {"pid": "0"}, {"pid": "2147483648"},
            {"committed": "0"}, {"started": ""}, {"ready": "other"},
            {"stopped": "1"}, {"result": "0:"},
        )
        with self.live_proof(path):
            for changes in cases:
                with self.subTest(changes=changes):
                    with mock.patch.object(codex_observer, "_task_query", return_value=self.live_output(record, **changes)):
                        with self.assertRaisesRegex(codex_observer.ObserverError, "^task-live-proof-invalid$"):
                            codex_observer.TaskBinding.from_environment(environment)

    def test_live_output_requires_one_complete_unambiguous_pane_and_metadata(self) -> None:
        environment, path, record = self.environment_and_record()
        valid = self.live_output(record)
        raw_cases = (b"", valid + valid, valid.rstrip(b"\n"), valid + b"\n", valid.replace(b"|0|10|", b"|0|10|extra|"), self.live_output(record, encoded="not-base64"), self.live_output(record, encoded="e30="), self.live_output(record, encoded=base64.urlsafe_b64encode(b'{"id":"private-one","id":"private-two"}').decode()))
        with self.live_proof(path):
            for raw in raw_cases:
                with self.subTest(raw_size=len(raw)):
                    with mock.patch.object(codex_observer, "_task_query", return_value=raw):
                        with self.assertRaises(codex_observer.ObserverError) as raised:
                            codex_observer.TaskBinding.from_environment(environment)
                        self.assertNotIn("private", str(raised.exception))

    def test_live_metadata_must_match_task_and_generation(self) -> None:
        environment, path, record = self.environment_and_record()
        with self.live_proof(path):
            for key, value in (("id", "different"), ("created", "replaced")):
                with self.subTest(key=key):
                    encoded = base64.urlsafe_b64encode(json.dumps({**record, key: value}).encode()).decode()
                    with mock.patch.object(codex_observer, "_task_query", return_value=self.live_output(record, encoded=encoded)):
                        with self.assertRaisesRegex(codex_observer.ObserverError, "^task-live-metadata-mismatch$"):
                            codex_observer.TaskBinding.from_environment(environment)

    def test_unrelated_process_and_reused_leader_pid_are_rejected(self) -> None:
        environment, path, _record = self.environment_and_record()
        for parent, started, error in ((1, "observer-start", "task-process-not-owned"), (30, "observer-start", "task-process-not-owned"), (10, "wrong-start", "task-process-replaced")):
            with self.subTest(parent=parent, error=error), self.live_proof(path):
                def identity(pid: int, _deadline: float) -> codex_observer._ProcessIdentity:
                    return codex_observer._ProcessIdentity(pid, parent if pid == 30 else 1, os.getuid(), started)
                with mock.patch.object(codex_observer, "_process_identity", side_effect=identity):
                    with self.assertRaisesRegex(codex_observer.ObserverError, f"^{error}$"):
                        codex_observer.TaskBinding.from_environment(environment)

    def test_ancestry_depth_is_bounded_and_pane_leader_can_bind(self) -> None:
        environment, path, _record = self.environment_and_record()
        with self.live_proof(path):
            with mock.patch.object(codex_observer, "MAX_TASK_ANCESTORS", 2):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-ancestry-limit$"):
                    codex_observer.TaskBinding.from_environment(environment)
            with mock.patch.object(codex_observer.os, "getpid", return_value=10):
                self.assertRegex(codex_observer.TaskBinding.from_environment(environment).generation, "^[0-9a-f]{64}$")

    def test_reread_rejects_session_process_socket_and_record_changes(self) -> None:
        environment, path, record = self.environment_and_record()
        with self.live_proof(path):
            live = self.live_output(record)
            with mock.patch.object(codex_observer, "_task_query", side_effect=[live, self.live_output(record, pane="%3")]):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-live-identity-changed$"):
                    codex_observer.TaskBinding.from_environment(environment)
            identity = codex_observer._ProcessIdentity(30, 10, os.getuid(), "first")
            with mock.patch.object(codex_observer, "_task_ancestry", side_effect=[(identity,), ()]):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-live-identity-changed$"):
                    codex_observer.TaskBinding.from_environment(environment)
            with mock.patch.object(codex_observer, "_socket_identity", side_effect=[(1, 2), (1, 3)]):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-live-identity-changed$"):
                    codex_observer.TaskBinding.from_environment(environment)
            original = path.read_bytes()
            with mock.patch.object(codex_observer, "_read_private", side_effect=[original, original + b" "]):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-live-identity-changed$"):
                    codex_observer.TaskBinding.from_environment(environment)

    def test_missing_tmux_and_expired_proof_budget_fail_closed(self) -> None:
        environment, path, _record = self.environment_and_record()
        with self.live_proof(path):
            with mock.patch.object(codex_observer.shutil, "which", return_value=None):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-proof-unavailable$"):
                    codex_observer.TaskBinding.from_environment(environment)
            with mock.patch.object(codex_observer, "TASK_PROOF_SECONDS", 0):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-proof-time-limit$"):
                    codex_observer.TaskBinding.from_environment(environment)

    def test_identical_record_replacement_is_rejected(self) -> None:
        environment, path, record = self.environment_and_record()
        original = path.read_bytes()
        def replace_record(*_args: Any) -> bytes:
            replacement = path.with_suffix(".replacement")
            replacement.write_bytes(original)
            replacement.chmod(0o600)
            replacement.replace(path)
            return self.live_output(record)
        with self.live_proof(path):
            with mock.patch.object(codex_observer, "_task_query", side_effect=replace_record):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-live-identity-changed$"):
                    codex_observer.TaskBinding.from_environment(environment)

    def test_task_record_must_match_live_socket_id_and_session(self) -> None:
        environment, path, record = self.environment_and_record()
        for field, value in (("schema_version", True), ("phase", "done"), ("socket", "/another/socket"), ("id", "wrong"), ("session", "agt_wrong"), ("created", ""), ("created", "invalid\0value")):
            with self.subTest(field=field, value=value):
                path.write_text(json.dumps({**record, field: value}), encoding="utf-8")
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-record-mismatch$"):
                    codex_observer.TaskBinding.from_environment(environment)

    def test_invalid_environment_missing_record_and_public_record_are_rejected(self) -> None:
        environment, path, _record = self.environment_and_record()
        for field, value in (("CLILANE_TMUX_SOCKET", "relative"), ("CLILANE_TMUX_SOCKET", "/invalid\0socket"), ("CLILANE_TASK_ID", "invalid"), ("CLILANE_TASK_ID", "01234567-89AB-cdef-0123-456789abcdef")):
            with self.subTest(field=field):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-environment-invalid$"):
                    codex_observer.TaskBinding.from_environment({**environment, field: value})
        path.chmod(0o644)
        with self.assertRaisesRegex(codex_observer.ObserverError, "^private-file-invalid$"):
            codex_observer.TaskBinding.from_environment(environment)
        path.unlink()
        with self.assertRaisesRegex(codex_observer.ObserverError, "^task-record-not-found-for-absolute-socket$"):
            codex_observer.TaskBinding.from_environment(environment)


class TaskProofBoundaryTests(ObserverFixture):
    def test_socket_proof_requires_same_user_socket_and_rejects_symlinks(self) -> None:
        path = self.root / "owned.sock"
        metadata = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=os.getuid(), st_dev=1, st_ino=2)
        with mock.patch.object(codex_observer.Path, "lstat", return_value=metadata):
            self.assertEqual(codex_observer._socket_identity(str(path)), (1, 2))
            for mode in (stat.S_IFLNK | 0o700, stat.S_IFREG | 0o600):
                metadata.st_mode = mode
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-socket-invalid$"):
                    codex_observer._socket_identity(str(path))
            metadata.st_mode = stat.S_IFSOCK | 0o600
            with mock.patch.object(codex_observer.os, "getuid", return_value=os.getuid() + 1):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-socket-invalid$"):
                    codex_observer._socket_identity(str(path))

    def test_darwin_process_proof_checks_pid_uid_state_start_and_one_row(self) -> None:
        valid = f"30 20 {os.getuid()} Ss Mon Oct  5 21:20:54 2026\n".encode()
        deadline = time.monotonic() + 3
        with mock.patch.object(codex_observer.sys, "platform", "darwin"):
            with mock.patch.object(codex_observer, "_task_query", return_value=valid):
                proof = codex_observer._process_identity(30, deadline)
                self.assertEqual(proof, codex_observer._ProcessIdentity(30, 20, os.getuid(), "Mon Oct 5 21:20:54 2026"))
            for invalid in (b"", valid + valid, valid.replace(b"30 20", b"31 20"), valid.replace(b" Ss ", b" Zs "), valid.replace(f" {os.getuid()} ".encode(), f" {os.getuid() + 1} ".encode()), valid.replace(b"2026", b"private-start")):
                with self.subTest(raw_size=len(invalid)):
                    with mock.patch.object(codex_observer, "_task_query", return_value=invalid):
                        with self.assertRaises(codex_observer.ObserverError) as raised:
                            codex_observer._process_identity(30, deadline)
                        self.assertNotIn("private", str(raised.exception))

    def test_linux_process_proof_uses_start_ticks_and_rejects_zombies(self) -> None:
        fields = ["S", "20", *("0" for _ in range(17)), "123456", "0"]
        path = self.private_file(("30 (a process ) name) " + " ".join(fields)).encode())
        with path.open("rb") as source:
            with mock.patch.object(codex_observer.sys, "platform", "linux"):
                with mock.patch.object(codex_observer.os, "open", side_effect=lambda *_args: os.dup(source.fileno())):
                    proof = codex_observer._process_identity(30, time.monotonic() + 3)
                    self.assertEqual(proof, codex_observer._ProcessIdentity(30, 20, os.getuid(), "123456"))
                    source.seek(0)
                    path.write_bytes(path.read_bytes().replace(b") S ", b") Z "))
                    with self.assertRaisesRegex(codex_observer.ObserverError, "^task-process-invalid$"):
                        codex_observer._process_identity(30, time.monotonic() + 3)

    def test_process_proof_rejects_unavailable_platform_and_pid(self) -> None:
        for pid in (True, 0, 1, -1, 1 << 31):
            with self.subTest(pid=pid):
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-process-invalid$"):
                    codex_observer._process_identity(pid, time.monotonic() + 3)
        with mock.patch.object(codex_observer.sys, "platform", "unsupported"):
            with self.assertRaisesRegex(codex_observer.ObserverError, "^task-proof-unavailable$"):
                codex_observer._process_identity(30, time.monotonic() + 3)

    def test_queries_bound_time_output_and_hide_child_errors(self) -> None:
        python = str(Path(sys.executable).resolve())
        self.assertEqual(codex_observer._task_query([python, "-B", "-c", "print('proof')"], time.monotonic() + 3, 32), b"proof\n")
        for code, seconds, limit, error in (
            ("print('x' * 1024)", 3, 32, "task-proof-output-limit"),
            ("import time; time.sleep(5)", 0.05, 32, "task-proof-time-limit"),
            ("import sys; sys.stderr.write('private-sentinel'); sys.exit(1)", 3, 32, "task-proof-unavailable"),
        ):
            with self.subTest(error=error):
                with self.assertRaisesRegex(codex_observer.ObserverError, f"^{error}$"):
                    codex_observer._task_query([python, "-B", "-c", code], time.monotonic() + seconds, limit)


@unittest.skipUnless(shutil.which("tmux"), "tmux is required for live task proof")
class TaskBindingIntegrationTests(unittest.TestCase):
    def test_managed_task_and_observer_child_bind_but_external_process_and_dead_task_do_not(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cob-") as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            socket_path = root / "t"
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.bind(str(socket_path))
            except PermissionError:
                self.skipTest("host sandbox denies private Unix socket IPC")
            socket_path.unlink()
            state = root / "state"
            state.mkdir(mode=0o700)
            (state / "registry").mkdir(mode=0o700)
            output = root / "proof.json"
            release = root / "release"
            worker = root / "worker.py"
            scripts = str(ROOT / "scripts")
            python = str(Path(sys.executable).resolve())
            child = f"import os,sys; sys.path.insert(0,{scripts!r}); from codex_observer import TaskBinding; print(TaskBinding.from_environment(os.environ).generation)"
            allowed_errors = {
                "task-record-mismatch", "task-record-not-found-for-absolute-socket",
                "private-directory-required", "private-file-invalid", "private-file-changed",
                "task-proof-time-limit", "task-proof-unavailable", "task-proof-output-limit",
                "task-process-invalid", "task-process-not-owned", "task-process-replaced",
                "task-ancestry-limit", "task-socket-invalid", "task-live-proof-invalid",
                "task-live-metadata-mismatch", "task-live-identity-changed", "task-environment-invalid",
            }
            worker_body = (
                "deadline=time.monotonic()+5\n"
                "while True:\n"
                "    try:\n"
                "        binding=TaskBinding.from_environment(os.environ)\n"
                "        break\n"
                "    except ObserverError as error:\n"
                "        if str(error) not in {'task-record-mismatch','task-record-not-found-for-absolute-socket'} or time.monotonic()>=deadline:\n"
                "            raise\n"
                "        time.sleep(0.02)\n"
                f"child=subprocess.run([{python!r},'-B','-c',{child!r}],capture_output=True,start_new_session=True,timeout=5)\n"
                "child_generation=child.stdout.decode().strip()\n"
                "if len(child_generation)!=64 or any(c not in '0123456789abcdef' for c in child_generation):\n"
                "    child_generation='invalid-child-proof'\n"
                "save({'generation':binding.generation,'child_generation':child_generation,'child_returncode':child.returncode})\n"
                "deadline=time.monotonic()+15\n"
                f"while not Path({str(release)!r}).exists() and time.monotonic()<deadline:\n"
                "    time.sleep(0.02)\n"
            )
            worker.write_text(
                "import json,os,subprocess,sys,time\nfrom pathlib import Path\n"
                f"sys.path.insert(0,{scripts!r})\n"
                "from codex_observer import ObserverError,TaskBinding\n"
                "def save(value):\n"
                f"    pending=Path({str(output.with_suffix('.pending'))!r})\n"
                "    pending.write_text(json.dumps(value))\n"
                f"    pending.replace({str(output)!r})\n"
                "try:\n" + "".join("    " + line + "\n" for line in worker_body.splitlines())
                + "except ObserverError as error:\n"
                + f"    save({{'error':str(error) if str(error) in {allowed_errors!r} else 'unexpected-observer-error'}})\n"
                + "except Exception:\n"
                + "    save({'error':'unexpected-worker-error'})\n",
                encoding="utf-8",
            )
            worker.chmod(0o600)
            environment = {
                "HOME": str(root), "PATH": os.environ.get("PATH", os.defpath),
                "USER": os.environ.get("USER", "observer-test"), "LANG": "C",
                "CLILANE_STATE_HOME": str(state), "CLILANE_TMUX_SOCKET": str(socket_path),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            tmux = shutil.which("tmux")
            control = [tmux, "-N", "-S", str(socket_path), "-f", "/dev/null"]
            record: dict[str, Any] | None = None
            try:
                launch = subprocess.run(
                    [python, "-B", str(ROOT / "bin" / "clilane"), "run", "binding-proof", "-C", str(root), "--", python, "-B", str(worker)],
                    env=environment, capture_output=True, timeout=12,
                )
                if launch.returncode and b"operation not permitted" in launch.stderr.lower():
                    self.skipTest("host sandbox denies private tmux IPC (Operation not permitted)")
                self.assertEqual(launch.returncode, 0, "isolated clilane task did not launch")
                records = list((state / "registry").glob("*/*.json"))
                self.assertEqual(len(records), 1)
                record = json.loads(records[0].read_bytes())
                expected = hashlib.sha256("\0".join(record[key] for key in ("socket", "id", "created", "session")).encode()).hexdigest()
                deadline = time.monotonic() + 8
                while not output.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(output.exists(), "managed task failed to establish live proof")
                self.assertEqual(json.loads(output.read_bytes()), {"generation": expected, "child_generation": expected, "child_returncode": 0})
                binding_environment = {**environment, "CLILANE_TASK_ID": record["id"]}
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-process-not-owned$"):
                    codex_observer.TaskBinding.from_environment(binding_environment)
                release.touch()
                deadline = time.monotonic() + 5
                while True:
                    pane = subprocess.run(control + ["list-panes", "-s", "-t", "=" + record["session"], "-F", "#{pane_dead}"], env=environment, capture_output=True, timeout=2)
                    if pane.stdout == b"1\n" or time.monotonic() >= deadline:
                        break
                    time.sleep(0.02)
                self.assertEqual(pane.stdout, b"1\n")
                with self.assertRaisesRegex(codex_observer.ObserverError, "^task-live-proof-invalid$"):
                    codex_observer.TaskBinding.from_environment(binding_environment)
            finally:
                release.touch(exist_ok=True)
                if record is None:
                    records = list((state / "registry").glob("*/*.json"))
                    if len(records) == 1:
                        record = json.loads(records[0].read_bytes())
                if type(record) is dict:
                    session = record.get("session")
                    task = record.get("id")
                    if (
                        type(task) is str
                        and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", task)
                        and record.get("socket") == str(socket_path)
                        and session == "agt_" + task.replace("-", "")[:12]
                    ):
                        subprocess.run(control + ["kill-session", "-t", "=" + session], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)


class CommandBoundaryTests(ObserverFixture):
    def commands(self, raw: bytes) -> list[dict[str, Any]]:
        path = self.private_file(raw, "commands")
        with path.open("rb") as stream:
            return list(codex_observer._commands(stream.fileno()))

    def test_command_stream_accepts_exact_lines_and_rejects_truncation(self) -> None:
        self.assertEqual(self.commands(b'{"op":"status"}\n{"op":"ready"}\n'), [{"op": "status"}, {"op": "ready"}])
        with self.assertRaisesRegex(codex_observer.ObserverError, "^truncated-command$"):
            self.commands(b'{"op":"status"}')
        with self.assertRaises(codex_observer.ProbeError):
            self.commands(b'{"op":"status","op":"ready"}\n')

    def test_command_count_line_input_and_time_limits(self) -> None:
        for constant, limit, raw, error in (("MAX_COMMANDS", 1, b'{}\n{}\n', "command-limit"), ("MAX_COMMAND_BYTES", 1, b'{}\n', "command-limit"), ("MAX_INPUT_BYTES", 2, b'{}\n', "input-byte-limit"), ("LIFETIME_SECONDS", 0, b'{}\n', "observer-time-limit")):
            with self.subTest(constant=constant):
                with mock.patch.object(codex_observer, constant, limit):
                    with self.assertRaisesRegex(codex_observer.ObserverError, f"^{error}$"):
                        self.commands(raw)

    def test_cli_failure_does_not_echo_private_argument_or_filesystem_error(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(codex_observer.TaskBinding, "from_environment", side_effect=OSError("private-path-sentinel")):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = codex_observer.main(["--journal", "private-journal-sentinel", "--journal-sha256", "0" * 64])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "codex_observer.py: observer-failed\n")


if __name__ == "__main__":
    unittest.main()
