from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn, Sequence


provider_evidence = sys.modules.get("provider_evidence")
if provider_evidence is None:
    spec = importlib.util.spec_from_file_location(
        "provider_evidence", Path(__file__).resolve(strict=True).with_name("provider_evidence.py")
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("provider-evidence-unavailable")
    provider_evidence = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = provider_evidence
    previous_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(provider_evidence)
    finally:
        sys.dont_write_bytecode = previous_bytecode


FIXTURE_PATH = "tests/fixtures/provider-evidence/codex-replay.jsonl"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 512 * 1024
MAX_RECORDS = 32
MAX_MESSAGES = 4096
MAX_EVENTS = 1024
MAX_OBSERVED_MS = 86_400_000
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
REQUEST_METHODS = {
    "item/commandExecution/requestApproval": "approval",
    "item/fileChange/requestApproval": "approval",
    "item/permissions/requestApproval": "approval",
    "item/tool/requestUserInput": "input",
}
REPORT_KEYS = {
    "schema_version", "analyzer", "analysis_complete", "qualification",
    "task_binding", "source_health", "session_binding", "session_id",
    "message_count", "duplicate_count", "ignored_notification_count",
    "provider_warning_count", "thread_read_count", "unhandled_message_count",
    "turn_count", "unresolved_request_count", "events", "provider",
    "provider_version", "source_interface", "source_capture_sha256",
    "executable_sha256", "capture_status",
}
EVENT_KEYS = {
    "sequence", "observed_ms", "event", "thread_id", "turn_id", "request_id",
    "request_kind", "request_method", "blocking", "state", "flags",
}
COUNT_KEYS = {
    "message_count", "duplicate_count", "ignored_notification_count",
    "provider_warning_count", "thread_read_count", "unhandled_message_count",
    "turn_count", "unresolved_request_count",
}


class ReplayError(Exception):
    pass


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ReplayError(code)


def _integer(value: Any, maximum: int) -> None:
    _require(type(value) is int and 0 <= value <= maximum, "invalid-integer")


def _object(value: Any, keys: set[str]) -> None:
    _require(type(value) is dict and set(value) == keys, "invalid-fields")


def _fixed(value: Any, expected: Any) -> None:
    _require(type(value) is type(expected) and value == expected, "invalid-value")


def _pin() -> tuple[str, str, str]:
    root = Path(__file__).resolve(strict=True).parents[1]
    try:
        hashes = provider_evidence.load_executable_manifest(
            root / provider_evidence.EXECUTABLE_MANIFEST_PATH
        )
    except (provider_evidence.EvidenceError, OSError) as error:
        raise ReplayError("manifest-unavailable") from error
    spec = provider_evidence.provider_capture.PROVIDER_SPECS["codex"]
    return spec.version, spec.source_interface, hashes["codex"]


def _replay(events: Any) -> None:
    _require(type(events) is list and 5 <= len(events) <= MAX_EVENTS, "invalid-events")
    turn_started = False
    turn_completed = False
    opened: dict[str, Any] | None = None
    resolved = False
    thread_state: tuple[str, tuple[str, ...]] | None = None
    terminal_idle = False
    previous_ms = 0
    waiting_flags: set[str] = set()
    for sequence, event in enumerate(events, 1):
        _object(event, EVENT_KEYS)
        _fixed(event["sequence"], sequence)
        _integer(event["observed_ms"], MAX_OBSERVED_MS)
        _require(event["observed_ms"] >= previous_ms, "nonmonotonic-time")
        previous_ms = event["observed_ms"]
        _fixed(event["thread_id"], "synthetic-codex-thread")
        name = event["event"]
        _require(type(name) is str and name in {
            "turn_started", "turn_completed", "request_opened", "request_resolved",
            "thread_state",
        }, "invalid-event")
        flags = event["flags"]
        _require(type(flags) is list and len(flags) <= 1 and all(
            type(flag) is str and flag in {"waitingOnApproval", "waitingOnUserInput"}
            for flag in flags
        ), "invalid-flags")
        if name in {"request_opened", "request_resolved"}:
            _fixed(event["turn_id"], "synthetic-codex-turn-1")
            _fixed(event["request_id"], "synthetic-codex-request-1")
            method = event["request_method"]
            _require(type(method) is str and method in REQUEST_METHODS, "invalid-request-method")
            _fixed(event["request_kind"], REQUEST_METHODS[method])
            _require(type(event["blocking"]) is bool, "invalid-blocking")
            if event["request_kind"] == "approval":
                _fixed(event["blocking"], True)
            _fixed(event["state"], None)
            _fixed(flags, [])
            _require(turn_started and not turn_completed, "request-outside-turn")
            if name == "request_opened":
                _require(opened is None, "duplicate-request-open")
                opened = event
            else:
                _require(opened is not None and not resolved, "invalid-request-resolution")
                _require(all(event[key] == opened[key] for key in {
                    "thread_id", "turn_id", "request_id", "request_kind",
                    "request_method", "blocking",
                }), "request-resolution-mismatch")
                resolved = True
        else:
            for key in ("request_id", "request_kind", "request_method", "blocking"):
                _fixed(event[key], None)
            if name == "thread_state":
                _fixed(event["turn_id"], None)
                state = event["state"]
                _require(type(state) is str and state in {"active", "idle"}, "invalid-thread-state")
                current = (state, tuple(flags))
                _require(current != thread_state, "duplicate-thread-state")
                thread_state = current
                if state == "idle":
                    _fixed(flags, [])
                    _require(not turn_started or resolved, "idle-before-request-resolution")
                    terminal_idle = resolved
                else:
                    _require(not turn_completed, "active-after-completion")
                    if flags:
                        _require(turn_started and not resolved, "waiting-outside-request-window")
                        waiting_flags.update(flags)
            else:
                _fixed(event["turn_id"], "synthetic-codex-turn-1")
                _fixed(flags, [])
                if name == "turn_started":
                    _fixed(event["state"], "inProgress")
                    _require(not turn_started, "duplicate-turn-start")
                    turn_started = True
                else:
                    _fixed(event["state"], "completed")
                    _require(turn_started and not turn_completed and resolved,
                             "invalid-turn-completion")
                    turn_completed = True
    _require(turn_completed and resolved and opened is not None, "incomplete-lifecycle")
    expected_flag = "waitingOnUserInput" if opened["request_kind"] == "input" else "waitingOnApproval"
    _require(waiting_flags <= {expected_flag}, "request-waiting-kind-mismatch")
    if opened["blocking"]:
        _require(waiting_flags == {expected_flag}, "missing-blocking-wait-state")
    _require(thread_state == ("idle", ()) and terminal_idle, "missing-final-idle")


def _validate_record(record: Any, pin: tuple[str, str, str]) -> None:
    _object(record, REPORT_KEYS)
    for key, expected in {
        "schema_version": 1, "analyzer": "codex-app-server-v1",
        "analysis_complete": True, "qualification": "unqualified",
        "task_binding": "unknown", "source_health": "unknown",
        "session_binding": "exact", "session_id": "synthetic-codex-session",
        "provider": "codex", "provider_version": pin[0], "source_interface": pin[1],
        "executable_sha256": pin[2], "capture_status": "complete",
    }.items():
        _fixed(record[key], expected)
    digest = record["source_capture_sha256"]
    _require(type(digest) is str and SHA256_PATTERN.fullmatch(digest) is not None
             and len(set(digest)) > 1, "invalid-source-digest")
    for key in COUNT_KEYS:
        _integer(record[key], MAX_MESSAGES)
    for key in ("provider_warning_count", "unhandled_message_count", "unresolved_request_count"):
        _fixed(record[key], 0)
    _fixed(record["turn_count"], 1)
    _replay(record["events"])
    accounted = (len(record["events"]) + record["duplicate_count"]
                 + record["ignored_notification_count"] + 2 * record["thread_read_count"] + 4)
    _require(record["message_count"] >= accounted, "inconsistent-message-count")


def canonical_replay_bytes(records: list[dict[str, Any]]) -> bytes:
    _require(type(records) is list and 1 <= len(records) <= MAX_RECORDS, "invalid-record-count")
    pin = _pin()
    seen: set[str] = set()
    lines: list[tuple[str, bytes]] = []
    for record in records:
        _validate_record(record, pin)
        digest = record["source_capture_sha256"]
        _require(digest not in seen, "duplicate-source-capture")
        seen.add(digest)
        line = (json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()
        _require(len(line) <= MAX_LINE_BYTES, "line-limit")
        lines.append((digest, line))
    raw = b"".join(line for _digest, line in sorted(lines))
    _require(len(raw) <= MAX_FILE_BYTES, "file-limit")
    return raw


def validate_replay_bytes(raw: bytes) -> list[dict[str, Any]]:
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_FILE_BYTES, "invalid-file-size")
    lines = raw.splitlines()
    _require(1 <= len(lines) <= MAX_RECORDS, "invalid-record-count")
    records: list[dict[str, Any]] = []
    for line in lines:
        _require(0 < len(line) <= MAX_LINE_BYTES, "line-limit")
        try:
            record = provider_evidence.strict_json(line.decode("utf-8"), "replay")
        except (provider_evidence.EvidenceError, UnicodeDecodeError) as error:
            raise ReplayError("invalid-json") from error
        records.append(record)
    _require(canonical_replay_bytes(records) == raw, "noncanonical-replay")
    return records


def export_capture(root: Path, capture_id: str) -> bytes:
    _require(isinstance(root, Path) and type(capture_id) is str, "invalid-source-arguments")
    try:
        report = provider_evidence.analyze_codex_capture(root, capture_id)
    except (provider_evidence.EvidenceError, OSError) as error:
        raise ReplayError("source-unavailable") from error
    return canonical_replay_bytes([report])


def main(argv: Sequence[str] | None = None) -> int:
    parser = SafeArgumentParser(
        description="Export verified partial Codex lifecycles; offline checks validate published replay only. "
        "Changing the provider pin requires fresh capture exports."
    )
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--fixture")
    parser.add_argument("--capture-root")
    parser.add_argument("--capture-id")
    args = parser.parse_args(argv)
    if args.check:
        if args.capture_root is not None or args.capture_id is not None:
            parser.error("conflicting arguments")
    elif args.fixture is not None or args.capture_root is None or args.capture_id is None:
        parser.error("missing export arguments")
    try:
        if args.check:
            fixture = Path(args.fixture) if args.fixture is not None else Path(__file__).resolve().parents[1] / FIXTURE_PATH
            raw = provider_evidence.read_regular_file(fixture, "replay")
            records = validate_replay_bytes(raw)
            print(f"Codex replay check passed: {len(records)} unqualified records; raw source not reverified")
        else:
            sys.stdout.buffer.write(export_capture(Path(args.capture_root), args.capture_id))
    except ReplayError as error:
        print(f"codex_replay: {error}", file=sys.stderr)
        return 1
    except (provider_evidence.EvidenceError, OSError):
        print("codex_replay: artifact-unavailable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
