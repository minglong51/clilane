#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, Sequence


SCHEMA_VERSION = 1
PROVIDERS = ("claude", "codex", "kimi")
EVENT_KINDS = (
    "approval_request",
    "duplicate",
    "heartbeat",
    "input_request",
    "reconnect",
    "request_recovery",
    "stale_session",
    "turn_state",
)
REQUEST_EVENT_KINDS = {
    "approval_request",
    "duplicate",
    "input_request",
    "request_recovery",
}
REQUEST_LIFECYCLE_EVENT_KINDS = {"approval_request", "input_request"}
STRUCTURED_SOURCE_KINDS = {"acp", "native_hook"}
FRESHNESS_RENEWAL_EVENTS = {"adapter_heartbeat", "adapter_ready"}
FIXTURE_PATHS = {
    "observed": "tests/fixtures/provider-evidence/normalized.jsonl",
    "synthetic": "tests/fixtures/provider-evidence/synthetic.jsonl",
}
MATRIX_PATH = "docs/designs/provider-capabilities.json"
SOURCE_INTERFACES = {
    "claude": {
        "acp": {"claude-acp"},
        "inferred": {"claude-inferred"},
        "native_hook": {"claude-native-hook"},
        "unknown": {"none"},
    },
    "codex": {
        "acp": {"codex-acp"},
        "inferred": {"codex-inferred"},
        "native_hook": {"codex-native-hook"},
        "unknown": {"none"},
    },
    "kimi": {
        "acp": {"kimi-acp"},
        "inferred": {"kimi-inferred"},
        "native_hook": {"kimi-native-hook"},
        "unknown": {"none"},
    },
}
ROW_KEYS = {
    "schema_version",
    "evidence_id",
    "evidence_mode",
    "provider",
    "provider_version",
    "source_kind",
    "source_interface",
    "event_kind",
    "task_id",
    "session_id",
    "request_id",
    "task_binding",
    "session_binding",
    "request_binding",
    "open_behavior",
    "close_behavior",
    "duplicate_handling",
    "stale_session_handling",
    "reconnect_result",
    "recovery_result",
    "freshness_seconds",
    "freshness_renews_on",
    "failure_behavior",
    "latency_ms",
    "capture_status",
    "status",
    "source_capture_sha256",
}
ROW_SORT_KEYS = (
    "provider",
    "provider_version",
    "source_interface",
    "event_kind",
    "evidence_id",
)
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,95}")
EXACT_VERSION_PATTERN = re.compile(
    r"[0-9]+(?:\.[0-9]+){1,3}(?:-(?:alpha|beta|rc)(?:\.[0-9]+)?)?"
)
EVIDENCE_ID_PATTERN = re.compile(r"evidence-[a-z0-9][a-z0-9-]{0,95}")
SYNTHETIC_ID_PATTERN = re.compile(r"synthetic-[a-z0-9][a-z0-9-]{0,95}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
SOURCE_FIXTURE_PATTERN = re.compile(r"[a-z0-9][a-z0-9._/-]{0,255}")
PRIVATE_TEXT_PATTERN = re.compile(
    r"(?i)(?:prompt|transcript|content|message|bearer|authorization|auth|"
    r"credential|cookie|api[_-]?key|token|secret|password|(?:^|[-_.])cwd(?:$|[-_.])|"
    r"(?:^|[-_.])path(?:$|[-_.])|(?:^|[-_.])home(?:$|[-_.])|-----begin|"
    r"(?:^|[\s=])~?/Users/|(?:^|[\s=])/home/|(?:^|[\s=])/private/|[A-Z]:\\)"
)
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 16 * 1024
MAX_LATENCY_SAMPLES = 100
MAX_LATENCY_MS = 300_000
MAX_FRESHNESS_SECONDS = 300


class EvidenceError(Exception):
    pass


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


def reject_json_constant(_value: str) -> NoReturn:
    raise EvidenceError("non-finite JSON number")


def reject_json_float(_value: str) -> NoReturn:
    raise EvidenceError("JSON floats are not allowed")


def bounded_json_int(value: str) -> int:
    if len(value.lstrip("-")) > 64:
        raise EvidenceError("JSON integer exceeds 64 digits")
    return int(value)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON key")
        result[key] = value
    return result


def strict_json(text: str, context: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_json_constant,
            parse_float=reject_json_float,
            parse_int=bounded_json_int,
        )
    except EvidenceError as error:
        raise EvidenceError(f"{context}: invalid JSON") from error
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise EvidenceError(f"{context}: invalid JSON") from error


def read_regular_file(path: Path, label: str) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise EvidenceError(f"{label}: expected a regular non-symlink file")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise EvidenceError(f"{label}: file exceeds {MAX_FILE_BYTES} bytes")
        raw = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"{label}: read failed") from error
    if len(raw) > MAX_FILE_BYTES:
        raise EvidenceError(f"{label}: file exceeds {MAX_FILE_BYTES} bytes")
    return raw


def require_exact_keys(row: dict[str, Any], line_number: int) -> None:
    missing = sorted(ROW_KEYS - set(row))
    unknown_count = len(set(row) - ROW_KEYS)
    if missing or unknown_count:
        details: list[str] = []
        if missing:
            details.append(f"missing required keys {missing}")
        if unknown_count:
            details.append(f"{unknown_count} unknown key(s)")
        raise EvidenceError(f"line {line_number}: {'; '.join(details)}")


def require_string(
    row: dict[str, Any], key: str, pattern: re.Pattern[str], line_number: int
) -> str:
    value = row[key]
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise EvidenceError(f"line {line_number}: invalid {key}")
    if PRIVATE_TEXT_PATTERN.search(value):
        raise EvidenceError(f"line {line_number}: private text in {key}")
    return value


def require_choice(
    row: dict[str, Any], key: str, choices: set[str], line_number: int
) -> str:
    value = row[key]
    if type(value) is not str or value not in choices:
        raise EvidenceError(f"line {line_number}: invalid {key}")
    return value


def require_optional_choice(
    row: dict[str, Any], key: str, choices: set[str], line_number: int
) -> str | None:
    value = row[key]
    if value is None:
        return None
    if type(value) is not str or value not in choices:
        raise EvidenceError(f"line {line_number}: invalid {key}")
    return value


def validate_relevance(
    row: dict[str, Any], event_kind: str, line_number: int
) -> None:
    request_id = row["request_id"]
    if event_kind in REQUEST_EVENT_KINDS:
        if (
            type(request_id) is not str
            or SYNTHETIC_ID_PATTERN.fullmatch(request_id) is None
            or PRIVATE_TEXT_PATTERN.search(request_id)
        ):
            raise EvidenceError(f"line {line_number}: invalid request_id")
        expected_request_id = (
            f"synthetic-{row['provider']}-{event_kind.replace('_', '-')}-request"
        )
        if request_id != expected_request_id:
            raise EvidenceError(f"line {line_number}: invalid request_id")
        if row["request_binding"] == "not_applicable":
            raise EvidenceError(f"line {line_number}: request_binding is required")
    elif request_id is not None or row["request_binding"] != "not_applicable":
        raise EvidenceError(
            f"line {line_number}: request_binding must be not_applicable"
        )

    lifecycle_event = event_kind in REQUEST_LIFECYCLE_EVENT_KINDS or event_kind == "turn_state"
    for key in ("open_behavior", "close_behavior"):
        if lifecycle_event and row[key] == "not_applicable":
            raise EvidenceError(f"line {line_number}: {key} is required")
        if not lifecycle_event and row[key] != "not_applicable":
            raise EvidenceError(f"line {line_number}: {key} must be not_applicable")

    relevance = {
        "duplicate_handling": "duplicate",
        "stale_session_handling": "stale_session",
        "reconnect_result": "reconnect",
        "recovery_result": "request_recovery",
    }
    for key, relevant_event in relevance.items():
        if event_kind == relevant_event and row[key] == "not_applicable":
            raise EvidenceError(f"line {line_number}: {key} is required")
        if event_kind != relevant_event and row[key] != "not_applicable":
            raise EvidenceError(f"line {line_number}: {key} must be not_applicable")

    freshness_seconds = row["freshness_seconds"]
    freshness_renews_on = row["freshness_renews_on"]
    if (freshness_seconds is None) != (freshness_renews_on is None):
        raise EvidenceError(f"line {line_number}: incomplete freshness declaration")
    if event_kind != "heartbeat" and freshness_seconds is not None:
        raise EvidenceError(
            f"line {line_number}: freshness is only recorded by heartbeat"
        )


def validate_passing_row(row: dict[str, Any], line_number: int) -> None:
    if row["capture_status"] == "incomplete" and row["status"] != "unknown":
        raise EvidenceError(f"line {line_number}: incomplete capture must be unknown")
    if row["status"] != "pass":
        return
    if row["capture_status"] != "complete":
        raise EvidenceError(f"line {line_number}: passing row needs a complete capture")
    if row["task_binding"] != "exact" or row["session_binding"] != "exact":
        raise EvidenceError(f"line {line_number}: passing row needs exact binding")
    if row["failure_behavior"] != "fail_closed":
        raise EvidenceError(f"line {line_number}: passing row must fail closed")
    event_kind = row["event_kind"]
    if event_kind in REQUEST_EVENT_KINDS and row["request_binding"] != "exact":
        raise EvidenceError(
            f"line {line_number}: passing request-bearing row needs exact binding"
        )
    if event_kind in REQUEST_LIFECYCLE_EVENT_KINDS:
        if row["open_behavior"] != "request_opened" or row["close_behavior"] not in {
            "request_cancelled",
            "request_expired",
            "request_resolved",
        }:
            raise EvidenceError(
                f"line {line_number}: passing request row needs exact open and close"
            )
    if event_kind == "turn_state" and (
        row["open_behavior"] != "turn_started"
        or row["close_behavior"] != "turn_idle"
    ):
        raise EvidenceError(f"line {line_number}: passing turn_state row is invalid")
    expected = {
        "duplicate": ("duplicate_handling", "deduplicated_noop"),
        "stale_session": ("stale_session_handling", "rejected_no_write"),
        "reconnect": ("reconnect_result", "reconnected"),
        "request_recovery": ("recovery_result", "unresolved_request_reemitted"),
    }
    if event_kind in expected:
        key, expected_value = expected[event_kind]
        if row[key] != expected_value:
            raise EvidenceError(f"line {line_number}: passing {event_kind} row is invalid")
    if event_kind == "heartbeat" and (
        row["freshness_seconds"] is None or row["freshness_renews_on"] is None
    ):
        raise EvidenceError(
            f"line {line_number}: passing heartbeat needs an exact freshness renewal"
        )
    if event_kind == "heartbeat" and row["freshness_renews_on"] != "adapter_heartbeat":
        raise EvidenceError(
            f"line {line_number}: passing heartbeat needs recurring renewal"
        )


def validate_row(value: Any, line_number: int) -> dict[str, Any]:
    if type(value) is not dict:
        raise EvidenceError(f"line {line_number}: row must be an object")
    row = value
    require_exact_keys(row, line_number)
    if type(row["schema_version"]) is not int or row["schema_version"] != SCHEMA_VERSION:
        raise EvidenceError(f"line {line_number}: unsupported schema_version")
    evidence_id = require_string(row, "evidence_id", EVIDENCE_ID_PATTERN, line_number)
    evidence_mode = require_choice(
        row, "evidence_mode", {"observed", "synthetic"}, line_number
    )
    provider = require_choice(row, "provider", set(PROVIDERS), line_number)
    provider_version = require_string(
        row, "provider_version", VERSION_PATTERN, line_number
    )
    if provider_version != "synthetic" and EXACT_VERSION_PATTERN.fullmatch(
        provider_version
    ) is None:
        raise EvidenceError(f"line {line_number}: provider_version must be exact")
    if evidence_mode == "observed" and provider_version == "synthetic":
        raise EvidenceError(f"line {line_number}: provider_version must be exact")
    source_kind = require_choice(
        row, "source_kind", {"acp", "inferred", "native_hook", "unknown"}, line_number
    )
    source_interface = row["source_interface"]
    if (
        type(source_interface) is not str
        or source_interface not in SOURCE_INTERFACES[provider][source_kind]
    ):
        raise EvidenceError(f"line {line_number}: invalid source declaration")
    event_kind = require_choice(row, "event_kind", set(EVENT_KINDS), line_number)
    expected_evidence_id = f"evidence-{provider}-{event_kind.replace('_', '-')}"
    if evidence_id != expected_evidence_id:
        raise EvidenceError(f"line {line_number}: invalid evidence_id")
    task_id = require_string(row, "task_id", SYNTHETIC_ID_PATTERN, line_number)
    session_id = require_string(row, "session_id", SYNTHETIC_ID_PATTERN, line_number)
    if task_id != f"synthetic-{provider}-task":
        raise EvidenceError(f"line {line_number}: invalid task_id")
    if session_id != f"synthetic-{provider}-session":
        raise EvidenceError(f"line {line_number}: invalid session_id")
    require_choice(
        row, "task_binding", {"ambiguous", "exact", "missing", "unknown"}, line_number
    )
    require_choice(
        row,
        "session_binding",
        {"ambiguous", "exact", "missing", "unknown"},
        line_number,
    )
    require_choice(
        row,
        "request_binding",
        {"ambiguous", "exact", "missing", "not_applicable", "unknown"},
        line_number,
    )
    require_choice(
        row,
        "open_behavior",
        {"missing", "not_applicable", "request_opened", "turn_started", "unknown"},
        line_number,
    )
    require_choice(
        row,
        "close_behavior",
        {
            "missing",
            "not_applicable",
            "request_cancelled",
            "request_expired",
            "request_resolved",
            "task_terminal",
            "turn_idle",
            "unknown",
        },
        line_number,
    )
    require_choice(
        row,
        "duplicate_handling",
        {"deduplicated_noop", "mutated", "not_applicable", "unknown"},
        line_number,
    )
    require_choice(
        row,
        "stale_session_handling",
        {"accepted", "not_applicable", "rejected_no_write", "unknown"},
        line_number,
    )
    require_choice(
        row,
        "reconnect_result",
        {"lost", "not_applicable", "reconnected", "unknown"},
        line_number,
    )
    require_choice(
        row,
        "recovery_result",
        {"lost", "not_applicable", "unknown", "unresolved_request_reemitted"},
        line_number,
    )
    freshness_seconds = row["freshness_seconds"]
    if freshness_seconds is not None and (
        type(freshness_seconds) is not int
        or not 1 <= freshness_seconds <= MAX_FRESHNESS_SECONDS
    ):
        raise EvidenceError(f"line {line_number}: invalid freshness_seconds")
    require_optional_choice(
        row,
        "freshness_renews_on",
        FRESHNESS_RENEWAL_EVENTS,
        line_number,
    )
    require_choice(
        row, "failure_behavior", {"fail_closed", "fail_open", "unknown"}, line_number
    )
    require_choice(row, "capture_status", {"complete", "incomplete"}, line_number)
    status = require_choice(row, "status", {"fail", "pass", "unknown"}, line_number)
    latency_ms = row["latency_ms"]
    if (
        type(latency_ms) is not list
        or len(latency_ms) > MAX_LATENCY_SAMPLES
        or any(
            type(sample) is not int or not 0 <= sample <= MAX_LATENCY_MS
            for sample in latency_ms
        )
        or latency_ms != sorted(latency_ms)
        or (status == "pass" and not latency_ms)
    ):
        raise EvidenceError(f"line {line_number}: invalid latency_ms")
    capture_hash = require_string(
        row, "source_capture_sha256", SHA256_PATTERN, line_number
    )
    if len(set(capture_hash)) == 1:
        raise EvidenceError(f"line {line_number}: placeholder source capture hash")
    validate_relevance(row, event_kind, line_number)
    validate_passing_row(row, line_number)
    return row


def canonical_row_bytes(rows: Sequence[dict[str, Any]]) -> bytes:
    ordered = sorted(rows, key=lambda row: tuple(row[key] for key in ROW_SORT_KEYS))
    return b"".join(
        (
            json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("utf-8")
        for row in ordered
    )


def load_rows_bytes(raw: bytes, expected_mode: str | None = None) -> list[dict[str, Any]]:
    if not raw.endswith(b"\n"):
        raise EvidenceError("fixture: missing final newline")
    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(raw.splitlines(), start=1):
        if not raw_line or len(raw_line) > MAX_LINE_BYTES:
            raise EvidenceError(f"line {line_number}: empty or oversized row")
        try:
            text = raw_line.decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceError(f"line {line_number}: invalid UTF-8") from error
        rows.append(validate_row(strict_json(text, f"line {line_number}"), line_number))
    if not rows:
        raise EvidenceError("fixture: no rows")
    if canonical_row_bytes(rows) != raw:
        raise EvidenceError("fixture: rows are not canonical and deterministically ordered")
    modes = {row["evidence_mode"] for row in rows}
    if len(modes) != 1:
        raise EvidenceError("fixture: mixed evidence modes")
    if expected_mode is not None and modes != {expected_mode}:
        raise EvidenceError("fixture: unexpected evidence mode")
    return rows


def load_rows(path: Path, expected_mode: str | None = None) -> list[dict[str, Any]]:
    return load_rows_bytes(read_regular_file(path, "fixture"), expected_mode)


def validate_source_fixture(source_fixture: str) -> None:
    if (
        SOURCE_FIXTURE_PATTERN.fullmatch(source_fixture) is None
        or PurePosixPath(source_fixture).is_absolute()
        or ".." in PurePosixPath(source_fixture).parts
    ):
        raise EvidenceError("invalid source fixture declaration")


def cell_from_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "binding": {
            "request": row["request_binding"],
            "session": row["session_binding"],
            "task": row["task_binding"],
        },
        "capture_status": row["capture_status"],
        "close_behavior": row["close_behavior"],
        "duplicate_handling": row["duplicate_handling"],
        "event_kind": row["event_kind"],
        "evidence_id": row["evidence_id"],
        "latency_ms": row["latency_ms"],
        "open_behavior": row["open_behavior"],
        "reconnect_result": row["reconnect_result"],
        "recovery_result": row["recovery_result"],
        "source_capture_sha256": row["source_capture_sha256"],
        "source_interface": row["source_interface"],
        "source_kind": row["source_kind"],
        "stale_session_handling": row["stale_session_handling"],
        "status": row["status"],
        "failure_behavior": row["failure_behavior"],
        "freshness": (
            None
            if row["freshness_seconds"] is None
            else {
                "renews_on": row["freshness_renews_on"],
                "seconds": row["freshness_seconds"],
            }
        ),
    }


def render_summary(matrix: dict[str, Any]) -> str:
    lines = [
        "### Provider capability evidence",
        "",
        (
            f"Evidence mode: `{matrix['evidence_mode']}`. Required cells: "
            f"{matrix['present_cells']}/{matrix['required_cells']}. "
            f"v0.6 gate: `{matrix['v0_6_gate']}`."
        ),
        "",
        "| Provider | Version | Source | Support | Freshness | Pass | Fail | Unknown |",
        "|---|---|---|---|---|---:|---:|---:|",
    ]
    for provider in matrix["providers"]:
        counts = {status: 0 for status in ("pass", "fail", "unknown")}
        for cell in provider["cells"]:
            counts[cell["status"]] += 1
        freshness = provider["freshness"]
        freshness_text = (
            "unknown"
            if freshness is None
            else f"{freshness['seconds']}s via {freshness['renews_on']}"
        )
        sources = ",".join(
            f"{source['kind']}:{source['interface']}" for source in provider["sources"]
        )
        lines.append(
            f"| {provider['provider']} | {provider['provider_version']} | "
            f"{sources} | {provider['support']} | "
            f"{freshness_text} | {counts['pass']} | {counts['fail']} | "
            f"{counts['unknown']} |"
        )
    lines.extend(
        [
            "",
            "| Provider | Capability | Status | Binding (task/session/request) | Open/close | Duplicate | Stale session | Reconnect/recovery | Latency ms | Capture | Evidence |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for provider in matrix["providers"]:
        for cell in provider["cells"]:
            binding = cell["binding"]
            lines.append(
                f"| {provider['provider']} | {cell['event_kind']} | {cell['status']} | "
                f"{binding['task']}/{binding['session']}/{binding['request']} | "
                f"{cell['open_behavior']}/{cell['close_behavior']} | "
                f"{cell['duplicate_handling']} | {cell['stale_session_handling']} | "
                f"{cell['reconnect_result']}/{cell['recovery_result']} | "
                f"{','.join(str(value) for value in cell['latency_ms'])} | "
                f"{cell['capture_status']} | {cell['evidence_id']} |"
            )
    return "\n".join(lines) + "\n"


def build_matrix(
    rows: Sequence[dict[str, Any]],
    source_fixture: str,
    source_fixture_sha256: str | None = None,
) -> dict[str, Any]:
    validate_source_fixture(source_fixture)
    validated = [validate_row(dict(row), index) for index, row in enumerate(rows, 1)]
    modes = {row["evidence_mode"] for row in validated}
    if len(modes) != 1:
        raise EvidenceError("fixture: mixed evidence modes")
    canonical = canonical_row_bytes(validated)
    fixture_digest = hashlib.sha256(canonical).hexdigest()
    if source_fixture_sha256 is not None and source_fixture_sha256 != fixture_digest:
        raise EvidenceError("fixture: source digest mismatch")
    evidence_ids: set[str] = set()
    by_cell: dict[tuple[str, str], dict[str, Any]] = {}
    versions: dict[str, set[str]] = {provider: set() for provider in PROVIDERS}
    for row in validated:
        evidence_id = row["evidence_id"]
        if evidence_id in evidence_ids:
            raise EvidenceError("fixture: duplicate evidence_id")
        evidence_ids.add(evidence_id)
        key = (row["provider"], row["event_kind"])
        if key in by_cell:
            raise EvidenceError(f"fixture: duplicate capability cell {key[0]}/{key[1]}")
        by_cell[key] = row
        provider = row["provider"]
        versions[provider].add(row["provider_version"])
    required = {(provider, event) for provider in PROVIDERS for event in EVENT_KINDS}
    missing = sorted(required - set(by_cell))
    extra = sorted(set(by_cell) - required)
    if missing or extra:
        raise EvidenceError(f"fixture: capability grid mismatch: missing={missing}, extra={extra}")
    provider_rows: list[dict[str, Any]] = []
    mode = next(iter(modes))
    for provider in PROVIDERS:
        if len(versions[provider]) != 1:
            raise EvidenceError(f"fixture: provider needs one exact version: {provider}")
        source_cells = [by_cell[(provider, event)] for event in EVENT_KINDS]
        cells = [cell_from_row(row) for row in source_cells]
        heartbeat = by_cell[(provider, "heartbeat")]
        freshness = (
            None
            if heartbeat["freshness_seconds"] is None
            else {
                "renews_on": heartbeat["freshness_renews_on"],
                "seconds": heartbeat["freshness_seconds"],
            }
        )
        provider_sources = sorted(
            {
                (row["source_kind"], row["source_interface"])
                for row in source_cells
            }
        )
        authoritative = (
            mode == "observed"
            and freshness is not None
            and len(provider_sources) == 1
            and all(
                row["capture_status"] == "complete"
                and row["failure_behavior"] == "fail_closed"
                and row["source_kind"] in STRUCTURED_SOURCE_KINDS
                and row["status"] == "pass"
                for row in source_cells
            )
        )
        provider_rows.append(
            {
                "authoritative": authoritative,
                "cells": cells,
                "freshness": freshness,
                "provider": provider,
                "provider_version": next(iter(versions[provider])),
                "sources": [
                    {"interface": interface, "kind": kind}
                    for kind, interface in provider_sources
                ],
                "support": (
                    "authoritative" if authoritative else "attach_only_unknown"
                ),
            }
        )
    support_by_provider = {
        provider["provider"]: provider["support"] for provider in provider_rows
    }
    matrix: dict[str, Any] = {
        "complete": True,
        "evidence_mode": mode,
        "present_cells": len(by_cell),
        "providers": provider_rows,
        "required_cells": len(required),
        "required_event_kinds": list(EVENT_KINDS),
        "schema_version": SCHEMA_VERSION,
        "source_fixture": source_fixture,
        "source_fixture_sha256": fixture_digest,
        "v0_6_gate": (
            "authoritative"
            if all(
                support_by_provider[provider] == "authoritative"
                for provider in ("claude", "codex")
            )
            else "experimental_preview"
        ),
    }
    matrix["human_summary"] = render_summary(matrix)
    return matrix


def matrix_bytes(matrix: dict[str, Any]) -> bytes:
    return (
        json.dumps(matrix, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def build_matrix_bytes(
    rows: Sequence[dict[str, Any]],
    source_fixture: str,
    source_fixture_sha256: str | None = None,
) -> bytes:
    return matrix_bytes(build_matrix(rows, source_fixture, source_fixture_sha256))


def check_artifacts(
    fixture_path: Path,
    matrix_path: Path,
    expected_mode: str,
    source_fixture: str,
) -> None:
    if source_fixture != FIXTURE_PATHS.get(expected_mode):
        raise EvidenceError("fixture: unexpected source declaration")
    fixture_bytes = read_regular_file(fixture_path, "fixture")
    rows = load_rows_bytes(fixture_bytes, expected_mode)
    expected = build_matrix_bytes(
        rows,
        source_fixture,
        hashlib.sha256(fixture_bytes).hexdigest(),
    )
    committed = read_regular_file(matrix_path, "capability matrix")
    if committed != expected:
        raise EvidenceError("capability matrix: deterministic drift")


def write_bytes_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise EvidenceError("capability matrix: invalid output target")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def artifact_paths(root: Path, evidence_mode: str) -> tuple[Path, Path, str]:
    fixture_relative = FIXTURE_PATHS[evidence_mode]
    return root / fixture_relative, root / MATRIX_PATH, fixture_relative


def matrix_for_mode(root: Path, evidence_mode: str) -> dict[str, Any]:
    fixture_path, _matrix_path, source_fixture = artifact_paths(root, evidence_mode)
    fixture_bytes = read_regular_file(fixture_path, "fixture")
    rows = load_rows_bytes(fixture_bytes, evidence_mode)
    return build_matrix(
        rows,
        source_fixture,
        hashlib.sha256(fixture_bytes).hexdigest(),
    )


def declared_matrix_mode(matrix_path: Path) -> str:
    raw = read_regular_file(matrix_path, "capability matrix")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError("capability matrix: invalid UTF-8") from error
    parsed = strict_json(text, "capability matrix")
    if type(parsed) is not dict:
        raise EvidenceError("capability matrix: expected an object")
    evidence_mode = parsed.get("evidence_mode")
    if type(evidence_mode) is not str or evidence_mode not in FIXTURE_PATHS:
        raise EvidenceError("capability matrix: invalid evidence mode")
    return evidence_mode


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = SafeArgumentParser(prog="provider_evidence.py", allow_abbrev=False)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--check", action="store_true")
    operation.add_argument("--write-matrix", action="store_true")
    operation.add_argument("--print-summary", action="store_true")
    parser.add_argument("--evidence-mode", choices=sorted(FIXTURE_PATHS))
    arguments = parser.parse_args(argv)
    if arguments.check and arguments.evidence_mode is not None:
        parser.error("--check does not accept --evidence-mode")
    if not arguments.check and arguments.evidence_mode is None:
        parser.error("--evidence-mode is required for this operation")
    return arguments


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        root = Path(__file__).resolve(strict=True).parents[1]
        if arguments.check:
            evidence_mode = declared_matrix_mode(root / MATRIX_PATH)
            fixture_path, matrix_path, source_fixture = artifact_paths(
                root, evidence_mode
            )
            check_artifacts(
                fixture_path,
                matrix_path,
                evidence_mode,
                source_fixture,
            )
            print(
                f"provider evidence check passed: {len(PROVIDERS) * len(EVENT_KINDS)} cells"
            )
        elif arguments.write_matrix:
            matrix = matrix_for_mode(root, arguments.evidence_mode)
            matrix_path = root / MATRIX_PATH
            write_bytes_atomic(matrix_path, matrix_bytes(matrix))
            print(f"provider evidence matrix written: {MATRIX_PATH}")
        else:
            matrix = matrix_for_mode(root, arguments.evidence_mode)
            sys.stdout.write(matrix["human_summary"])
    except (EvidenceError, OSError) as error:
        print(f"provider_evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
