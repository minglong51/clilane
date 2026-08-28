#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, NoReturn, Sequence


def _load_provider_capture() -> Any:
    loaded = sys.modules.get("provider_capture")
    if loaded is not None:
        return loaded
    path = Path(__file__).resolve(strict=True).with_name("provider_capture.py")
    spec = importlib.util.spec_from_file_location("provider_capture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("provider capture engine unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


provider_capture = _load_provider_capture()


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
EXECUTABLE_MANIFEST_PATH = "docs/designs/provider-executables.json"
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
        "native_hook": {"codex-app-server", "codex-native-hook"},
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
RECEIPT_KEYS = {
    "budgets",
    "capture_bytes",
    "capture_id",
    "capture_present",
    "capture_status",
    "duration_ms",
    "executable_sha256",
    "frame_count",
    "incomplete_reasons",
    "payload_bytes",
    "provider",
    "provider_outcome",
    "provider_version",
    "schema_version",
    "source_capture_sha256",
    "source_interface",
    "streams",
    "termination",
}
INCOMPLETE_REASONS = {
    "aggregate_budget",
    "collector_signal",
    "descendant_process",
    "executable_changed",
    "per_capture_budget",
    "timeout",
}
TERMINATION_REASONS = {
    "byte_cap",
    "collector_signal",
    "descendant_process",
    "hook_eof",
    "provider_exit",
    "provider_signal",
    "timeout",
}
SOURCE_DECLARATIONS = {
    "claude-native-hook": ("claude", "native_hook"),
    "codex-app-server": ("codex", "native_hook"),
    "kimi-acp": ("kimi", "acp"),
}


@dataclass(frozen=True)
class VerifiedCapture:
    provider: str
    provider_version: str
    source_interface: str
    capture_status: str
    source_capture_sha256: str
    executable_sha256: str


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


def _metadata(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _open_private_member(
    root: provider_capture.CaptureRoot,
    name: str,
    maximum_bytes: int,
    label: str,
) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=root.directory_fd)
        metadata = os.fstat(descriptor)
        path_metadata = os.stat(name, dir_fd=root.directory_fd, follow_symlinks=False)
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise EvidenceError(f"{label}: unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size > maximum_bytes
        or _metadata(metadata) != _metadata(path_metadata)
    ):
        os.close(descriptor)
        raise EvidenceError(f"{label}: unsafe")
    return descriptor, metadata


def _member_unchanged(
    root: provider_capture.CaptureRoot,
    name: str,
    descriptor: int,
    original: os.stat_result,
) -> bool:
    try:
        descriptor_metadata = os.fstat(descriptor)
        path_metadata = os.stat(name, dir_fd=root.directory_fd, follow_symlinks=False)
    except OSError:
        return False
    return (
        _metadata(original) == _metadata(descriptor_metadata)
        and _metadata(original) == _metadata(path_metadata)
        and provider_capture._root_identity_matches(root)
    )


def _read_private_member(
    root: provider_capture.CaptureRoot,
    name: str,
    maximum_bytes: int,
    label: str,
) -> bytes:
    descriptor, metadata = _open_private_member(root, name, maximum_bytes, label)
    try:
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum_bytes or len(raw) != metadata.st_size:
            raise EvidenceError(f"{label}: oversized")
        if not _member_unchanged(root, name, descriptor, metadata):
            raise EvidenceError(f"{label}: changed")
        return raw
    except OSError as error:
        raise EvidenceError(f"{label}: read failed") from error
    finally:
        os.close(descriptor)


def _require_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise EvidenceError(f"{label}: invalid object")
    return value


def _require_integer(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = provider_capture.MAX_BUDGET_BYTES,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise EvidenceError(f"{label}: invalid integer")
    return value


def _require_hash(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise EvidenceError(f"{label}: invalid digest")
    return value


def load_executable_manifest_with_digest(
    path: Path,
) -> tuple[dict[str, str], str]:
    raw = read_regular_file(path, "provider executable manifest")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError("provider executable manifest: invalid UTF-8") from error
    manifest = _require_object(
        strict_json(text, "provider executable manifest"),
        {"platform", "providers", "schema_version"},
        "provider executable manifest",
    )
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise EvidenceError("provider executable manifest: unsupported schema")
    if manifest["platform"] != "darwin-arm64":
        raise EvidenceError("provider executable manifest: unsupported platform")
    entries = manifest["providers"]
    if type(entries) is not list:
        raise EvidenceError("provider executable manifest: invalid providers")
    expected: dict[str, str] = {}
    for entry in entries:
        item = _require_object(
            entry,
            {
                "executable_sha256",
                "provider",
                "provider_version",
                "source_interface",
            },
            "provider executable manifest entry",
        )
        provider = item["provider"]
        if type(provider) is not str or provider not in provider_capture.PROVIDER_SPECS:
            raise EvidenceError("provider executable manifest: invalid provider")
        if provider in expected:
            raise EvidenceError("provider executable manifest: duplicate provider")
        spec = provider_capture.PROVIDER_SPECS[provider]
        if (
            item["provider_version"] != spec.version
            or item["source_interface"] != spec.source_interface
        ):
            raise EvidenceError("provider executable manifest: identity mismatch")
        digest = _require_hash(
            item["executable_sha256"], "provider executable manifest"
        )
        if len(set(digest)) == 1:
            raise EvidenceError("provider executable manifest: placeholder digest")
        expected[provider] = digest
    if set(expected) != set(PROVIDERS):
        raise EvidenceError("provider executable manifest: incomplete providers")
    canonical = (
        json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if raw != canonical:
        raise EvidenceError("provider executable manifest: noncanonical")
    return expected, hashlib.sha256(raw).hexdigest()


def load_executable_manifest(path: Path) -> dict[str, str]:
    expected, _digest = load_executable_manifest_with_digest(path)
    return expected


def _provider_executables_digest(value: str | None) -> str:
    if value is None:
        root = Path(__file__).resolve(strict=True).parents[1]
        _expected, value = load_executable_manifest_with_digest(
            root / EXECUTABLE_MANIFEST_PATH
        )
    return _require_hash(value, "provider executable manifest")


def _validate_receipt(value: Any, expected_capture_id: str) -> dict[str, Any]:
    receipt = _require_object(value, RECEIPT_KEYS, "capture receipt")
    if receipt["schema_version"] != provider_capture.SCHEMA_VERSION:
        raise EvidenceError("capture receipt: unsupported schema")
    if receipt["capture_id"] != expected_capture_id:
        raise EvidenceError("capture receipt: identity mismatch")
    provider = receipt["provider"]
    if type(provider) is not str or provider not in provider_capture.PROVIDER_SPECS:
        raise EvidenceError("capture receipt: invalid provider")
    spec = provider_capture.PROVIDER_SPECS[provider]
    if receipt["provider_version"] != spec.version:
        raise EvidenceError("capture receipt: version mismatch")
    if receipt["source_interface"] != spec.source_interface:
        raise EvidenceError("capture receipt: interface mismatch")
    capture_status = receipt["capture_status"]
    if type(capture_status) is not str or capture_status not in {
        "complete",
        "incomplete",
    }:
        raise EvidenceError("capture receipt: invalid status")
    if receipt["provider_outcome"] != "unknown":
        raise EvidenceError("capture receipt: invalid outcome")
    reasons = receipt["incomplete_reasons"]
    if (
        type(reasons) is not list
        or any(type(reason) is not str or reason not in INCOMPLETE_REASONS for reason in reasons)
        or len(reasons) != len(set(reasons))
        or (capture_status == "complete") != (not reasons)
    ):
        raise EvidenceError("capture receipt: invalid incompleteness")
    if type(receipt["capture_present"]) is not bool:
        raise EvidenceError("capture receipt: invalid presence")
    capture_bytes = _require_integer(receipt["capture_bytes"], "capture receipt")
    payload_bytes = _require_integer(receipt["payload_bytes"], "capture receipt")
    frame_count = _require_integer(receipt["frame_count"], "capture receipt")
    _require_integer(
        receipt["duration_ms"],
        "capture receipt",
        maximum=(provider_capture.MAX_TIMEOUT_SECONDS + 10) * 1000,
    )
    executable_hash = _require_hash(receipt["executable_sha256"], "capture receipt")
    if len(set(executable_hash)) == 1:
        raise EvidenceError("capture receipt: placeholder executable digest")

    budgets = _require_object(
        receipt["budgets"],
        {
            "aggregate_bytes",
            "aggregate_counts",
            "capture_limit_bytes",
            "per_capture_bytes",
            "receipt_bytes_excluded",
        },
        "capture receipt budgets",
    )
    per_capture = _require_integer(
        budgets["per_capture_bytes"], "capture receipt budgets", minimum=1
    )
    aggregate = _require_integer(
        budgets["aggregate_bytes"], "capture receipt budgets", minimum=1
    )
    capture_limit = _require_integer(
        budgets["capture_limit_bytes"], "capture receipt budgets"
    )
    if (
        aggregate < per_capture
        or capture_limit > per_capture
        or capture_limit > aggregate
        or budgets["aggregate_counts"] != "capture_files"
        or budgets["receipt_bytes_excluded"] is not True
        or capture_bytes > capture_limit
        or payload_bytes > capture_bytes
    ):
        raise EvidenceError("capture receipt budgets: inconsistent")

    streams = _require_object(
        receipt["streams"], {"stdin", "stdout", "stderr"}, "capture receipt streams"
    )
    stream_bytes = 0
    for stream in ("stdin", "stdout", "stderr"):
        item = _require_object(
            streams[stream], {"bytes", "sha256"}, "capture receipt stream"
        )
        stream_bytes += _require_integer(item["bytes"], "capture receipt stream")
        _require_hash(item["sha256"], "capture receipt stream")
    if stream_bytes != payload_bytes:
        raise EvidenceError("capture receipt streams: inconsistent")

    termination = _require_object(
        receipt["termination"],
        {"collector_signal", "exit_code", "reason", "signal"},
        "capture receipt termination",
    )
    if (
        type(termination["reason"]) is not str
        or termination["reason"] not in TERMINATION_REASONS
    ):
        raise EvidenceError("capture receipt termination: invalid reason")
    for key in ("collector_signal", "exit_code", "signal"):
        value = termination[key]
        if value is not None:
            _require_integer(value, "capture receipt termination", maximum=255)

    capture_hash = receipt["source_capture_sha256"]
    if receipt["capture_present"]:
        _require_hash(capture_hash, "capture receipt")
        if capture_bytes < len(provider_capture.CAPTURE_MAGIC):
            raise EvidenceError("capture receipt: invalid capture size")
    elif (
        capture_status != "incomplete"
        or capture_hash is not None
        or capture_bytes != 0
        or payload_bytes != 0
        or frame_count != 0
    ):
        raise EvidenceError("capture receipt: invalid absent capture")
    return receipt


class _DigestingReader:
    def __init__(self, descriptor: int) -> None:
        self.descriptor = descriptor
        self.digest = hashlib.sha256()
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = 64 * 1024
        chunks: list[bytes] = []
        remaining = size
        while remaining > 0:
            chunk = os.read(self.descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        self.digest.update(raw)
        self.bytes_read += len(raw)
        return raw


def _verify_capture(
    root: provider_capture.CaptureRoot,
    capture_id: str,
    receipt: dict[str, Any],
) -> VerifiedCapture | None:
    if not receipt["capture_present"]:
        return None
    name = f"{capture_id}.capture"
    descriptor, metadata = _open_private_member(
        root, name, provider_capture.MAX_BUDGET_BYTES, "capture"
    )
    reader = _DigestingReader(descriptor)
    streams = {
        "I": {"bytes": 0, "sha256": hashlib.sha256()},
        "O": {"bytes": 0, "sha256": hashlib.sha256()},
        "E": {"bytes": 0, "sha256": hashlib.sha256()},
    }
    frame_count = 0
    payload_bytes = 0
    try:
        for stream, _observed_ns, payload in provider_capture.iter_capture_frames(reader):
            streams[stream]["bytes"] += len(payload)
            streams[stream]["sha256"].update(payload)
            payload_bytes += len(payload)
            frame_count += 1
        if not _member_unchanged(root, name, descriptor, metadata):
            raise EvidenceError("capture: changed")
    except provider_capture.CaptureError as error:
        raise EvidenceError("capture: invalid framing") from error
    except OSError as error:
        raise EvidenceError("capture: read failed") from error
    finally:
        os.close(descriptor)

    receipt_streams = receipt["streams"]
    if (
        reader.bytes_read != metadata.st_size
        or reader.bytes_read != receipt["capture_bytes"]
        or reader.digest.hexdigest() != receipt["source_capture_sha256"]
        or payload_bytes != receipt["payload_bytes"]
        or frame_count != receipt["frame_count"]
        or any(
            streams[key]["bytes"] != receipt_streams[name]["bytes"]
            or streams[key]["sha256"].hexdigest() != receipt_streams[name]["sha256"]
            for key, name in (("I", "stdin"), ("O", "stdout"), ("E", "stderr"))
        )
    ):
        raise EvidenceError("capture: receipt mismatch")
    return VerifiedCapture(
        provider=receipt["provider"],
        provider_version=receipt["provider_version"],
        source_interface=receipt["source_interface"],
        capture_status=receipt["capture_status"],
        source_capture_sha256=receipt["source_capture_sha256"],
        executable_sha256=receipt["executable_sha256"],
    )


def _verified_captures(capture_root: Path) -> set[VerifiedCapture]:
    try:
        repository = provider_capture.repository_paths(Path(__file__))
        root = provider_capture.validate_capture_root(capture_root, repository)
        provider_capture._lock_root(root)
    except provider_capture.CaptureError as error:
        raise EvidenceError("capture root: invalid") from error
    captures: set[VerifiedCapture] = set()
    try:
        try:
            names = sorted(os.listdir(root.directory_fd))
        except OSError as error:
            raise EvidenceError("capture root: unreadable") from error
        receipt_names = [name for name in names if name.endswith(".receipt.json")]
        for receipt_name in receipt_names:
            capture_id = receipt_name.removesuffix(".receipt.json")
            if provider_capture.CAPTURE_ID_PATTERN.fullmatch(capture_id) is None:
                raise EvidenceError("capture receipt: invalid name")
            raw_receipt = _read_private_member(
                root,
                receipt_name,
                provider_capture.MAX_RECEIPT_BYTES,
                "capture receipt",
            )
            try:
                receipt_text = raw_receipt.decode("utf-8")
            except UnicodeDecodeError as error:
                raise EvidenceError("capture receipt: invalid UTF-8") from error
            receipt = _validate_receipt(
                strict_json(receipt_text, "capture receipt"), capture_id
            )
            expected = (
                json.dumps(
                    receipt,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            if raw_receipt != expected:
                raise EvidenceError("capture receipt: noncanonical")
            capture = _verify_capture(root, capture_id, receipt)
            if capture is not None:
                captures.add(capture)
        return captures
    finally:
        root.close()


def _candidate_rows(raw: bytes) -> list[dict[str, Any]]:
    if len(raw) > MAX_FILE_BYTES or not raw.endswith(b"\n"):
        raise EvidenceError("candidate fixture: invalid size or termination")
    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(raw.splitlines(), start=1):
        if not raw_line or len(raw_line) > MAX_LINE_BYTES:
            raise EvidenceError(f"line {line_number}: empty or oversized row")
        try:
            text = raw_line.decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceError(f"line {line_number}: invalid UTF-8") from error
        row = validate_row(strict_json(text, f"line {line_number}"), line_number)
        if row["evidence_mode"] != "observed":
            raise EvidenceError(f"line {line_number}: expected observed evidence")
        rows.append(row)
    if not rows:
        raise EvidenceError("candidate fixture: no rows")
    return rows


def verify_observed_provenance(
    rows: Sequence[dict[str, Any]],
    capture_root: Path,
    expected_executable_sha256: dict[str, str],
) -> None:
    captures = _verified_captures(capture_root)
    for line_number, row in enumerate(rows, start=1):
        declaration = SOURCE_DECLARATIONS.get(row["source_interface"])
        if declaration != (row["provider"], row["source_kind"]):
            raise EvidenceError(f"line {line_number}: unsupported observed source")
        expected = VerifiedCapture(
            provider=row["provider"],
            provider_version=row["provider_version"],
            source_interface=row["source_interface"],
            capture_status=row["capture_status"],
            source_capture_sha256=row["source_capture_sha256"],
            executable_sha256=expected_executable_sha256[row["provider"]],
        )
        if expected not in captures:
            raise EvidenceError(f"line {line_number}: unverified source capture")


def validate_unanalyzed_observed_rows(rows: Sequence[dict[str, Any]]) -> None:
    relevance = {
        "duplicate_handling": "duplicate",
        "stale_session_handling": "stale_session",
        "reconnect_result": "reconnect",
        "recovery_result": "request_recovery",
    }
    for line_number, row in enumerate(rows, start=1):
        event_kind = row["event_kind"]
        lifecycle_event = (
            event_kind in REQUEST_LIFECYCLE_EVENT_KINDS or event_kind == "turn_state"
        )
        expected = {
            "status": "unknown",
            "task_binding": "unknown",
            "session_binding": "unknown",
            "request_binding": "unknown"
            if event_kind in REQUEST_EVENT_KINDS
            else "not_applicable",
            "open_behavior": "unknown" if lifecycle_event else "not_applicable",
            "close_behavior": "unknown" if lifecycle_event else "not_applicable",
            "latency_ms": [],
            "freshness_seconds": None,
            "freshness_renews_on": None,
            "failure_behavior": "unknown",
        }
        expected.update(
            {
                key: "unknown" if event_kind == relevant_event else "not_applicable"
                for key, relevant_event in relevance.items()
            }
        )
        if any(row[key] != value for key, value in expected.items()):
            raise EvidenceError(
                f"line {line_number}: observed semantics require an analyzer"
            )


def normalize_observed_bytes(
    raw: bytes,
    capture_root: Path,
    expected_executable_sha256: dict[str, str],
    provider_executables_sha256: str | None = None,
) -> bytes:
    rows = _candidate_rows(raw)
    canonical = canonical_row_bytes(rows)
    build_matrix(
        rows,
        FIXTURE_PATHS["observed"],
        hashlib.sha256(canonical).hexdigest(),
        provider_executables_sha256=provider_executables_sha256,
    )
    verify_observed_provenance(rows, capture_root, expected_executable_sha256)
    return canonical


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
    *,
    provider_executables_sha256: str | None = None,
    semantics_analyzed: bool = False,
) -> dict[str, Any]:
    validate_source_fixture(source_fixture)
    executable_manifest_digest = _provider_executables_digest(
        provider_executables_sha256
    )
    validated = [validate_row(dict(row), index) for index, row in enumerate(rows, 1)]
    modes = {row["evidence_mode"] for row in validated}
    if len(modes) != 1:
        raise EvidenceError("fixture: mixed evidence modes")
    mode = next(iter(modes))
    if mode == "observed" and not semantics_analyzed:
        validate_unanalyzed_observed_rows(validated)
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
        "provider_executables_sha256": executable_manifest_digest,
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
    *,
    provider_executables_sha256: str | None = None,
) -> bytes:
    return matrix_bytes(
        build_matrix(
            rows,
            source_fixture,
            source_fixture_sha256,
            provider_executables_sha256=provider_executables_sha256,
        )
    )


def check_artifacts(
    fixture_path: Path,
    matrix_path: Path,
    expected_mode: str,
    source_fixture: str,
    *,
    provider_executables_sha256: str | None = None,
) -> None:
    if source_fixture != FIXTURE_PATHS.get(expected_mode):
        raise EvidenceError("fixture: unexpected source declaration")
    fixture_bytes = read_regular_file(fixture_path, "fixture")
    rows = load_rows_bytes(fixture_bytes, expected_mode)
    expected = build_matrix_bytes(
        rows,
        source_fixture,
        hashlib.sha256(fixture_bytes).hexdigest(),
        provider_executables_sha256=provider_executables_sha256,
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


def matrix_for_mode(
    root: Path,
    evidence_mode: str,
    *,
    provider_executables_sha256: str | None = None,
) -> dict[str, Any]:
    fixture_path, _matrix_path, source_fixture = artifact_paths(root, evidence_mode)
    fixture_bytes = read_regular_file(fixture_path, "fixture")
    rows = load_rows_bytes(fixture_bytes, evidence_mode)
    return build_matrix(
        rows,
        source_fixture,
        hashlib.sha256(fixture_bytes).hexdigest(),
        provider_executables_sha256=provider_executables_sha256,
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
    operation.add_argument("--write-observed", action="store_true")
    parser.add_argument("--evidence-mode", choices=sorted(FIXTURE_PATHS))
    parser.add_argument("--capture-root")
    arguments = parser.parse_args(argv)
    if arguments.write_observed:
        if arguments.evidence_mode is not None or arguments.capture_root is None:
            parser.error("--write-observed requires only --capture-root")
    else:
        if arguments.capture_root is not None:
            parser.error("--capture-root is only valid with --write-observed")
        if arguments.check and arguments.evidence_mode is not None:
            parser.error("--check does not accept --evidence-mode")
        if not arguments.check and arguments.evidence_mode is None:
            parser.error("--evidence-mode is required for this operation")
    return arguments


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        root = Path(__file__).resolve(strict=True).parents[1]
        (
            expected_executable_sha256,
            provider_executables_sha256,
        ) = load_executable_manifest_with_digest(
            root / EXECUTABLE_MANIFEST_PATH
        )
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
                provider_executables_sha256=provider_executables_sha256,
            )
            print(
                f"provider evidence check passed: {len(PROVIDERS) * len(EVENT_KINDS)} cells"
            )
        elif arguments.write_observed:
            raw = sys.stdin.buffer.read(MAX_FILE_BYTES + 1)
            if len(raw) > MAX_FILE_BYTES:
                raise EvidenceError("candidate fixture: oversized")
            canonical = normalize_observed_bytes(
                raw,
                Path(arguments.capture_root),
                expected_executable_sha256,
                provider_executables_sha256,
            )
            fixture_path = root / FIXTURE_PATHS["observed"]
            write_bytes_atomic(fixture_path, canonical)
            print(
                f"provider evidence fixture written: {FIXTURE_PATHS['observed']}"
            )
        elif arguments.write_matrix:
            matrix = matrix_for_mode(
                root,
                arguments.evidence_mode,
                provider_executables_sha256=provider_executables_sha256,
            )
            matrix_path = root / MATRIX_PATH
            write_bytes_atomic(matrix_path, matrix_bytes(matrix))
            print(f"provider evidence matrix written: {MATRIX_PATH}")
        else:
            matrix = matrix_for_mode(
                root,
                arguments.evidence_mode,
                provider_executables_sha256=provider_executables_sha256,
            )
            sys.stdout.write(matrix["human_summary"])
    except (EvidenceError, OSError) as error:
        print(f"provider_evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
