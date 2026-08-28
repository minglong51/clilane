from __future__ import annotations

import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_ENGINE_PATH = ROOT / "scripts/provider_capture.py"
CAPTURE_SPEC = importlib.util.spec_from_file_location(
    "provider_capture", CAPTURE_ENGINE_PATH
)
if CAPTURE_SPEC is None or CAPTURE_SPEC.loader is None:
    raise RuntimeError(f"cannot load {CAPTURE_ENGINE_PATH}")
provider_capture = importlib.util.module_from_spec(CAPTURE_SPEC)
sys.modules[CAPTURE_SPEC.name] = provider_capture
CAPTURE_SPEC.loader.exec_module(provider_capture)

SCRIPT_PATH = ROOT / "scripts/provider_evidence.py"
SPEC = importlib.util.spec_from_file_location("provider_evidence", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT_PATH}")
provider_evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = provider_evidence
SPEC.loader.exec_module(provider_evidence)

COLLECTOR_SCRIPTS = {
    provider: ROOT / f"scripts/collect_{provider}_evidence.py"
    for provider in ("claude", "codex", "kimi")
}

EXPECTED_PROVIDERS = ("claude", "codex", "kimi")
EXPECTED_EVENT_KINDS = (
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
SOURCE_FIXTURE = "tests/fixtures/provider-evidence/synthetic.jsonl"
PROVIDER_VERSIONS = {
    "claude": "1.2.3",
    "codex": "2.3.4",
    "kimi": "3.4.5",
}
T7_ARTIFACTS = (
    SCRIPT_PATH,
    Path(__file__).resolve(),
    ROOT / "tests/fixtures/provider-evidence/synthetic.jsonl",
    ROOT / "docs/designs/provider-capabilities.json",
    ROOT / "docs/designs/provider-executables.json",
)


def write_fake_provider(
    directory: Path,
    provider: str,
    command_source: str = "",
    *,
    version_output: bytes | None = None,
) -> Path:
    spec = provider_capture.PROVIDER_SPECS[provider]
    selected_version = spec.version_outputs[0] if version_output is None else version_output
    executable = directory / f"fake-{provider}"
    source = (
        "#!/usr/bin/env python3\n"
        "import os\n"
        "import signal\n"
        "import subprocess\n"
        "import sys\n"
        "import time\n"
        f"version_output = {selected_version!r}\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    if os.getcwd() != '/':\n"
        "        raise SystemExit(93)\n"
        "    os.write(1, version_output)\n"
        "    raise SystemExit(0)\n"
        f"if sys.argv[1:] != {list(spec.command)!r}:\n"
        "    raise SystemExit(91)\n"
        f"{command_source}"
    )
    executable.write_text(source, encoding="utf-8")
    executable.chmod(0o755)
    return executable


def run_collector(
    provider: str,
    capture_root: Path,
    capture_id: str,
    executable: Path,
    payload: bytes = b"",
    *,
    per_capture_bytes: int = 1 << 20,
    aggregate_bytes: int = 1 << 21,
    timeout_seconds: int = 3,
    provider_control_fd: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [
        sys.executable,
        "-B",
        str(COLLECTOR_SCRIPTS[provider]),
        "--capture-root",
        str(capture_root),
        "--capture-id",
        capture_id,
        "--per-capture-bytes",
        str(per_capture_bytes),
        "--aggregate-bytes",
        str(aggregate_bytes),
        "--timeout-seconds",
        str(timeout_seconds),
        "--provider-executable",
        str(executable),
    ]
    pass_fds: tuple[int, ...] = ()
    if provider_control_fd is not None:
        command.extend(("--provider-control-fd", str(provider_control_fd)))
        pass_fds = (provider_control_fd,)
    return subprocess.run(
        command,
        cwd=ROOT,
        input=payload,
        capture_output=True,
        check=False,
        env=environment,
        pass_fds=pass_fds,
        timeout=15,
    )


def read_receipt(capture_root: Path, capture_id: str) -> dict[str, Any]:
    return json.loads(
        (capture_root / f"{capture_id}.receipt.json").read_text(encoding="utf-8")
    )


def make_row(
    provider: str = "claude",
    event_kind: str = "heartbeat",
    *,
    evidence_mode: str = "synthetic",
    status: str | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    if status is None:
        status = "unknown" if evidence_mode == "synthetic" else "pass"
    passing = status == "pass"
    source_kind = "native_hook" if passing or evidence_mode == "observed" else "unknown"
    request_event = event_kind in REQUEST_EVENT_KINDS
    request_transition = event_kind in {"approval_request", "input_request"}
    turn_transition = event_kind == "turn_state"
    evidence_id = f"evidence-{provider}-{event_kind.replace('_', '-')}"
    row: dict[str, Any] = {
        "schema_version": 1,
        "evidence_id": evidence_id,
        "evidence_mode": evidence_mode,
        "provider": provider,
        "provider_version": PROVIDER_VERSIONS[provider],
        "source_interface": (
            f"{provider}-native-hook" if source_kind == "native_hook" else "none"
        ),
        "source_kind": source_kind,
        "event_kind": event_kind,
        "task_id": f"synthetic-{provider}-task",
        "session_id": f"synthetic-{provider}-session",
        "request_id": f"synthetic-{provider}-{event_kind.replace('_', '-')}-request"
        if request_event
        else None,
        "task_binding": "exact" if passing else "unknown",
        "session_binding": "exact" if passing else "unknown",
        "request_binding": "exact"
        if passing and request_event
        else "unknown"
        if request_event
        else "not_applicable",
        "open_behavior": "request_opened"
        if passing and request_transition
        else "turn_started"
        if passing and turn_transition
        else "unknown"
        if request_transition or turn_transition
        else "not_applicable",
        "close_behavior": "request_resolved"
        if passing and request_transition
        else "turn_idle"
        if passing and turn_transition
        else "unknown"
        if request_transition or turn_transition
        else "not_applicable",
        "duplicate_handling": "deduplicated_noop"
        if passing and event_kind == "duplicate"
        else "unknown"
        if event_kind == "duplicate"
        else "not_applicable",
        "stale_session_handling": "rejected_no_write"
        if passing and event_kind == "stale_session"
        else "unknown"
        if event_kind == "stale_session"
        else "not_applicable",
        "reconnect_result": "reconnected"
        if passing and event_kind == "reconnect"
        else "unknown"
        if event_kind == "reconnect"
        else "not_applicable",
        "recovery_result": "unresolved_request_reemitted"
        if passing and event_kind == "request_recovery"
        else "unknown"
        if event_kind == "request_recovery"
        else "not_applicable",
        "latency_ms": [10, 20] if passing else [],
        "status": status,
        "source_capture_sha256": hashlib.sha256(evidence_id.encode()).hexdigest(),
        "capture_status": "complete",
        "freshness_seconds": 60 if passing and event_kind == "heartbeat" else None,
        "freshness_renews_on": "adapter_heartbeat"
        if passing and event_kind == "heartbeat"
        else None,
        "failure_behavior": "fail_closed" if passing else "unknown",
    }
    row.update(overrides)
    return row


def make_grid(
    *, evidence_mode: str = "synthetic", status: str | None = None
) -> list[dict[str, Any]]:
    return [
        make_row(
            provider,
            event_kind,
            evidence_mode=evidence_mode,
            status=status,
        )
        for provider in EXPECTED_PROVIDERS
        for event_kind in EXPECTED_EVENT_KINDS
    ]


def validate_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        provider_evidence.validate_row(copy.deepcopy(row), line_number)
        for line_number, row in enumerate(rows, start=1)
    ]


def tree_snapshot(root: Path) -> dict[str, tuple[int, int, str]]:
    result: dict[str, tuple[int, int, str]] = {}
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode):
            payload = hashlib.sha256(path.read_bytes()).hexdigest()
        elif stat.S_ISLNK(metadata.st_mode):
            payload = f"symlink:{os.readlink(path)}"
        else:
            payload = f"type:{stat.S_IFMT(metadata.st_mode)}"
        result[str(path.relative_to(root))] = (
            stat.S_IMODE(metadata.st_mode),
            metadata.st_mtime_ns,
            payload,
        )
    return result


class StrictJsonAndRowTests(unittest.TestCase):
    def test_strict_json_rejects_ambiguous_forms(self) -> None:
        invalid_documents = (
            '{"outer":{"value":1,"value":2}}',
            '{"value":NaN}',
            '{"value":Infinity}',
            '{"value":-Infinity}',
            '{"value":' + "9" * 65 + "}",
        )
        for document in invalid_documents:
            with self.subTest(document=document):
                with self.assertRaises(provider_evidence.EvidenceError):
                    provider_evidence.strict_json(document, "test fixture")

    def test_row_requires_exact_fields(self) -> None:
        row = make_row()
        self.assertEqual(provider_evidence.validate_row(copy.deepcopy(row), 1), row)
        for key in tuple(row):
            incomplete = copy.deepcopy(row)
            del incomplete[key]
            with self.subTest(missing=key):
                with self.assertRaises(provider_evidence.EvidenceError):
                    provider_evidence.validate_row(incomplete, 1)
        extra = copy.deepcopy(row)
        extra["prompt"] = "privacy-canary"
        with self.assertRaises(provider_evidence.EvidenceError):
            provider_evidence.validate_row(extra, 1)

    def test_row_rejects_wrong_exact_types_and_unknown_enums(self) -> None:
        cases = (
            ("schema_version", True),
            ("latency_ms", [True]),
            ("freshness_seconds", True),
            ("provider", "Claude"),
            ("event_kind", "terminal_state"),
            ("source_kind", "terminal_log"),
            ("capture_status", "truncated"),
            ("failure_behavior", "best_effort"),
            ("source_capture_sha256", "A" * 64),
            ("source_capture_sha256", "a" * 63),
            ("source_capture_sha256", "0" * 64),
        )
        for key, value in cases:
            row = make_row()
            row[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(provider_evidence.EvidenceError):
                    provider_evidence.validate_row(row, 1)
        for symbolic_version in ("latest", "unknown", "nightly2026", "HEAD1", "dev-1"):
            row = make_row(evidence_mode="observed")
            row["provider_version"] = symbolic_version
            with self.subTest(provider_version=symbolic_version):
                with self.assertRaises(provider_evidence.EvidenceError):
                    provider_evidence.validate_row(row, 1)

    def test_passing_rows_enforce_event_specific_proof(self) -> None:
        for event_kind in EXPECTED_EVENT_KINDS:
            with self.subTest(valid=event_kind):
                provider_evidence.validate_row(
                    make_row(event_kind=event_kind, evidence_mode="observed"), 1
                )
        cases: list[tuple[str, str, Any]] = [
            ("heartbeat", "task_binding", "unknown"),
            ("heartbeat", "session_binding", "ambiguous"),
            ("heartbeat", "capture_status", "incomplete"),
            ("heartbeat", "failure_behavior", "fail_open"),
            ("heartbeat", "freshness_seconds", None),
            ("heartbeat", "freshness_seconds", 301),
            ("heartbeat", "freshness_renews_on", "duplicate"),
            ("heartbeat", "freshness_renews_on", "adapter_ready"),
            ("heartbeat", "latency_ms", []),
            ("input_request", "request_binding", "ambiguous"),
            ("input_request", "open_behavior", "missing"),
            ("approval_request", "close_behavior", "missing"),
            ("approval_request", "close_behavior", "task_terminal"),
            ("duplicate", "request_binding", "ambiguous"),
            ("duplicate", "duplicate_handling", "mutated"),
            ("stale_session", "stale_session_handling", "accepted"),
            ("reconnect", "reconnect_result", "lost"),
            ("request_recovery", "request_binding", "ambiguous"),
            ("request_recovery", "recovery_result", "lost"),
            ("turn_state", "open_behavior", "missing"),
            ("turn_state", "close_behavior", "missing"),
        ]
        for event_kind, key, value in cases:
            row = make_row(event_kind=event_kind, evidence_mode="observed")
            row[key] = value
            with self.subTest(event_kind=event_kind, key=key, value=value):
                with self.assertRaises(provider_evidence.EvidenceError):
                    provider_evidence.validate_row(row, 1)

    def test_uncertain_and_failed_rows_remain_valid_but_incomplete_cannot_pass(self) -> None:
        provider_evidence.validate_row(make_row(), 1)
        provider_evidence.validate_row(
            make_row(evidence_mode="observed", status="fail"), 1
        )
        provider_evidence.validate_row(
            make_row(capture_status="incomplete", status="unknown"), 1
        )
        with self.assertRaises(provider_evidence.EvidenceError):
            provider_evidence.validate_row(
                make_row(
                    evidence_mode="observed",
                    capture_status="incomplete",
                    status="pass",
                ),
                1,
            )

    def test_privacy_canaries_are_rejected_without_echo(self) -> None:
        canary = "CANARY_SECRET_TOKEN_7e34487d"
        cases: list[tuple[str, Any]] = [
            ("provider_version", canary),
            ("provider_version", "ghp_012345678901234567890123456789012345"),
            ("source_interface", "canary-secret-token"),
            ("status", canary),
            ("task_id", "/Users/private/CANARY_SECRET_TOKEN_7e34487d"),
            ("session_id", "real-session-7e34487d"),
            ("evidence_id", "evidence-real-session-7e34487d"),
        ]
        for key, value in cases:
            row = make_row()
            row[key] = value
            with self.subTest(key=key):
                with self.assertRaises(provider_evidence.EvidenceError) as raised:
                    provider_evidence.validate_row(row, 41)
                self.assertNotIn(canary, str(raised.exception))
                self.assertNotIn(str(value), str(raised.exception))

        row = make_row()
        row["prompt"] = canary
        with self.assertRaises(provider_evidence.EvidenceError) as raised:
            provider_evidence.validate_row(row, 41)
        self.assertNotIn(canary, str(raised.exception))


class CanonicalRenderingTests(unittest.TestCase):
    def test_canonical_jsonl_is_exact_and_permutation_stable(self) -> None:
        rows = validate_rows(make_grid())
        canonical = provider_evidence.canonical_row_bytes(rows)
        self.assertEqual(canonical, provider_evidence.canonical_row_bytes(list(reversed(rows))))
        expected = b"".join(
            (
                json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
                + "\n"
            ).encode("utf-8")
            for row in rows
        )
        self.assertEqual(canonical, expected)
        self.assertTrue(canonical.endswith(b"\n"))
        self.assertFalse(canonical.endswith(b"\n\n"))
        self.assertNotIn(b'": ', canonical)
        self.assertNotIn(b'", "', canonical)

    def test_load_rows_rejects_noncanonical_bytes(self) -> None:
        rows = validate_rows(make_grid())
        canonical = provider_evidence.canonical_row_bytes(rows)
        first, *remaining = canonical.splitlines()
        variants = {
            "missing-newline": canonical.rstrip(b"\n"),
            "blank-line": canonical + b"\n",
            "reordered": b"\n".join(reversed(canonical.splitlines())) + b"\n",
            "spaced-json": first.replace(b'":', b'": ', 1)
            + b"\n"
            + b"\n".join(remaining)
            + b"\n",
            "invalid-utf8": b"\xff\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture.jsonl"
            fixture.write_bytes(canonical)
            self.assertEqual(provider_evidence.load_rows(fixture), rows)
            for name, data in variants.items():
                with self.subTest(name=name):
                    fixture.write_bytes(data)
                    with self.assertRaises(provider_evidence.EvidenceError):
                        provider_evidence.load_rows(fixture)

    def test_matrix_and_summary_are_deterministic_and_fixture_bound(self) -> None:
        rows = validate_rows(make_grid())
        matrix = provider_evidence.build_matrix(rows, SOURCE_FIXTURE)
        permuted = provider_evidence.build_matrix(list(reversed(rows)), SOURCE_FIXTURE)
        self.assertEqual(matrix, permuted)
        self.assertEqual(
            provider_evidence.matrix_bytes(matrix),
            provider_evidence.matrix_bytes(permuted),
        )
        self.assertEqual(matrix["schema_version"], 1)
        self.assertEqual(matrix["evidence_mode"], "synthetic")
        self.assertEqual(matrix["source_fixture"], SOURCE_FIXTURE)
        self.assertEqual(
            matrix["source_fixture_sha256"],
            hashlib.sha256(provider_evidence.canonical_row_bytes(rows)).hexdigest(),
        )
        self.assertTrue(matrix["complete"])
        self.assertEqual(matrix["present_cells"], 24)
        self.assertEqual(matrix["required_cells"], 24)
        self.assertIn("v0_6_gate", matrix)
        self.assertEqual(
            [provider["provider"] for provider in matrix["providers"]],
            list(EXPECTED_PROVIDERS),
        )
        for provider in matrix["providers"]:
            self.assertEqual(
                [cell["event_kind"] for cell in provider["cells"]],
                list(EXPECTED_EVENT_KINDS),
            )
        without_summary = {
            key: value for key, value in matrix.items() if key != "human_summary"
        }
        self.assertEqual(matrix["human_summary"], provider_evidence.render_summary(without_summary))
        expected_bytes = (
            json.dumps(matrix, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        self.assertEqual(provider_evidence.matrix_bytes(matrix), expected_bytes)
        self.assertNotIn(str(ROOT).encode(), expected_bytes)

    def test_capture_hash_changes_propagate_to_matrix_and_fixture_digest(self) -> None:
        rows = validate_rows(make_grid())
        original = provider_evidence.build_matrix(rows, SOURCE_FIXTURE)
        changed_rows = copy.deepcopy(rows)
        changed_hash = hashlib.sha256(b"changed-capture").hexdigest()
        changed_rows[0]["source_capture_sha256"] = changed_hash
        changed_rows = validate_rows(changed_rows)
        changed = provider_evidence.build_matrix(changed_rows, SOURCE_FIXTURE)
        self.assertNotEqual(
            original["source_fixture_sha256"], changed["source_fixture_sha256"]
        )
        changed_cell = next(
            cell
            for provider in changed["providers"]
            if provider["provider"] == changed_rows[0]["provider"]
            for cell in provider["cells"]
            if cell["event_kind"] == changed_rows[0]["event_kind"]
        )
        self.assertEqual(changed_cell["source_capture_sha256"], changed_hash)
        self.assertNotEqual(
            provider_evidence.matrix_bytes(original),
            provider_evidence.matrix_bytes(changed),
        )


class CompletenessAndAuthorityTests(unittest.TestCase):
    def test_required_grid_is_the_exact_twenty_four_cell_cross_product(self) -> None:
        rows = validate_rows(make_grid())
        expected = {
            (provider, event_kind)
            for provider in EXPECTED_PROVIDERS
            for event_kind in EXPECTED_EVENT_KINDS
        }
        self.assertEqual(
            {(row["provider"], row["event_kind"]) for row in rows}, expected
        )
        self.assertEqual(len(expected), 24)
        for missing_index, missing_row in enumerate(rows):
            with self.subTest(
                provider=missing_row["provider"], event_kind=missing_row["event_kind"]
            ):
                incomplete = rows[:missing_index] + rows[missing_index + 1 :]
                with self.assertRaises(provider_evidence.EvidenceError) as raised:
                    provider_evidence.build_matrix(incomplete, SOURCE_FIXTURE)
                self.assertIn(missing_row["provider"], str(raised.exception))
                self.assertIn(missing_row["event_kind"], str(raised.exception))

    def test_duplicate_cells_evidence_ids_modes_and_versions_fail_closed(self) -> None:
        rows = validate_rows(make_grid())
        variants: dict[str, list[dict[str, Any]]] = {}
        variants["duplicate-cell"] = rows + [copy.deepcopy(rows[0])]
        duplicate_id = copy.deepcopy(rows)
        duplicate_id[1]["evidence_id"] = duplicate_id[0]["evidence_id"]
        variants["duplicate-evidence-id"] = duplicate_id
        mixed_mode = copy.deepcopy(rows)
        mixed_mode[0]["evidence_mode"] = "observed"
        variants["mixed-mode"] = mixed_mode
        mixed_version = copy.deepcopy(rows)
        mixed_version[1]["provider_version"] = "9.9.9"
        variants["mixed-version"] = mixed_version
        for name, variant in variants.items():
            with self.subTest(name=name):
                with self.assertRaises(provider_evidence.EvidenceError):
                    provider_evidence.build_matrix(validate_rows(variant), SOURCE_FIXTURE)

    def test_synthetic_and_uncertain_evidence_never_authorize(self) -> None:
        synthetic_pass = validate_rows(make_grid(status="pass"))
        synthetic_matrix = provider_evidence.build_matrix(
            synthetic_pass, SOURCE_FIXTURE
        )
        self.assertTrue(synthetic_matrix["complete"])
        self.assertTrue(
            all(
                not provider["authoritative"]
                and provider["support"] == "attach_only_unknown"
                for provider in synthetic_matrix["providers"]
            )
        )

        observed_unknown = validate_rows(
            make_grid(evidence_mode="observed", status="unknown")
        )
        unknown_matrix = provider_evidence.build_matrix(
            observed_unknown, "tests/fixtures/provider-evidence/normalized.jsonl"
        )
        self.assertTrue(unknown_matrix["complete"])
        self.assertTrue(
            all(
                not provider["authoritative"]
                and provider["support"] == "attach_only_unknown"
                for provider in unknown_matrix["providers"]
            )
        )

    def test_analyzed_observed_authority_requires_every_cell_and_structured_source(
        self,
    ) -> None:
        source_fixture = "tests/fixtures/provider-evidence/normalized.jsonl"
        rows = validate_rows(make_grid(evidence_mode="observed"))
        with self.assertRaisesRegex(
            provider_evidence.EvidenceError,
            "observed semantics require an analyzer",
        ):
            provider_evidence.build_matrix(rows, source_fixture)
        matrix = provider_evidence.build_matrix(
            rows, source_fixture, semantics_analyzed=True
        )
        self.assertTrue(
            all(
                provider["authoritative"]
                and provider["support"] == "authoritative"
                for provider in matrix["providers"]
            )
        )

        for event_kind in EXPECTED_EVENT_KINDS:
            degraded = copy.deepcopy(rows)
            target = next(
                row
                for row in degraded
                if row["provider"] == "claude" and row["event_kind"] == event_kind
            )
            target["status"] = "unknown"
            with self.subTest(event_kind=event_kind):
                degraded_matrix = provider_evidence.build_matrix(
                    validate_rows(degraded),
                    source_fixture,
                    semantics_analyzed=True,
                )
                claude = next(
                    provider
                    for provider in degraded_matrix["providers"]
                    if provider["provider"] == "claude"
                )
                self.assertFalse(claude["authoritative"])
                self.assertEqual(claude["support"], "attach_only_unknown")

        inferred = copy.deepcopy(rows)
        for row in inferred:
            if row["provider"] == "claude":
                row["source_kind"] = "inferred"
                row["source_interface"] = "claude-inferred"
        inferred_matrix = provider_evidence.build_matrix(
            validate_rows(inferred), source_fixture, semantics_analyzed=True
        )
        claude = next(
            provider
            for provider in inferred_matrix["providers"]
            if provider["provider"] == "claude"
        )
        self.assertFalse(claude["authoritative"])
        self.assertEqual(claude["support"], "attach_only_unknown")

        mixed_source = copy.deepcopy(rows)
        mixed_source[0]["source_kind"] = "acp"
        mixed_source[0]["source_interface"] = "claude-acp"
        mixed_matrix = provider_evidence.build_matrix(
            validate_rows(mixed_source), source_fixture, semantics_analyzed=True
        )
        claude = next(
            provider
            for provider in mixed_matrix["providers"]
            if provider["provider"] == "claude"
        )
        self.assertFalse(claude["authoritative"])
        self.assertEqual(claude["support"], "attach_only_unknown")


class CheckArtifactTests(unittest.TestCase):
    def write_artifacts(
        self, directory: Path
    ) -> tuple[Path, Path, list[dict[str, Any]], dict[str, Any]]:
        rows = validate_rows(make_grid())
        fixture = directory / "synthetic.jsonl"
        matrix_path = directory / "provider-capabilities.json"
        fixture.write_bytes(provider_evidence.canonical_row_bytes(rows))
        matrix = provider_evidence.build_matrix(rows, SOURCE_FIXTURE)
        matrix_path.write_bytes(provider_evidence.matrix_bytes(matrix))
        return fixture, matrix_path, rows, matrix

    def test_check_accepts_valid_artifacts_and_leaves_tree_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            fixture, matrix_path, _, _ = self.write_artifacts(directory)
            before = tree_snapshot(directory)
            provider_evidence.check_artifacts(
                fixture, matrix_path, "synthetic", SOURCE_FIXTURE
            )
            self.assertEqual(tree_snapshot(directory), before)

    def test_declared_matrix_mode_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            matrix_path = Path(directory_name) / "provider-capabilities.json"
            matrix_path.write_bytes(b'{"evidence_mode":"observed"}\n')
            self.assertEqual(
                provider_evidence.declared_matrix_mode(matrix_path), "observed"
            )
            invalid_documents = (
                b"\xff\n",
                b"[]\n",
                b'{"evidence_mode":"private"}\n',
                b'{"evidence_mode":"synthetic","evidence_mode":"observed"}\n',
            )
            for document in invalid_documents:
                with self.subTest(document=document):
                    matrix_path.write_bytes(document)
                    with self.assertRaises(provider_evidence.EvidenceError):
                        provider_evidence.declared_matrix_mode(matrix_path)

    def test_executable_manifest_pins_exact_provider_binaries(self) -> None:
        path = ROOT / provider_evidence.EXECUTABLE_MANIFEST_PATH
        expected = provider_evidence.load_executable_manifest(path)
        self.assertEqual(
            expected,
            {
                "claude": "9f7c2260251765a18d0b35198669dacc1912f6e8129a3b01f6b58d93365ff1f1",
                "codex": "f0d8762236594359b60cfbe17f4c7e945a3ce8d1c91e74778838c968d250fb6c",
                "kimi": "92bf3b4b6643e7c4cc12c82e5680cc5b54a5a6768a301de815e5e9a02d2184bb",
            },
        )
        with tempfile.TemporaryDirectory() as directory_name:
            invalid_path = Path(directory_name) / "provider-executables.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["providers"][0]["executable_sha256"] = "0" * 64
            invalid_path.write_bytes(
                (
                    json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True)
                    + "\n"
                ).encode("utf-8")
            )
            with self.assertRaises(provider_evidence.EvidenceError):
                provider_evidence.load_executable_manifest(invalid_path)

    def test_check_rejects_fixture_matrix_summary_and_provenance_drift_without_healing(
        self,
    ) -> None:
        def noncanonical_fixture(
            fixture: Path, matrix_path: Path, matrix: dict[str, Any]
        ) -> None:
            lines = fixture.read_bytes().splitlines()
            fixture.write_bytes(b"\n".join(reversed(lines)) + b"\n")

        def noncanonical_matrix(
            fixture: Path, matrix_path: Path, matrix: dict[str, Any]
        ) -> None:
            matrix_path.write_text(json.dumps(matrix), encoding="utf-8")

        def summary_drift(
            fixture: Path, matrix_path: Path, matrix: dict[str, Any]
        ) -> None:
            matrix["human_summary"] += "drift\n"
            matrix_path.write_bytes(provider_evidence.matrix_bytes(matrix))

        def provenance_drift(
            fixture: Path, matrix_path: Path, matrix: dict[str, Any]
        ) -> None:
            matrix["source_fixture_sha256"] = "f" * 64
            without_summary = {
                key: value for key, value in matrix.items() if key != "human_summary"
            }
            matrix["human_summary"] = provider_evidence.render_summary(without_summary)
            matrix_path.write_bytes(provider_evidence.matrix_bytes(matrix))

        mutations = {
            "fixture-order": noncanonical_fixture,
            "matrix-bytes": noncanonical_matrix,
            "summary": summary_drift,
            "provenance": provenance_drift,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory_name:
                directory = Path(directory_name)
                fixture, matrix_path, _, matrix = self.write_artifacts(directory)
                mutate(fixture, matrix_path, matrix)
                before = tree_snapshot(directory)
                with self.assertRaises(provider_evidence.EvidenceError):
                    provider_evidence.check_artifacts(
                        fixture, matrix_path, "synthetic", SOURCE_FIXTURE
                    )
                self.assertEqual(tree_snapshot(directory), before)

    def test_check_rejects_mode_source_privacy_and_malformed_matrix_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            fixture, matrix_path, rows, _ = self.write_artifacts(directory)
            with self.assertRaises(provider_evidence.EvidenceError):
                provider_evidence.check_artifacts(
                    fixture, matrix_path, "observed", SOURCE_FIXTURE
                )
            with self.assertRaises(provider_evidence.EvidenceError):
                provider_evidence.check_artifacts(
                    fixture, matrix_path, "synthetic", "private/raw.jsonl"
                )

            canary = "CANARY_SECRET_TOKEN_765d45e1"
            private_row = copy.deepcopy(rows[0])
            private_row["prompt"] = canary
            fixture.write_bytes(
                (
                    json.dumps(
                        private_row,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8")
            )
            with self.assertRaises(provider_evidence.EvidenceError) as raised:
                provider_evidence.check_artifacts(
                    fixture, matrix_path, "synthetic", SOURCE_FIXTURE
                )
            self.assertNotIn(canary, str(raised.exception))

            fixture.write_bytes(provider_evidence.canonical_row_bytes(rows))
            matrix_path.write_bytes(b"\xff\n")
            with self.assertRaises(provider_evidence.EvidenceError):
                provider_evidence.check_artifacts(
                    fixture, matrix_path, "synthetic", SOURCE_FIXTURE
                )

    def test_main_maps_validation_failure_to_one_without_traceback(self) -> None:
        with mock.patch.object(
            provider_evidence,
            "check_artifacts",
            side_effect=provider_evidence.EvidenceError("safe validation failure"),
        ), contextlib.redirect_stderr(io.StringIO()) as stderr:
            result = provider_evidence.main(["--check"])
        self.assertEqual(result, 1)
        self.assertIn("safe validation failure", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_main_check_follows_the_committed_matrix_mode(self) -> None:
        with mock.patch.object(
            provider_evidence, "declared_matrix_mode", return_value="observed"
        ), mock.patch.object(
            provider_evidence, "check_artifacts"
        ) as check, contextlib.redirect_stdout(io.StringIO()):
            result = provider_evidence.main(["--check"])
        self.assertEqual(result, 0)
        fixture_path, matrix_path, evidence_mode, source_fixture = check.call_args.args
        self.assertEqual(evidence_mode, "observed")
        self.assertEqual(
            source_fixture,
            "tests/fixtures/provider-evidence/normalized.jsonl",
        )
        self.assertEqual(fixture_path.name, "normalized.jsonl")
        self.assertEqual(matrix_path.name, "provider-capabilities.json")

    def test_main_rejects_private_path_overrides(self) -> None:
        private_path = "/Users/alice/private/raw-capture.jsonl"
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as raised:
                provider_evidence.main(
                    ["--check", "--fixture", private_path, "--matrix", "other.json"]
                )
        self.assertEqual(raised.exception.code, 2)
        self.assertNotIn(private_path, stderr.getvalue())

    def test_check_subprocess_is_cwd_independent_and_does_not_write_artifacts(
        self,
    ) -> None:
        before = {
            str(path.relative_to(ROOT)): (
                stat.S_IMODE(path.stat().st_mode),
                path.stat().st_mtime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            for path in T7_ARTIFACTS
        }
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [sys.executable, "-I", "-S", str(SCRIPT_PATH), "--check"],
                cwd=directory,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                completed.stdout, "provider evidence check passed: 24 cells\n"
            )
            self.assertEqual(completed.stderr, "")

            invalid_commands = (
                ("--check", "--evidence-mode", "synthetic"),
                ("--check", "--capture-root", "/tmp/capture-root"),
                ("--write-matrix",),
                ("--write-observed",),
            )
            for arguments in invalid_commands:
                with self.subTest(arguments=arguments):
                    invalid = subprocess.run(
                        [sys.executable, "-I", "-S", str(SCRIPT_PATH), *arguments],
                        cwd=directory,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(invalid.returncode, 2)

        after = {
            str(path.relative_to(ROOT)): (
                stat.S_IMODE(path.stat().st_mode),
                path.stat().st_mtime_ns,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            for path in T7_ARTIFACTS
        }
        self.assertEqual(after, before)

    def test_provider_evidence_script_imports_only_standard_library_modules(self) -> None:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module.split(".", 1)[0])
        allowed = set(sys.stdlib_module_names) | {"__future__", "provider_capture"}
        self.assertEqual(imported - allowed, set())


class ObservedNormalizationTests(unittest.TestCase):
    def observed_fixture(
        self, base: Path, *, private_payload: bytes = b'{"synthetic":"probe"}\n'
    ) -> tuple[
        Path,
        list[dict[str, Any]],
        dict[str, dict[str, Any]],
        dict[str, str],
    ]:
        base = base.resolve()
        capture_root = base / "captures"
        executable_root = base / "executables"
        capture_root.mkdir(mode=0o700)
        executable_root.mkdir()
        receipts: dict[str, dict[str, Any]] = {}
        for provider in EXPECTED_PROVIDERS:
            executable = write_fake_provider(
                executable_root,
                provider,
                (
                    "sys.stdin.buffer.read()\n"
                    "os.write(1, b'{\"synthetic\":\"response\"}\\n')\n"
                ),
            )
            completed = run_collector(
                provider,
                capture_root,
                f"capture-{provider}-observed",
                executable,
                private_payload,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            receipts[provider] = read_receipt(
                capture_root, f"capture-{provider}-observed"
            )

        declarations = {
            "claude": ("native_hook", "claude-native-hook"),
            "codex": ("native_hook", "codex-app-server"),
            "kimi": ("acp", "kimi-acp"),
        }
        rows: list[dict[str, Any]] = []
        for provider in EXPECTED_PROVIDERS:
            source_kind, source_interface = declarations[provider]
            receipt = receipts[provider]
            for event_kind in EXPECTED_EVENT_KINDS:
                rows.append(
                    make_row(
                        provider,
                        event_kind,
                        evidence_mode="observed",
                        status="unknown",
                        provider_version=receipt["provider_version"],
                        source_kind=source_kind,
                        source_interface=source_interface,
                        source_capture_sha256=receipt["source_capture_sha256"],
                    )
                )
        executable_hashes = {
            provider: receipt["executable_sha256"]
            for provider, receipt in receipts.items()
        }
        return capture_root, rows, receipts, executable_hashes

    def test_normalization_canonicalizes_and_verifies_all_collector_sources(self) -> None:
        canary = b"PRIVATE_CAPTURE_CANARY_61f0"
        with tempfile.TemporaryDirectory() as directory_name:
            capture_root, rows, _receipts, executable_hashes = self.observed_fixture(
                Path(directory_name), private_payload=canary
            )
            candidate = b"".join(
                (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
                for row in reversed(rows)
            )
            normalized = provider_evidence.normalize_observed_bytes(
                candidate, capture_root, executable_hashes
            )
            self.assertEqual(
                normalized,
                provider_evidence.canonical_row_bytes(validate_rows(rows)),
            )
            self.assertNotIn(canary, normalized)
            matrix = provider_evidence.build_matrix(
                provider_evidence.load_rows_bytes(normalized, "observed"),
                "tests/fixtures/provider-evidence/normalized.jsonl",
            )
            self.assertEqual(matrix["present_cells"], 24)
            self.assertTrue(
                all(
                    provider["support"] == "attach_only_unknown"
                    for provider in matrix["providers"]
                )
            )
            self.assertEqual(
                [provider["sources"] for provider in matrix["providers"]],
                [
                    [{"interface": "claude-native-hook", "kind": "native_hook"}],
                    [{"interface": "codex-app-server", "kind": "native_hook"}],
                    [{"interface": "kimi-acp", "kind": "acp"}],
                ],
            )

    def test_normalization_rejects_raw_receipt_and_provenance_tampering_privately(
        self,
    ) -> None:
        canary = "PRIVATE_CAPTURE_CANARY_03c2"
        with tempfile.TemporaryDirectory() as directory_name:
            capture_root, rows, _receipts, executable_hashes = self.observed_fixture(
                Path(directory_name), private_payload=canary.encode()
            )
            candidate = provider_evidence.canonical_row_bytes(validate_rows(rows))
            capture_path = capture_root / "capture-claude-observed.capture"
            original_capture = capture_path.read_bytes()
            capture_path.write_bytes(original_capture[:-1] + b"X")
            with self.assertRaises(provider_evidence.EvidenceError) as raised:
                provider_evidence.normalize_observed_bytes(
                    candidate, capture_root, executable_hashes
                )
            self.assertNotIn(canary, str(raised.exception))
            capture_path.write_bytes(original_capture)
            capture_path.chmod(0o600)

            receipt_path = capture_root / "capture-codex-observed.receipt.json"
            original_receipt = receipt_path.read_bytes()
            receipt = json.loads(original_receipt)
            receipt["streams"]["stdout"]["sha256"] = hashlib.sha256(b"wrong").hexdigest()
            receipt_path.write_bytes(
                (
                    json.dumps(receipt, separators=(",", ":"), sort_keys=True) + "\n"
                ).encode("utf-8")
            )
            with self.assertRaises(provider_evidence.EvidenceError) as raised:
                provider_evidence.normalize_observed_bytes(
                    candidate, capture_root, executable_hashes
                )
            self.assertNotIn(canary, str(raised.exception))
            receipt_path.write_bytes(original_receipt)
            receipt_path.chmod(0o600)

            receipt = json.loads(original_receipt)
            receipt["executable_sha256"] = hashlib.sha256(b"lookalike").hexdigest()
            receipt_path.write_bytes(
                (
                    json.dumps(receipt, separators=(",", ":"), sort_keys=True) + "\n"
                ).encode("utf-8")
            )
            with self.assertRaises(provider_evidence.EvidenceError) as raised:
                provider_evidence.normalize_observed_bytes(
                    candidate, capture_root, executable_hashes
                )
            self.assertNotIn(canary, str(raised.exception))
            receipt_path.write_bytes(original_receipt)
            receipt_path.chmod(0o600)

            unbound = copy.deepcopy(rows)
            unbound[0]["source_capture_sha256"] = hashlib.sha256(b"unbound").hexdigest()
            with self.assertRaises(provider_evidence.EvidenceError) as raised:
                provider_evidence.normalize_observed_bytes(
                    provider_evidence.canonical_row_bytes(validate_rows(unbound)),
                    capture_root,
                    executable_hashes,
                )
            self.assertNotIn(canary, str(raised.exception))

    def test_normalization_maps_malformed_receipt_types_to_evidence_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            capture_root, rows, receipts, executable_hashes = self.observed_fixture(
                Path(directory_name)
            )
            candidate = provider_evidence.canonical_row_bytes(validate_rows(rows))
            receipt_path = capture_root / "capture-claude-observed.receipt.json"
            original = receipt_path.read_bytes()
            for key_path in (("capture_status",), ("termination", "reason")):
                receipt = copy.deepcopy(receipts["claude"])
                target = receipt
                for key in key_path[:-1]:
                    target = target[key]
                target[key_path[-1]] = []
                receipt_path.write_bytes(
                    (
                        json.dumps(receipt, separators=(",", ":"), sort_keys=True)
                        + "\n"
                    ).encode("utf-8")
                )
                with self.subTest(key_path=key_path), self.assertRaises(
                    provider_evidence.EvidenceError
                ):
                    provider_evidence.normalize_observed_bytes(
                        candidate, capture_root, executable_hashes
                    )
                receipt_path.write_bytes(original)
                receipt_path.chmod(0o600)

    def test_normalization_rejects_unsafe_capture_and_misclassified_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            capture_root, rows, _receipts, executable_hashes = self.observed_fixture(
                Path(directory_name)
            )
            candidate = provider_evidence.canonical_row_bytes(validate_rows(rows))
            capture_path = capture_root / "capture-kimi-observed.capture"
            capture_path.chmod(0o644)
            with self.assertRaises(provider_evidence.EvidenceError):
                provider_evidence.normalize_observed_bytes(
                    candidate, capture_root, executable_hashes
                )
            capture_path.chmod(0o600)

            misclassified = copy.deepcopy(rows)
            codex_row = next(row for row in misclassified if row["provider"] == "codex")
            codex_row["source_kind"] = "acp"
            with self.assertRaises(provider_evidence.EvidenceError):
                provider_evidence.normalize_observed_bytes(
                    provider_evidence.canonical_row_bytes(misclassified),
                    capture_root,
                    executable_hashes,
                )

    def test_normalization_rejects_unanalyzed_semantic_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            capture_root, rows, _receipts, executable_hashes = self.observed_fixture(
                Path(directory_name)
            )
            heartbeat = next(
                row
                for row in rows
                if row["provider"] == "claude" and row["event_kind"] == "heartbeat"
            )
            passing = copy.deepcopy(rows)
            passing_heartbeat = next(
                row
                for row in passing
                if row["provider"] == "claude" and row["event_kind"] == "heartbeat"
            )
            passing_heartbeat.update(
                {
                    "failure_behavior": "fail_closed",
                    "freshness_renews_on": "adapter_heartbeat",
                    "freshness_seconds": 60,
                    "latency_ms": [10],
                    "session_binding": "exact",
                    "status": "pass",
                    "task_binding": "exact",
                }
            )
            failed = copy.deepcopy(rows)
            failed[0]["status"] = "fail"
            ambiguous = copy.deepcopy(rows)
            ambiguous[rows.index(heartbeat)]["session_binding"] = "ambiguous"
            for candidate in (passing, failed, ambiguous):
                with self.assertRaisesRegex(
                    provider_evidence.EvidenceError,
                    "observed semantics require an analyzer",
                ):
                    provider_evidence.normalize_observed_bytes(
                        provider_evidence.canonical_row_bytes(candidate),
                        capture_root,
                        executable_hashes,
                    )


class ProviderCollectorTests(unittest.TestCase):
    def test_all_entrypoints_capture_fixed_binary_streams_without_repo_writes(
        self,
    ) -> None:
        before = tree_snapshot(ROOT)
        payload = b"input-\x00-\xff"
        command_source = (
            "if os.getcwd() != '/':\n"
            "    raise SystemExit(92)\n"
            "payload = sys.stdin.buffer.read()\n"
            "os.write(2, b'error-\\x00-\\xff')\n"
            "os.write(1, b'output-\\x00-')\n"
            "os.write(1, payload)\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            for provider in EXPECTED_PROVIDERS:
                with self.subTest(provider=provider):
                    capture_root = base / f"capture-{provider}"
                    capture_root.mkdir(mode=0o700)
                    executable = write_fake_provider(
                        base,
                        provider,
                        "" if provider == "claude" else command_source,
                    )
                    capture_id = f"capture-{provider}-roundtrip"
                    completed = run_collector(
                        provider,
                        capture_root,
                        capture_id,
                        executable,
                        payload,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    expected_stdout = (
                        b"" if provider == "claude" else b"output-\x00-" + payload
                    )
                    self.assertEqual(completed.stdout, expected_stdout)
                    self.assertEqual(completed.stderr, b"")
                    capture_path = capture_root / f"{capture_id}.capture"
                    receipt_path = capture_root / f"{capture_id}.receipt.json"
                    raw = capture_path.read_bytes()
                    receipt = read_receipt(capture_root, capture_id)
                    frames = list(
                        provider_capture.iter_capture_frames(io.BytesIO(raw))
                    )
                    streams = {
                        stream: b"".join(
                            frame_payload
                            for frame_stream, _observed_ns, frame_payload in frames
                            if frame_stream == stream
                        )
                        for stream in ("I", "O", "E")
                    }
                    self.assertEqual(streams["I"], payload)
                    self.assertEqual(
                        streams["O"], b"" if provider == "claude" else expected_stdout
                    )
                    self.assertEqual(
                        streams["E"],
                        b"" if provider == "claude" else b"error-\x00-\xff",
                    )
                    self.assertEqual(receipt["provider"], provider)
                    self.assertEqual(
                        receipt["source_interface"],
                        provider_capture.PROVIDER_SPECS[provider].source_interface,
                    )
                    self.assertEqual(receipt["capture_status"], "complete")
                    self.assertEqual(receipt["provider_outcome"], "unknown")
                    self.assertEqual(receipt["incomplete_reasons"], [])
                    self.assertIs(receipt["capture_present"], True)
                    self.assertEqual(
                        receipt["source_capture_sha256"], hashlib.sha256(raw).hexdigest()
                    )
                    self.assertEqual(receipt["frame_count"], len(frames))
                    self.assertEqual(stat.S_IMODE(capture_path.stat().st_mode), 0o600)
                    self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
                    self.assertFalse((capture_root / f"{capture_id}.receipt.tmp").exists())
                    receipt_bytes = receipt_path.read_bytes()
                    self.assertNotIn(str(capture_root).encode(), receipt_bytes)
                    self.assertNotIn(str(executable).encode(), receipt_bytes)
                    self.assertNotIn(payload, receipt_bytes)
        self.assertEqual(tree_snapshot(ROOT), before)
        self.assertFalse((ROOT / "scripts/__pycache__").exists())

    def test_provider_control_fd_emits_exact_private_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            read_descriptor, write_descriptor = os.pipe()
            spec = provider_capture.PROVIDER_SPECS["kimi"]
            executable = base / "fake-kimi-control"
            executable.write_text(
                (
                    "#!/usr/bin/env python3\n"
                    "import os\n"
                    "import sys\n"
                    f"control_descriptor = {write_descriptor}\n"
                    "try:\n"
                    "    os.fstat(control_descriptor)\n"
                    "except OSError:\n"
                    "    pass\n"
                    "else:\n"
                    "    raise SystemExit(96)\n"
                    f"version_output = {spec.version_outputs[0]!r}\n"
                    "if sys.argv[1:] == ['--version']:\n"
                    "    os.write(1, version_output)\n"
                    "    raise SystemExit(0)\n"
                    f"if sys.argv[1:] != {list(spec.command)!r}:\n"
                    "    raise SystemExit(91)\n"
                    "sys.stdin.buffer.read()\n"
                ),
                encoding="utf-8",
            )
            executable.chmod(0o755)
            try:
                completed = run_collector(
                    "kimi",
                    capture_root,
                    "capture-control-lifecycle",
                    executable,
                    provider_control_fd=write_descriptor,
                )
            finally:
                os.close(write_descriptor)
            chunks = bytearray()
            try:
                while True:
                    chunk = os.read(read_descriptor, 4096)
                    if not chunk:
                        break
                    chunks.extend(chunk)
            finally:
                os.close(read_descriptor)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(completed.stderr, b"")
            text = bytes(chunks).decode("ascii")
            records: list[tuple[str, int]] = []
            for line in text.splitlines(keepends=True):
                self.assertTrue(line.endswith("\n"))
                fields = line[:-1].split(" ")
                self.assertEqual(len(fields), 2)
                self.assertIn(fields[0], {"S", "E"})
                self.assertTrue(fields[1].isascii() and fields[1].isdigit())
                self.assertGreater(int(fields[1]), 0)
                records.append((fields[0], int(fields[1])))
            self.assertEqual([event for event, _pid in records], ["S", "E", "S", "E"])
            self.assertEqual(records[0][1], records[1][1])
            self.assertEqual(records[2][1], records[3][1])

    def test_provider_control_fd_validation_is_fail_closed(self) -> None:
        self.assertEqual(provider_capture.provider_control_fd("3"), 3)
        for value in ("0", "2", "-3", " 3", "٣"):
            with self.subTest(value=value):
                with self.assertRaises(provider_capture.argparse.ArgumentTypeError):
                    provider_capture.provider_control_fd(value)

        read_descriptor, write_descriptor = os.pipe()
        try:
            with self.assertRaisesRegex(
                provider_capture.CaptureError,
                "provider-control-fd-invalid",
            ):
                provider_capture._configure_provider_control_fd(read_descriptor)
            os.set_inheritable(write_descriptor, True)
            self.assertEqual(
                provider_capture._configure_provider_control_fd(write_descriptor),
                write_descriptor,
            )
            self.assertFalse(os.get_inheritable(write_descriptor))
        finally:
            os.close(read_descriptor)
            os.close(write_descriptor)

        with tempfile.TemporaryDirectory() as directory:
            regular_descriptor = os.open(
                Path(directory) / "regular",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                with self.assertRaisesRegex(
                    provider_capture.CaptureError,
                    "provider-control-fd-invalid",
                ):
                    provider_capture._configure_provider_control_fd(regular_descriptor)
            finally:
                os.close(regular_descriptor)

        closed_read, closed_descriptor = os.pipe()
        os.close(closed_descriptor)
        try:
            with self.assertRaisesRegex(
                provider_capture.CaptureError,
                "provider-control-fd-invalid",
            ):
                provider_capture._configure_provider_control_fd(closed_descriptor)
        finally:
            os.close(closed_read)

    def test_provider_control_write_failure_stops_before_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            executable = write_fake_provider(base, "kimi")
            read_descriptor, write_descriptor = os.pipe()
            os.close(read_descriptor)
            try:
                completed = run_collector(
                    "kimi",
                    capture_root,
                    "capture-control-write-failure",
                    executable,
                    provider_control_fd=write_descriptor,
                )
            finally:
                os.close(write_descriptor)
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(
                completed.stderr,
                b"collect_kimi_evidence: provider-control-write-failed\n",
            )
            self.assertFalse(
                (capture_root / "capture-control-write-failure.capture").exists()
            )
            self.assertFalse(
                (capture_root / "capture-control-write-failure.receipt.json").exists()
            )

    def test_root_rejection_precedes_executable_resolution_and_is_inode_based(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repository = base / "repository"
            git_dir = base / "git-dir"
            repository.mkdir()
            git_dir.mkdir()
            paths = provider_capture.RepositoryPaths(repository, git_dir)
            nested = repository / "private-capture"
            nested.mkdir(mode=0o700)
            ancestor = base / "ancestor"
            ancestor.mkdir(mode=0o700)
            nested_repository = ancestor / "nested-repository"
            nested_repository.mkdir()
            wrong_mode = base / "wrong-mode"
            wrong_mode.mkdir(mode=0o755)
            safe = base / "safe"
            safe.mkdir(mode=0o700)
            symlink = base / "safe-link"
            symlink.symlink_to(safe, target_is_directory=True)

            with self.assertRaises(provider_capture.CaptureError):
                provider_capture.validate_capture_root(nested, paths)
            with self.assertRaises(provider_capture.CaptureError):
                provider_capture.validate_capture_root(
                    ancestor,
                    provider_capture.RepositoryPaths(nested_repository, git_dir),
                )
            with self.assertRaises(provider_capture.CaptureError):
                provider_capture.validate_capture_root(wrong_mode, paths)
            with self.assertRaises(provider_capture.CaptureError):
                provider_capture.validate_capture_root(symlink, paths)

            with mock.patch.object(provider_capture, "resolve_executable") as resolver:
                with self.assertRaises(provider_capture.CaptureError):
                    provider_capture.collect(
                        provider_capture.PROVIDER_SPECS["claude"],
                        wrong_mode,
                        "capture-preflight",
                        4096,
                        8192,
                        1,
                        None,
                        io.BytesIO(b"private"),
                        io.BytesIO(),
                        paths,
                    )
            resolver.assert_not_called()
            self.assertEqual(tuple(wrong_mode.iterdir()), ())

            root = provider_capture.validate_capture_root(safe, paths)
            root.close()

            race = base / "race"
            race.mkdir(mode=0o700)

            def mutate_root(
                _spec: Any,
                _override: Any,
                _cwd: Any,
                _root: Any,
                _required_capture_bytes: Any,
            ) -> Any:
                race.chmod(0o755)
                return mock.sentinel.identity

            try:
                with mock.patch.object(
                    provider_capture,
                    "resolve_executable",
                    side_effect=mutate_root,
                ):
                    with self.assertRaises(provider_capture.CaptureError):
                        provider_capture.collect(
                            provider_capture.PROVIDER_SPECS["claude"],
                            race,
                            "capture-root-race",
                            4096,
                            8192,
                            1,
                            None,
                            io.BytesIO(b"private"),
                            io.BytesIO(),
                            paths,
                        )
            finally:
                race.chmod(0o700)
            self.assertFalse((race / "capture-root-race.capture").exists())
            self.assertFalse((race / "capture-root-race.receipt.json").exists())

    def test_root_moved_into_repository_rolls_back_private_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repository = base / "repository"
            git_dir = base / "git-dir"
            capture_root = base / "capture"
            repository.mkdir()
            git_dir.mkdir()
            capture_root.mkdir(mode=0o700)
            moved_root = repository / "moved-capture"
            executable = write_fake_provider(base, "claude")
            original_capture_stdin = provider_capture.capture_stdin

            def move_then_capture(*args: Any, **kwargs: Any) -> Any:
                capture_root.rename(moved_root)
                return original_capture_stdin(*args, **kwargs)

            with mock.patch.object(
                provider_capture,
                "capture_stdin",
                side_effect=move_then_capture,
            ):
                with self.assertRaisesRegex(
                    provider_capture.CaptureError,
                    "capture-root-changed",
                ):
                    provider_capture.collect(
                        provider_capture.PROVIDER_SPECS["claude"],
                        capture_root,
                        "capture-root-move",
                        4096,
                        8192,
                        1,
                        str(executable),
                        io.BytesIO(b"private-root-race"),
                        io.BytesIO(),
                        provider_capture.RepositoryPaths(repository, git_dir),
                    )
            self.assertFalse((moved_root / "capture-root-move.capture").exists())
            self.assertFalse(
                (moved_root / "capture-root-move.receipt.json").exists()
            )
            for path in moved_root.iterdir():
                if path.is_file():
                    self.assertNotIn(b"private-root-race", path.read_bytes())

    def test_budget_validation_and_fd_bound_free_space_boundaries(self) -> None:
        invalid = (
            (True, 2, 1),
            (0, 1, 1),
            (2, 1, 1),
            (1, 1, 0),
            (1, 1, provider_capture.MAX_TIMEOUT_SECONDS + 1),
            (provider_capture.MAX_BUDGET_BYTES + 1, provider_capture.MAX_BUDGET_BYTES + 1, 1),
        )
        for per_capture, aggregate, timeout in invalid:
            with self.subTest(
                per_capture=per_capture, aggregate=aggregate, timeout=timeout
            ):
                with self.assertRaises(provider_capture.CaptureError):
                    provider_capture.validate_request(
                        "capture-budget", per_capture, aggregate, timeout
                    )

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            repository = base / "repository"
            git_dir = base / "git"
            capture_root.mkdir(mode=0o700)
            repository.mkdir()
            git_dir.mkdir()
            root = provider_capture.validate_capture_root(
                capture_root,
                provider_capture.RepositoryPaths(repository, git_dir),
            )
            provider_capture._lock_root(root)
            limit = 4096
            one_short = mock.Mock(
                f_frsize=1,
                f_bsize=1,
                f_bavail=limit + provider_capture.MAX_RECEIPT_BYTES - 1,
            )
            with mock.patch.object(provider_capture.os, "fstatvfs", return_value=one_short):
                with self.assertRaises(provider_capture.CaptureError):
                    provider_capture.reserve_capture(
                        root, "capture-space-short", limit, limit * 2
                    )
            self.assertEqual(
                {path.name for path in capture_root.iterdir()},
                {".clilane-provider-capture.lock"},
            )
            exact = mock.Mock(
                f_frsize=1,
                f_bsize=1,
                f_bavail=limit + provider_capture.MAX_RECEIPT_BYTES,
            )
            with mock.patch.object(provider_capture.os, "fstatvfs", return_value=exact):
                descriptor, selected_limit, reasons = provider_capture.reserve_capture(
                    root, "capture-space-exact", limit, limit * 2
                )
            os.close(descriptor)
            self.assertEqual(selected_limit, limit)
            self.assertEqual(reasons, ("per_capture_budget",))
            root.close()

    def test_exact_and_overflow_caps_are_parseable_incomplete_unknown(self) -> None:
        payload = b"exact-cap-payload"
        limit = (
            len(provider_capture.CAPTURE_MAGIC)
            + provider_capture.FRAME_HEADER.size
            + len(payload)
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            executable = write_fake_provider(base, "claude")
            for suffix, selected_payload in (("exact", payload), ("over", payload + b"x")):
                with self.subTest(suffix=suffix):
                    capture_root = base / suffix
                    capture_root.mkdir(mode=0o700)
                    capture_id = f"capture-cap-{suffix}"
                    completed = run_collector(
                        "claude",
                        capture_root,
                        capture_id,
                        executable,
                        selected_payload,
                        per_capture_bytes=limit,
                        aggregate_bytes=limit + 1024,
                    )
                    self.assertEqual(completed.returncode, 3, completed.stderr)
                    raw = (capture_root / f"{capture_id}.capture").read_bytes()
                    receipt = read_receipt(capture_root, capture_id)
                    frames = list(
                        provider_capture.iter_capture_frames(io.BytesIO(raw))
                    )
                    self.assertEqual(len(raw), limit)
                    self.assertEqual(frames[0][2], payload)
                    self.assertEqual(receipt["capture_status"], "incomplete")
                    self.assertEqual(receipt["provider_outcome"], "unknown")
                    self.assertEqual(
                        receipt["incomplete_reasons"], ["per_capture_budget"]
                    )
                    self.assertEqual(
                        receipt["source_capture_sha256"], hashlib.sha256(raw).hexdigest()
                    )

    def test_subframe_and_exact_magic_budgets_have_explicit_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            executable = write_fake_provider(base, "claude")
            for limit in (1, len(provider_capture.CAPTURE_MAGIC) - 1):
                with self.subTest(limit=limit):
                    capture_root = base / f"capture-{limit}"
                    capture_root.mkdir(mode=0o700)
                    capture_id = f"capture-budget-{limit}"
                    completed = run_collector(
                        "claude",
                        capture_root,
                        capture_id,
                        executable,
                        b"private",
                        per_capture_bytes=limit,
                        aggregate_bytes=limit,
                    )
                    self.assertEqual(completed.returncode, 3, completed.stderr)
                    receipt = read_receipt(capture_root, capture_id)
                    self.assertIs(receipt["capture_present"], False)
                    self.assertIsNone(receipt["source_capture_sha256"])
                    self.assertEqual(
                        receipt["incomplete_reasons"],
                        ["per_capture_budget", "aggregate_budget"],
                    )
                    self.assertFalse(
                        (capture_root / f"{capture_id}.capture").exists()
                    )

            limit = len(provider_capture.CAPTURE_MAGIC)
            capture_root = base / "capture-magic"
            capture_root.mkdir(mode=0o700)
            capture_id = "capture-budget-magic"
            completed = run_collector(
                "claude",
                capture_root,
                capture_id,
                executable,
                b"private",
                per_capture_bytes=limit,
                aggregate_bytes=limit,
            )
            self.assertEqual(completed.returncode, 3, completed.stderr)
            raw = (capture_root / f"{capture_id}.capture").read_bytes()
            receipt = read_receipt(capture_root, capture_id)
            self.assertEqual(raw, provider_capture.CAPTURE_MAGIC)
            self.assertEqual(
                list(provider_capture.iter_capture_frames(io.BytesIO(raw))),
                [],
            )
            self.assertIs(receipt["capture_present"], True)
            self.assertEqual(
                receipt["source_capture_sha256"], hashlib.sha256(raw).hexdigest()
            )
            self.assertEqual(
                receipt["incomplete_reasons"],
                ["per_capture_budget", "aggregate_budget"],
            )

    def test_existing_capture_bytes_enforce_the_aggregate_cap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            existing = capture_root / "existing.capture"
            existing.write_bytes(b"x" * 80)
            existing.chmod(0o600)
            executable = write_fake_provider(base, "claude")
            completed = run_collector(
                "claude",
                capture_root,
                "capture-aggregate",
                executable,
                b"y" * 1024,
                per_capture_bytes=256,
                aggregate_bytes=296,
            )
            self.assertEqual(completed.returncode, 3, completed.stderr)
            receipt = read_receipt(capture_root, "capture-aggregate")
            self.assertEqual(receipt["budgets"]["capture_limit_bytes"], 216)
            self.assertEqual(receipt["incomplete_reasons"], ["aggregate_budget"])
            total = sum(path.stat().st_size for path in capture_root.glob("*.capture"))
            self.assertLessEqual(total, 296)

            exhausted = run_collector(
                "claude",
                capture_root,
                "capture-aggregate-exhausted",
                executable,
                b"private-payload",
                per_capture_bytes=256,
                aggregate_bytes=296,
            )
            self.assertEqual(exhausted.returncode, 3, exhausted.stderr)
            exhausted_receipt = read_receipt(
                capture_root, "capture-aggregate-exhausted"
            )
            self.assertIs(exhausted_receipt["capture_present"], False)
            self.assertIsNone(exhausted_receipt["source_capture_sha256"])
            self.assertEqual(exhausted_receipt["capture_bytes"], 0)
            self.assertEqual(
                exhausted_receipt["incomplete_reasons"], ["aggregate_budget"]
            )
            self.assertFalse(
                (capture_root / "capture-aggregate-exhausted.capture").exists()
            )

            external = base / "external-capture"
            external.write_bytes(b"external")
            external.chmod(0o600)
            os.link(external, capture_root / "linked.capture")
            rejected = run_collector(
                "claude",
                capture_root,
                "capture-linked-inventory",
                executable,
                b"private",
                per_capture_bytes=256,
                aggregate_bytes=1024,
            )
            self.assertEqual(rejected.returncode, 1)
            self.assertEqual(
                rejected.stderr,
                b"collect_claude_evidence: capture-inventory-unsafe\n",
            )
            self.assertEqual(external.read_bytes(), b"external")
            self.assertFalse(
                (capture_root / "capture-linked-inventory.capture").exists()
            )

    def test_provider_failure_remains_complete_evidence_with_unknown_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            executable = write_fake_provider(base, "kimi", "raise SystemExit(7)\n")
            completed = run_collector(
                "kimi", capture_root, "capture-provider-failure", executable
            )
            self.assertEqual(completed.returncode, 4, completed.stderr)
            receipt = read_receipt(capture_root, "capture-provider-failure")
            self.assertEqual(receipt["capture_status"], "complete")
            self.assertEqual(receipt["provider_outcome"], "unknown")
            self.assertEqual(receipt["termination"]["reason"], "provider_exit")
            self.assertEqual(receipt["termination"]["exit_code"], 7)

    def test_timeout_kills_descendant_after_leader_exit_and_commits_receipt(self) -> None:
        command_source = (
            "child = os.fork()\n"
            "if child == 0:\n"
            "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "    time.sleep(30)\n"
            "    os._exit(0)\n"
            "os.write(1, str(child).encode('ascii') + b'\\n')\n"
            "os._exit(0)\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            executable = write_fake_provider(base, "codex", command_source)
            started = time.monotonic()
            completed = run_collector(
                "codex",
                capture_root,
                "capture-descendant-timeout",
                executable,
                timeout_seconds=1,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(completed.returncode, 3, completed.stderr)
            self.assertLess(elapsed, 6)
            descendant = int(completed.stdout.strip())
            try:
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    try:
                        os.kill(descendant, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.02)
                else:
                    self.fail("provider descendant survived bounded cleanup")
            finally:
                try:
                    os.kill(descendant, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            receipt = read_receipt(capture_root, "capture-descendant-timeout")
            self.assertEqual(receipt["capture_status"], "incomplete")
            self.assertEqual(receipt["incomplete_reasons"], ["timeout"])
            self.assertEqual(receipt["termination"]["reason"], "timeout")

    def test_nonreading_provider_cannot_block_stdin_past_timeout(self) -> None:
        command_source = (
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "os.write(1, str(os.getpid()).encode('ascii') + b'\\n')\n"
            "time.sleep(30)\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            executable = write_fake_provider(base, "kimi", command_source)
            started = time.monotonic()
            completed = run_collector(
                "kimi",
                capture_root,
                "capture-nonreading-stdin",
                executable,
                b"x" * (1 << 20),
                per_capture_bytes=2 << 20,
                aggregate_bytes=3 << 20,
                timeout_seconds=1,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(completed.returncode, 3, completed.stderr)
            self.assertLess(elapsed, 6)
            provider_pid = int(completed.stdout.strip())
            try:
                os.kill(provider_pid, 0)
            except ProcessLookupError:
                pass
            else:
                try:
                    os.kill(provider_pid, signal.SIGKILL)
                finally:
                    self.fail("non-reading provider survived bounded cleanup")
            receipt = read_receipt(capture_root, "capture-nonreading-stdin")
            self.assertEqual(receipt["capture_status"], "incomplete")
            self.assertEqual(receipt["termination"]["reason"], "timeout")

    def test_clean_stdio_does_not_hide_a_live_provider_descendant(self) -> None:
        command_source = (
            "child = os.fork()\n"
            "if child == 0:\n"
            "    os.close(0)\n"
            "    os.close(1)\n"
            "    os.close(2)\n"
            "    time.sleep(30)\n"
            "    os._exit(0)\n"
            "os.write(1, str(child).encode('ascii') + b'\\n')\n"
            "os._exit(0)\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            executable = write_fake_provider(base, "kimi", command_source)
            completed = run_collector(
                "kimi", capture_root, "capture-hidden-descendant", executable
            )
            self.assertEqual(completed.returncode, 3, completed.stderr)
            descendant = int(completed.stdout.strip())
            try:
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    try:
                        os.kill(descendant, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.02)
                else:
                    self.fail("provider descendant survived clean-stdio cleanup")
            finally:
                try:
                    os.kill(descendant, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            receipt = read_receipt(capture_root, "capture-hidden-descendant")
            self.assertEqual(receipt["capture_status"], "incomplete")
            self.assertEqual(
                receipt["incomplete_reasons"], ["descendant_process"]
            )
            self.assertEqual(
                receipt["termination"]["reason"], "descendant_process"
            )

    def test_version_descendant_is_killed_before_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            marker = base / "version-child-pid"
            executable = base / "fake-kimi-version-child"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import os\n"
                "import sys\n"
                "import time\n"
                "if sys.argv[1:] == ['--version']:\n"
                "    child = os.fork()\n"
                "    if child == 0:\n"
                "        os.close(0)\n"
                "        os.close(1)\n"
                "        os.close(2)\n"
                "        time.sleep(30)\n"
                "        os._exit(0)\n"
                f"    with open({str(marker)!r}, 'w', encoding='ascii') as output:\n"
                "        output.write(str(child))\n"
                "    os.write(1, b'0.38.0\\n')\n"
                "    os._exit(0)\n"
                "raise SystemExit(91)\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            completed = run_collector(
                "kimi", capture_root, "capture-version-descendant", executable
            )
            self.assertEqual(completed.returncode, 1)
            descendant = int(marker.read_text(encoding="ascii"))
            try:
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    try:
                        os.kill(descendant, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.02)
                else:
                    self.fail("version descendant survived cleanup")
            finally:
                try:
                    os.kill(descendant, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.assertFalse((capture_root / "capture-version-descendant.capture").exists())
            self.assertFalse(
                (capture_root / "capture-version-descendant.receipt.json").exists()
            )

    def test_external_signal_commits_incomplete_receipt_and_releases_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            ready = base / "provider-ready"
            executable = write_fake_provider(
                base,
                "kimi",
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                f"with open({str(ready)!r}, 'w', encoding='ascii') as output:\n"
                "    output.write(str(os.getpid()))\n"
                "time.sleep(30)\n",
            )
            command = [
                sys.executable,
                "-B",
                str(COLLECTOR_SCRIPTS["kimi"]),
                "--capture-root",
                str(capture_root),
                "--capture-id",
                "capture-signal",
                "--per-capture-bytes",
                str(1 << 20),
                "--aggregate-bytes",
                str(1 << 21),
                "--timeout-seconds",
                "20",
                "--provider-executable",
                str(executable),
            ]
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            if process.stdin is None:
                self.fail("collector stdin was not created")
            process.stdin.close()
            process.stdin = None
            try:
                deadline = time.monotonic() + 5
                while not ready.exists():
                    if time.monotonic() >= deadline:
                        self.fail("provider did not reach its ready handshake")
                    time.sleep(0.01)
                provider_pid = int(ready.read_text(encoding="ascii"))
                started = time.monotonic()
                process.send_signal(signal.SIGTERM)
                time.sleep(0.05)
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=8)
                elapsed = time.monotonic() - started
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
            self.assertEqual(process.returncode, 128 + signal.SIGTERM, stderr)
            self.assertEqual(stdout, b"")
            self.assertLess(elapsed, 4)
            receipt = read_receipt(capture_root, "capture-signal")
            self.assertEqual(receipt["capture_status"], "incomplete")
            self.assertEqual(receipt["incomplete_reasons"], ["collector_signal"])
            self.assertEqual(
                receipt["termination"]["collector_signal"], signal.SIGTERM
            )
            try:
                os.kill(provider_pid, 0)
            except ProcessLookupError:
                pass
            else:
                try:
                    os.kill(provider_pid, signal.SIGKILL)
                finally:
                    self.fail("provider survived double-signal cleanup")
            self.assertFalse(
                (capture_root / "capture-signal.receipt.tmp").exists()
            )

            replacement = write_fake_provider(
                base, "kimi", "sys.stdin.buffer.read()\n"
            )
            resumed = run_collector(
                "kimi", capture_root, "capture-after-signal", replacement
            )
            self.assertEqual(resumed.returncode, 0, resumed.stderr)

    def test_signals_at_capture_start_and_finalize_still_commit_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repository = base / "repository"
            git_dir = base / "git-dir"
            repository.mkdir()
            git_dir.mkdir()
            paths = provider_capture.RepositoryPaths(repository, git_dir)
            executable = write_fake_provider(base, "claude")
            original_start = provider_capture.CaptureWriter.start
            original_finish = provider_capture.CaptureWriter.finish

            def signal_after_start(writer: Any) -> Any:
                original_start(writer)
                raise provider_capture.CollectorSignal(signal.SIGTERM)

            def signal_after_finish(writer: Any) -> Any:
                result = original_finish(writer)
                raise provider_capture.CollectorSignal(signal.SIGTERM)

            for suffix, target, replacement in (
                ("start", "start", signal_after_start),
                ("finish", "finish", signal_after_finish),
            ):
                with self.subTest(suffix=suffix):
                    capture_root = base / suffix
                    capture_root.mkdir(mode=0o700)
                    capture_id = f"capture-signal-{suffix}-window"
                    with mock.patch.object(
                        provider_capture.CaptureWriter,
                        target,
                        replacement,
                    ):
                        result = provider_capture.collect(
                            provider_capture.PROVIDER_SPECS["claude"],
                            capture_root,
                            capture_id,
                            4096,
                            8192,
                            1,
                            str(executable),
                            io.BytesIO(b"private"),
                            io.BytesIO(),
                            paths,
                        )
                    self.assertEqual(result.exit_status, 128 + signal.SIGTERM)
                    receipt = read_receipt(capture_root, capture_id)
                    self.assertEqual(receipt["capture_status"], "incomplete")
                    self.assertEqual(
                        receipt["incomplete_reasons"], ["collector_signal"]
                    )
                    self.assertEqual(
                        receipt["termination"]["collector_signal"], signal.SIGTERM
                    )
                    raw = (capture_root / f"{capture_id}.capture").read_bytes()
                    list(provider_capture.iter_capture_frames(io.BytesIO(raw)))

    def test_executable_change_is_fail_closed_but_receipted(self) -> None:
        command_source = (
            "os.chmod(os.path.dirname(sys.argv[0]), 0o700)\n"
            "os.chmod(sys.argv[0], 0o700)\n"
            "with open(sys.argv[0], 'ab') as executable:\n"
            "    executable.write(b'\\n')\n"
            "os.write(1, b'changed')\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            executable = write_fake_provider(base, "kimi", command_source)
            completed = run_collector(
                "kimi", capture_root, "capture-executable-change", executable
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual(completed.stdout, b"changed")
            receipt = read_receipt(capture_root, "capture-executable-change")
            self.assertEqual(receipt["capture_status"], "incomplete")
            self.assertEqual(receipt["incomplete_reasons"], ["executable_changed"])
            self.assertEqual(receipt["provider_outcome"], "unknown")

    def test_command_executes_the_verified_private_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            repository = base / "repository"
            git_dir = base / "git-dir"
            capture_root = base / "capture"
            repository.mkdir()
            git_dir.mkdir()
            capture_root.mkdir(mode=0o700)
            executable = write_fake_provider(
                base,
                "kimi",
                "os.write(1, b'SNAPSHOT_GOOD')\n",
            )
            original_popen = provider_capture.subprocess.Popen
            staged_paths: list[Path] = []

            def replace_original_at_launch(
                command: Any,
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                selected = list(command)
                if selected[1:] == ["acp"]:
                    staged_path = Path(selected[0])
                    staged_paths.append(staged_path)
                    self.assertNotEqual(staged_path, executable)
                    self.assertEqual(staged_path.parents[1], capture_root)
                    with self.assertRaises(PermissionError):
                        staged_path.unlink()
                    metadata = executable.stat()
                    raw = executable.read_bytes()
                    replacement = raw.replace(b"SNAPSHOT_GOOD", b"SNAPSHOT_EVIL")
                    self.assertEqual(len(replacement), len(raw))
                    executable.write_bytes(replacement)
                    executable.chmod(0o755)
                    os.utime(
                        executable,
                        ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
                    )
                return original_popen(command, *args, **kwargs)

            with mock.patch.object(
                provider_capture.subprocess,
                "Popen",
                replace_original_at_launch,
            ):
                with tempfile.TemporaryFile() as source:
                    result = provider_capture.collect(
                        provider_capture.PROVIDER_SPECS["kimi"],
                        capture_root,
                        "capture-staged-executable",
                        4096,
                        8192,
                        2,
                        str(executable),
                        source,
                        io.BytesIO(),
                        provider_capture.RepositoryPaths(repository, git_dir),
                    )
            self.assertEqual(result.exit_status, 0)
            self.assertEqual(len(staged_paths), 1)
            raw_capture = (
                capture_root / "capture-staged-executable.capture"
            ).read_bytes()
            frames = list(
                provider_capture.iter_capture_frames(io.BytesIO(raw_capture))
            )
            stdout = b"".join(
                payload for stream, _observed_ns, payload in frames if stream == "O"
            )
            self.assertEqual(stdout, b"SNAPSHOT_GOOD")
            self.assertFalse(staged_paths[0].exists())
            self.assertFalse(
                any(
                    path.name.startswith(".clilane-provider-stage-")
                    for path in capture_root.iterdir()
                )
            )

    def test_version_same_size_rewrite_with_restored_mtime_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            executable = base / "fake-kimi-version-rewrite"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import os\n"
                "import sys\n"
                "if sys.argv[1:] == ['--version']:\n"
                "    directory = os.path.dirname(sys.argv[0])\n"
                "    os.chmod(directory, 0o700)\n"
                "    os.chmod(sys.argv[0], 0o700)\n"
                "    metadata = os.stat(sys.argv[0])\n"
                "    with open(sys.argv[0], 'r+b') as target:\n"
                "        raw = target.read()\n"
                "        target.seek(0)\n"
                "        target.write(raw.replace(b'ORIGINAL_A', b'MUTATED__A'))\n"
                "        target.truncate()\n"
                "    os.utime(\n"
                "        sys.argv[0],\n"
                "        ns=(metadata.st_atime_ns, metadata.st_mtime_ns),\n"
                "    )\n"
                "    os.chmod(sys.argv[0], 0o500)\n"
                "    os.chmod(directory, 0o500)\n"
                "    os.write(1, b'0.38.0\\n')\n"
                "    raise SystemExit(0)\n"
                "marker = b'ORIGINAL_A'\n"
                "raise SystemExit(91)\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            completed = run_collector(
                "kimi",
                capture_root,
                "capture-version-rewrite",
                executable,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertEqual(
                completed.stderr,
                b"collect_kimi_evidence: provider-executable-changed\n",
            )
            self.assertFalse(
                (capture_root / "capture-version-rewrite.capture").exists()
            )
            self.assertFalse(
                (capture_root / "capture-version-rewrite.receipt.json").exists()
            )

    def test_signal_at_stage_ownership_transfer_cleans_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            repository = base / "repository"
            git_dir = base / "git-dir"
            capture_root.mkdir(mode=0o700)
            repository.mkdir()
            git_dir.mkdir()
            executable = write_fake_provider(base, "kimi")
            root = provider_capture.validate_capture_root(
                capture_root,
                provider_capture.RepositoryPaths(repository, git_dir),
            )
            provider_capture._lock_root(root)
            original_stage = provider_capture._stage_executable
            original_cleanup = provider_capture._cleanup_executable
            previous_signal_state = provider_capture.ACTIVE_SIGNAL_STATE
            previous_signal_handler = signal.getsignal(signal.SIGTERM)
            cleanup_calls = 0

            def interrupt(number: int, _frame: Any) -> None:
                state = provider_capture.ACTIVE_SIGNAL_STATE
                if state is not None and state.depth > 0:
                    if state.pending is None:
                        state.pending = number
                    return
                raise provider_capture.CollectorSignal(number)

            def stage_then_signal(*args: Any, **kwargs: Any) -> Any:
                identity = original_stage(*args, **kwargs)
                signal.raise_signal(signal.SIGTERM)
                return identity

            def cleanup_during_second_signal(*args: Any, **kwargs: Any) -> Any:
                nonlocal cleanup_calls
                cleanup_calls += 1
                signal.raise_signal(signal.SIGTERM)
                return original_cleanup(*args, **kwargs)

            provider_capture.ACTIVE_SIGNAL_STATE = provider_capture.SignalState()
            signal.signal(signal.SIGTERM, interrupt)
            try:
                with mock.patch.object(
                    provider_capture,
                    "_stage_executable",
                    side_effect=stage_then_signal,
                ), mock.patch.object(
                    provider_capture,
                    "_cleanup_executable",
                    side_effect=cleanup_during_second_signal,
                ):
                    with self.assertRaises(provider_capture.CollectorSignal):
                        provider_capture.resolve_executable(
                            provider_capture.PROVIDER_SPECS["kimi"],
                            str(executable),
                            provider_capture.PROVIDER_COMMAND_CWD,
                            root,
                            4096,
                        )
            finally:
                signal.signal(signal.SIGTERM, previous_signal_handler)
                provider_capture.ACTIVE_SIGNAL_STATE = previous_signal_state
                root.close()
            self.assertEqual(cleanup_calls, 1)
            self.assertFalse(
                any(
                    path.name.startswith(".clilane-provider-stage-")
                    for path in capture_root.iterdir()
                )
            )

    def test_receipt_publication_is_atomic_and_no_clobber(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            repository = base / "repository"
            git_dir = base / "git"
            capture_root.mkdir(mode=0o700)
            repository.mkdir()
            git_dir.mkdir()
            root = provider_capture.validate_capture_root(
                capture_root,
                provider_capture.RepositoryPaths(repository, git_dir),
            )
            with mock.patch.object(provider_capture.os, "link", side_effect=OSError):
                with self.assertRaises(provider_capture.CaptureError):
                    provider_capture._write_receipt(
                        root, "capture-atomic", {"schema_version": 1}
                    )
            self.assertFalse((capture_root / "capture-atomic.receipt.json").exists())
            self.assertFalse((capture_root / "capture-atomic.receipt.tmp").exists())

            original_fsync = os.fsync
            fsync_calls = 0

            def fail_directory_fsync(descriptor: int) -> None:
                nonlocal fsync_calls
                fsync_calls += 1
                if fsync_calls == 2:
                    raise OSError
                original_fsync(descriptor)

            with mock.patch.object(provider_capture.os, "fsync", fail_directory_fsync):
                with self.assertRaises(provider_capture.CaptureError):
                    provider_capture._write_receipt(
                        root, "capture-fsync-failure", {"schema_version": 1}
                    )
            self.assertFalse(
                (capture_root / "capture-fsync-failure.receipt.json").exists()
            )
            self.assertFalse(
                (capture_root / "capture-fsync-failure.receipt.tmp").exists()
            )

            original_link = os.link

            def replace_temporary_before_link(
                source: str,
                destination: str,
                **kwargs: Any,
            ) -> None:
                source_dir_fd = kwargs["src_dir_fd"]
                os.unlink(source, dir_fd=source_dir_fd)
                replacement = os.open(
                    source,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=source_dir_fd,
                )
                try:
                    os.write(replacement, b'{"forged":true}\n')
                    os.fsync(replacement)
                finally:
                    os.close(replacement)
                original_link(source, destination, **kwargs)

            with mock.patch.object(
                provider_capture.os,
                "link",
                replace_temporary_before_link,
            ):
                with self.assertRaises(provider_capture.CaptureError):
                    provider_capture._write_receipt(
                        root,
                        "capture-replaced-temp",
                        {"schema_version": 1},
                    )
            self.assertFalse(
                (capture_root / "capture-replaced-temp.receipt.json").exists()
            )
            self.assertFalse(
                (capture_root / "capture-replaced-temp.receipt.tmp").exists()
            )

            link_calls = 0

            def signal_once(*args: Any, **kwargs: Any) -> None:
                nonlocal link_calls
                link_calls += 1
                if link_calls == 1:
                    raise provider_capture.CollectorSignal(signal.SIGTERM)
                original_link(*args, **kwargs)

            with mock.patch.object(provider_capture.os, "link", signal_once):
                with self.assertRaises(provider_capture.CollectorSignal):
                    provider_capture._write_receipt(
                        root, "capture-signal-commit", {"schema_version": 1}
                    )
            self.assertTrue(
                (capture_root / "capture-signal-commit.receipt.json").exists()
            )
            self.assertFalse(
                (capture_root / "capture-signal-commit.receipt.tmp").exists()
            )

            provider_capture._write_receipt(
                root, "capture-atomic", {"schema_version": 1}
            )
            with self.assertRaises(provider_capture.CaptureError):
                provider_capture._write_receipt(
                    root, "capture-atomic", {"schema_version": 2}
                )
            self.assertEqual(
                json.loads(
                    (capture_root / "capture-atomic.receipt.json").read_text(
                        encoding="utf-8"
                    )
                ),
                {"schema_version": 1},
            )
            root.close()

    def test_root_lock_rejects_a_concurrent_collector(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            executable = write_fake_provider(
                base,
                "kimi",
                "sys.stdin.buffer.read()\ntime.sleep(1.5)\nos.write(1, b'done')\n",
            )
            common = [
                sys.executable,
                "-B",
                str(COLLECTOR_SCRIPTS["kimi"]),
                "--capture-root",
                str(capture_root),
                "--per-capture-bytes",
                str(1 << 20),
                "--aggregate-bytes",
                str(1 << 21),
                "--timeout-seconds",
                "5",
                "--provider-executable",
                str(executable),
            ]
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            first = subprocess.Popen(
                [*common, "--capture-id", "capture-lock-first"],
                cwd=ROOT,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            if first.stdin is None:
                self.fail("first collector stdin was not created")
            first.stdin.close()
            first.stdin = None
            try:
                deadline = time.monotonic() + 5
                while not (capture_root / "capture-lock-first.capture").exists():
                    if time.monotonic() >= deadline:
                        self.fail("first collector did not reserve its capture")
                    time.sleep(0.01)
                second = subprocess.run(
                    [*common, "--capture-id", "capture-lock-second"],
                    cwd=ROOT,
                    input=b"",
                    capture_output=True,
                    check=False,
                    env=environment,
                    timeout=5,
                )
                first_stdout, first_stderr = first.communicate(timeout=10)
            finally:
                if first.poll() is None:
                    first.terminate()
                    first.wait(timeout=5)
            self.assertEqual(second.returncode, 1)
            self.assertEqual(
                second.stderr, b"collect_kimi_evidence: capture-root-busy\n"
            )
            self.assertFalse((capture_root / "capture-lock-second.capture").exists())
            self.assertEqual(first.returncode, 0, first_stderr)
            self.assertEqual(first_stdout, b"done")

    def test_version_privacy_and_cli_surface_fail_closed(self) -> None:
        canary = b"private-version-canary"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            capture_root = base / "capture"
            capture_root.mkdir(mode=0o700)
            executable = write_fake_provider(
                base,
                "kimi",
                version_output=b"0.38.0\n" + canary + b"\n",
            )
            completed = run_collector(
                "kimi", capture_root, "capture-private-version", executable
            )
            self.assertEqual(completed.returncode, 1)
            self.assertNotIn(canary, completed.stderr)
            self.assertNotIn(str(executable).encode(), completed.stderr)
            self.assertEqual(
                {path.name for path in capture_root.iterdir()},
                {".clilane-provider-capture.lock"},
            )

            invalid = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(COLLECTOR_SCRIPTS["kimi"]),
                    "--source-interface",
                    "private-canary",
                ],
                cwd=ROOT,
                capture_output=True,
                check=False,
            )
            self.assertEqual(invalid.returncode, 2)
            self.assertNotIn(b"private-canary", invalid.stderr)

    def test_codex_launcher_resolution_pins_the_packaged_native_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            launcher = base / "package/bin/codex.js"
            launcher.parent.mkdir(parents=True)
            launcher.write_text("#!/usr/bin/env node\n", encoding="utf-8")
            native = (
                base
                / "package/node_modules/@openai/codex-darwin-arm64"
                / "vendor/aarch64-apple-darwin/bin/codex"
            )
            native.parent.mkdir(parents=True)
            native.write_bytes(b"native")
            with mock.patch.object(provider_capture.platform, "system", return_value="Darwin"):
                with mock.patch.object(
                    provider_capture.platform, "machine", return_value="arm64"
                ):
                    self.assertEqual(provider_capture._codex_native_path(launcher), native)

    def test_collector_engine_uses_only_standard_library_modules(self) -> None:
        tree = ast.parse(CAPTURE_ENGINE_PATH.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module.split(".", 1)[0])
        allowed = set(sys.stdlib_module_names) | {"__future__"}
        self.assertEqual(imported - allowed, set())


if __name__ == "__main__":
    unittest.main()
