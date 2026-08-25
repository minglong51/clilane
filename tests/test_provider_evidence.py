from __future__ import annotations

import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts/provider_evidence.py"
SPEC = importlib.util.spec_from_file_location("provider_evidence", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT_PATH}")
provider_evidence = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = provider_evidence
SPEC.loader.exec_module(provider_evidence)

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
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        metadata = path.stat()
        result[str(path.relative_to(root))] = (
            stat.S_IMODE(metadata.st_mode),
            metadata.st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest(),
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

    def test_observed_authority_requires_every_cell_and_structured_source(self) -> None:
        source_fixture = "tests/fixtures/provider-evidence/normalized.jsonl"
        rows = validate_rows(make_grid(evidence_mode="observed"))
        matrix = provider_evidence.build_matrix(rows, source_fixture)
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
                    validate_rows(degraded), source_fixture
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
            validate_rows(inferred), source_fixture
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
            validate_rows(mixed_source), source_fixture
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
                ("--write-matrix",),
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
        allowed = set(sys.stdlib_module_names) | {"__future__"}
        self.assertEqual(imported - allowed, set())


if __name__ == "__main__":
    unittest.main()
