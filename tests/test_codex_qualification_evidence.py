from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
try:
    import codex_qualification_evidence as evidence
finally:
    sys.path.pop(0)


def encoded(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class QualificationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = (ROOT / evidence.FIXTURE_PATH).read_bytes()
        self.value = json.loads(self.raw)

    def reject(self, value: Any) -> None:
        with self.assertRaises((evidence.EvidenceError, evidence.codex_replay.ReplayError,
                                evidence.qualification.ProbeError)):
            evidence.validate_evidence(encoded(value))

    def test_complete_package_preserves_replay_and_runtime_unknowns(self) -> None:
        value = evidence.validate_evidence(self.raw)
        self.assertEqual(value["runtime_support"], "attach_only_unknown")
        self.assertEqual(len(value["capabilities"]), 8)
        self.assertEqual({row["scenario"] for row in value["scenarios"]},
                         {"input", "permissions", "command", "file"})
        for record in value["scenarios"]:
            self.assertEqual(record["replay"]["qualification"], "unqualified")
            self.assertEqual(record["replay"]["task_binding"], "unknown")
            self.assertEqual(record["replay"]["source_health"], "unknown")

    def test_scenario_order_does_not_change_canonical_bytes(self) -> None:
        self.assertEqual(evidence.canonical_evidence(list(reversed(self.value["scenarios"]))),
                         self.raw)

    def test_missing_duplicate_and_extra_scenarios_rejected(self) -> None:
        for records in (self.value["scenarios"][:-1], self.value["scenarios"] * 2,
                        [self.value["scenarios"][0]] * 4):
            with self.subTest(count=len(records)):
                self.reject({**self.value, "scenarios": records})

    def test_claiming_live_authority_or_changing_capability_claims_rejected(self) -> None:
        for key, value in (("runtime_support", "authoritative"), ("evidence_complete", False),
                           ("scope", "production")):
            self.reject({**self.value, key: value})
        for key, value in (("task_binding", "exact"), ("source_health", "healthy"),
                           ("qualification", "qualified")):
            changed = copy.deepcopy(self.value)
            changed["scenarios"][0]["replay"][key] = value
            self.reject(changed)
        changed = copy.deepcopy(self.value)
        changed["capabilities"][0]["scenarios"] = ["permissions"]
        self.reject(changed)

    def test_missing_failed_numeric_and_unknown_checks_rejected(self) -> None:
        for kind in ("missing", "false", "numeric", "extra"):
            changed = copy.deepcopy(self.value)
            checks = changed["scenarios"][0]["proof"]["checks"]
            if kind == "missing":
                del checks["recurring_heartbeat_renewed"]
            elif kind == "extra":
                checks["unreviewed_claim"] = True
            else:
                checks["recurring_heartbeat_renewed"] = False if kind == "false" else 1
            with self.subTest(kind=kind):
                self.reject(changed)

    def test_stale_harness_binary_and_provider_version_rejected(self) -> None:
        for key, value in (("harness_sha256", "c" * 64), ("executable_sha256", "d" * 64),
                           ("provider_version", "0.162.1")):
            changed = copy.deepcopy(self.value)
            changed["scenarios"][0]["proof"][key] = value
            self.reject(changed)
        with mock.patch.object(evidence.qualification, "evidence_source_sha256", return_value="e" * 64):
            self.reject(self.value)

    def test_reused_or_mismatched_capture_and_journal_rejected(self) -> None:
        changed = copy.deepcopy(self.value)
        changed["scenarios"][0]["proof"]["source_capture_sha256"] = "abcdef01" * 8
        self.reject(changed)
        for key in ("source_capture_sha256", "observer_journal_sha256"):
            changed = copy.deepcopy(self.value)
            first, second = changed["scenarios"][:2]
            second["proof"][key] = first["proof"][key]
            if key == "source_capture_sha256":
                second["replay"][key] = first["replay"][key]
            self.reject(changed)

    def test_missing_unbounded_noninteger_and_unsorted_latencies_rejected(self) -> None:
        for samples in ([], [0], [-1], [True], [1.5], [300001], [2, 1]):
            changed = copy.deepcopy(self.value)
            changed["scenarios"][0]["proof"]["measurements"]["source_to_observer_ms"] = samples
            with self.subTest(samples=samples):
                self.reject(changed)
        changed = copy.deepcopy(self.value)
        changed["scenarios"][0]["proof"]["measurements"]["heartbeat_round_trip_ms"] = [1]
        self.reject(changed)

    def test_wrong_request_method_cannot_satisfy_scenario(self) -> None:
        changed = copy.deepcopy(self.value)
        record = changed["scenarios"][0]
        for event in record["replay"]["events"]:
            if event["request_method"] is not None:
                event["request_method"] = "item/permissions/requestApproval"
        self.reject(changed)

    def test_unknown_private_fields_and_noncanonical_json_rejected(self) -> None:
        for target in ("package", "proof", "replay"):
            changed = copy.deepcopy(self.value)
            destination = changed if target == "package" else changed["scenarios"][0][target]
            destination["private_transcript"] = "SYNTHETIC_PRIVATE_SENTINEL"
            self.reject(changed)
        for raw in (b"{}", self.raw + b"\n", self.raw.replace(b'"provider":"codex"',
                                                              b'"provider":"codex","provider":"codex"', 1)):
            with self.assertRaises((evidence.EvidenceError, evidence.qualification.ProbeError)):
                evidence.validate_evidence(raw)

    def test_export_refuses_leftover_credentials_before_reading_captures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            (root / "config").mkdir(mode=0o700)
            (root / "config/auth.json").write_bytes(b"synthetic credentials")
            with mock.patch.object(evidence.codex_replay, "export_capture") as capture:
                with self.assertRaisesRegex(evidence.EvidenceError, "^credentials-not-cleaned$"):
                    evidence.export_run(root)
                capture.assert_not_called()

    def test_export_rejects_changed_journal(self) -> None:
        record = self.value["scenarios"][0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            (root / "journal").mkdir(mode=0o700)
            for path, raw in ((root / "qualification.json", encoded(record["proof"])),
                              (root / "journal/source.jsonl", b'{}\n')):
                path.write_bytes(raw)
                path.chmod(0o600)
            with mock.patch.object(evidence.codex_replay, "export_capture",
                                   return_value=encoded(record["replay"])):
                with self.assertRaisesRegex(evidence.EvidenceError, "^journal-proof-mismatch$"):
                    evidence.export_run(root)


if __name__ == "__main__":
    unittest.main()
