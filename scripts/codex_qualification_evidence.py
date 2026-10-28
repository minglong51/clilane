from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

import codex_qualification as qualification
import codex_replay
from codex_observer import MAX_JOURNAL_BYTES, TaskBinding, _read_private
from provider_capture import repository_paths, validate_capture_root
from provider_evidence import EvidenceError, MAX_LATENCY_MS, read_regular_file
from provider_probe import SafeArgumentParser, strict_message


FIXTURE_PATH = "docs/designs/codex-qualification.json"
MAX_BYTES = 256 * 1024
BASE_CHECKS = {
    "stale_delivery_rejected", "duplicate_delivery_noop", "freshness_expired",
    "observer_process_restarted", "replay_stayed_unknown", "fresh_source_read_required",
    "provider_process_unchanged", "stale_source_session_rejected",
    "stale_source_turn_rejected", "recurring_heartbeat_renewed",
    "old_observer_instance_rejected", "journal_matches_source", "live_task_binding_verified",
}
SCENARIO_CHECKS = {
    "input": {"pending_input_recovered", "input_request_resolved"},
    "permissions": {"pending_permission_approval_recovered", "permission_approval_resolved",
                    "permission_grant_empty"},
    "command": {"pending_command_approval_recovered", "command_approval_resolved",
                "action_declined_without_target_creation", "provider_diagnostics_match_denial"},
    "file": {"pending_file_approval_recovered", "file_approval_resolved",
             "action_declined_without_target_creation", "provider_diagnostics_match_denial"},
}
RESULT_KEYS = {
    "schema_version", "scope", "qualification", "provider", "provider_version",
    "source_capture_sha256", "executable_sha256", "checks", "message_count",
    "thread_read_count", "freshness_seconds", "harness_sha256", "observer_journal_sha256",
    "measurements",
}
CAPABILITIES = (
    "approval_request", "duplicate", "heartbeat", "input_request",
    "reconnect", "request_recovery", "stale_session", "turn_state",
)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise EvidenceError(code)


def validate_result(result: Any, replay: dict[str, Any], scenario: str) -> None:
    require(type(result) is dict and set(result) == RESULT_KEYS, "invalid-proof-fields")
    require(type(result["schema_version"]) is int and result["schema_version"] == 2,
            "unsupported-proof-version")
    expected = {
        "scope": f"phase0-{scenario}-observer-restart", "qualification": "unqualified",
        "provider": "codex", "provider_version": replay["provider_version"],
        "source_capture_sha256": replay["source_capture_sha256"],
        "executable_sha256": replay["executable_sha256"],
        "message_count": replay["message_count"], "thread_read_count": replay["thread_read_count"],
        "freshness_seconds": qualification.FRESHNESS_NS // 1_000_000_000,
        "harness_sha256": qualification.evidence_source_sha256(),
    }
    require(all(type(result[key]) is type(value) and result[key] == value
                for key, value in expected.items()), "proof-source-mismatch")
    require(replay["thread_read_count"] >= 4 and replay["unhandled_message_count"] == 0
            and replay["unresolved_request_count"] == 0, "incomplete-live-proof")
    checks = result["checks"]
    require(type(checks) is dict and set(checks) == BASE_CHECKS | SCENARIO_CHECKS[scenario]
            and all(value is True for value in checks.values()), "incomplete-proof-checks")
    digest = result["observer_journal_sha256"]
    require(type(digest) is str and codex_replay.SHA256_PATTERN.fullmatch(digest) is not None
            and len(set(digest)) > 1, "invalid-journal-digest")
    measurements = result["measurements"]
    require(type(measurements) is dict and set(measurements) == {
        "source_to_observer_ms", "heartbeat_round_trip_ms",
    }, "invalid-measurements")
    for samples in measurements.values():
        require(type(samples) is list and 1 <= len(samples) <= replay["message_count"]
                and all(type(value) is int and 1 <= value <= MAX_LATENCY_MS for value in samples)
                and samples == sorted(samples), "invalid-latency-samples")
    require(len(measurements["heartbeat_round_trip_ms"]) == 2, "missing-recurring-heartbeat")
    methods = {event["request_method"] for event in replay["events"]
               if event["event"] == "request_opened"}
    require(methods == {qualification.SCENARIOS[scenario]}, "scenario-request-mismatch")


def canonical_evidence(records: Sequence[dict[str, Any]]) -> bytes:
    require(len(records) == len(qualification.SCENARIOS), "incomplete-scenario-set")
    by_scenario: dict[str, dict[str, Any]] = {}
    captures: set[str] = set()
    journals: set[str] = set()
    for record in records:
        require(type(record) is dict and set(record) == {"scenario", "proof", "replay"},
                "invalid-scenario-fields")
        scenario = record["scenario"]
        require(type(scenario) is str and scenario in qualification.SCENARIOS
                and scenario not in by_scenario, "invalid-scenario")
        replay = record["replay"]
        codex_replay.canonical_replay_bytes([replay])
        validate_result(record["proof"], replay, scenario)
        capture, journal = replay["source_capture_sha256"], record["proof"]["observer_journal_sha256"]
        require(capture not in captures and journal not in journals, "reused-proof-source")
        captures.add(capture)
        journals.add(journal)
        by_scenario[scenario] = record
    scenarios = sorted(by_scenario)
    first = by_scenario[scenarios[0]]["replay"]
    capabilities = []
    for capability in CAPABILITIES:
        covered = ["input"] if capability == "input_request" else (
            ["command", "file", "permissions"] if capability == "approval_request" else scenarios
        )
        capabilities.append({"capability": capability, "status": "pass", "scenarios": covered})
    result = {
        "schema_version": 1, "provider": "codex", "provider_version": first["provider_version"],
        "source_interface": "codex-app-server", "scope": "phase0-clilane-owned-app-server",
        "evidence_complete": True, "runtime_support": "attach_only_unknown",
        "latency_scope": "journal-write-through-observer-acknowledgement",
        "capabilities": capabilities, "scenarios": [by_scenario[name] for name in scenarios],
    }
    raw = (json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(len(raw) <= MAX_BYTES, "evidence-byte-limit")
    return raw


def validate_evidence(raw: bytes) -> dict[str, Any]:
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "evidence-byte-limit")
    value = strict_message(raw)
    records = value.get("scenarios")
    require(type(records) is list, "invalid-scenario-set")
    require(canonical_evidence(records) == raw, "noncanonical-evidence")
    return value


def export_run(root: Path) -> dict[str, Any]:
    require(root.is_absolute() and root.resolve() == root, "run-root-not-canonical")
    validated = validate_capture_root(root, repository_paths(Path(__file__)))
    validated.close()
    require(not os.path.lexists(root / "config" / "auth.json"), "credentials-not-cleaned")
    proof = strict_message(_read_private(root / "qualification.json", MAX_BYTES))
    require(set(proof) == RESULT_KEYS, "invalid-proof-fields")
    scopes = {f"phase0-{name}-observer-restart": name for name in qualification.SCENARIOS}
    scope = proof.get("scope")
    require(type(scope) is str and scope in scopes, "invalid-proof-scope")
    scenario = scopes[scope]
    replay = json.loads(codex_replay.export_capture(root / "captures", qualification.CAPTURE_ID))
    validate_result(proof, replay, scenario)
    journal = _read_private(root / "journal" / "source.jsonl", MAX_JOURNAL_BYTES)
    require(hashlib.sha256(journal).hexdigest() == proof["observer_journal_sha256"],
            "journal-proof-mismatch")
    rows = journal.splitlines()
    require(bool(rows), "journal-empty")
    header = strict_message(rows[0])
    generation = header.get("task_generation")
    require(type(generation) is str and codex_replay.SHA256_PATTERN.fullmatch(generation) is not None,
            "invalid-task-generation")
    qualification.verify_journal(root, TaskBinding(generation), replay, scenario_name=scenario)
    output_messages = sum(strict_message(row)["stream"] == "O" for row in rows[1:])
    require(len(proof["measurements"]["source_to_observer_ms"]) == output_messages,
            "observation-count-mismatch")
    return {"scenario": scenario, "proof": proof, "replay": replay}


def main(argv: Sequence[str] | None = None) -> int:
    parser = SafeArgumentParser(
        prog="codex_qualification_evidence.py", allow_abbrev=False,
        description="Export verified historical Codex qualification proof; this does not establish current source health.",
    )
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--check", action="store_true", help="Check committed proof without reading private captures.")
    operation.add_argument("--run-root", action="append", help="Repeat for the four private input, permissions, command, and file runs.")
    arguments = parser.parse_args(argv)
    try:
        if arguments.check:
            path = Path(__file__).resolve().parents[1] / FIXTURE_PATH
            validate_evidence(read_regular_file(path, "qualification evidence"))
            print("Codex qualification evidence passed: 8 capabilities, 4 scenarios; historical proof only")
        else:
            require(len(arguments.run_root) == len(qualification.SCENARIOS), "incomplete-scenario-set")
            records = [export_run(Path(path)) for path in arguments.run_root]
            sys.stdout.buffer.write(canonical_evidence(records))
        return 0
    except (EvidenceError, codex_replay.ReplayError, qualification.ObserverError,
            qualification.ProbeError) as error:
        print(f"codex_qualification_evidence.py: {error}", file=sys.stderr)
    except OSError:
        print("codex_qualification_evidence.py: source-unavailable", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
