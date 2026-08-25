from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import json
import os
import pwd
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bin" / "clilane"
LOADER = importlib.machinery.SourceFileLoader("clilane_profiles_test", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
clilane = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = clilane
LOADER.exec_module(clilane)


def profile_value(
    *,
    provider: str = "claude",
    command: list[str] | None = None,
    cwd: dict[str, str] | None = None,
    inherit: list[str] | None = None,
    env_set: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "provider": provider,
        "command": ["/bin/echo", "ok"] if command is None else command,
        "cwd": cwd or {"mode": "explicit"},
        "env": {
            "inherit": [] if inherit is None else inherit,
            "set": {} if env_set is None else env_set,
        },
    }


def profile_document(
    profiles: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "profiles": profiles or {"default": profile_value()},
    }


def write_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(mode)


class TemporaryProfileCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.profile_path = self.root / "config" / "clilane" / "profiles.json"
        self.cwd = self.root / "project with spaces"
        self.cwd.mkdir()
        self.environment = {
            "HOME": str(self.root),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "USER": "profile-user",
            "LANG": "C",
            "AUTH_ALLOWED": "allowed-value",
            "DENIED_TOKEN": "denied-value",
            "XDG_CONFIG_HOME": str(self.root / "config"),
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_profiles(self, value: object | None = None, mode: int = 0o600) -> None:
        write_json(
            self.profile_path,
            profile_document() if value is None else value,
            mode,
        )


class RunParserTests(unittest.TestCase):
    def test_options_are_valid_before_or_after_name(self) -> None:
        before = clilane.parse_run_request(
            ["--wait", "--timeout", "2", "-C", "/tmp", "job", "--", "echo", "ok"]
        )
        after = clilane.parse_run_request(
            ["job", "--wait", "--timeout=2", "--cwd=/tmp", "--", "echo", "ok"]
        )
        self.assertEqual(before, after)
        self.assertTrue(before.cwd_explicit)
        self.assertEqual(before.command, ("echo", "ok"))

    def test_profile_request_has_no_raw_command(self) -> None:
        request = clilane.parse_run_request(
            ["job", "--profile", "Claude.Main", "-C", "/tmp"]
        )
        self.assertEqual(request.profile, "Claude.Main")
        self.assertIsNone(request.command)

    def test_parser_rejects_invalid_combinations(self) -> None:
        cases = {
            "missing mode": ["job"],
            "missing name": ["--", "echo"],
            "empty raw": ["job", "--"],
            "raw profile conflict": ["job", "--profile", "p", "--", "echo"],
            "timeout without wait": ["job", "--timeout", "1", "--", "echo"],
            "blank hook": ["job", "--on-exit=", "--", "echo"],
            "duplicate cwd": ["job", "-C", "/tmp", "--cwd=/tmp", "--", "echo"],
            "duplicate wait": ["job", "--wait", "--wait", "--", "echo"],
            "unknown option": ["job", "--wat", "--", "echo"],
            "extra positional": ["job", "extra", "--", "echo"],
        }
        for label, parts in cases.items():
            with self.subTest(label=label), self.assertRaises(clilane.CliLaneError):
                clilane.parse_run_request(parts)


class StrictJsonTests(TemporaryProfileCase):
    def test_strict_decoder_rejects_duplicates_constants_and_large_integers(self) -> None:
        variants = [
            b'{"schema_version":1,"schema_version":1,"profiles":{}}',
            b'{"schema_version":NaN,"profiles":{}}',
            b'{"schema_version":1,"profiles":{"p":{"provider":"x","provider":"y"}}}',
            ('{"schema_version":' + "9" * 65 + ',"profiles":{}}').encode(),
        ]
        for raw in variants:
            self.profile_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.profile_path.write_bytes(raw)
            self.profile_path.chmod(0o600)
            with self.subTest(raw=raw[:40]), self.assertRaises(clilane.CliLaneError):
                clilane.load_profiles(self.profile_path)

    def test_schema_version_requires_exact_integer_type(self) -> None:
        for value in (True, 1.0, "1", 2):
            self.write_profiles({"schema_version": value, "profiles": {}})
            with self.subTest(value=value), self.assertRaises(clilane.CliLaneError):
                clilane.load_profiles(self.profile_path)

    def test_escaped_lone_surrogates_are_rejected_as_invalid_json(self) -> None:
        self.profile_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        for field in ("command", "environment"):
            if field == "command":
                raw = (
                    b'{"schema_version":1,"profiles":{"clean":{"provider":"claude",'
                    b'"command":["\\ud800"],"cwd":{"mode":"explicit"},'
                    b'"env":{"inherit":[],"set":{}}}}}'
                )
            else:
                raw = (
                    b'{"schema_version":1,"profiles":{"clean":{"provider":"claude",'
                    b'"command":["/bin/true"],"cwd":{"mode":"explicit"},'
                    b'"env":{"inherit":[],"set":{"MODE":"\\ud800"}}}}}'
                )
            self.profile_path.write_bytes(raw)
            self.profile_path.chmod(0o600)
            with self.subTest(field=field), self.assertRaises(clilane.CliLaneError):
                clilane.load_profiles(self.profile_path)

    def test_exact_size_boundary(self) -> None:
        raw = json.dumps(profile_document(), separators=(",", ":")).encode()
        exact = raw + b" " * (clilane.CONFIG_MAX_BYTES - len(raw))
        self.profile_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.profile_path.write_bytes(exact)
        self.profile_path.chmod(0o600)
        self.assertIn("default", clilane.load_profiles(self.profile_path))
        self.profile_path.write_bytes(exact + b" ")
        with self.assertRaises(clilane.CliLaneError):
            clilane.load_profiles(self.profile_path)


class ProfileDescriptorTests(TemporaryProfileCase):
    def test_rejects_symlink_nonregular_owner_and_unsafe_mode(self) -> None:
        real = self.root / "real.json"
        write_json(real, profile_document())
        self.profile_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.profile_path.symlink_to(real)
        with self.assertRaises(clilane.CliLaneError):
            clilane.load_profiles(self.profile_path)
        self.profile_path.unlink()
        self.profile_path.mkdir()
        with self.assertRaises(clilane.CliLaneError):
            clilane.load_profiles(self.profile_path)
        self.profile_path.rmdir()
        self.write_profiles(mode=0o622)
        with self.assertRaises(clilane.CliLaneError):
            clilane.load_profiles(self.profile_path)
        self.profile_path.chmod(0o600)
        details = self.profile_path.stat()
        wrong_owner = SimpleNamespace(
            st_mode=details.st_mode,
            st_uid=details.st_uid + 1,
            st_size=details.st_size,
        )
        with mock.patch.object(clilane.os, "fstat", return_value=wrong_owner):
            with self.assertRaises(clilane.CliLaneError):
                clilane.load_profiles(self.profile_path)

    def test_fifo_is_rejected_without_blocking(self) -> None:
        self.profile_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.mkfifo(self.profile_path, 0o600)
        with self.assertRaises(clilane.CliLaneError):
            clilane.load_profiles(self.profile_path)

    def test_read_is_bound_to_open_descriptor_during_path_swap(self) -> None:
        original = profile_document({"before": profile_value()})
        replacement = profile_document({"after": profile_value()})
        self.write_profiles(original)
        moved = self.root / "opened.json"
        incoming = self.root / "incoming.json"
        original_fstat = os.fstat
        swapped = False

        def swap_path(descriptor: int) -> os.stat_result:
            nonlocal swapped
            details = original_fstat(descriptor)
            if not swapped:
                swapped = True
                os.replace(self.profile_path, moved)
                write_json(incoming, replacement)
                os.replace(incoming, self.profile_path)
            return details

        with mock.patch.object(clilane.os, "fstat", side_effect=swap_path):
            loaded = clilane.load_profiles(self.profile_path)
        self.assertEqual(set(loaded), {"before"})
        self.assertEqual(set(clilane.load_profiles(self.profile_path)), {"after"})


class ProfileSchemaTests(TemporaryProfileCase):
    def test_rejects_unknown_and_missing_fields_at_every_level(self) -> None:
        base = profile_document()
        variants: list[dict[str, object]] = []
        extra_root = copy.deepcopy(base)
        extra_root["extra"] = True
        variants.append(extra_root)
        missing_root = copy.deepcopy(base)
        del missing_root["profiles"]
        variants.append(missing_root)
        extra_profile = copy.deepcopy(base)
        extra_profile["profiles"]["default"]["extra"] = True
        variants.append(extra_profile)
        missing_profile = copy.deepcopy(base)
        del missing_profile["profiles"]["default"]["provider"]
        variants.append(missing_profile)
        extra_cwd = copy.deepcopy(base)
        extra_cwd["profiles"]["default"]["cwd"]["path"] = "/tmp"
        variants.append(extra_cwd)
        extra_env = copy.deepcopy(base)
        extra_env["profiles"]["default"]["env"]["extra"] = []
        variants.append(extra_env)
        for index, document in enumerate(variants):
            self.write_profiles(document)
            with self.subTest(index=index), self.assertRaises(clilane.CliLaneError):
                clilane.load_profiles(self.profile_path)

    def test_validates_names_commands_cwd_and_environment(self) -> None:
        invalid_profiles = [
            {"bad name": profile_value()},
            {"p": profile_value(provider="bad provider")},
            {"p": profile_value(command=[])},
            {"p": profile_value(command=["ok", ""])},
            {"p": profile_value(command=["ok", "bad\x00arg"])},
            {"p": profile_value(cwd={"mode": "fixed", "path": "relative"})},
            {"p": profile_value(cwd={"mode": "unknown"})},
            {"p": profile_value(inherit=["A", "A"])},
            {"p": profile_value(inherit=["BAD-NAME"])},
            {"p": profile_value(inherit=["TERM"])},
            {"p": profile_value(inherit=["CLILANE_LOG"])},
            {"p": profile_value(inherit=["AGT_STATE_HOME"])},
            {"p": profile_value(env_set={"BAD-NAME": "x"})},
            {"p": profile_value(env_set={"SERVICE_TOKEN": "x"})},
            {"p": profile_value(env_set={"service_Password": "x"})},
            {"p": profile_value(env_set={"TMUX_PANE": "x"})},
            {"p": profile_value(env_set={"OK": "bad\x00value"})},
        ]
        for index, profiles in enumerate(invalid_profiles):
            self.write_profiles(profile_document(profiles))
            with self.subTest(index=index), self.assertRaises(clilane.CliLaneError):
                clilane.load_profiles(self.profile_path)

    def test_lookup_is_exact_and_environment_is_allowlisted(self) -> None:
        self.write_profiles(
            profile_document(
                {
                    "Case.Sensitive": profile_value(
                        inherit=["AUTH_ALLOWED"],
                        env_set={"MODE": "clean", "PATH": "/profile/path"},
                    )
                }
            )
        )
        request = clilane.parse_run_request(
            ["task", "--profile", "Case.Sensitive", "-C", str(self.cwd)]
        )
        before = dict(os.environ)
        spec = clilane.resolve_run_request(request, self.environment, str(self.root))
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(spec.provider, "claude")
        self.assertEqual(spec.environment["AUTH_ALLOWED"], "allowed-value")
        self.assertEqual(spec.environment["MODE"], "clean")
        self.assertEqual(spec.environment["PATH"], "/profile/path")
        self.assertNotIn("DENIED_TOKEN", spec.environment)
        wrong_case = clilane.parse_run_request(
            ["task", "--profile", "case.sensitive", "-C", str(self.cwd)]
        )
        with self.assertRaises(clilane.CliLaneError):
            clilane.resolve_run_request(wrong_case, self.environment, str(self.root))

    def test_explicit_and_fixed_cwd_rules(self) -> None:
        fixed = self.root / "fixed"
        fixed.mkdir()
        self.write_profiles(
            profile_document(
                {
                    "explicit": profile_value(),
                    "fixed": profile_value(cwd={"mode": "fixed", "path": str(fixed)}),
                }
            )
        )
        with self.assertRaises(clilane.CliLaneError):
            clilane.resolve_run_request(
                clilane.parse_run_request(["a", "--profile", "explicit"]),
                self.environment,
                str(self.root),
            )
        with self.assertRaises(clilane.CliLaneError):
            clilane.resolve_run_request(
                clilane.parse_run_request(
                    ["b", "--profile", "fixed", "-C", str(self.cwd)]
                ),
                self.environment,
                str(self.root),
            )
        spec = clilane.resolve_run_request(
            clilane.parse_run_request(["b", "--profile", "fixed"]),
            self.environment,
            str(self.root),
        )
        self.assertEqual(spec.cwd, str(fixed.resolve()))

    def test_missing_or_nul_inherited_values_are_fatal(self) -> None:
        self.write_profiles(
            profile_document({"p": profile_value(inherit=["AUTH_ALLOWED"])})
        )
        request = clilane.parse_run_request(
            ["task", "--profile", "p", "-C", str(self.cwd)]
        )
        for environment in (
            {key: value for key, value in self.environment.items() if key != "AUTH_ALLOWED"},
            {**self.environment, "AUTH_ALLOWED": "bad\x00value"},
        ):
            with self.assertRaises(clilane.CliLaneError):
                clilane.resolve_run_request(request, environment, str(self.root))


class LaunchBoundaryTests(TemporaryProfileCase):
    def test_raw_resolution_preserves_legacy_filter_without_mutating_global_env(self) -> None:
        source = {
            "HOME": str(self.root),
            "PATH": "/bin",
            "RAW_TOKEN": "legacy",
            "CLILANE_EXIT_CODE": "stale",
            "AGT_PRIVATE": "stale",
            "PWD": "/discarded",
            "TERM": "discarded",
            "BAD-NAME": "discarded",
            "NUL_VALUE": "bad\x00value",
        }
        request = clilane.parse_run_request(
            ["raw", "-C", str(self.cwd), "--", "/bin/echo", "ok"]
        )
        before = dict(os.environ)
        spec = clilane.resolve_run_request(request, source, str(self.root))
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(spec.environment["RAW_TOKEN"], "legacy")
        self.assertNotIn("PWD", spec.environment)
        self.assertNotIn("TERM", spec.environment)
        self.assertNotIn("BAD-NAME", spec.environment)
        self.assertNotIn("NUL_VALUE", spec.environment)
        self.assertEqual(spec.environment["CLILANE_EXIT_CODE"], "stale")
        self.assertEqual(spec.environment["AGT_PRIVATE"], "stale")

    def test_complete_launch_spec_rejects_invalid_shared_boundary_values(self) -> None:
        base = {
            "name": "boundary",
            "cwd_value": str(self.cwd),
            "command": ["/bin/true"],
            "wait": True,
            "timeout": None,
            "on_exit": None,
            "environment": {},
            "profile": "clean",
            "provider": "claude",
        }
        mutations = [
            {"wait": 1},
            {"timeout": 0},
            {"timeout": -1},
            {"timeout": float("nan")},
            {"timeout": float("inf")},
            {"profile": None},
            {"provider": None},
            {"profile": "bad profile"},
            {"provider": "bad provider"},
            {"environment": {"TERM": "xterm"}},
            {"environment": {"CLILANE_EXIT_CODE": "0"}},
            {"environment": {"AGT_PRIVATE": "value"}},
        ]
        for mutation in mutations:
            arguments = {**base, **mutation}
            with self.subTest(mutation=mutation), self.assertRaises(clilane.CliLaneError):
                clilane.complete_launch_spec(**arguments)

    def test_rejected_preflight_does_not_call_runtime_boundaries(self) -> None:
        request = clilane.parse_run_request(
            ["raw", "-C", str(self.root / "missing"), "--", "/bin/echo"]
        )
        with mock.patch.object(clilane, "tmux") as tmux_call, mock.patch.object(
            clilane.uuid, "uuid4"
        ) as identifier:
            with self.assertRaises(clilane.CliLaneError):
                clilane.resolve_run_request(request, self.environment, str(self.root))
        tmux_call.assert_not_called()
        identifier.assert_not_called()

    def test_environment_delta_uses_one_batched_rpc_independent_of_key_count(self) -> None:
        applied = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
        with mock.patch.object(clilane, "tmux", return_value=applied) as tmux_call:
            clilane.set_task_environment(
                "session",
                {f"KEY_{index:03d}": str(index) for index in range(100)},
                {"OLD", "DROP"},
            )
        self.assertEqual(tmux_call.call_count, 1)
        queue = tmux_call.call_args.args[0]
        self.assertIn(";", queue)
        assignments = [
            queue[index + 3]
            for index, value in enumerate(queue[:-3])
            if value == "set-environment" and queue[index + 2] == "session"
        ]
        self.assertEqual(assignments, sorted(assignments))

    def test_tmux_queue_escapes_only_structural_trailing_semicolons(self) -> None:
        applied = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
        values = {
            "BARE": ";",
            "TRAILING": "value;",
            "BACKSLASH": "value\\;",
            "DOUBLE_BACKSLASH": "value\\\\;",
            "INNER": "a;b",
        }
        with mock.patch.object(clilane, "tmux", return_value=applied) as tmux_call:
            clilane.set_task_environment("session", values, set())
        queue = tmux_call.call_args.args[0]
        encoded: dict[str, str] = {}
        for index, token in enumerate(queue):
            if token == "set-environment" and queue[index + 2] == "session":
                encoded[queue[index + 3]] = queue[index + 4]
        self.assertEqual(encoded["BARE"], "\\;")
        self.assertEqual(encoded["TRAILING"], "value\\;")
        self.assertEqual(encoded["BACKSLASH"], "value\\\\;")
        self.assertEqual(encoded["DOUBLE_BACKSLASH"], "value\\\\\\;")
        self.assertEqual(encoded["INNER"], "a;b")

    def test_absolute_socket_routing_preserves_distinct_registry_identity(self) -> None:
        old_socket = clilane.SOCKET
        old_binary = clilane.TMUX_BINARY_OVERRIDE
        old_override = clilane.TMUX_SOCKET_OVERRIDE
        try:
            clilane.SOCKET = "/tmp/one/shared.sock"
            first_digest = clilane.socket_digest()
            clilane.SOCKET = "/tmp/two/shared.sock"
            self.assertNotEqual(first_digest, clilane.socket_digest())
            clilane.SOCKET = "logical-socket"
            clilane.configure_tmux_control(
                "/usr/bin/tmux", "/tmp/runtime/shared.sock"
            )
            self.assertEqual(clilane.socket_identity(), "logical-socket")
            self.assertEqual(
                clilane.tmux_socket_arguments(),
                ["-S", "/tmp/runtime/shared.sock"],
            )
        finally:
            clilane.SOCKET = old_socket
            clilane.TMUX_BINARY_OVERRIDE = old_binary
            clilane.TMUX_SOCKET_OVERRIDE = old_override

    def test_portable_process_budget_accepts_boundary_and_rejects_overflow(self) -> None:
        arguments = ["/bin/true"]
        environment = {"VALUE": ""}
        remaining = clilane.EXEC_FOOTPRINT_MAX_BYTES - clilane.process_footprint(
            arguments, environment
        )
        environment["VALUE"] = "x" * remaining
        self.assertEqual(
            clilane.process_footprint(arguments, environment),
            clilane.EXEC_FOOTPRINT_MAX_BYTES,
        )
        clilane.require_portable_footprint("boundary", arguments, environment)
        environment["VALUE"] += "x"
        with self.assertRaises(clilane.CliLaneError):
            clilane.require_portable_footprint("overflow", arguments, environment)

    def test_oversized_materialized_environment_fails_before_artifacts(self) -> None:
        spec = clilane.complete_launch_spec(
            name="oversized",
            cwd_value=str(self.cwd),
            command=["/bin/true"],
            wait=False,
            timeout=None,
            on_exit=None,
            environment={"VALUE": "x" * clilane.EXEC_FOOTPRINT_MAX_BYTES},
            profile="clean",
            provider="claude",
        )
        state = self.root / "state"
        with mock.patch.dict(
            os.environ,
            {"CLILANE_STATE_HOME": str(state)},
            clear=False,
        ), mock.patch.object(clilane, "tmux") as tmux_call, mock.patch.object(
            clilane.uuid, "uuid4"
        ) as identifier:
            with self.assertRaises(clilane.CliLaneError):
                clilane.preflight_launch(spec)
        tmux_call.assert_not_called()
        identifier.assert_not_called()
        self.assertFalse(state.exists())

    def test_oversized_tmux_client_environment_fails_before_tmux_call(self) -> None:
        spec = clilane.complete_launch_spec(
            name="oversized-client",
            cwd_value=str(self.cwd),
            command=["/bin/true"],
            wait=False,
            timeout=None,
            on_exit=None,
            environment={},
            profile="clean",
            provider="claude",
        )
        with mock.patch.object(
            clilane,
            "tmux_client_environment",
            return_value={"LC_DENIED": "x" * clilane.EXEC_FOOTPRINT_MAX_BYTES},
        ), mock.patch.object(
            clilane, "tmux_binary", return_value="/usr/bin/tmux"
        ), mock.patch.object(clilane, "tmux") as tmux_call:
            with self.assertRaises(clilane.CliLaneError):
                clilane.preflight_launch(spec)
        tmux_call.assert_not_called()

    def test_live_tmux_preflight_and_creation_share_registry_lock(self) -> None:
        spec = clilane.complete_launch_spec(
            name="ordered",
            cwd_value=str(self.cwd),
            command=["/bin/true"],
            wait=False,
            timeout=None,
            on_exit=None,
            environment={},
            profile="clean",
            provider="claude",
        )
        events: list[str] = []
        lock = mock.MagicMock()
        lock.__enter__.side_effect = lambda: events.append("lock-enter")
        lock.__exit__.side_effect = lambda *_args: events.append("lock-exit")

        def preflight(_spec: object, inspect_tmux: bool = True) -> set[str]:
            events.append("preflight-live" if inspect_tmux else "preflight-static")
            return set()

        def stop_before_allocation() -> list[object]:
            events.append("list-tasks")
            raise RuntimeError("stop")

        with mock.patch.object(clilane, "preflight_launch", side_effect=preflight), mock.patch.object(
            clilane, "registry_lock", return_value=lock
        ), mock.patch.object(clilane, "list_tasks", side_effect=stop_before_allocation):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                clilane.run_task(spec)
        self.assertEqual(
            events,
            [
                "preflight-static",
                "lock-enter",
                "preflight-live",
                "list-tasks",
                "lock-exit",
            ],
        )


class HubConfigTests(TemporaryProfileCase):
    def setUp(self) -> None:
        super().setUp()
        self.hub_path = self.root / "hub.json"
        self.fixed = self.root / "fixed"
        self.fixed.mkdir()
        self.write_profiles(
            profile_document(
                {
                    "explicit": profile_value(
                        provider="claude",
                        inherit=["AUTH_ALLOWED"],
                        env_set={"MODE": "one"},
                    ),
                    "fixed": profile_value(
                        provider="codex",
                        cwd={"mode": "fixed", "path": str(self.fixed)},
                    ),
                }
            )
        )

    def write_hub(self, value: object) -> None:
        write_json(self.hub_path, value)

    def load_hub(self) -> list[dict[str, object]]:
        return clilane.load_hub_presets(
            str(self.hub_path),
            allow_missing=False,
            launch_environment=self.environment,
            profiles_file=str(self.profile_path),
        )

    def test_v1_remains_strict_bounded_and_shape_compatible(self) -> None:
        value = {
            "schema_version": 1,
            "agents": [{"name": "legacy", "command": ["/bin/echo"], "dir": str(self.cwd)}],
        }
        self.write_hub(value)
        self.assertEqual(
            self.load_hub(),
            [{"name": "legacy", "command": ["/bin/echo"], "dir": str(self.cwd)}],
        )
        raw = json.dumps(value, separators=(",", ":")).encode()
        exact = raw + b" " * (clilane.CONFIG_MAX_BYTES - len(raw))
        self.hub_path.write_bytes(exact)
        self.assertEqual(self.load_hub()[0]["name"], "legacy")
        self.hub_path.write_bytes(exact + b" ")
        with self.assertRaises(clilane.CliLaneError):
            self.load_hub()

        username = pwd.getpwuid(os.getuid()).pw_name
        home = Path(f"~{username}").expanduser()
        value = {
            "schema_version": 1,
            "agents": [
                {"name": "legacy", "command": ["/bin/echo"], "dir": f"~{username}"}
            ],
        }
        self.write_hub(value)
        without_home = {key: item for key, item in self.environment.items() if key != "HOME"}
        loaded = clilane.load_hub_presets(
            str(self.hub_path),
            allow_missing=False,
            launch_environment=without_home,
            profiles_file=str(self.profile_path),
        )
        self.assertEqual(loaded[0]["dir"], str(home))
        self.hub_path.write_bytes(
            b'{"schema_version":1,"agents":[],"agents":[]}'
        )
        with self.assertRaises(clilane.CliLaneError):
            self.load_hub()

    def test_v2_command_and_profile_variants(self) -> None:
        self.write_hub(
            {
                "schema_version": 2,
                "agents": [
                    {"name": "raw", "command": ["/bin/echo"], "dir": str(self.cwd)},
                    {"name": "clean", "profile": "explicit", "dir": str(self.cwd)},
                    {"name": "fixed-clean", "profile": "fixed"},
                ],
            }
        )
        presets = self.load_hub()
        self.assertEqual([preset["launch_mode"] for preset in presets], ["raw", "profile", "profile"])
        self.assertEqual(presets[1]["provider"], "claude")
        self.assertEqual(presets[2]["dir"], str(self.fixed.resolve()))
        self.assertTrue(all(len(str(preset["selection_digest"])) == 64 for preset in presets))

    def test_v2_rejects_mode_and_cwd_ambiguity(self) -> None:
        entries = [
            {"name": "both", "command": ["echo"], "profile": "explicit", "dir": str(self.cwd)},
            {"name": "neither"},
            {"name": "explicit", "profile": "explicit"},
            {"name": "fixed", "profile": "fixed", "dir": str(self.cwd)},
        ]
        for entry in entries:
            self.write_hub({"schema_version": 2, "agents": [entry]})
            with self.subTest(entry=entry), self.assertRaises(clilane.CliLaneError):
                self.load_hub()

    def test_reorder_succeeds_but_selected_mutations_fail(self) -> None:
        hub = {
            "schema_version": 2,
            "agents": [
                {"name": "other", "command": ["/bin/true"], "dir": str(self.root)},
                {"name": "selected", "profile": "explicit", "dir": str(self.cwd)},
            ],
        }
        self.write_hub(hub)
        selected = self.load_hub()[1]
        reordered = copy.deepcopy(hub)
        reordered["agents"].reverse()
        self.write_hub(reordered)
        same = clilane.revalidate_hub_preset(
            selected, str(self.hub_path), str(self.profile_path), self.environment
        )
        self.assertEqual(same["name"], "selected")

        mutations: list[tuple[dict[str, object], dict[str, object]]] = []
        renamed_hub = copy.deepcopy(hub)
        renamed_hub["agents"][1]["name"] = "renamed"
        mutations.append((renamed_hub, profile_document({
            "explicit": profile_value(provider="claude", inherit=["AUTH_ALLOWED"], env_set={"MODE": "one"}),
            "fixed": profile_value(provider="codex", cwd={"mode": "fixed", "path": str(self.fixed)}),
        })))
        directory_hub = copy.deepcopy(hub)
        directory_hub["agents"][1]["dir"] = str(self.root)
        mutations.append((directory_hub, copy.deepcopy(profile_document({
            "explicit": profile_value(provider="claude", inherit=["AUTH_ALLOWED"], env_set={"MODE": "one"}),
            "fixed": profile_value(provider="codex", cwd={"mode": "fixed", "path": str(self.fixed)}),
        }))))
        profile_ref_hub = copy.deepcopy(hub)
        profile_ref_hub["agents"][1]["profile"] = "fixed"
        del profile_ref_hub["agents"][1]["dir"]
        mutations.append((profile_ref_hub, copy.deepcopy(profile_document({
            "explicit": profile_value(provider="claude", inherit=["AUTH_ALLOWED"], env_set={"MODE": "one"}),
            "fixed": profile_value(provider="codex", cwd={"mode": "fixed", "path": str(self.fixed)}),
        }))))

        base_profiles = profile_document({
            "explicit": profile_value(provider="claude", inherit=["AUTH_ALLOWED"], env_set={"MODE": "one"}),
            "fixed": profile_value(provider="codex", cwd={"mode": "fixed", "path": str(self.fixed)}),
        })
        for field, value in (
            ("provider", "kimi"),
            ("command", ["/bin/false"]),
            ("cwd", {"mode": "fixed", "path": str(self.fixed)}),
            ("env", {"inherit": ["AUTH_ALLOWED"], "set": {"MODE": "two"}}),
        ):
            changed_profiles = copy.deepcopy(base_profiles)
            changed_profiles["profiles"]["explicit"][field] = value
            changed_hub = copy.deepcopy(hub)
            if field == "cwd":
                del changed_hub["agents"][1]["dir"]
            mutations.append((changed_hub, changed_profiles))

        for index, (changed_hub, changed_profiles) in enumerate(mutations):
            self.write_hub(changed_hub)
            self.write_profiles(changed_profiles)
            with self.subTest(index=index), self.assertRaises(clilane.CliLaneError):
                clilane.revalidate_hub_preset(
                    selected,
                    str(self.hub_path),
                    str(self.profile_path),
                    self.environment,
                )

    def test_v2_symlink_retarget_invalidates_selection(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        link = self.root / "selected-directory"
        first.mkdir()
        second.mkdir()
        link.symlink_to(first, target_is_directory=True)
        self.write_hub(
            {
                "schema_version": 2,
                "agents": [
                    {"name": "selected", "profile": "explicit", "dir": str(link)}
                ],
            }
        )
        selected = self.load_hub()[0]
        self.assertEqual(selected["dir"], str(first.resolve()))
        link.unlink()
        link.symlink_to(second, target_is_directory=True)
        with self.assertRaises(clilane.CliLaneError):
            clilane.revalidate_hub_preset(
                selected,
                str(self.hub_path),
                str(self.profile_path),
                self.environment,
            )

    def test_v2_raw_mutations_fail_launch_before_task_creation(self) -> None:
        original = {
            "schema_version": 2,
            "agents": [
                {"name": "raw", "command": ["/bin/echo", "one"], "dir": str(self.cwd)}
            ],
        }
        for mutation in ("command", "directory"):
            self.write_hub(original)
            selected = self.load_hub()[0]
            changed = copy.deepcopy(original)
            if mutation == "command":
                changed["agents"][0]["command"] = ["/bin/echo", "two"]
            else:
                changed["agents"][0]["dir"] = str(self.root)
            self.write_hub(changed)
            context_data = {
                "config": str(self.hub_path),
                "profiles": str(self.profile_path),
            }
            with mock.patch.object(
                clilane, "hub_context_data", return_value=context_data
            ), mock.patch.object(
                clilane, "hub_launch_environment", return_value=self.environment
            ), mock.patch.object(clilane, "run_task") as run_task:
                with self.subTest(mutation=mutation), self.assertRaises(clilane.CliLaneError):
                    clilane.launch_hub_preset(selected, "raw-task", "context")
            run_task.assert_not_called()


@unittest.skipUnless(shutil.which("tmux"), "tmux is required")
class RealTmuxProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "config"
        self.state = self.root / "state"
        self.project = self.root / "project with spaces"
        self.project.mkdir()
        self.tmux_root = self.root / "tmux"
        self.tmux_root.mkdir(mode=0o700)
        self.socket = f"p-{uuid.uuid4().hex[:8]}"
        self.tmux_binary = shutil.which("tmux")
        assert self.tmux_binary is not None
        self.environment = dict(os.environ)
        self.environment.update(
            XDG_CONFIG_HOME=str(self.config),
            CLILANE_STATE_HOME=str(self.state),
            CLILANE_TMUX_SOCKET=self.socket,
            CLILANE_LEGACY_CUSTOM="clilane-preserved",
            AGT_LEGACY_CUSTOM="agt-preserved",
            TMUX_TMPDIR=str(self.tmux_root),
            TELEGRAM_BOT_TOKEN="telegram-denied-sentinel",
            AWS_SECRET_ACCESS_KEY="aws-denied-sentinel",
            CLOUD_TOKEN="cloud-denied-sentinel",
            CUSTOM_TMUX_SENTINEL="tmux-denied-sentinel",
            PROVIDER_AUTH_TOKEN="provider-allowed-sentinel",
            LC_NUMERIC="locale-denied-sentinel",
            LC_CTYPE="C",
        )
        self.profile_path = self.config / "clilane" / "profiles.json"
        self.hub_path = self.config / "clilane" / "hub.json"

    def tearDown(self) -> None:
        subprocess.run(
            [self.tmux_binary, "-L", self.socket, "-f", "/dev/null", "kill-server"],
            env=self.environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        clilane.TMUX_BINARY_OVERRIDE = None
        clilane.TMUX_SOCKET_OVERRIDE = None
        self.temporary.cleanup()

    def run_cli(self, *parts: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *parts],
            env=self.environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )

    def dump_command(self, output: Path) -> list[str]:
        body = (
            "import json,os,pathlib;"
            f"pathlib.Path({str(output)!r}).write_text(json.dumps(dict(os.environ),sort_keys=True))"
        )
        return [sys.executable, "-c", body]

    def write_profile(self, output: Path, mode: int = 0o600) -> None:
        write_json(
            self.profile_path,
            profile_document(
                {
                    "clean": profile_value(
                        command=self.dump_command(output),
                        inherit=["PROVIDER_AUTH_TOKEN"],
                        env_set={
                            "PATH": "/profile-only",
                            "SAFE_MODE": "clean",
                            "BARE_SEMI": ";",
                            "TRAILING_SEMI": "value;",
                            "BACKSLASH_SEMI": "value\\;",
                            "DOUBLE_BACKSLASH_SEMI": "value\\\\;",
                            "INNER_SEMI": "a;b",
                            "EMPTY_VALUE": "",
                            "QUOTED_VALUE": "a 'single' and \"double\"",
                            "WHITESPACE_VALUE": " first\nsecond\t ",
                            "UNICODE_VALUE": "snowman-☃",
                            "LEADING_DASH_VALUE": "-value",
                        },
                    )
                }
            ),
            mode,
        )

    def assert_clean_environment(self, output: Path) -> None:
        child = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(child["PROVIDER_AUTH_TOKEN"], "provider-allowed-sentinel")
        self.assertEqual(child["SAFE_MODE"], "clean")
        self.assertEqual(child["PATH"], "/profile-only")
        self.assertEqual(child["BARE_SEMI"], ";")
        self.assertEqual(child["TRAILING_SEMI"], "value;")
        self.assertEqual(child["BACKSLASH_SEMI"], "value\\;")
        self.assertEqual(child["DOUBLE_BACKSLASH_SEMI"], "value\\\\;")
        self.assertEqual(child["INNER_SEMI"], "a;b")
        self.assertEqual(child["EMPTY_VALUE"], "")
        self.assertEqual(child["QUOTED_VALUE"], "a 'single' and \"double\"")
        self.assertEqual(child["WHITESPACE_VALUE"], " first\nsecond\t ")
        self.assertEqual(child["UNICODE_VALUE"], "snowman-☃")
        self.assertEqual(child["LEADING_DASH_VALUE"], "-value")
        self.assertTrue(Path(child["CLILANE_TMUX_SOCKET"]).is_absolute())
        for key in (
            "TELEGRAM_BOT_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "CLOUD_TOKEN",
            "CUSTOM_TMUX_SENTINEL",
            "LC_NUMERIC",
            "TMUX_TMPDIR",
            "CLILANE_LEGACY_CUSTOM",
            "AGT_LEGACY_CUSTOM",
        ):
            self.assertNotIn(key, child)

    def assert_state_has_no_secret_values(self) -> None:
        for path in self.state.rglob("*"):
            if not path.is_file():
                continue
            payload = path.read_bytes()
            for value in (
                b"telegram-denied-sentinel",
                b"aws-denied-sentinel",
                b"cloud-denied-sentinel",
                b"tmux-denied-sentinel",
                b"provider-allowed-sentinel",
            ):
                self.assertNotIn(value, payload)

    def test_direct_profile_raw_and_hub_v2_child_environments(self) -> None:
        direct_output = self.root / "direct environment.json"
        self.write_profile(direct_output)
        direct = self.run_cli(
            "run",
            "--wait",
            "direct-clean",
            "--profile",
            "clean",
            "-C",
            str(self.project),
        )
        self.assertEqual(direct.returncode, 0, direct.stderr)
        self.assert_clean_environment(direct_output)
        self.assert_state_has_no_secret_values()
        self.assertEqual(self.run_cli("rm", "direct-clean").returncode, 0)

        semicolon_project = self.root / "project;"
        semicolon_project.mkdir()
        semicolon_output = self.root / "semicolon environment.json"
        self.write_profile(semicolon_output)
        semicolon = self.run_cli(
            "run",
            "semicolon-clean",
            "--wait",
            "--profile",
            "clean",
            "-C",
            str(semicolon_project),
        )
        self.assertEqual(semicolon.returncode, 0, semicolon.stderr)
        self.assert_clean_environment(semicolon_output)
        self.assertEqual(self.run_cli("rm", "semicolon-clean").returncode, 0)

        hook_child_output = self.root / "hook child environment.json"
        hook_output = self.root / "hook environment.json"
        self.write_profile(hook_child_output)
        hook_body = (
            "import json,os,pathlib;"
            f"pathlib.Path({str(hook_output)!r}).write_text(json.dumps(dict(os.environ)))"
        )
        hook = self.run_cli(
            "run",
            "hook-clean",
            "--wait",
            "--on-exit",
            f"{shlex.quote(sys.executable)} -c {shlex.quote(hook_body)}",
            "--profile",
            "clean",
            "-C",
            str(self.project),
        )
        self.assertEqual(hook.returncode, 0, hook.stderr)
        self.assert_clean_environment(hook_output)
        hook_environment = json.loads(hook_output.read_text(encoding="utf-8"))
        self.assertEqual(hook_environment["CLILANE_EXIT_CODE"], "0")
        self.assertEqual(hook_environment["CLILANE_SIGNAL"], "")
        self.assertEqual(self.run_cli("rm", "hook-clean").returncode, 0)

        raw_output = self.root / "raw environment.json"
        raw = self.run_cli(
            "run",
            "raw-legacy",
            "--wait",
            "-C",
            str(self.project),
            "--",
            *self.dump_command(raw_output),
        )
        self.assertEqual(raw.returncode, 0, raw.stderr)
        raw_child = json.loads(raw_output.read_text(encoding="utf-8"))
        self.assertEqual(raw_child["TELEGRAM_BOT_TOKEN"], "telegram-denied-sentinel")
        self.assertEqual(raw_child["CLOUD_TOKEN"], "cloud-denied-sentinel")
        self.assertEqual(raw_child["CLILANE_LEGACY_CUSTOM"], "clilane-preserved")
        self.assertEqual(raw_child["AGT_LEGACY_CUSTOM"], "agt-preserved")
        self.assertEqual(self.run_cli("rm", "raw-legacy").returncode, 0)

        hub_output = self.root / "hub environment.json"
        self.write_profile(hub_output)
        write_json(
            self.hub_path,
            {
                "schema_version": 2,
                "agents": [
                    {"name": "clean-hub", "profile": "clean", "dir": str(self.project)}
                ],
            },
        )
        old_socket = clilane.SOCKET
        try:
            clilane.SOCKET = self.socket
            clilane.TMUX_BINARY_OVERRIDE = None
            clilane.TMUX_SOCKET_OVERRIDE = None
            with mock.patch.dict(os.environ, self.environment, clear=True):
                clilane.ensure_server_available()
                clilane.ensure_hub_session()
                context = clilane.create_hub_context(None)
                preset = clilane.load_hub_presets(
                    str(self.hub_path),
                    allow_missing=False,
                    launch_environment=self.environment,
                    profiles_file=str(self.profile_path),
                )[0]
                task = clilane.launch_hub_preset(preset, "hub-clean", context)
                self.assertEqual(clilane.wait_task(task.id, 10), 0)
                clilane.remove_task(task.id, False, 1)
        finally:
            clilane.SOCKET = old_socket
        self.assert_clean_environment(hub_output)
        self.assert_state_has_no_secret_values()

    def test_rejected_profile_creates_no_artifacts(self) -> None:
        output = self.root / "unused.json"
        self.write_profile(output, mode=0o666)
        rejected = self.run_cli(
            "run",
            "rejected",
            "--profile",
            "clean",
            "-C",
            str(self.project),
        )
        self.assertNotEqual(rejected.returncode, 0)
        files = [path for path in self.state.rglob("*") if path.is_file()]
        self.assertEqual(files, [])
        probe = subprocess.run(
            [self.tmux_binary, "-L", self.socket, "-f", "/dev/null", "list-sessions"],
            env=self.environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(probe.returncode, 0)

    def test_environment_update_failure_rolls_back_allocated_artifacts(self) -> None:
        spec = clilane.complete_launch_spec(
            name="rollback-clean",
            cwd_value=str(self.project),
            command=["/bin/true"],
            wait=False,
            timeout=None,
            on_exit=None,
            environment={"PATH": "/profile-only"},
            profile="clean",
            provider="claude",
        )
        old_socket = clilane.SOCKET
        try:
            clilane.SOCKET = self.socket
            clilane.TMUX_BINARY_OVERRIDE = None
            clilane.TMUX_SOCKET_OVERRIDE = None
            with mock.patch.dict(os.environ, self.environment, clear=True), mock.patch.object(
                clilane,
                "set_task_environment",
                side_effect=clilane.CliLaneError("injected environment failure"),
            ):
                with self.assertRaisesRegex(
                    clilane.CliLaneError, "injected environment failure"
                ):
                    clilane.run_task(spec)
        finally:
            clilane.SOCKET = old_socket
        artifacts = [
            path
            for path in self.state.rglob("*")
            if path.is_file() and path.suffix in {".json", ".log", ".previous"}
        ]
        self.assertEqual(artifacts, [])
        probe = subprocess.run(
            [self.tmux_binary, "-L", self.socket, "-f", "/dev/null", "list-sessions"],
            env=self.environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(probe.returncode, 0)

    def test_clean_profile_opens_agent_view_without_tooling_path(self) -> None:
        from tests.hub_pty import _Terminal

        write_json(
            self.profile_path,
            profile_document(
                {
                    "clean": profile_value(
                        command=[sys.executable, "-c", "import time; time.sleep(30)"],
                        env_set={"PATH": "/profile-only"},
                    )
                }
            ),
        )
        started = self.run_cli(
            "run",
            "clean-agent-view",
            "--profile",
            "clean",
            "-C",
            str(self.project),
        )
        self.assertEqual(started.returncode, 0, started.stderr)
        attach_environment = {
            **self.environment,
            "TERM": "xterm-256color",
            "SSH_AUTH_SOCK": "/tmp/denied-agent.sock",
        }
        terminal = _Terminal(["attach", "clean-agent-view"], attach_environment)
        try:
            terminal.expect("LOCAL · clean-agent-view")
            mark = terminal.mark()
            terminal.send(b"\x11")
            terminal.expect("type message · Tab agent", mark)
            windows = subprocess.run(
                [
                    self.tmux_binary,
                    "-L",
                    self.socket,
                    "-f",
                    "/dev/null",
                    "list-windows",
                    "-a",
                    "-F",
                    "#{session_name}|#{window_name}",
                ],
                env=attach_environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            ).stdout.splitlines()
            session = next(
                line.split("|", 1)[0]
                for line in windows
                if line.endswith("|clean-agent-view")
            )
            secondary_output = self.root / "secondary environment.json"
            body = (
                "import json,os,pathlib;"
                f"pathlib.Path({str(secondary_output)!r}).write_text(json.dumps(dict(os.environ)))"
            )
            created = subprocess.run(
                [
                    self.tmux_binary,
                    "-L",
                    self.socket,
                    "-f",
                    "/dev/null",
                    "new-window",
                    "-d",
                    "-t",
                    f"{session}:",
                    "-c",
                    str(self.project),
                    sys.executable,
                    "-c",
                    body,
                ],
                env=attach_environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            deadline = time.monotonic() + 5
            while not secondary_output.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            secondary = json.loads(secondary_output.read_text(encoding="utf-8"))
            self.assertNotIn("SSH_AUTH_SOCK", secondary)
            terminal.send(b"\x11")
            self.assertEqual(terminal.wait(), 0)
        finally:
            terminal.close()
            self.run_cli("rm", "--force", "clean-agent-view")


if __name__ == "__main__":
    unittest.main()
