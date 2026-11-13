from __future__ import annotations

import concurrent.futures
import importlib.machinery
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "bin" / "clilane"
LOADER = importlib.machinery.SourceFileLoader("clilane_reliability_test", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
clilane = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = clilane
LOADER.exec_module(clilane)


@unittest.skipUnless(shutil.which("tmux"), "tmux is required")
class JobReliabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="clr-", dir="/tmp")
        self.root = Path(self.temporary.name).resolve()
        self.project = self.root / "project"
        self.project.mkdir()
        self.socket = f"clr-{uuid.uuid4().hex[:10]}"
        self.tmux_root = self.root / "tmux"
        self.tmux_root.mkdir(mode=0o700)
        self.environment = {key: value for key, value in os.environ.items() if key in {
            "HOME", "PATH", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "TMPDIR",
        }}
        self.environment.update(
            CLILANE_STATE_HOME=str(self.root / "state"), CLILANE_TMUX_SOCKET=self.socket,
            TMUX_TMPDIR=str(self.tmux_root), XDG_CONFIG_HOME=str(self.root / "config"),
            TERM="xterm-256color",
        )
        self.patches = [
            mock.patch.dict(os.environ, self.environment, clear=True),
            mock.patch.object(clilane, "SOCKET", self.socket),
            mock.patch.object(clilane, "TMUX_BINARY_OVERRIDE", None),
            mock.patch.object(clilane, "TMUX_SOCKET_OVERRIDE", None),
        ]
        for patch in self.patches:
            patch.start()
        self.contexts: list[str] = []

    def tearDown(self) -> None:
        try:
            for task in clilane.list_tasks():
                clilane.remove_task(task.id, True, 0)
            for context in self.contexts:
                clilane.discard_unattached_hub_context(context)
        finally:
            for patch in reversed(self.patches):
                patch.stop()
            self.temporary.cleanup()

    def cli(self, *parts: str, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *parts], env=environment or self.environment,
            cwd=self.project, capture_output=True, text=True, timeout=20,
        )

    def launch(self, name: str, command: list[str], *options: str) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        result = self.cli("run", name, "--json", *options, "--", *command)
        return result, json.loads(result.stdout)

    def context(self) -> str:
        context = clilane.create_hub_context(None)
        self.contexts.append(context)
        return context

    def counter_command(self, code: int = 0, delay: float = 0) -> list[str]:
        return [sys.executable, "-c", (
            "import pathlib,time;"
            f"p=pathlib.Path({str(self.root / 'counter')!r});"
            "p.open('a').write('x');"
            f"time.sleep({delay});raise SystemExit({code})"
        )]

    def test_recorded_result_and_output_survive_terminal_loss(self) -> None:
        result, data = self.launch("finished", ["/bin/sh", "-c", "echo retained-output; exit 7"], "--wait")
        self.assertEqual(result.returncode, 7, result.stderr)
        original = clilane.resolve_task(str(data["id"]), exact_id=True)
        saved = clilane.read_history(clilane.history_path(original.id, original.log))
        self.assertEqual(saved["exit_code"], 7)
        self.assertTrue(saved["terminal_complete"])
        clilane.tmux(["kill-session", "-t", original.session])
        archived = clilane.resolve_task(original.id, include_history=True, exact_id=True)
        self.assertTrue(archived.archived)
        self.assertEqual(archived.pane, "")
        self.assertEqual(archived.state, "failed")
        self.assertIn("retained-output", self.cli("read", original.id, "--all").stdout)
        self.assertEqual(self.cli("wait", original.id).returncode, 7)

    def test_supervisor_death_does_not_invent_a_child_receipt(self) -> None:
        result, data = self.launch("lost", ["/bin/sh", "-c", "echo started; sleep 30"])
        self.assertEqual(result.returncode, 0, result.stderr)
        task = clilane.resolve_task(str(data["id"]), exact_id=True)
        os.kill(task.pid, signal.SIGKILL)
        clilane.terminate_session_descendants(task.pid, 0, task.process_started)
        clilane.tmux(["kill-session", "-t", task.session])
        archived = clilane.resolve_task(task.id, include_history=True, exact_id=True)
        self.assertEqual(archived.state, "unknown")
        self.assertIsNone(archived.exit_code)
        with self.assertRaisesRegex(clilane.CliLaneError, "unknown"):
            clilane.resume_hub_task(archived, [], "")
        self.assertNotEqual(self.cli("wait", task.id).returncode, 0)

    def test_failed_recovery_keeps_original_record_and_output(self) -> None:
        result, data = self.launch("original", ["/bin/echo", "preserved"], "--wait")
        self.assertEqual(result.returncode, 0, result.stderr)
        task = clilane.resolve_task(str(data["id"]), exact_id=True)
        context = self.context()
        history = clilane.history_path(task.id, task.log)
        before = history.read_bytes(), Path(task.log).read_bytes()
        self.project.rename(self.root / "moved")
        with self.assertRaisesRegex(clilane.CliLaneError, "not a directory"):
            clilane.resume_hub_task(task, [], context)
        self.assertEqual(before, (history.read_bytes(), Path(task.log).read_bytes()))
        self.assertEqual(clilane.resolve_task(task.id, exact_id=True).pane, task.pane)

    def test_recovery_creates_linked_attempt_without_replacing_original(self) -> None:
        result, data = self.launch("original", ["/bin/echo", "retained"], "--wait")
        self.assertEqual(result.returncode, 0, result.stderr)
        task = clilane.resolve_task(str(data["id"]), exact_id=True)
        output = Path(task.log).read_bytes()
        resumed = clilane.resume_hub_task(task, [], self.context())
        self.assertNotEqual(resumed.id, task.id)
        self.assertEqual(resumed.resumed_from, task.id)
        self.assertEqual(clilane.wait_task(resumed.id, 5), 0)
        self.assertEqual(clilane.resolve_task(task.id, exact_id=True).id, task.id)
        self.assertEqual(Path(task.log).read_bytes(), output)
        self.assertNotEqual(resumed.log, task.log)

    def test_stale_snapshots_cannot_erase_receipts_or_newer_bindings(self) -> None:
        _, data = self.launch("snapshot", ["/bin/echo", "done"], "--wait")
        task = clilane.resolve_task(str(data["id"]), exact_id=True)
        clilane.update_history(task.id, task.log, {"binding": {"revision": 2, "final_id": "recorded"}})
        clilane.update_history(task.id, task.log, {
            "exit_code": None, "terminal_complete": False, "committed": False,
            "binding": {"revision": 1, "final_id": None},
        })
        saved = clilane.read_history(clilane.history_path(task.id, task.log))
        self.assertEqual(saved["exit_code"], 0)
        self.assertTrue(saved["terminal_complete"] and saved["committed"])
        self.assertEqual(saved["binding"]["final_id"], "recorded")
        clilane.update_history(task.id, task.log, {"binding": {"revision": 3, "final_id": None}})
        self.assertIsNone(clilane.read_history(clilane.history_path(task.id, task.log))["binding"]["final_id"])

    def test_retry_returns_same_job_and_result_without_repeating_hook(self) -> None:
        command = self.counter_command(code=7)
        hook = f"printf x >> {self.root / 'hook-count'}"
        options = ("--request-id", "occurrence:2026-11-08", "--wait", "--on-exit", hook)
        first, original = self.launch("once", command, *options)
        replay, repeated = self.launch("once", command, *options)
        self.assertEqual((first.returncode, replay.returncode), (7, 7))
        self.assertEqual(original["id"], repeated["id"])
        self.assertFalse(original["reused"])
        self.assertTrue(repeated["reused"])
        self.assertEqual(repeated["state"], "failed")
        self.assertEqual((self.root / "counter").read_text(), "x")
        self.assertEqual((self.root / "hook-count").read_text(), "x")
        task = clilane.resolve_task(str(original["id"]), exact_id=True)
        clilane.tmux(["kill-session", "-t", task.session])
        replay, archived = self.launch("once", command, *options)
        self.assertEqual(replay.returncode, 7)
        self.assertEqual(archived["id"], original["id"])
        self.assertEqual((self.root / "counter").read_text(), "x")

    def test_concurrent_request_retries_launch_one_process(self) -> None:
        command = self.counter_command(delay=0.5)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: self.launch("once", command, "--request-id", "concurrent", "--wait"), range(3)))
        self.assertEqual({result.returncode for result, _ in results}, {0})
        self.assertEqual(len({data["id"] for _, data in results}), 1)
        self.assertEqual(sum(not data["reused"] for _, data in results), 1)
        self.assertEqual((self.root / "counter").read_text(), "x")

    def test_changed_explicit_intent_conflicts_but_observer_options_do_not(self) -> None:
        command = self.counter_command()
        _, original = self.launch("once", command, "--request-id", "bound", "--wait")
        for name, changed, options in (
            ("different", command, ()),
            ("once", ["/bin/echo", "different"], ()),
            ("once", command, ("-C", str(self.root))),
            ("once", command, ("--on-exit", "echo different")),
        ):
            with self.subTest(name=name, options=options):
                result, data = self.launch(name, changed, "--request-id", "bound", *options)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(data["error"]["code"], "request_conflict")
                self.assertEqual(data["task_id"], original["id"])
        result, data = self.launch("once", command, "--request-id", "bound", "--wait", "--timeout", "1")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(data["id"], original["id"])
        self.assertEqual((self.root / "counter").read_text(), "x")

    def test_profile_and_environment_are_bound_by_first_launch(self) -> None:
        profiles = self.root / "config" / "clilane" / "profiles.json"
        profiles.parent.mkdir(parents=True)
        output = self.root / "setting"
        profiles.write_text(json.dumps({"schema_version": 1, "profiles": {"original": {
            "provider": "codex", "command": [sys.executable, "-c", f"import os,pathlib;pathlib.Path({str(output)!r}).write_text(os.environ['BOUND_SETTING'])"],
            "cwd": {"mode": "explicit"}, "env": {"inherit": ["BOUND_SETTING"], "set": {}},
        }}}))
        profiles.chmod(0o600)
        self.environment["BOUND_SETTING"] = "first-private-value"
        args = ("run", "profile-job", "--request-id", "profile-occurrence", "--json", "--wait", "--profile", "original", "-C", str(self.project))
        first = self.cli(*args)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        original = json.loads(first.stdout)
        profiles.unlink()
        self.environment["BOUND_SETTING"] = "changed-private-value"
        replay = self.cli(*args)
        self.assertEqual(replay.returncode, 0, replay.stdout + replay.stderr)
        self.assertEqual(json.loads(replay.stdout)["id"], original["id"])
        self.assertEqual(output.read_text(), "first-private-value")
        claim = next((self.root / "state" / "requests").glob("*.json")).read_text()
        self.assertNotIn("private-value", claim)
        self.assertNotIn("profile-occurrence", claim)
        self.assertNotIn("BOUND_SETTING", claim)

    def test_cleanup_keeps_request_claim_and_uuid_name_cannot_redirect_retry(self) -> None:
        command = self.counter_command()
        _, original = self.launch("once", command, "--request-id", "retained", "--wait")
        self.assertEqual(self.cli("clean").returncode, 0)
        _, replacement = self.launch(str(original["id"]), ["/bin/echo", "other job"], "--wait")
        self.assertNotEqual(original["id"], replacement["id"])
        retry, data = self.launch("once", command, "--request-id", "retained", "--wait")
        self.assertEqual(retry.returncode, 1)
        self.assertEqual(data["error"]["code"], "request_unavailable")
        self.assertEqual(data["task_id"], original["id"])
        with self.assertRaises(clilane.CliLaneError):
            clilane.wait_task_result(str(original["id"]), 1, exact_id=True)
        self.assertEqual((self.root / "counter").read_text(), "x")

    def test_pre_metadata_failure_retains_claim_and_never_relaunches(self) -> None:
        command = self.counter_command()
        request = clilane.parse_run_request(["once", "--request-id", "interrupted", "--", *command])
        with mock.patch.object(clilane, "write_record", side_effect=OSError("injected metadata failure")):
            with self.assertRaises(clilane.LaunchRequestError) as caught:
                clilane.run_requested_task(request, self.environment, str(self.project))
        original_id = caught.exception.task_id
        self.assertIsNotNone(original_id)
        self.assertIn(original_id, str(caught.exception))
        replay, data = self.launch("once", command, "--request-id", "interrupted")
        self.assertEqual(replay.returncode, 1)
        self.assertEqual(data["task_id"], original_id)
        self.assertFalse((self.root / "counter").exists())
        self.assertEqual(clilane.list_tasks(), [])

    def test_post_dispatch_failure_keeps_the_same_attempt(self) -> None:
        command = self.counter_command(delay=10)
        request = clilane.parse_run_request(["once", "--request-id", "dispatched", "--", *command])
        original_tmux = clilane.tmux

        def fail_commit(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if "@agt_committed" in arguments and arguments[-1] == "1":
                deadline = time.monotonic() + 5
                while not (self.root / "counter").exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue((self.root / "counter").exists())
                raise clilane.CliLaneError("injected lost commit response")
            return original_tmux(arguments, **kwargs)

        with mock.patch.object(clilane, "tmux", side_effect=fail_commit):
            with self.assertRaises(clilane.LaunchRequestError) as caught:
                clilane.run_requested_task(request, self.environment, str(self.project))
        replay, data = self.launch("once", command, "--request-id", "dispatched")
        self.assertEqual(replay.returncode, 0, replay.stdout + replay.stderr)
        self.assertEqual(data["id"], caught.exception.task_id)
        self.assertTrue(data["reused"])
        self.assertEqual((self.root / "counter").read_text(), "x")

    def test_json_wait_reports_timeout_without_starting_again(self) -> None:
        command = self.counter_command(delay=2)
        result, initial = self.launch("slow", command, "--request-id", "slow-occurrence", "--wait", "--timeout", "0.05")
        self.assertEqual(result.returncode, 124)
        self.assertTrue(initial["timed_out"])
        self.assertEqual(initial["state"], "running")
        result, final = self.launch("slow", command, "--request-id", "slow-occurrence", "--wait")
        self.assertEqual(result.returncode, 0)
        self.assertFalse(final["timed_out"])
        self.assertEqual(final["state"], "succeeded")
        self.assertEqual(final["id"], initial["id"])
        self.assertEqual((self.root / "counter").read_text(), "x")

    def test_same_key_on_another_socket_conflicts_without_launch(self) -> None:
        command = self.counter_command()
        _, original = self.launch("once", command, "--request-id", "shared-state", "--wait")
        other = dict(self.environment, CLILANE_TMUX_SOCKET=self.socket + "-other")
        result = self.cli("run", "once", "--request-id", "shared-state", "--json", "--", *command, environment=other)
        data = json.loads(result.stdout)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(data["error"]["code"], "request_socket_conflict")
        self.assertEqual(data["task_id"], original["id"])
        self.assertEqual(json.loads(self.cli("list", "--json", environment=other).stdout), [])
        self.assertEqual((self.root / "counter").read_text(), "x")


if __name__ == "__main__":
    unittest.main()
