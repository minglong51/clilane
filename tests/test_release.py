from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "smoke.yml"
EXECUTABLE = ROOT / "bin" / "clilane"


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def step_script(name: str) -> str:
    lines = workflow_text().splitlines(keepends=True)
    marker = f"- name: {name}"
    for index, line in enumerate(lines):
        if line.strip() != marker:
            continue
        for run_index in range(index + 1, len(lines)):
            run_line = lines[run_index]
            if run_line.strip() != "run: |":
                continue
            indentation = len(run_line) - len(run_line.lstrip())
            body = []
            for body_line in lines[run_index + 1 :]:
                if body_line.strip():
                    body_indentation = len(body_line) - len(body_line.lstrip())
                    if body_indentation <= indentation:
                        break
                body.append(body_line)
            return textwrap.dedent("".join(body))
        break
    raise AssertionError(f"workflow step not found: {name}")


def job_block(name: str) -> str:
    text = workflow_text()
    match = re.search(rf"(?m)^  {re.escape(name)}:\n", text)
    if match is None:
        raise AssertionError(f"workflow job not found: {name}")
    following = re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", text[match.end() :])
    end = len(text) if following is None else match.end() + following.start()
    return text[match.start() : end]


def run_script(
    script: str,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.update(environment)
    return subprocess.run(
        ["bash", "-c", script],
        cwd=cwd,
        env=merged,
        text=True,
        capture_output=True,
        check=False,
    )


def initialize_repository(path: Path, version: str = "1.2.3") -> str:
    executable = path / "bin" / "clilane"
    executable.parent.mkdir(parents=True)
    executable.write_text(
        "#!/bin/sh\nprintf 'clilane %s\\n'\n" % version,
        encoding="utf-8",
    )
    executable.chmod(0o755)
    (path / "README.md").write_text("release fixture\n", encoding="utf-8")
    commands = (
        ("git", "init", "-q"),
        ("git", "config", "user.name", "Release Test"),
        ("git", "config", "user.email", "release@example.invalid"),
        ("git", "add", "bin/clilane", "README.md"),
        ("git", "commit", "-q", "-m", "release fixture"),
        ("git", "tag", f"v{version}"),
    )
    for command in commands:
        subprocess.run(command, cwd=path, check=True, capture_output=True, text=True)
    return subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def output_values(path: Path) -> dict[str, str]:
    return dict(
        line.split("=", 1)
        for line in path.read_text(encoding="utf-8").splitlines()
    )


class WorkflowStructureTests(unittest.TestCase):
    def test_tag_trigger_and_conditional_cancellation(self) -> None:
        text = workflow_text()
        header = text.split("permissions:", 1)[0]
        self.assertIn("pull_request:", header)
        self.assertRegex(header, r"(?m)^    branches:\n      - main$")
        self.assertRegex(header, r'(?m)^    tags:\n      - "v\*"$')
        self.assertIn(
            "cancel-in-progress: ${{ !startsWith(github.ref, 'refs/tags/') }}",
            text,
        )
        cancellable = lambda ref: not ref.startswith("refs/tags/")
        self.assertTrue(cancellable("refs/heads/main"))
        self.assertTrue(cancellable("refs/pull/12/merge"))
        self.assertFalse(cancellable("refs/tags/v1.2.3"))

    def test_release_waits_for_full_existing_matrix(self) -> None:
        smoke = job_block("smoke")
        release = job_block("release")
        self.assertIn("- os: macos-15", smoke)
        self.assertIn("- os: ubuntu-latest", smoke)
        self.assertIn("python3 -m unittest -v tests.test_profiles", smoke)
        self.assertIn("python3 -m unittest -v tests.test_release", smoke)
        self.assertRegex(release, r"(?m)^    needs: smoke$")
        self.assertIn(
            "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')",
            release,
        )

    def test_write_permission_is_release_job_scoped(self) -> None:
        text = workflow_text()
        before_jobs = text.split("jobs:", 1)[0]
        release = job_block("release")
        self.assertRegex(before_jobs, r"(?m)^permissions:\n  contents: read$")
        self.assertNotIn("contents: write", before_jobs)
        self.assertRegex(release, r"(?m)^    permissions:\n      contents: write$")
        self.assertEqual(text.count("contents: write"), 1)

    def test_executable_version_is_not_repeated_in_workflow(self) -> None:
        match = re.search(r'(?m)^VERSION = "([0-9]+\.[0-9]+\.[0-9]+)"$', EXECUTABLE.read_text())
        self.assertIsNotNone(match)
        self.assertNotIn(match.group(1), workflow_text())
        self.assertIn('CLILANE_VERSION=%s\\n', workflow_text())

    def test_publish_is_one_non_clobbering_create_operation(self) -> None:
        release = job_block("release")
        publish = step_script("Publish immutable release")
        self.assertEqual(release.count("gh release create"), 1)
        self.assertNotIn("gh release upload", release)
        self.assertNotIn("gh release edit", release)
        self.assertNotIn("gh release delete", release)
        self.assertNotIn("--clobber", release)
        self.assertIn('"$RELEASE_ARTIFACT" "$RELEASE_CHECKSUM"', publish)
        self.assertIn("--verify-tag", publish)
        self.assertIn('refs/tags/', workflow_text())
        self.assertNotRegex(release.lower(), r"brew (bump|install|upgrade|tap)")


class ReleaseIdentityTests(unittest.TestCase):
    def test_matching_tag_version_and_commit_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha = initialize_repository(root)
            output = root / "output"
            result = run_script(
                step_script("Validate release identity"),
                root,
                {
                    "GITHUB_REF": "refs/tags/v1.2.3",
                    "GITHUB_REF_NAME": "v1.2.3",
                    "GITHUB_SHA": sha,
                    "GITHUB_OUTPUT": str(output),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                output_values(output),
                {"version": "1.2.3", "tag": "v1.2.3"},
            )

    def test_mismatching_tag_and_version_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha = initialize_repository(root)
            result = run_script(
                step_script("Validate release identity"),
                root,
                {
                    "GITHUB_REF": "refs/tags/v9.9.9",
                    "GITHUB_REF_NAME": "v9.9.9",
                    "GITHUB_SHA": sha,
                    "GITHUB_OUTPUT": str(root / "output"),
                },
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match executable version", result.stderr)

    def test_tag_ref_must_resolve_to_checked_out_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / "README.md").write_text("later commit\n", encoding="utf-8")
            subprocess.run(
                ("git", "add", "README.md"),
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ("git", "commit", "-q", "-m", "later"),
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            sha = subprocess.run(
                ("git", "rev-parse", "HEAD"),
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            result = run_script(
                step_script("Validate release identity"),
                root,
                {
                    "GITHUB_REF": "refs/tags/v1.2.3",
                    "GITHUB_REF_NAME": "v1.2.3",
                    "GITHUB_SHA": sha,
                    "GITHUB_OUTPUT": str(root / "output"),
                },
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not resolve to checked-out commit", result.stderr)


class ReleaseArtifactTests(unittest.TestCase):
    def test_archive_is_deterministic_exact_and_receipted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            runner_temp = Path(directory) / "runner"
            root.mkdir()
            runner_temp.mkdir()
            sha = initialize_repository(root)
            output = Path(directory) / "output"
            result = run_script(
                step_script("Build deterministic release assets"),
                root,
                {
                    "GITHUB_SHA": sha,
                    "GITHUB_OUTPUT": str(output),
                    "RELEASE_VERSION": "1.2.3",
                    "RUNNER_TEMP": str(runner_temp),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            values = output_values(output)
            artifact = Path(values["artifact"])
            checksum = Path(values["checksum"])
            verification = runner_temp / "clilane-1.2.3.tar.gz.verification"
            self.assertEqual(artifact.read_bytes(), verification.read_bytes())
            digest, name = checksum.read_text(encoding="ascii").split()
            self.assertEqual(digest, hashlib.sha256(artifact.read_bytes()).hexdigest())
            self.assertEqual(name, artifact.name)
            with tarfile.open(artifact, "r:gz") as archive:
                member = archive.getmember("clilane-1.2.3/bin/clilane")
                self.assertEqual(member.mode, 0o755)
                extracted = archive.extractfile(member)
                self.assertIsNotNone(extracted)
                self.assertEqual(extracted.read(), (root / "bin" / "clilane").read_bytes())


class ReleaseConflictTests(unittest.TestCase):
    def fake_gh(self, root: Path) -> Path:
        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        executable = fake_bin / "gh"
        executable.write_text(
            "#!/usr/bin/env python3\n"
            "import os\n"
            "import sys\n"
            "if os.environ.get('FAKE_GH_FAIL'):\n"
            "    raise SystemExit(2)\n"
            "sys.stdout.write(os.environ.get('FAKE_RELEASES_JSON', '[[]]'))\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        return fake_bin

    def conflict_result(
        self,
        root: Path,
        releases: list[list[dict[str, object]]],
        fail: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        fake_bin = self.fake_gh(root)
        environment = {
            "FAKE_RELEASES_JSON": json.dumps(releases),
            "GITHUB_REPOSITORY": "owner/repository",
            "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
            "RELEASE_ARTIFACT_NAME": "clilane-1.2.3.tar.gz",
            "RELEASE_CHECKSUM_NAME": "clilane-1.2.3.tar.gz.sha256",
            "RELEASE_TAG": "v1.2.3",
            "RUNNER_TEMP": str(root),
        }
        if fail:
            environment["FAKE_GH_FAIL"] = "1"
        return run_script(
            step_script("Refuse release conflicts"),
            root,
            environment,
        )

    def test_empty_release_list_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.conflict_result(Path(directory), [[]])
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_release_or_draft_fails(self) -> None:
        for draft in (False, True):
            with self.subTest(draft=draft), tempfile.TemporaryDirectory() as directory:
                release = {"tag_name": "v1.2.3", "draft": draft, "assets": []}
                result = self.conflict_result(Path(directory), [[release]])
                self.assertNotEqual(result.returncode, 0)
                expected = "existing draft" if draft else "existing release"
                self.assertIn(expected, result.stderr)

    def test_conflicting_artifact_or_checksum_fails(self) -> None:
        for name in ("clilane-1.2.3.tar.gz", "clilane-1.2.3.tar.gz.sha256"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                release = {
                    "tag_name": "v1.2.2",
                    "draft": False,
                    "assets": [{"name": name}],
                }
                result = self.conflict_result(Path(directory), [[release]])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"existing asset {name}", result.stderr)

    def test_release_inventory_failure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.conflict_result(Path(directory), [[]], fail=True)
            self.assertNotEqual(result.returncode, 0)

    def test_publish_invokes_one_create_with_both_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            log = root / "gh.json"
            executable = fake_bin / "gh"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import json\n"
                "import os\n"
                "import sys\n"
                "with open(os.environ['FAKE_GH_LOG'], 'a', encoding='utf-8') as handle:\n"
                "    handle.write(json.dumps(sys.argv[1:]) + '\\n')\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            artifact = root / "clilane-1.2.3.tar.gz"
            checksum = root / "clilane-1.2.3.tar.gz.sha256"
            artifact.touch()
            checksum.touch()
            result = run_script(
                step_script("Publish immutable release"),
                root,
                {
                    "FAKE_GH_LOG": str(log),
                    "GITHUB_REPOSITORY": "owner/repository",
                    "GITHUB_SHA": "a" * 40,
                    "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                    "RELEASE_ARTIFACT": str(artifact),
                    "RELEASE_CHECKSUM": str(checksum),
                    "RELEASE_TAG": "v1.2.3",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][:3], ["release", "create", "v1.2.3"])
            self.assertIn(str(artifact), calls[0])
            self.assertIn(str(checksum), calls[0])
            self.assertIn("--verify-tag", calls[0])


if __name__ == "__main__":
    unittest.main()
