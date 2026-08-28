#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import selectors
import secrets
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn, Sequence


ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE_MANIFEST_PATH = ROOT / "docs/designs/provider-executables.json"
COLLECTORS = {
    "claude": ROOT / "scripts/collect_claude_evidence.py",
    "codex": ROOT / "scripts/collect_codex_evidence.py",
    "kimi": ROOT / "scripts/collect_kimi_evidence.py",
}
PROVIDER_VERSIONS = {"claude": "2.1.245", "codex": "0.149.1", "kimi": "0.38.0"}
PROBE_PROMPT = (
    "Reply with exactly CLILANE_PROBE_OK and no other text. Do not call tools."
)
EXPECTED_RESPONSE = "CLILANE_PROBE_OK"
CAPTURE_ID_PATTERN = re.compile(r"capture-[a-z0-9][a-z0-9-]{0,95}")
PASSTHROUGH_ENVIRONMENT = (
    "HOME",
    "PATH",
    "TMPDIR",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "CODEX_HOME",
)
PER_CAPTURE_BYTES = 256 * 1024
AGGREGATE_BYTES = 1024 * 1024
COLLECTOR_TIMEOUT_SECONDS = 90
INITIALIZE_TIMEOUT_SECONDS = 5.0
SESSION_TIMEOUT_SECONDS = 20.0
TURN_TIMEOUT_SECONDS = 60.0
EXIT_TIMEOUT_SECONDS = 5.0
ABORT_TIMEOUT_SECONDS = 3.0
COLLECTOR_SIGNAL_TIMEOUT_SECONDS = 15.0
CLAUDE_HOOK_TIMEOUT_SECONDS = 5
CLAUDE_MODEL = "claude-haiku-4-5-20251001"
CLAUDE_SESSION_ID = "00000000-0000-4000-8000-000000000245"
CLAUDE_MAX_BUDGET_USD = "0.10"
CLAUDE_CAPTURE_SUFFIXES = ("session-start", "prompt-submit", "stop")
MAX_LINE_BYTES = 64 * 1024
MAX_STDOUT_BYTES = 192 * 1024
MAX_STDERR_BYTES = 32 * 1024
MAX_INPUT_BYTES = 16 * 1024
MAX_MESSAGE_COUNT = 256
MAX_IDENTIFIER_CHARACTERS = 256
MAX_CONTROL_BYTES = 1024
MAX_CONTROL_EVENTS = 4
READ_CHUNK_BYTES = 16 * 1024
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
SOURCE_INTERFACES = {
    "claude": ("2.1.245", "claude-native-hook"),
    "codex": ("0.149.1", "codex-app-server"),
    "kimi": ("0.38.0", "kimi-acp"),
}
CODEX_TARGETS = {
    ("Darwin", "arm64"): ("codex-darwin-arm64", "aarch64-apple-darwin"),
    ("Darwin", "x86_64"): ("codex-darwin-x64", "x86_64-apple-darwin"),
    ("Linux", "aarch64"): ("codex-linux-arm64", "aarch64-unknown-linux-musl"),
    ("Linux", "x86_64"): ("codex-linux-x64", "x86_64-unknown-linux-musl"),
}


class ProbeError(Exception):
    pass


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


def _load_provider_capture() -> Any:
    loaded = sys.modules.get("provider_capture")
    if loaded is not None:
        return loaded
    path = ROOT / "scripts/provider_capture.py"
    spec = importlib.util.spec_from_file_location("provider_capture", path)
    if spec is None or spec.loader is None:
        raise ProbeError("capture-engine-unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise ProbeError("capture-engine-unavailable") from error
    finally:
        sys.dont_write_bytecode = previous
    return module


@dataclass(frozen=True)
class ProbeConfig:
    provider: str
    capture_root: Path
    capture_id: str
    provider_executable: Path
    workspace: Path
    config_dir: Path | None = None


@dataclass(frozen=True)
class ProbeResult:
    provider: str
    provider_version: str
    message_count: int
    stdout_bytes: int


@dataclass
class PinnedExecutable:
    path: Path
    sha256: str
    metadata: tuple[int, int, int, int]
    descriptor: int | None = None
    stage_parent_fd: int | None = None
    stage_directory_fd: int | None = None
    stage_name: str | None = None
    stage_directory_identity: tuple[int, int] | None = None


def _reject_constant(_value: str) -> NoReturn:
    raise ProbeError("protocol-json-invalid")


def _bounded_integer(value: str) -> int:
    if len(value) > 20:
        raise ProbeError("protocol-json-invalid")
    return int(value)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProbeError("protocol-json-invalid")
        result[key] = value
    return result


def strict_message(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_int=_bounded_integer,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, ProbeError) as error:
        raise ProbeError("protocol-json-invalid") from error
    if type(value) is not dict:
        raise ProbeError("protocol-message-invalid")
    return value


def current_platform() -> str:
    machine = platform.machine()
    if machine == "aarch64":
        machine = "arm64"
    return f"{platform.system().lower()}-{machine}"


def _file_metadata(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _read_manifest(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > 16 * 1024
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise ProbeError("executable-manifest-invalid")
        raw = bytearray()
        while len(raw) <= 16 * 1024:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, 16 * 1024 + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(raw) > 16 * 1024
            or len(raw) != before.st_size
            or _file_metadata(after) != _file_metadata(before)
        ):
            raise ProbeError("executable-manifest-invalid")
        return bytes(raw)
    except OSError as error:
        raise ProbeError("executable-manifest-invalid") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def load_executable_manifest(path: Path = EXECUTABLE_MANIFEST_PATH) -> dict[str, str]:
    raw = _read_manifest(path)
    manifest = strict_message(raw)
    if set(manifest) != {"platform", "providers", "schema_version"}:
        raise ProbeError("executable-manifest-invalid")
    if manifest["schema_version"] != 1 or manifest["platform"] != current_platform():
        raise ProbeError("executable-manifest-invalid")
    entries = manifest["providers"]
    if type(entries) is not list:
        raise ProbeError("executable-manifest-invalid")
    expected: dict[str, str] = {}
    for entry in entries:
        if type(entry) is not dict or set(entry) != {
            "executable_sha256",
            "provider",
            "provider_version",
            "source_interface",
        }:
            raise ProbeError("executable-manifest-invalid")
        provider = entry["provider"]
        if type(provider) is not str or provider not in SOURCE_INTERFACES:
            raise ProbeError("executable-manifest-invalid")
        version, source_interface = SOURCE_INTERFACES[provider]
        digest = entry["executable_sha256"]
        if (
            provider in expected
            or entry["provider_version"] != version
            or entry["source_interface"] != source_interface
            or type(digest) is not str
            or SHA256_PATTERN.fullmatch(digest) is None
            or len(set(digest)) == 1
        ):
            raise ProbeError("executable-manifest-invalid")
        expected[provider] = digest
    if set(expected) != set(SOURCE_INTERFACES):
        raise ProbeError("executable-manifest-invalid")
    canonical = (
        json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if raw != canonical:
        raise ProbeError("executable-manifest-invalid")
    return expected


def _codex_native_path(launcher: Path) -> Path:
    resolved = launcher.resolve(strict=True)
    if resolved.name != "codex.js":
        return resolved
    target = CODEX_TARGETS.get((platform.system(), platform.machine()))
    if target is None:
        raise ProbeError("provider-platform-unsupported")
    package_name, triple = target
    package_root = resolved.parent.parent
    candidates = (
        package_root
        / "node_modules"
        / "@openai"
        / package_name
        / "vendor"
        / triple
        / "bin"
        / "codex",
        package_root / "vendor" / triple / "bin" / "codex",
    )
    for candidate in candidates:
        try:
            return candidate.resolve(strict=True)
        except OSError:
            continue
    raise ProbeError("provider-native-executable-not-found")


def _hash_descriptor(descriptor: int) -> tuple[str, tuple[int, int, int, int]]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o111 == 0:
        raise ProbeError("provider-executable-invalid")
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, READ_CHUNK_BYTES, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    if _file_metadata(after) != _file_metadata(before):
        raise ProbeError("provider-executable-changed")
    return digest.hexdigest(), _file_metadata(after)


def _hash_executable(path: Path) -> PinnedExecutable:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        digest, metadata = _hash_descriptor(descriptor)
        return PinnedExecutable(path=path, sha256=digest, metadata=metadata)
    except OSError as error:
        raise ProbeError("provider-executable-invalid") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _stage_pinned_descriptor(
    source_descriptor: int,
    source_metadata: tuple[int, int, int, int],
    expected_sha256: str,
    parent: Path,
) -> PinnedExecutable:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    parent_fd: int | None = None
    stage_directory_fd: int | None = None
    writer: int | None = None
    stage_descriptor: int | None = None
    stage_name: str | None = None
    pinned: PinnedExecutable | None = None
    try:
        parent_fd = os.open(parent, directory_flags)
        parent_metadata = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.getuid()
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        ):
            raise ProbeError("provider-stage-unsafe")
        for _attempt in range(8):
            candidate = f".clilane-provider-stage-{secrets.token_hex(16)}"
            try:
                os.mkdir(candidate, 0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            stage_name = candidate
            break
        if stage_name is None:
            raise ProbeError("provider-stage-unavailable")
        stage_directory_fd = os.open(stage_name, directory_flags, dir_fd=parent_fd)
        stage_directory_metadata = os.fstat(stage_directory_fd)
        if (
            not stat.S_ISDIR(stage_directory_metadata.st_mode)
            or stage_directory_metadata.st_uid != os.getuid()
            or stat.S_IMODE(stage_directory_metadata.st_mode) != 0o700
        ):
            raise ProbeError("provider-stage-unsafe")
        writer = os.open(
            "provider",
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=stage_directory_fd,
        )
        digest = hashlib.sha256()
        offset = 0
        while True:
            chunk = os.pread(source_descriptor, READ_CHUNK_BYTES, offset)
            if not chunk:
                break
            digest.update(chunk)
            written_offset = 0
            while written_offset < len(chunk):
                written = os.write(writer, chunk[written_offset:])
                if written < 1:
                    raise ProbeError("provider-stage-write-failed")
                written_offset += written
            offset += len(chunk)
        if _file_metadata(os.fstat(source_descriptor)) != source_metadata:
            raise ProbeError("provider-executable-changed")
        if digest.hexdigest() != expected_sha256:
            raise ProbeError("provider-executable-changed")
        os.fchmod(writer, 0o500)
        os.fsync(writer)
        written_metadata = os.fstat(writer)
        if (
            not stat.S_ISREG(written_metadata.st_mode)
            or written_metadata.st_uid != os.getuid()
            or stat.S_IMODE(written_metadata.st_mode) != 0o500
            or written_metadata.st_nlink != 1
            or written_metadata.st_size != source_metadata[2]
        ):
            raise ProbeError("provider-stage-unsafe")
        os.close(writer)
        writer = None
        stage_descriptor = os.open(
            "provider", file_flags, dir_fd=stage_directory_fd
        )
        stage_hash, stage_metadata = _hash_descriptor(stage_descriptor)
        if stage_hash != expected_sha256:
            raise ProbeError("provider-stage-changed")
        os.fchmod(stage_directory_fd, 0o500)
        os.fsync(stage_directory_fd)
        os.fsync(parent_fd)
        pinned = PinnedExecutable(
            path=parent / stage_name / "provider",
            sha256=stage_hash,
            metadata=stage_metadata,
            descriptor=stage_descriptor,
            stage_parent_fd=parent_fd,
            stage_directory_fd=stage_directory_fd,
            stage_name=stage_name,
            stage_directory_identity=(
                stage_directory_metadata.st_dev,
                stage_directory_metadata.st_ino,
            ),
        )
        return pinned
    except OSError as error:
        raise ProbeError("provider-stage-failed") from error
    finally:
        if writer is not None:
            os.close(writer)
        if pinned is None:
            if stage_descriptor is not None:
                os.close(stage_descriptor)
            if stage_directory_fd is not None:
                try:
                    os.fchmod(stage_directory_fd, 0o700)
                    os.unlink("provider", dir_fd=stage_directory_fd)
                except OSError:
                    pass
                os.close(stage_directory_fd)
            if stage_name is not None and parent_fd is not None:
                try:
                    os.rmdir(stage_name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except OSError:
                    pass
            if parent_fd is not None:
                os.close(parent_fd)


def _cleanup_pinned(pinned: PinnedExecutable) -> None:
    if pinned.stage_name is None:
        if pinned.descriptor is not None:
            os.close(pinned.descriptor)
            pinned.descriptor = None
        return
    if (
        pinned.descriptor is None
        or pinned.stage_parent_fd is None
        or pinned.stage_directory_fd is None
        or pinned.stage_directory_identity is None
    ):
        raise ProbeError("provider-stage-cleanup-failed")
    error: OSError | None = None
    try:
        os.fchmod(pinned.stage_directory_fd, 0o700)
        os.close(pinned.descriptor)
        pinned.descriptor = None
        metadata = os.stat(
            "provider",
            dir_fd=pinned.stage_directory_fd,
            follow_symlinks=False,
        )
        if _file_metadata(metadata) != pinned.metadata:
            raise OSError("provider stage changed")
        os.unlink("provider", dir_fd=pinned.stage_directory_fd)
        os.fsync(pinned.stage_directory_fd)
    except OSError as caught:
        error = caught
    finally:
        os.close(pinned.stage_directory_fd)
        pinned.stage_directory_fd = None
    try:
        metadata = os.stat(
            pinned.stage_name,
            dir_fd=pinned.stage_parent_fd,
            follow_symlinks=False,
        )
        if (metadata.st_dev, metadata.st_ino) != pinned.stage_directory_identity:
            raise OSError("provider stage directory changed")
        os.rmdir(pinned.stage_name, dir_fd=pinned.stage_parent_fd)
        os.fsync(pinned.stage_parent_fd)
    except OSError as caught:
        if error is None:
            error = caught
    finally:
        os.close(pinned.stage_parent_fd)
        pinned.stage_parent_fd = None
    pinned.stage_name = None
    pinned.stage_directory_identity = None
    if error is not None:
        raise ProbeError("provider-stage-cleanup-failed") from error


def _executable_matches(pinned: PinnedExecutable) -> bool:
    if pinned.descriptor is not None:
        try:
            path_metadata = pinned.path.lstat()
            digest, metadata = _hash_descriptor(pinned.descriptor)
        except (OSError, ProbeError):
            return False
        return (
            _file_metadata(path_metadata) == pinned.metadata
            and digest == pinned.sha256
            and metadata == pinned.metadata
        )
    try:
        current = _hash_executable(pinned.path)
    except ProbeError:
        return False
    return current.sha256 == pinned.sha256 and current.metadata == pinned.metadata


def pin_executable(
    provider: str,
    path: Path,
    expected_sha256: dict[str, str],
    stage_directory: Path | None = None,
) -> PinnedExecutable:
    try:
        resolved = path.resolve(strict=True)
        if provider == "codex":
            resolved = _codex_native_path(resolved)
    except OSError as error:
        raise ProbeError("provider-executable-invalid") from error
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
        digest, metadata = _hash_descriptor(descriptor)
        if digest != expected_sha256[provider]:
            raise ProbeError("provider-executable-hash-mismatch")
        if stage_directory is not None:
            return _stage_pinned_descriptor(
                descriptor,
                metadata,
                digest,
                stage_directory,
            )
        return PinnedExecutable(path=resolved, sha256=digest, metadata=metadata)
    except OSError as error:
        raise ProbeError("provider-executable-invalid") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _identifier(value: Any) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_IDENTIFIER_CHARACTERS
        or "\x00" in value
    ):
        raise ProbeError("protocol-identifier-invalid")
    return value


def _request_id(value: Any) -> str | int:
    if type(value) is str:
        return _identifier(value)
    if type(value) is int and -(1 << 63) <= value < (1 << 63):
        return value
    raise ProbeError("protocol-request-id-invalid")


def _private_directory(path: Path, *, empty: bool) -> Path:
    if not path.is_absolute():
        raise ProbeError("private-directory-invalid")
    lexical = Path(os.path.abspath(os.fspath(path)))
    try:
        metadata = lexical.lstat()
        resolved = lexical.resolve(strict=True)
    except OSError as error:
        raise ProbeError("private-directory-invalid") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ProbeError("private-directory-invalid")
    if empty:
        try:
            with os.scandir(resolved) as entries:
                if next(entries, None) is not None:
                    raise ProbeError("workspace-not-empty")
        except OSError as error:
            raise ProbeError("private-directory-invalid") from error
    return resolved


def _path_contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def sanitized_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    original = os.environ if source is None else source
    environment: dict[str, str] = {}
    for name in PASSTHROUGH_ENVIRONMENT:
        value = original.get(name)
        if value is None:
            continue
        if not value or "\x00" in value or len(value) > 4096:
            raise ProbeError("provider-environment-invalid")
        environment[name] = value
    home = environment.get("HOME")
    if home is None or not Path(home).is_absolute():
        raise ProbeError("provider-environment-invalid")
    search_path = environment.get("PATH", os.defpath)
    entries = search_path.split(os.pathsep)
    if any(not entry or not Path(entry).is_absolute() for entry in entries):
        raise ProbeError("provider-environment-invalid")
    for name in (
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "CODEX_HOME",
    ):
        if name in environment and not Path(environment[name]).is_absolute():
            raise ProbeError("provider-environment-invalid")
    environment["PATH"] = search_path
    environment["PWD"] = "/"
    environment["OLDPWD"] = "/"
    environment["NO_COLOR"] = "1"
    environment["TERM"] = "dumb"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def claude_environment(
    config_dir: Path, workspace: Path, temporary_directory: Path
) -> dict[str, str]:
    environment = sanitized_environment()
    for name in (
        "CODEX_HOME",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "1",
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
            "CLAUDE_CODE_DISABLE_BACKGROUND_TASKS": "1",
            "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION": "false",
            "CLAUDE_CODE_SKIP_PROMPT_HISTORY": "1",
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
            "CLAUDE_CODE_TMPDIR": str(temporary_directory),
            "CLAUDE_CONFIG_DIR": str(config_dir),
            "BROWSER": "/usr/bin/false",
            "DISABLE_AUTOUPDATER": "1",
            "DISABLE_ERROR_REPORTING": "1",
            "DISABLE_FEEDBACK_COMMAND": "1",
            "DISABLE_TELEMETRY": "1",
            "OTEL_LOGS_EXPORTER": "none",
            "OTEL_METRICS_EXPORTER": "none",
            "OTEL_TRACES_EXPORTER": "none",
            "PWD": str(workspace),
            "TMPDIR": str(temporary_directory),
        }
    )
    return environment


class ExactText:
    def __init__(self, expected: str) -> None:
        self.expected = expected
        self.offset = 0

    def feed(self, value: Any) -> None:
        if type(value) is not str or not value:
            raise ProbeError("provider-response-invalid")
        end = self.offset + len(value)
        if end > len(self.expected) or self.expected[self.offset : end] != value:
            raise ProbeError("provider-response-mismatch")
        self.offset = end

    def finish(self) -> None:
        if self.offset != len(self.expected):
            raise ProbeError("provider-response-mismatch")


def _claude_capture_ids(capture_id: str) -> dict[str, str]:
    identifiers = {
        suffix: f"{capture_id}-{suffix}" for suffix in CLAUDE_CAPTURE_SUFFIXES
    }
    if any(CAPTURE_ID_PATTERN.fullmatch(value) is None for value in identifiers.values()):
        raise ProbeError("capture-id-invalid")
    return identifiers


def _write_private_bytes(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written < 1:
                raise ProbeError("private-file-write-failed")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(raw)
        ):
            raise ProbeError("private-file-invalid")
    except OSError as error:
        raise ProbeError("private-file-write-failed") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    raw = (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    _write_private_bytes(path, raw)


def _claude_hook(
    config: ProbeConfig, pinned: PinnedExecutable, capture_id: str
) -> dict[str, Any]:
    return {
        "args": [
            "-B",
            str(COLLECTORS["claude"]),
            "--capture-root",
            str(config.capture_root),
            "--capture-id",
            capture_id,
            "--per-capture-bytes",
            str(64 * 1024),
            "--aggregate-bytes",
            str(256 * 1024),
            "--timeout-seconds",
            str(CLAUDE_HOOK_TIMEOUT_SECONDS),
            "--provider-executable",
            str(pinned.path),
            "--expected-executable-sha256",
            pinned.sha256,
        ],
        "command": str(Path(sys.executable).resolve(strict=True)),
        "timeout": 10,
        "type": "command",
    }


def _claude_settings(
    config: ProbeConfig, pinned: PinnedExecutable, capture_ids: dict[str, str]
) -> dict[str, Any]:
    return {
        "hooks": {
            "SessionStart": [
                {
                    "hooks": [
                        _claude_hook(config, pinned, capture_ids["session-start"])
                    ],
                    "matcher": "startup",
                }
            ],
            "Stop": [
                {"hooks": [_claude_hook(config, pinned, capture_ids["stop"])]}
            ],
            "UserPromptSubmit": [
                {
                    "hooks": [
                        _claude_hook(config, pinned, capture_ids["prompt-submit"])
                    ]
                }
            ],
        }
    }


def _read_private_file(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > maximum_bytes
        ):
            raise ProbeError("private-file-invalid")
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(READ_CHUNK_BYTES, maximum_bytes + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        path_metadata = path.lstat()
        if (
            len(raw) > maximum_bytes
            or len(raw) != before.st_size
            or _file_metadata(after) != _file_metadata(before)
            or _file_metadata(path_metadata) != _file_metadata(before)
        ):
            raise ProbeError("private-file-invalid")
        return bytes(raw)
    except OSError as error:
        raise ProbeError("private-file-invalid") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _verify_claude_receipts(
    config: ProbeConfig,
    pinned: PinnedExecutable,
    capture_ids: dict[str, str],
) -> None:
    capture_engine = _load_provider_capture()
    expected_names = {
        name
        for capture_id in capture_ids.values()
        for name in (f"{capture_id}.capture", f"{capture_id}.receipt.json")
    }
    try:
        observed_names = {
            entry.name
            for entry in os.scandir(config.capture_root)
            if entry.name.startswith(f"{config.capture_id}-")
        }
    except OSError as error:
        raise ProbeError("capture-inventory-invalid") from error
    if observed_names != expected_names:
        raise ProbeError("capture-inventory-invalid")
    expected_events = {
        "session-start": "SessionStart",
        "prompt-submit": "UserPromptSubmit",
        "stop": "Stop",
    }
    for suffix, capture_id in capture_ids.items():
        capture = _read_private_file(
            config.capture_root / f"{capture_id}.capture", 64 * 1024
        )
        receipt_raw = _read_private_file(
            config.capture_root / f"{capture_id}.receipt.json", 8 * 1024
        )
        receipt = strict_message(receipt_raw)
        canonical = (
            json.dumps(receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("utf-8")
        termination = receipt.get("termination")
        streams = receipt.get("streams")
        if (
            receipt_raw != canonical
            or receipt.get("capture_id") != capture_id
            or receipt.get("provider") != "claude"
            or receipt.get("provider_version") != PROVIDER_VERSIONS["claude"]
            or receipt.get("source_interface") != "claude-native-hook"
            or receipt.get("capture_status") != "complete"
            or receipt.get("provider_outcome") != "unknown"
            or receipt.get("incomplete_reasons") != []
            or receipt.get("capture_present") is not True
            or receipt.get("capture_bytes") != len(capture)
            or type(receipt.get("payload_bytes")) is not int
            or receipt["payload_bytes"] < 1
            or type(receipt.get("frame_count")) is not int
            or receipt["frame_count"] < 1
            or receipt.get("source_capture_sha256")
            != hashlib.sha256(capture).hexdigest()
            or receipt.get("executable_sha256") != pinned.sha256
            or type(streams) is not dict
            or set(streams) != {"stdin", "stdout", "stderr"}
            or type(streams.get("stdin")) is not dict
            or streams["stdin"].get("bytes") != receipt.get("payload_bytes")
            or type(streams.get("stdout")) is not dict
            or streams["stdout"].get("bytes") != 0
            or type(streams.get("stderr")) is not dict
            or streams["stderr"].get("bytes") != 0
            or type(termination) is not dict
            or termination
            != {
                "collector_signal": None,
                "exit_code": None,
                "reason": "hook_eof",
                "signal": None,
            }
        ):
            raise ProbeError("capture-receipt-invalid")
        try:
            frames = list(capture_engine.iter_capture_frames(io.BytesIO(capture)))
        except Exception as error:
            raise ProbeError("capture-framing-invalid") from error
        if (
            len(frames) != receipt["frame_count"]
            or any(stream != "I" for stream, _observed_ns, _payload in frames)
        ):
            raise ProbeError("capture-framing-invalid")
        payload = b"".join(frame_payload for _stream, _observed_ns, frame_payload in frames)
        if len(payload) != receipt["payload_bytes"]:
            raise ProbeError("capture-framing-invalid")
        event = strict_message(payload)
        if (
            event.get("session_id") != CLAUDE_SESSION_ID
            or event.get("cwd") != str(config.workspace)
            or event.get("permission_mode") != "dontAsk"
            or event.get("hook_event_name") != expected_events[suffix]
        ):
            raise ProbeError("capture-event-invalid")
        if suffix == "session-start" and (
            event.get("source") != "startup" or event.get("model") != CLAUDE_MODEL
        ):
            raise ProbeError("capture-event-invalid")
        if suffix == "prompt-submit" and event.get("prompt") != PROBE_PROMPT:
            raise ProbeError("capture-event-invalid")
        if suffix == "stop" and (
            event.get("stop_hook_active") is not False
            or event.get("last_assistant_message") != EXPECTED_RESPONSE
        ):
            raise ProbeError("capture-event-invalid")


def _group_exists(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _wait_for_provider_group_exit(
    process: subprocess.Popen[bytes], timeout_seconds: float
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        process.poll()
        if not _group_exists(process):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(remaining, 0.05))


def _terminate_provider_group(process: subprocess.Popen[bytes]) -> None:
    if not _group_exists(process):
        process.poll()
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.poll()
        return
    except PermissionError as error:
        raise ProbeError("provider-termination-failed") from error
    if not _wait_for_provider_group_exit(process, COLLECTOR_SIGNAL_TIMEOUT_SECONDS):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError as error:
            raise ProbeError("provider-termination-failed") from error
        if not _wait_for_provider_group_exit(
            process, COLLECTOR_SIGNAL_TIMEOUT_SECONDS
        ):
            raise ProbeError("provider-termination-failed")


def _open_private_output(path: Path) -> int:
    flags = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ProbeError("private-file-invalid") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size != 0
    ):
        os.close(descriptor)
        raise ProbeError("private-file-invalid")
    return descriptor


def _close_process_pipes(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is None or stream.closed:
            continue
        try:
            stream.close()
        except OSError:
            pass


def _close_selector(selector: selectors.BaseSelector) -> None:
    for key in tuple(selector.get_map().values()):
        try:
            if type(key.fileobj) is int:
                os.close(key.fileobj)
            else:
                key.fileobj.close()
        except OSError:
            pass
    selector.close()


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _wait_for_process_group_exit(
    process_group_id: int, timeout_seconds: float
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while _process_group_exists(process_group_id):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(remaining, 0.05))
    return True


def _signal_process_group(process_group_id: int, number: int) -> None:
    try:
        os.killpg(process_group_id, number)
    except ProcessLookupError:
        pass
    except PermissionError as error:
        raise ProbeError("provider-termination-failed") from error


def _sync_and_close_descriptors(descriptors: Sequence[int]) -> None:
    failure: OSError | None = None
    for descriptor in descriptors:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if failure is None:
                failure = error
        finally:
            try:
                os.close(descriptor)
            except OSError as error:
                if failure is None:
                    failure = error
    if failure is not None:
        raise ProbeError("private-file-sync-failed") from failure


def _write_private_output(descriptor: int, payload: bytes) -> None:
    offset = 0
    try:
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written < 1:
                raise ProbeError("private-file-write-failed")
            offset += written
    except OSError as error:
        raise ProbeError("private-file-write-failed") from error


def _run_claude_process(
    config: ProbeConfig,
    pinned: PinnedExecutable,
    settings_path: Path,
    prompt_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    temporary_directory: Path,
) -> tuple[int, int]:
    if config.config_dir is None:
        raise ProbeError("config-directory-required")
    command = (
        str(pinned.path),
        "-p",
        "--input-format",
        "text",
        "--output-format",
        "text",
        "--no-session-persistence",
        "--setting-sources",
        "user",
        "--settings",
        str(settings_path),
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--disable-slash-commands",
        "--no-chrome",
        "--tools",
        "",
        "--permission-mode",
        "dontAsk",
        "--model",
        CLAUDE_MODEL,
        "--max-budget-usd",
        CLAUDE_MAX_BUDGET_USD,
        "--prompt-suggestions",
        "false",
        "--session-id",
        CLAUDE_SESSION_ID,
    )
    stdout_descriptor = _open_private_output(stdout_path)
    try:
        stderr_descriptor = _open_private_output(stderr_path)
    except BaseException:
        os.close(stdout_descriptor)
        raise
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    stdout = bytearray()
    stderr_bytes = 0
    try:
        selector = selectors.DefaultSelector()
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=config.workspace,
                env=claude_environment(
                    config.config_dir, config.workspace, temporary_directory
                ),
                start_new_session=True,
                close_fds=True,
            )
        except OSError as error:
            raise ProbeError("provider-spawn-failed") from error
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise ProbeError("provider-spawn-failed")
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        if not _executable_matches(pinned):
            raise ProbeError("provider-executable-changed")
        prompt = _read_private_file(prompt_path, MAX_INPUT_BYTES)
        if prompt != PROBE_PROMPT.encode("ascii"):
            raise ProbeError("private-prompt-invalid")
        try:
            process.stdin.write(prompt)
            process.stdin.flush()
            process.stdin.close()
        except (BrokenPipeError, OSError) as error:
            raise ProbeError("provider-input-failed") from error
        deadline = time.monotonic() + TURN_TIMEOUT_SECONDS
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError("provider-timeout")
            for key, _mask in selector.select(min(remaining, 0.05)):
                try:
                    chunk = os.read(key.fd, READ_CHUNK_BYTES)
                except OSError as error:
                    raise ProbeError("provider-output-failed") from error
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if key.data == "stdout":
                    _write_private_output(stdout_descriptor, chunk)
                    stdout.extend(chunk)
                    if len(stdout) > MAX_LINE_BYTES:
                        raise ProbeError("provider-output-budget-exceeded")
                else:
                    _write_private_output(stderr_descriptor, chunk)
                    stderr_bytes += len(chunk)
                    if stderr_bytes > MAX_STDERR_BYTES:
                        raise ProbeError("provider-error-budget-exceeded")
        return_code = process.wait()
        if _group_exists(process):
            raise ProbeError("provider-descendant-process")
        if return_code != 0:
            raise ProbeError("provider-failed")
        if stderr_bytes != 0:
            raise ProbeError("provider-stderr-output")
        if bytes(stdout) != (EXPECTED_RESPONSE + "\n").encode("ascii"):
            raise ProbeError("provider-response-mismatch")
        if not _executable_matches(pinned):
            raise ProbeError("provider-executable-changed")
        return len(stdout), stderr_bytes
    except BaseException:
        if process is not None:
            _terminate_provider_group(process)
        raise
    finally:
        if selector is not None:
            _close_selector(selector)
        if process is not None:
            _close_process_pipes(process)
        _sync_and_close_descriptors((stdout_descriptor, stderr_descriptor))


def run_claude_probe(config: ProbeConfig, pinned: PinnedExecutable) -> ProbeResult:
    if config.config_dir is None:
        raise ProbeError("config-directory-required")
    capture_ids = _claude_capture_ids(config.capture_id)
    settings_path = config.config_dir / "probe-settings.json"
    prompt_path = config.config_dir / "probe-prompt.txt"
    stdout_path = config.config_dir / "probe-stdout.bin"
    stderr_path = config.config_dir / "probe-stderr.bin"
    temporary_directory = config.config_dir / "tmp"
    try:
        os.mkdir(temporary_directory, 0o700)
        temporary_directory.chmod(0o700)
    except OSError as error:
        raise ProbeError("private-directory-create-failed") from error
    _write_private_json(settings_path, _claude_settings(config, pinned, capture_ids))
    _write_private_bytes(prompt_path, PROBE_PROMPT.encode("ascii"))
    _write_private_bytes(stdout_path, b"")
    _write_private_bytes(stderr_path, b"")
    try:
        directory_descriptor = os.open(
            config.config_dir,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        os.fsync(directory_descriptor)
    except OSError as error:
        raise ProbeError("private-directory-sync-failed") from error
    finally:
        if "directory_descriptor" in locals():
            os.close(directory_descriptor)
    stdout_bytes, _stderr_bytes = _run_claude_process(
        config,
        pinned,
        settings_path,
        prompt_path,
        stdout_path,
        stderr_path,
        temporary_directory,
    )
    _verify_claude_receipts(config, pinned, capture_ids)
    return ProbeResult(
        provider="claude",
        provider_version=PROVIDER_VERSIONS["claude"],
        message_count=len(capture_ids),
        stdout_bytes=stdout_bytes,
    )


class JsonLineTransport:
    def __init__(self, config: ProbeConfig, pinned: PinnedExecutable) -> None:
        collector = COLLECTORS[config.provider]
        try:
            control_read, control_write = os.pipe()
            os.set_blocking(control_read, False)
            os.set_inheritable(control_read, False)
            os.set_inheritable(control_write, False)
        except OSError as error:
            for descriptor_name in ("control_read", "control_write"):
                descriptor = locals().get(descriptor_name)
                if type(descriptor) is int:
                    os.close(descriptor)
            raise ProbeError("collector-control-unavailable") from error
        command = (
            sys.executable,
            "-B",
            str(collector),
            "--capture-root",
            str(config.capture_root),
            "--capture-id",
            config.capture_id,
            "--per-capture-bytes",
            str(PER_CAPTURE_BYTES),
            "--aggregate-bytes",
            str(AGGREGATE_BYTES),
            "--timeout-seconds",
            str(COLLECTOR_TIMEOUT_SECONDS),
            "--provider-executable",
            str(config.provider_executable),
            "--expected-executable-sha256",
            pinned.sha256,
            "--provider-control-fd",
            str(control_write),
        )
        self.control_fd = control_read
        self.control_buffer = bytearray()
        self.control_bytes = 0
        self.control_event_count = 0
        self.active_provider_pgid: int | None = None
        self.live_provider_pgids: set[int] = set()
        self.control_valid = True
        self.control_eof = False
        if not _executable_matches(pinned):
            os.close(control_read)
            os.close(control_write)
            raise ProbeError("provider-executable-changed")
        try:
            try:
                self.process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=Path("/"),
                    env=sanitized_environment(),
                    start_new_session=True,
                    close_fds=True,
                    pass_fds=(control_write,),
                )
            except OSError as error:
                raise ProbeError("collector-spawn-failed") from error
            finally:
                os.close(control_write)
        except BaseException:
            os.close(control_read)
            self.control_fd = -1
            raise
        self.stdout_buffer = bytearray()
        self.stdout_bytes = 0
        self.stderr_bytes = 0
        self.input_bytes = 0
        self.message_count = 0
        self.stdin_closed = False
        selector: selectors.BaseSelector | None = None
        try:
            if (
                self.process.stdin is None
                or self.process.stdout is None
                or self.process.stderr is None
            ):
                raise ProbeError("collector-spawn-failed")
            selector = selectors.DefaultSelector()
            selector.register(self.process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(self.process.stderr, selectors.EVENT_READ, "stderr")
            selector.register(control_read, selectors.EVENT_READ, "control")
            if not _executable_matches(pinned):
                raise ProbeError("provider-executable-changed")
        except BaseException as original:
            termination_error: BaseException | None = None
            try:
                self._terminate()
            except BaseException as error:
                termination_error = error
            finally:
                if selector is not None:
                    _close_selector(selector)
                    self.control_fd = -1
                elif self.control_fd >= 0:
                    os.close(self.control_fd)
                    self.control_fd = -1
                _close_process_pipes(self.process)
            if termination_error is not None:
                raise termination_error from original
            raise
        self.selector = selector

    def _invalidate_control(self, fail_closed: bool) -> None:
        self.control_valid = False
        if fail_closed:
            raise ProbeError("collector-control-invalid")

    def _feed_control(self, payload: bytes, *, fail_closed: bool) -> None:
        self.control_bytes += len(payload)
        if self.control_bytes > MAX_CONTROL_BYTES:
            self._invalidate_control(fail_closed)
            return
        self.control_buffer.extend(payload)
        while True:
            newline = self.control_buffer.find(b"\n")
            if newline < 0:
                if len(self.control_buffer) > 32:
                    self._invalidate_control(fail_closed)
                return
            raw = bytes(self.control_buffer[:newline])
            del self.control_buffer[: newline + 1]
            match = re.fullmatch(rb"([SE]) ([1-9][0-9]{0,9})", raw)
            if match is None:
                self._invalidate_control(fail_closed)
                continue
            process_group_id = int(match.group(2))
            if process_group_id > (1 << 31) - 1:
                self._invalidate_control(fail_closed)
                continue
            self.control_event_count += 1
            if self.control_event_count > MAX_CONTROL_EVENTS:
                self._invalidate_control(fail_closed)
            if match.group(1) == b"S":
                self.live_provider_pgids.add(process_group_id)
                if self.active_provider_pgid is not None:
                    self._invalidate_control(fail_closed)
                self.active_provider_pgid = process_group_id
            else:
                self.live_provider_pgids.discard(process_group_id)
                if self.active_provider_pgid != process_group_id:
                    self._invalidate_control(fail_closed)
                self.active_provider_pgid = None

    def _read_control_available(self, *, fail_closed: bool) -> None:
        while self.control_fd >= 0:
            try:
                chunk = os.read(self.control_fd, READ_CHUNK_BYTES)
            except BlockingIOError:
                return
            except OSError as error:
                self._invalidate_control(fail_closed)
                if fail_closed:
                    raise ProbeError("collector-control-failed") from error
                return
            if chunk:
                self._feed_control(chunk, fail_closed=fail_closed)
                continue
            descriptor = self.control_fd
            self.control_fd = -1
            self.control_eof = True
            selector = getattr(self, "selector", None)
            if selector is not None:
                try:
                    selector.unregister(descriptor)
                except (KeyError, ValueError):
                    pass
            try:
                os.close(descriptor)
            except OSError:
                pass
            if self.control_buffer:
                self._invalidate_control(fail_closed)
            return

    def _wait_for_collector_exit(self, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while self.process.poll() is None:
            self._read_control_available(fail_closed=False)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(remaining, 0.05))
        self._read_control_available(fail_closed=False)
        return True

    def _signal_live_provider_groups(self) -> set[int]:
        remaining: set[int] = set()
        for process_group_id in tuple(self.live_provider_pgids):
            _signal_process_group(process_group_id, signal.SIGTERM)
            if not _wait_for_process_group_exit(
                process_group_id, COLLECTOR_SIGNAL_TIMEOUT_SECONDS
            ):
                _signal_process_group(process_group_id, signal.SIGKILL)
                remaining.add(process_group_id)
        return remaining

    def send(self, message: dict[str, Any]) -> None:
        if self.stdin_closed or self.process.poll() is not None:
            raise ProbeError("collector-not-running")
        try:
            raw = (
                json.dumps(
                    message,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii")
        except (TypeError, ValueError) as error:
            raise ProbeError("client-message-invalid") from error
        if len(raw) > MAX_LINE_BYTES or self.input_bytes + len(raw) > MAX_INPUT_BYTES:
            raise ProbeError("client-message-budget-exceeded")
        try:
            self.process.stdin.write(raw)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise ProbeError("collector-input-failed") from error
        self.input_bytes += len(raw)

    def _line(self) -> bytes | None:
        newline = self.stdout_buffer.find(b"\n")
        if newline < 0:
            if len(self.stdout_buffer) > MAX_LINE_BYTES:
                raise ProbeError("protocol-line-budget-exceeded")
            return None
        raw = bytes(self.stdout_buffer[:newline])
        del self.stdout_buffer[: newline + 1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if not raw or len(raw) > MAX_LINE_BYTES:
            raise ProbeError("protocol-line-invalid")
        return raw

    def _read_ready(self, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("protocol-timeout")
        events = self.selector.select(min(remaining, 0.05))
        if not events:
            if self.process.poll() is not None and not self.selector.get_map():
                raise ProbeError("collector-exited-early")
            return
        for key, _mask in events:
            if key.data == "control":
                self._read_control_available(fail_closed=True)
                continue
            try:
                chunk = os.read(key.fd, READ_CHUNK_BYTES)
            except OSError as error:
                raise ProbeError("collector-output-failed") from error
            if not chunk:
                try:
                    self.selector.unregister(key.fileobj)
                except KeyError:
                    pass
                key.fileobj.close()
                continue
            if key.data == "stdout":
                self.stdout_bytes += len(chunk)
                if self.stdout_bytes > MAX_STDOUT_BYTES:
                    raise ProbeError("protocol-byte-budget-exceeded")
                self.stdout_buffer.extend(chunk)
                if (
                    b"\n" not in self.stdout_buffer
                    and len(self.stdout_buffer) > MAX_LINE_BYTES
                ):
                    raise ProbeError("protocol-line-budget-exceeded")
            else:
                self.stderr_bytes += len(chunk)
                if self.stderr_bytes > MAX_STDERR_BYTES:
                    raise ProbeError("collector-error-budget-exceeded")

    def receive(self, deadline: float) -> dict[str, Any]:
        while True:
            raw = self._line()
            if raw is not None:
                self.message_count += 1
                if self.message_count > MAX_MESSAGE_COUNT:
                    raise ProbeError("protocol-message-budget-exceeded")
                return strict_message(raw)
            if not self.selector.get_map() and self.process.poll() is not None:
                if self.stdout_buffer:
                    raise ProbeError("protocol-line-truncated")
                raise ProbeError("collector-exited-early")
            self._read_ready(deadline)

    def _close_stdin(self) -> None:
        if self.stdin_closed:
            return
        self.stdin_closed = True
        try:
            self.process.stdin.close()
        except OSError:
            pass

    def _drain(self, deadline: float) -> None:
        while self.selector.get_map():
            if time.monotonic() >= deadline:
                return
            try:
                self._read_ready(deadline)
            except ProbeError as error:
                if str(error) == "protocol-timeout":
                    return
                raise

    def finish(self) -> None:
        baseline_stdout_bytes = self.stdout_bytes
        if self.stdout_buffer:
            raise ProbeError("post-terminal-provider-output")
        self._close_stdin()
        deadline = time.monotonic() + EXIT_TIMEOUT_SECONDS
        self._drain(deadline)
        remaining = max(deadline - time.monotonic(), 0)
        try:
            return_code = self.process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            self._terminate()
            raise ProbeError("collector-exit-timeout") from error
        if return_code != 0:
            raise ProbeError("collector-failed")
        if self.stdout_bytes != baseline_stdout_bytes or self.stdout_buffer:
            raise ProbeError("post-terminal-provider-output")
        if self.stderr_bytes != 0:
            raise ProbeError("collector-stderr-output")
        if self.selector.get_map():
            raise ProbeError("collector-pipe-not-closed")
        if (
            not self.control_valid
            or not self.control_eof
            or self.control_buffer
            or self.active_provider_pgid is not None
            or self.live_provider_pgids
            or self.control_event_count != MAX_CONTROL_EVENTS
        ):
            raise ProbeError("collector-control-invalid")

    def abort(self) -> None:
        self._close_stdin()
        deadline = time.monotonic() + ABORT_TIMEOUT_SECONDS
        try:
            self._drain(deadline)
        except ProbeError:
            pass
        self._terminate()

    def _terminate(self) -> None:
        forced = False
        if self.process.poll() is None:
            try:
                self.process.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                self.process.poll()
            except OSError as error:
                raise ProbeError("collector-termination-failed") from error
            if self.process.poll() is None and not self._wait_for_collector_exit(
                COLLECTOR_SIGNAL_TIMEOUT_SECONDS
            ):
                forced = not self._wait_for_collector_exit(
                    COLLECTOR_TIMEOUT_SECONDS + COLLECTOR_SIGNAL_TIMEOUT_SECONDS
                )
        else:
            self._read_control_available(fail_closed=False)
        reported_groups = set(self.live_provider_pgids)
        remaining_groups: set[int] = set()
        if forced or self.process.poll() is not None:
            remaining_groups = self._signal_live_provider_groups()
        if forced:
            try:
                self.process.kill()
                self.process.wait(timeout=COLLECTOR_SIGNAL_TIMEOUT_SECONDS)
            except ProcessLookupError:
                self.process.poll()
            except (OSError, subprocess.TimeoutExpired) as error:
                raise ProbeError("collector-termination-failed") from error
            self._read_control_available(fail_closed=False)
        for process_group_id in reported_groups | remaining_groups:
            if _process_group_exists(process_group_id):
                _signal_process_group(process_group_id, signal.SIGKILL)
            if not _wait_for_process_group_exit(
                process_group_id, COLLECTOR_SIGNAL_TIMEOUT_SECONDS
            ):
                raise ProbeError("provider-termination-failed")
        if reported_groups:
            self.live_provider_pgids.difference_update(reported_groups)
            self.active_provider_pgid = None
        if forced:
            raise ProbeError("collector-termination-forced")
        if not self.control_valid or self.live_provider_pgids:
            raise ProbeError("collector-control-invalid")

    def close(self) -> None:
        _close_selector(self.selector)
        self.control_fd = -1
        _close_process_pipes(self.process)


class CodexProtocol:
    INITIALIZE_ID = "clilane-init-1"
    THREAD_ID = "clilane-thread-1"
    TURN_ID = "clilane-turn-1"
    INTERRUPT_ID = "clilane-interrupt-1"

    def __init__(self, transport: JsonLineTransport, workspace: Path) -> None:
        self.transport = transport
        self.workspace = workspace
        self.thread_id: str | None = None
        self.session_id: str | None = None
        self.turn_id: str | None = None
        self.agent_item_id: str | None = None
        self.text = ExactText(EXPECTED_RESPONSE)
        self.interrupt_sent = False

    def _send_interrupt(self) -> None:
        if self.thread_id is None or self.turn_id is None or self.interrupt_sent:
            return
        self.interrupt_sent = True
        self.transport.send(
            {
                "id": self.INTERRUPT_ID,
                "method": "turn/interrupt",
                "params": {"threadId": self.thread_id, "turnId": self.turn_id},
            }
        )

    def _reverse_request(self, message: dict[str, Any]) -> NoReturn:
        method = message.get("method")
        request_id = _request_id(message.get("id"))
        if type(method) is not str:
            raise ProbeError("protocol-message-invalid")
        responses: dict[str, dict[str, Any]] = {
            "item/commandExecution/requestApproval": {"decision": "cancel"},
            "item/fileChange/requestApproval": {"decision": "cancel"},
            "item/permissions/requestApproval": {"permissions": {}},
            "item/tool/requestUserInput": {"answers": {}},
            "mcpServer/elicitation/request": {"action": "cancel"},
            "item/tool/call": {"contentItems": [], "success": False},
            "execCommandApproval": {"decision": "abort"},
            "applyPatchApproval": {"decision": "abort"},
        }
        if method in {"account/chatgptAuthTokens/refresh", "attestation/generate"}:
            self._send_interrupt()
            raise ProbeError("unsafe-provider-request")
        if method in responses:
            self.transport.send({"id": request_id, "result": responses[method]})
        else:
            self.transport.send(
                {
                    "id": request_id,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            )
        self._send_interrupt()
        raise ProbeError("unexpected-provider-request")

    def _notification(self, message: dict[str, Any]) -> bool:
        method = message.get("method")
        params = message.get("params")
        if type(method) is not str:
            raise ProbeError("protocol-message-invalid")
        lowered = method.lower()
        if any(
            marker in lowered
            for marker in (
                "commandexecution",
                "filechange",
                "tool",
                "mcp",
                "websearch",
                "imagegeneration",
            )
        ):
            self._send_interrupt()
            raise ProbeError("provider-side-effect-attempt")
        if method == "item/agentMessage/delta":
            if type(params) is not dict:
                raise ProbeError("protocol-message-invalid")
            if (
                params.get("threadId") != self.thread_id
                or params.get("turnId") != self.turn_id
            ):
                raise ProbeError("protocol-binding-mismatch")
            item_id = _identifier(params.get("itemId"))
            if self.agent_item_id is None:
                self.agent_item_id = item_id
            elif self.agent_item_id != item_id:
                raise ProbeError("protocol-binding-mismatch")
            self.text.feed(params.get("delta"))
            return False
        if method in {"item/started", "item/completed"}:
            if type(params) is not dict or type(params.get("item")) is not dict:
                raise ProbeError("protocol-message-invalid")
            item_type = params["item"].get("type")
            if item_type not in {"userMessage", "agentMessage", "reasoning"}:
                self._send_interrupt()
                raise ProbeError("provider-side-effect-attempt")
            return False
        if method != "turn/completed":
            return False
        if type(params) is not dict or params.get("threadId") != self.thread_id:
            raise ProbeError("protocol-binding-mismatch")
        turn = params.get("turn")
        if (
            type(turn) is not dict
            or turn.get("id") != self.turn_id
            or turn.get("status") != "completed"
        ):
            raise ProbeError("provider-turn-failed")
        self.text.finish()
        return True

    def _receive_response(self, expected_id: str, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            message = self.transport.receive(deadline)
            if "jsonrpc" in message:
                raise ProbeError("protocol-envelope-invalid")
            if "method" in message:
                if "id" in message:
                    self._reverse_request(message)
                self._notification(message)
                continue
            if message.get("id") != expected_id:
                raise ProbeError("protocol-response-id-mismatch")
            if "error" in message:
                raise ProbeError("provider-request-failed")
            result = message.get("result")
            if type(result) is not dict:
                raise ProbeError("protocol-response-invalid")
            return result

    def run(self) -> None:
        self.transport.send(
            {
                "id": self.INITIALIZE_ID,
                "method": "initialize",
                "params": {
                    "clientInfo": {
                        "name": "clilane_provider_evidence",
                        "title": "CLILane Provider Evidence",
                        "version": "0.9.0",
                    }
                },
            }
        )
        self._receive_response(self.INITIALIZE_ID, INITIALIZE_TIMEOUT_SECONDS)
        self.transport.send({"method": "initialized"})
        self.transport.send(
            {
                "id": self.THREAD_ID,
                "method": "thread/start",
                "params": {
                    "approvalPolicy": "never",
                    "config": {
                        "features.hooks": False,
                        "features.plugins": False,
                        "web_search": "disabled",
                    },
                    "cwd": str(self.workspace),
                    "developerInstructions": PROBE_PROMPT,
                    "ephemeral": True,
                    "personality": "none",
                    "sandbox": "read-only",
                },
            }
        )
        result = self._receive_response(self.THREAD_ID, SESSION_TIMEOUT_SECONDS)
        thread = result.get("thread")
        if type(thread) is not dict:
            raise ProbeError("protocol-response-invalid")
        self.thread_id = _identifier(thread.get("id"))
        self.session_id = _identifier(thread.get("sessionId"))
        self.transport.send(
            {
                "id": self.TURN_ID,
                "method": "turn/start",
                "params": {
                    "approvalPolicy": "never",
                    "clientUserMessageId": "clilane-probe-1",
                    "effort": "low",
                    "input": [{"type": "text", "text": PROBE_PROMPT}],
                    "personality": "none",
                    "sandboxPolicy": {"networkAccess": False, "type": "readOnly"},
                    "summary": "none",
                    "threadId": self.thread_id,
                },
            }
        )
        result = self._receive_response(self.TURN_ID, SESSION_TIMEOUT_SECONDS)
        turn = result.get("turn")
        if type(turn) is not dict:
            raise ProbeError("protocol-response-invalid")
        self.turn_id = _identifier(turn.get("id"))
        if turn.get("status") not in {None, "inProgress"}:
            raise ProbeError("provider-turn-failed")
        deadline = time.monotonic() + TURN_TIMEOUT_SECONDS
        while True:
            message = self.transport.receive(deadline)
            if "jsonrpc" in message:
                raise ProbeError("protocol-envelope-invalid")
            if "method" in message:
                if "id" in message:
                    self._reverse_request(message)
                if self._notification(message):
                    return
                continue
            raise ProbeError("protocol-response-id-mismatch")


class KimiProtocol:
    INITIALIZE_ID = 1
    SESSION_ID = 2
    PROMPT_ID = 3

    def __init__(self, transport: JsonLineTransport, workspace: Path) -> None:
        self.transport = transport
        self.workspace = workspace
        self.session_id: str | None = None
        self.text = ExactText(EXPECTED_RESPONSE)
        self.cancel_sent = False

    def _send_cancel(self) -> None:
        if self.session_id is None or self.cancel_sent:
            return
        self.cancel_sent = True
        self.transport.send(
            {
                "jsonrpc": "2.0",
                "method": "session/cancel",
                "params": {"sessionId": self.session_id},
            }
        )

    def _reverse_request(self, message: dict[str, Any]) -> NoReturn:
        method = message.get("method")
        request_id = _request_id(message.get("id"))
        if type(method) is not str:
            raise ProbeError("protocol-message-invalid")
        if method == "session/request_permission":
            self.transport.send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"outcome": {"outcome": "cancelled"}},
                }
            )
        else:
            self.transport.send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            )
        self._send_cancel()
        raise ProbeError("unexpected-provider-request")

    def _notification(self, message: dict[str, Any]) -> None:
        if message.get("method") != "session/update":
            raise ProbeError("protocol-notification-invalid")
        params = message.get("params")
        if type(params) is not dict or params.get("sessionId") != self.session_id:
            raise ProbeError("protocol-binding-mismatch")
        update = params.get("update")
        if type(update) is not dict:
            raise ProbeError("protocol-message-invalid")
        update_kind = update.get("sessionUpdate")
        if update_kind == "agent_message_chunk":
            content = update.get("content")
            if type(content) is not dict or content.get("type") != "text":
                raise ProbeError("provider-response-invalid")
            self.text.feed(content.get("text"))
            return
        if update_kind in {"tool_call", "tool_call_update"}:
            self._send_cancel()
            raise ProbeError("provider-side-effect-attempt")
        if update_kind not in {
            "agent_thought_chunk",
            "plan",
            "available_commands_update",
            "current_mode_update",
            "config_option_update",
            "usage_update",
        }:
            raise ProbeError("protocol-notification-invalid")

    def _message(self, deadline: float) -> dict[str, Any]:
        message = self.transport.receive(deadline)
        if message.get("jsonrpc") != "2.0":
            raise ProbeError("protocol-envelope-invalid")
        return message

    def _receive_response(self, expected_id: int, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            message = self._message(deadline)
            if "method" in message:
                if "id" in message:
                    self._reverse_request(message)
                self._notification(message)
                continue
            if message.get("id") != expected_id:
                raise ProbeError("protocol-response-id-mismatch")
            if "error" in message:
                raise ProbeError("provider-request-failed")
            result = message.get("result")
            if type(result) is not dict:
                raise ProbeError("protocol-response-invalid")
            return result

    def run(self) -> None:
        self.transport.send(
            {
                "jsonrpc": "2.0",
                "id": self.INITIALIZE_ID,
                "method": "initialize",
                "params": {
                    "clientCapabilities": {
                        "fs": {"readTextFile": False, "writeTextFile": False},
                        "terminal": False,
                    },
                    "clientInfo": {"name": "clilane-evidence", "version": "0.9.0"},
                    "protocolVersion": 1,
                },
            }
        )
        result = self._receive_response(
            self.INITIALIZE_ID, INITIALIZE_TIMEOUT_SECONDS
        )
        if type(result.get("protocolVersion")) is not int or result.get(
            "protocolVersion"
        ) != 1:
            raise ProbeError("protocol-version-mismatch")
        self.transport.send(
            {
                "jsonrpc": "2.0",
                "id": self.SESSION_ID,
                "method": "session/new",
                "params": {"cwd": str(self.workspace), "mcpServers": []},
            }
        )
        result = self._receive_response(self.SESSION_ID, SESSION_TIMEOUT_SECONDS)
        self.session_id = _identifier(result.get("sessionId"))
        self.transport.send(
            {
                "jsonrpc": "2.0",
                "id": self.PROMPT_ID,
                "method": "session/prompt",
                "params": {
                    "prompt": [{"type": "text", "text": PROBE_PROMPT}],
                    "sessionId": self.session_id,
                },
            }
        )
        result = self._receive_response(self.PROMPT_ID, TURN_TIMEOUT_SECONDS)
        if result.get("stopReason") != "end_turn":
            raise ProbeError("provider-turn-failed")
        self.text.finish()


def validate_config(config: ProbeConfig) -> ProbeConfig:
    if config.provider not in COLLECTORS:
        raise ProbeError("provider-invalid")
    if CAPTURE_ID_PATTERN.fullmatch(config.capture_id) is None:
        raise ProbeError("capture-id-invalid")
    if not config.provider_executable.is_absolute():
        raise ProbeError("provider-executable-not-absolute")
    capture_root = _private_directory(config.capture_root, empty=False)
    workspace = _private_directory(config.workspace, empty=True)
    config_dir: Path | None = None
    if config.provider == "claude":
        if config.config_dir is None:
            raise ProbeError("config-directory-required")
        config_dir = _private_directory(config.config_dir, empty=True)
    elif config.config_dir is not None:
        raise ProbeError("config-directory-not-applicable")
    private_directories = [capture_root, workspace]
    if config_dir is not None:
        private_directories.append(config_dir)
    if any(
        _path_contains(left, right) or _path_contains(right, left)
        for index, left in enumerate(private_directories)
        for right in private_directories[index + 1 :]
    ):
        raise ProbeError("private-directories-overlap")
    if config.provider == "claude":
        capture_ids = _claude_capture_ids(config.capture_id)
        try:
            names = {entry.name for entry in os.scandir(capture_root)}
        except OSError as error:
            raise ProbeError("capture-inventory-invalid") from error
        if names - {".clilane-provider-capture.lock"}:
            raise ProbeError("claude-capture-root-not-fresh")
        if any(
            f"{capture_id}.capture" in names
            or f"{capture_id}.receipt.json" in names
            for capture_id in capture_ids.values()
        ):
            raise ProbeError("capture-id-in-use")
    return ProbeConfig(
        provider=config.provider,
        capture_root=capture_root,
        capture_id=config.capture_id,
        provider_executable=config.provider_executable,
        workspace=workspace,
        config_dir=config_dir,
    )


def run_probe(config: ProbeConfig) -> ProbeResult:
    validated = validate_config(config)
    expected_sha256 = load_executable_manifest(EXECUTABLE_MANIFEST_PATH)
    pinned = pin_executable(
        validated.provider,
        validated.provider_executable,
        expected_sha256,
        validated.config_dir if validated.provider == "claude" else None,
    )
    try:
        validated = ProbeConfig(
            provider=validated.provider,
            capture_root=validated.capture_root,
            capture_id=validated.capture_id,
            provider_executable=pinned.path,
            workspace=validated.workspace,
            config_dir=validated.config_dir,
        )
        if validated.provider == "claude":
            return run_claude_probe(validated, pinned)
        transport = JsonLineTransport(validated, pinned)
        try:
            protocol: CodexProtocol | KimiProtocol
            if validated.provider == "codex":
                protocol = CodexProtocol(transport, validated.workspace)
            else:
                protocol = KimiProtocol(transport, validated.workspace)
            protocol.run()
            transport.finish()
            return ProbeResult(
                provider=validated.provider,
                provider_version=PROVIDER_VERSIONS[validated.provider],
                message_count=transport.message_count,
                stdout_bytes=transport.stdout_bytes,
            )
        except BaseException:
            transport.abort()
            raise
        finally:
            transport.close()
    finally:
        _cleanup_pinned(pinned)


def parse_args(argv: Sequence[str]) -> ProbeConfig:
    parser = SafeArgumentParser(prog="provider_probe.py", allow_abbrev=False)
    parser.add_argument("--provider", required=True, choices=("claude", "codex", "kimi"))
    parser.add_argument("--capture-root", required=True)
    parser.add_argument("--capture-id", required=True)
    parser.add_argument("--provider-executable", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--config-dir")
    arguments = parser.parse_args(argv)
    return ProbeConfig(
        provider=arguments.provider,
        capture_root=Path(arguments.capture_root),
        capture_id=arguments.capture_id,
        provider_executable=Path(arguments.provider_executable),
        workspace=Path(arguments.workspace),
        config_dir=Path(arguments.config_dir) if arguments.config_dir else None,
    )


def main(argv: Sequence[str] | None = None) -> int:
    try:
        run_probe(parse_args(sys.argv[1:] if argv is None else argv))
    except ProbeError as error:
        print(f"provider_probe.py: {error}", file=sys.stderr)
        return 1
    except Exception:
        print("provider_probe.py: internal-error", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
