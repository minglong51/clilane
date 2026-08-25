#!/usr/bin/env python3

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import selectors
import secrets
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterator, NoReturn, Sequence


SCHEMA_VERSION = 1
CAPTURE_MAGIC = b"CLILANE_PROVIDER_CAPTURE_V1\n"
FRAME_HEADER = struct.Struct(">cQQQ")
CHUNK_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 8 * 1024
MAX_VERSION_BYTES = 4 * 1024
MAX_BUDGET_BYTES = 1 << 40
MAX_TIMEOUT_SECONDS = 24 * 60 * 60
VERSION_TIMEOUT_SECONDS = 5.0
TERMINATE_GRACE_SECONDS = 1.0
DRAIN_GRACE_SECONDS = 1.0
PROVIDER_COMMAND_CWD = Path("/")
CAPTURE_ID_PATTERN = re.compile(r"capture-[a-z0-9][a-z0-9-]{0,95}")
PROVIDER_EXIT_FAILURE = 4
INCOMPLETE_EXIT = 3


class CaptureError(Exception):
    pass


class CollectorSignal(BaseException):
    def __init__(self, number: int) -> None:
        self.number = number


@dataclass
class SignalState:
    depth: int = 0
    pending: int | None = None
    settling: bool = False


class SignalDeferral:
    def __enter__(self) -> None:
        if ACTIVE_SIGNAL_STATE is not None:
            ACTIVE_SIGNAL_STATE.depth += 1

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        state = ACTIVE_SIGNAL_STATE
        if state is None:
            return
        state.depth -= 1
        if state.depth == 0 and state.pending is not None and _kind is None:
            number = state.pending
            state.pending = None
            raise CollectorSignal(number)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


ACTIVE_SIGNAL_STATE: SignalState | None = None


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    executable: str
    version: str
    version_outputs: tuple[bytes, ...]
    source_interface: str
    mode: str
    command: tuple[str, ...]


@dataclass(frozen=True)
class RepositoryPaths:
    worktree: Path
    git_dir: Path


@dataclass
class CaptureRoot:
    path: Path
    directory_fd: int
    identity: tuple[int, int]
    lock_fd: int | None = None

    def close(self) -> None:
        if self.lock_fd is not None:
            fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
            os.close(self.lock_fd)
            self.lock_fd = None
        os.close(self.directory_fd)


@dataclass
class ExecutableIdentity:
    path: Path
    version: str
    sha256: str
    metadata: tuple[int, int, int, int]
    descriptor: int | None = None
    stage_name: str | None = None
    stage_directory_fd: int | None = None
    stage_directory_identity: tuple[int, int] | None = None


@dataclass(frozen=True)
class Observation:
    reason: str
    exit_code: int | None
    provider_signal: int | None
    collector_signal: int | None
    incomplete_reasons: tuple[str, ...]


@dataclass(frozen=True)
class CaptureResult:
    receipt: dict[str, Any]
    exit_status: int


PROVIDER_SPECS = {
    "claude": ProviderSpec(
        name="claude",
        executable="claude",
        version="2.1.245",
        version_outputs=(
            b"2.1.245 (Claude Code)\n",
            b"2.1.245 (Claude Code)\r\n",
        ),
        source_interface="claude-native-hook",
        mode="stdin",
        command=(),
    ),
    "codex": ProviderSpec(
        name="codex",
        executable="codex",
        version="0.149.1",
        version_outputs=(b"codex-cli 0.149.1\n", b"codex-cli 0.149.1\r\n"),
        source_interface="codex-app-server",
        mode="command",
        command=("app-server", "--stdio", "--strict-config"),
    ),
    "kimi": ProviderSpec(
        name="kimi",
        executable="kimi",
        version="0.38.0",
        version_outputs=(b"0.38.0\n", b"0.38.0\r\n"),
        source_interface="kimi-acp",
        mode="command",
        command=("acp",),
    ),
}


CODEX_TARGETS = {
    ("Darwin", "arm64"): ("codex-darwin-arm64", "aarch64-apple-darwin"),
    ("Darwin", "x86_64"): ("codex-darwin-x64", "x86_64-apple-darwin"),
    ("Linux", "aarch64"): ("codex-linux-arm64", "aarch64-unknown-linux-musl"),
    ("Linux", "x86_64"): ("codex-linux-x64", "x86_64-unknown-linux-musl"),
}


def positive_integer(value: str) -> int:
    if not value.isascii() or not value.isdigit() or len(value) > 13:
        raise argparse.ArgumentTypeError("expected a positive integer")
    result = int(value)
    if result < 1 or result > MAX_BUDGET_BYTES:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return result


def positive_timeout(value: str) -> int:
    result = positive_integer(value)
    if result > MAX_TIMEOUT_SECONDS:
        raise argparse.ArgumentTypeError("expected a positive timeout")
    return result


def _metadata(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _read_git_file(path: Path) -> Path:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 4096:
            raise CaptureError("repository-metadata-invalid")
        chunks: list[bytes] = []
        remaining = 4097
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if _metadata(after) != _metadata(before):
            raise CaptureError("repository-metadata-changed")
        raw = b"".join(chunks)
        if len(raw) > 4096:
            raise CaptureError("repository-metadata-invalid")
    except OSError as error:
        raise CaptureError("repository-metadata-invalid") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)
    try:
        line = raw.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise CaptureError("repository-metadata-invalid") from error
    prefix = "gitdir: "
    if not line.startswith(prefix) or "\n" in line or "\r" in line:
        raise CaptureError("repository-metadata-invalid")
    target = Path(line[len(prefix) :])
    if not target.is_absolute():
        target = path.parent / target
    try:
        resolved = target.resolve(strict=True)
        if not resolved.is_dir():
            raise CaptureError("repository-metadata-invalid")
        return resolved
    except OSError as error:
        raise CaptureError("repository-metadata-invalid") from error


def repository_paths(module_path: Path | None = None) -> RepositoryPaths:
    source = Path(__file__) if module_path is None else module_path
    try:
        worktree = source.resolve(strict=True).parents[1]
        git_marker = worktree / ".git"
        marker_metadata = git_marker.lstat()
        if stat.S_ISLNK(marker_metadata.st_mode):
            raise CaptureError("repository-metadata-invalid")
        if stat.S_ISDIR(marker_metadata.st_mode):
            git_dir = git_marker.resolve(strict=True)
        else:
            git_dir = _read_git_file(git_marker)
    except (IndexError, OSError) as error:
        raise CaptureError("repository-metadata-unavailable") from error
    return RepositoryPaths(worktree=worktree, git_dir=git_dir)


def _ancestor_identities(path: Path) -> set[tuple[int, int]]:
    identities: set[tuple[int, int]] = set()
    current = path
    while True:
        try:
            metadata = current.stat()
        except OSError as error:
            raise CaptureError("path-identity-unavailable") from error
        identities.add((metadata.st_dev, metadata.st_ino))
        parent = current.parent
        if parent == current:
            return identities
        current = parent


def _overlaps_by_identity(left: Path, right: Path) -> bool:
    left_metadata = left.stat()
    right_metadata = right.stat()
    left_identity = (left_metadata.st_dev, left_metadata.st_ino)
    right_identity = (right_metadata.st_dev, right_metadata.st_ino)
    return (
        left_identity in _ancestor_identities(right)
        or right_identity in _ancestor_identities(left)
    )


def validate_capture_root(capture_root: Path, paths: RepositoryPaths) -> CaptureRoot:
    if not capture_root.is_absolute():
        raise CaptureError("capture-root-not-absolute")
    lexical = Path(os.path.abspath(os.fspath(capture_root)))
    try:
        metadata = lexical.lstat()
        resolved = lexical.resolve(strict=True)
    except OSError as error:
        raise CaptureError("capture-root-unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or lexical != resolved:
        raise CaptureError("capture-root-symlinked")
    if not stat.S_ISDIR(metadata.st_mode):
        raise CaptureError("capture-root-not-directory")
    if metadata.st_uid != os.getuid():
        raise CaptureError("capture-root-wrong-owner")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise CaptureError("capture-root-wrong-mode")
    try:
        if _overlaps_by_identity(resolved, paths.worktree) or _overlaps_by_identity(
            resolved, paths.git_dir
        ):
            raise CaptureError("capture-root-overlaps-repository")
    except OSError as error:
        raise CaptureError("path-identity-unavailable") from error
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(resolved, flags)
        opened = os.fstat(directory_fd)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise CaptureError("capture-root-changed")
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise CaptureError("capture-root-changed")
    except BaseException:
        if "directory_fd" in locals():
            os.close(directory_fd)
        raise
    return CaptureRoot(
        path=resolved,
        directory_fd=directory_fd,
        identity=(opened.st_dev, opened.st_ino),
    )


def _root_identity_matches(root: CaptureRoot) -> bool:
    try:
        metadata = root.path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and (metadata.st_dev, metadata.st_ino) == root.identity
        and metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700
    )


def _lock_root(root: CaptureRoot) -> None:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            ".clilane-provider-capture.lock",
            flags,
            0o600,
            dir_fd=root.directory_fd,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise CaptureError("capture-lock-unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError) as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise CaptureError("capture-root-busy") from error
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    root.lock_fd = descriptor


def _aggregate_bytes(root: CaptureRoot) -> int:
    total = 0
    for name in os.listdir(root.directory_fd):
        if not name.endswith(".capture"):
            continue
        try:
            metadata = os.stat(name, dir_fd=root.directory_fd, follow_symlinks=False)
        except OSError as error:
            raise CaptureError("capture-inventory-changed") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise CaptureError("capture-inventory-unsafe")
        total += metadata.st_size
        if total > MAX_BUDGET_BYTES:
            raise CaptureError("capture-inventory-oversized")
    return total


def validate_request(
    capture_id: str,
    per_capture_bytes: int,
    aggregate_bytes: int,
    timeout_seconds: int,
) -> None:
    if CAPTURE_ID_PATTERN.fullmatch(capture_id) is None:
        raise CaptureError("capture-id-invalid")
    if (
        type(per_capture_bytes) is not int
        or type(aggregate_bytes) is not int
        or type(timeout_seconds) is not int
        or per_capture_bytes < 1
        or aggregate_bytes < per_capture_bytes
        or timeout_seconds < 1
        or per_capture_bytes > MAX_BUDGET_BYTES
        or aggregate_bytes > MAX_BUDGET_BYTES
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise CaptureError("capture-arguments-invalid")


def preflight_capture(
    root: CaptureRoot,
    capture_id: str,
    per_capture_bytes: int,
    aggregate_bytes: int,
) -> tuple[int, tuple[str, ...]]:
    used = _aggregate_bytes(root)
    remaining = max(aggregate_bytes - used, 0)
    limit = min(per_capture_bytes, remaining)
    reasons: list[str] = []
    if limit == per_capture_bytes:
        reasons.append("per_capture_budget")
    if limit == remaining:
        reasons.append("aggregate_budget")
    filesystem = os.fstatvfs(root.directory_fd)
    block_size = filesystem.f_frsize or filesystem.f_bsize
    available_bytes = filesystem.f_bavail * block_size
    if available_bytes < limit + MAX_RECEIPT_BYTES:
        raise CaptureError("capture-root-insufficient-space")
    names = (
        f"{capture_id}.capture",
        f"{capture_id}.receipt.json",
        f"{capture_id}.receipt.tmp",
    )
    for name in names:
        try:
            os.stat(name, dir_fd=root.directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise CaptureError("capture-destination-unavailable") from error
        raise CaptureError("capture-id-exists")
    return limit, tuple(reasons)


def _create_capture(root: CaptureRoot, capture_id: str) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    capture_name = f"{capture_id}.capture"
    try:
        descriptor = os.open(capture_name, flags, 0o600, dir_fd=root.directory_fd)
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise CaptureError("capture-destination-unsafe")
        return descriptor
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
            try:
                os.unlink(capture_name, dir_fd=root.directory_fd)
            except OSError:
                pass
        raise


def reserve_capture(
    root: CaptureRoot,
    capture_id: str,
    per_capture_bytes: int,
    aggregate_bytes: int,
) -> tuple[int | None, int, tuple[str, ...]]:
    limit, reasons = preflight_capture(
        root, capture_id, per_capture_bytes, aggregate_bytes
    )
    if limit < len(CAPTURE_MAGIC):
        return None, limit, reasons
    return _create_capture(root, capture_id), limit, reasons


class CaptureWriter:
    def __init__(self, descriptor: int, limit: int) -> None:
        self.descriptor = descriptor
        self.limit = limit
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise CaptureError("capture-destination-unsafe")
        self.initial_identity = (metadata.st_dev, metadata.st_ino)
        self.final_metadata: tuple[int, int, int, int] | None = None
        self.capture_bytes = 0
        self.payload_bytes = 0
        self.sequence = 0
        self.digest = hashlib.sha256()
        self.stream_bytes = {b"I": 0, b"O": 0, b"E": 0}
        self.stream_digests = {
            b"I": hashlib.sha256(),
            b"O": hashlib.sha256(),
            b"E": hashlib.sha256(),
        }
        self.started_ns = time.monotonic_ns()
        self.closed = False

    @property
    def at_limit(self) -> bool:
        return self.capture_bytes >= self.limit

    def payload_capacity(self) -> int:
        return max(self.limit - self.capture_bytes - FRAME_HEADER.size, 0)

    def _write(self, raw: bytes) -> None:
        offset = 0
        while offset < len(raw):
            written = os.write(self.descriptor, raw[offset:])
            if written < 1:
                raise CaptureError("capture-write-failed")
            segment = raw[offset : offset + written]
            self.digest.update(segment)
            self.capture_bytes += written
            offset += written

    def start(self) -> bool:
        if self.limit < len(CAPTURE_MAGIC):
            return False
        self._write(CAPTURE_MAGIC)
        return not self.at_limit

    def write_frame(self, stream: bytes, payload: bytes) -> int:
        if stream not in self.stream_bytes or not payload:
            raise CaptureError("capture-frame-invalid")
        retained = min(len(payload), self.payload_capacity())
        if retained < 1:
            return 0
        observed_ns = max(time.monotonic_ns() - self.started_ns, 0)
        self._write(FRAME_HEADER.pack(stream, self.sequence, observed_ns, retained))
        segment = payload[:retained]
        self._write(segment)
        self.payload_bytes += retained
        self.stream_bytes[stream] += retained
        self.stream_digests[stream].update(segment)
        self.sequence += 1
        return retained

    def finish(self) -> str:
        if self.closed:
            raise CaptureError("capture-writer-closed")
        try:
            os.ftruncate(self.descriptor, self.capture_bytes)
            os.fsync(self.descriptor)
            metadata = os.fstat(self.descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or (metadata.st_dev, metadata.st_ino) != self.initial_identity
                or metadata.st_size != self.capture_bytes
            ):
                raise CaptureError("capture-destination-changed")
            self.final_metadata = _metadata(metadata)
        except OSError as error:
            raise CaptureError("capture-finalize-failed") from error
        finally:
            os.close(self.descriptor)
            self.closed = True
        return self.digest.hexdigest()


def _capture_path_matches(
    root: CaptureRoot, capture_id: str, writer: CaptureWriter
) -> bool:
    if writer.final_metadata is None:
        return False
    try:
        metadata = os.stat(
            f"{capture_id}.capture",
            dir_fd=root.directory_fd,
            follow_symlinks=False,
        )
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and metadata.st_nlink == 1
        and _metadata(metadata) == writer.final_metadata
    )


def iter_capture_frames(source: BinaryIO) -> Iterator[tuple[str, int, bytes]]:
    magic = source.read(len(CAPTURE_MAGIC))
    if magic != CAPTURE_MAGIC:
        raise CaptureError("capture-framing-invalid")
    expected_sequence = 0
    previous_observed_ns = 0
    cumulative_bytes = len(CAPTURE_MAGIC)
    while True:
        header = source.read(FRAME_HEADER.size)
        if not header:
            return
        if len(header) != FRAME_HEADER.size:
            raise CaptureError("capture-framing-truncated")
        stream, sequence, observed_ns, length = FRAME_HEADER.unpack(header)
        if (
            stream not in {b"I", b"O", b"E"}
            or sequence != expected_sequence
            or observed_ns < previous_observed_ns
            or length > CHUNK_BYTES
            or cumulative_bytes + FRAME_HEADER.size + length > MAX_BUDGET_BYTES
        ):
            raise CaptureError("capture-framing-invalid")
        payload = source.read(length)
        if len(payload) != length:
            raise CaptureError("capture-framing-truncated")
        yield stream.decode("ascii"), observed_ns, payload
        expected_sequence += 1
        previous_observed_ns = observed_ns
        cumulative_bytes += FRAME_HEADER.size + length


def _signal_group(process: subprocess.Popen[bytes], number: int) -> None:
    try:
        os.killpg(process.pid, number)
    except ProcessLookupError:
        pass


def _group_exists(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _discard_ready(selector: selectors.BaseSelector, wait_seconds: float) -> None:
    for key, _mask in selector.select(wait_seconds):
        try:
            chunk = os.read(key.fd, CHUNK_BYTES)
        except OSError:
            chunk = b""
        if not chunk:
            try:
                selector.unregister(key.fileobj)
            except KeyError:
                pass
            key.fileobj.close()


def _provider_environment(cwd: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PWD"] = str(cwd)
    environment["OLDPWD"] = str(cwd)
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ):
        environment.pop(name, None)
    return environment


def _terminate_and_drain(
    process: subprocess.Popen[bytes], selector: selectors.BaseSelector
) -> int:
    with SignalDeferral():
        _signal_group(process, signal.SIGTERM)
        term_deadline = time.monotonic() + TERMINATE_GRACE_SECONDS
        while time.monotonic() < term_deadline and _group_exists(process):
            _discard_ready(
                selector,
                min(0.05, max(term_deadline - time.monotonic(), 0)),
            )
            process.poll()
        if _group_exists(process):
            _signal_group(process, signal.SIGKILL)
        kill_deadline = time.monotonic() + DRAIN_GRACE_SECONDS
        while time.monotonic() < kill_deadline and (
            selector.get_map() or _group_exists(process)
        ):
            _discard_ready(
                selector,
                min(0.05, max(kill_deadline - time.monotonic(), 0)),
            )
            process.poll()
        for key in list(selector.get_map().values()):
            selector.unregister(key.fileobj)
            key.fileobj.close()
        try:
            return process.wait(timeout=TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise CaptureError("provider-cleanup-failed") from error


def _small_command(command: Sequence[str], cwd: Path) -> tuple[int, bytes]:
    selector = selectors.DefaultSelector()
    process: subprocess.Popen[bytes] | None = None
    try:
        with SignalDeferral():
            try:
                process = subprocess.Popen(
                    list(command),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    cwd=cwd,
                    env=_provider_environment(cwd),
                    start_new_session=True,
                    close_fds=True,
                )
            except OSError as error:
                raise CaptureError("provider-version-failed") from error
            if process.stdout is None:
                raise CaptureError("provider-version-failed")
            selector.register(process.stdout, selectors.EVENT_READ)
        output = bytearray()
        deadline = time.monotonic() + VERSION_TIMEOUT_SECONDS
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= deadline:
                _terminate_and_drain(process, selector)
                raise CaptureError("provider-version-timeout")
            for key, _mask in selector.select(0.05):
                try:
                    chunk = os.read(key.fd, CHUNK_BYTES)
                except OSError as error:
                    raise CaptureError("provider-version-failed") from error
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                output.extend(chunk)
                if len(output) > MAX_VERSION_BYTES:
                    _terminate_and_drain(process, selector)
                    raise CaptureError("provider-version-oversized")
        return_code = process.wait()
        if _group_exists(process):
            _terminate_and_drain(process, selector)
            raise CaptureError("provider-version-descendant-process")
        return return_code, bytes(output)
    finally:
        selector.close()
        if process is not None and process.poll() is None:
            cleanup_selector = selectors.DefaultSelector()
            if process.stdout is not None and not process.stdout.closed:
                cleanup_selector.register(process.stdout, selectors.EVENT_READ)
            try:
                _terminate_and_drain(process, cleanup_selector)
            finally:
                cleanup_selector.close()


def _secure_which(name: str) -> Path:
    search_path = os.environ.get("PATH")
    if search_path is None:
        raise CaptureError("provider-executable-not-found")
    entries = search_path.split(os.pathsep)
    if any(not entry or not Path(entry).is_absolute() for entry in entries):
        raise CaptureError("provider-path-unsafe")
    candidate = shutil.which(name, path=search_path)
    if candidate is None:
        raise CaptureError("provider-executable-not-found")
    return Path(candidate)


def _codex_native_path(launcher: Path) -> Path:
    resolved = launcher.resolve(strict=True)
    if resolved.name != "codex.js":
        return resolved
    target = CODEX_TARGETS.get((platform.system(), platform.machine()))
    if target is None:
        raise CaptureError("provider-platform-unsupported")
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
    raise CaptureError("provider-native-executable-not-found")


def _hash_descriptor(descriptor: int) -> tuple[str, tuple[int, int, int, int]]:
    digest = hashlib.sha256()
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise CaptureError("provider-executable-invalid")
    offset = 0
    while True:
        chunk = os.pread(descriptor, CHUNK_BYTES, offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    if _metadata(after) != _metadata(before):
        raise CaptureError("provider-executable-changed")
    return digest.hexdigest(), _metadata(after)


def _hash_executable(path: Path) -> tuple[str, tuple[int, int, int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        return _hash_descriptor(descriptor)
    except OSError as error:
        raise CaptureError("provider-executable-unreadable") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _identity_matches(
    identity: ExecutableIdentity, *, verify_hash: bool = False
) -> bool:
    try:
        metadata = identity.path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or _metadata(metadata) != identity.metadata:
        return False
    if identity.descriptor is not None and (
        metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o500
        or metadata.st_nlink != 1
    ):
        return False
    if not verify_hash:
        return True
    try:
        if identity.descriptor is None:
            executable_hash, pinned_metadata = _hash_executable(identity.path)
        else:
            executable_hash, pinned_metadata = _hash_descriptor(identity.descriptor)
    except (CaptureError, OSError):
        return False
    return executable_hash == identity.sha256 and pinned_metadata == identity.metadata


def _cleanup_executable(root: CaptureRoot, identity: ExecutableIdentity) -> None:
    if identity.stage_name is None or identity.stage_directory_fd is None:
        if identity.descriptor is not None:
            os.close(identity.descriptor)
            identity.descriptor = None
        return
    error: OSError | None = None
    try:
        os.fchmod(identity.stage_directory_fd, 0o700)
        if identity.descriptor is not None:
            os.close(identity.descriptor)
            identity.descriptor = None
        metadata = os.stat(
            "provider",
            dir_fd=identity.stage_directory_fd,
            follow_symlinks=False,
        )
        if (metadata.st_dev, metadata.st_ino) != (
            identity.metadata[0],
            identity.metadata[1],
        ):
            raise OSError("provider stage changed")
        os.unlink("provider", dir_fd=identity.stage_directory_fd)
    except OSError as caught:
        error = caught
    finally:
        os.close(identity.stage_directory_fd)
        identity.stage_directory_fd = None
    try:
        metadata = os.stat(
            identity.stage_name,
            dir_fd=root.directory_fd,
            follow_symlinks=False,
        )
        if identity.stage_directory_identity is None or (
            metadata.st_dev,
            metadata.st_ino,
        ) != identity.stage_directory_identity:
            raise OSError("provider stage directory changed")
        os.rmdir(identity.stage_name, dir_fd=root.directory_fd)
        os.fsync(root.directory_fd)
    except OSError as caught:
        if error is None:
            error = caught
    identity.stage_name = None
    identity.stage_directory_identity = None
    if error is not None:
        raise CaptureError("provider-stage-cleanup-failed") from error


def _stage_executable(
    root: CaptureRoot,
    resolved: Path,
    version: str,
    required_capture_bytes: int,
) -> ExecutableIdentity:
    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    stage_directory_fd: int | None = None
    stage_descriptor: int | None = None
    stage_writer: int | None = None
    stage_name: str | None = None
    identity: ExecutableIdentity | None = None
    try:
        source = os.open(resolved, source_flags)
        source_metadata = os.fstat(source)
        if not stat.S_ISREG(source_metadata.st_mode):
            raise CaptureError("provider-executable-invalid")
        filesystem = os.fstatvfs(root.directory_fd)
        block_size = filesystem.f_frsize or filesystem.f_bsize
        available_bytes = filesystem.f_bavail * block_size
        if available_bytes < (
            source_metadata.st_size + required_capture_bytes + MAX_RECEIPT_BYTES
        ):
            raise CaptureError("capture-root-insufficient-space")
        for _attempt in range(8):
            candidate = f".clilane-provider-stage-{secrets.token_hex(16)}"
            try:
                os.mkdir(candidate, 0o700, dir_fd=root.directory_fd)
            except FileExistsError:
                continue
            stage_name = candidate
            break
        if stage_name is None:
            raise CaptureError("provider-stage-unavailable")
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        stage_directory_fd = os.open(
            stage_name,
            directory_flags,
            dir_fd=root.directory_fd,
        )
        directory_metadata = os.fstat(stage_directory_fd)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.getuid()
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
        ):
            raise CaptureError("provider-stage-unsafe")
        write_flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        stage_writer = os.open(
            "provider",
            write_flags,
            0o600,
            dir_fd=stage_directory_fd,
        )
        digest = hashlib.sha256()
        while True:
            chunk = os.read(source, CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(stage_writer, chunk[offset:])
                if written < 1:
                    raise CaptureError("provider-stage-write-failed")
                offset += written
        if _metadata(os.fstat(source)) != _metadata(source_metadata):
            raise CaptureError("provider-executable-changed")
        os.fchmod(stage_writer, 0o500)
        os.fsync(stage_writer)
        written_metadata = os.fstat(stage_writer)
        if (
            not stat.S_ISREG(written_metadata.st_mode)
            or written_metadata.st_uid != os.getuid()
            or stat.S_IMODE(written_metadata.st_mode) != 0o500
            or written_metadata.st_nlink != 1
            or written_metadata.st_size != source_metadata.st_size
        ):
            raise CaptureError("provider-stage-unsafe")
        os.close(stage_writer)
        stage_writer = None
        stage_descriptor = os.open(
            "provider",
            source_flags,
            dir_fd=stage_directory_fd,
        )
        stage_hash, stage_metadata = _hash_descriptor(stage_descriptor)
        if stage_hash != digest.hexdigest():
            raise CaptureError("provider-stage-changed")
        os.fchmod(stage_directory_fd, 0o500)
        os.fsync(stage_directory_fd)
        os.fsync(root.directory_fd)
        identity = ExecutableIdentity(
            path=root.path / stage_name / "provider",
            version=version,
            sha256=stage_hash,
            metadata=stage_metadata,
            descriptor=stage_descriptor,
            stage_name=stage_name,
            stage_directory_fd=stage_directory_fd,
            stage_directory_identity=(
                directory_metadata.st_dev,
                directory_metadata.st_ino,
            ),
        )
        return identity
    except OSError as error:
        raise CaptureError("provider-stage-failed") from error
    finally:
        if "source" in locals():
            os.close(source)
        if stage_writer is not None:
            os.close(stage_writer)
        if identity is None:
            if stage_descriptor is not None:
                os.close(stage_descriptor)
            if stage_directory_fd is not None:
                try:
                    os.fchmod(stage_directory_fd, 0o700)
                    os.unlink("provider", dir_fd=stage_directory_fd)
                except OSError:
                    pass
                os.close(stage_directory_fd)
            if stage_name is not None:
                try:
                    os.rmdir(stage_name, dir_fd=root.directory_fd)
                    os.fsync(root.directory_fd)
                except OSError:
                    pass


def resolve_executable(
    spec: ProviderSpec,
    override: str | None,
    cwd: Path,
    root: CaptureRoot,
    required_capture_bytes: int,
) -> ExecutableIdentity:
    if override is None:
        selected = _secure_which(spec.executable)
    else:
        selected = Path(override)
        if not selected.is_absolute():
            raise CaptureError("provider-executable-not-absolute")
    try:
        resolved = selected.resolve(strict=True)
        if spec.name == "codex":
            resolved = _codex_native_path(resolved)
        metadata = resolved.lstat()
    except OSError as error:
        raise CaptureError("provider-executable-invalid") from error
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise CaptureError("provider-executable-invalid")
    identity: ExecutableIdentity | None = None
    try:
        with SignalDeferral():
            identity = _stage_executable(
                root,
                resolved,
                spec.version,
                required_capture_bytes,
            )
        if not _root_identity_matches(root):
            raise CaptureError("capture-root-changed")
        return_code, raw_version = _small_command(
            (str(identity.path), "--version"),
            cwd,
        )
        if return_code != 0:
            raise CaptureError("provider-version-failed")
        if raw_version not in spec.version_outputs:
            raise CaptureError("provider-version-invalid")
        if not _identity_matches(identity, verify_hash=True):
            raise CaptureError("provider-executable-changed")
        return identity
    except BaseException as error:
        if isinstance(error, (CollectorSignal, KeyboardInterrupt)):
            _settle_signals()
        if identity is not None:
            with SignalDeferral():
                _cleanup_executable(root, identity)
        raise


def _cap_observation(reasons: tuple[str, ...]) -> Observation:
    return Observation(
        reason="byte_cap",
        exit_code=None,
        provider_signal=None,
        collector_signal=None,
        incomplete_reasons=reasons,
    )


def _collector_signal_observation(number: int) -> Observation:
    state = ACTIVE_SIGNAL_STATE
    if state is not None:
        state.pending = None
        state.settling = True
    return Observation(
        reason="collector_signal",
        exit_code=None,
        provider_signal=None,
        collector_signal=number,
        incomplete_reasons=("collector_signal",),
    )


def _settle_signals() -> None:
    state = ACTIVE_SIGNAL_STATE
    if state is not None:
        state.pending = None
        state.settling = True


def _source_descriptor(source: BinaryIO) -> int | None:
    try:
        return source.fileno()
    except (AttributeError, OSError):
        return None


def capture_stdin(
    writer: CaptureWriter,
    source: BinaryIO,
    timeout_seconds: int,
    cap_reasons: tuple[str, ...],
) -> Observation:
    descriptor = _source_descriptor(source)
    selector: selectors.BaseSelector | None = None
    if descriptor is not None:
        selector = selectors.DefaultSelector()
        try:
            selector.register(descriptor, selectors.EVENT_READ)
        except OSError as error:
            selector.close()
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise CaptureError("stdin-not-pollable") from error
            except OSError as stat_error:
                raise CaptureError("stdin-not-pollable") from stat_error
            selector = None
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return Observation("timeout", None, None, None, ("timeout",))
            if selector is not None and not selector.select(min(remaining, 0.05)):
                continue
            try:
                chunk = (
                    os.read(descriptor, CHUNK_BYTES)
                    if descriptor is not None
                    else source.read(CHUNK_BYTES)
                )
            except OSError as error:
                raise CaptureError("stdin-read-failed") from error
            if not chunk:
                return Observation("hook_eof", None, None, None, ())
            if type(chunk) is not bytes:
                raise CaptureError("stdin-read-invalid")
            retained = writer.write_frame(b"I", chunk)
            if retained != len(chunk) or writer.at_limit:
                return _cap_observation(cap_reasons)
    except CollectorSignal as interruption:
        return _collector_signal_observation(interruption.number)
    except KeyboardInterrupt:
        return _collector_signal_observation(signal.SIGINT)
    finally:
        if selector is not None:
            selector.close()


def _close_registered(
    selector: selectors.BaseSelector, fileobj: BinaryIO, *, close: bool
) -> None:
    try:
        selector.unregister(fileobj)
    except (KeyError, ValueError):
        pass
    if close and not fileobj.closed:
        fileobj.close()


def _write_sink(sink: BinaryIO, payload: bytes, deadline: float) -> bool:
    descriptor = _source_descriptor(sink)
    try:
        if descriptor is None:
            written = sink.write(payload)
            if written != len(payload):
                raise CaptureError("provider-stdout-write-failed")
            sink.flush()
            return True
        was_blocking = os.get_blocking(descriptor)
        os.set_blocking(descriptor, False)
        selector: selectors.BaseSelector | None = None
        try:
            offset = 0
            while offset < len(payload):
                try:
                    written = os.write(descriptor, payload[offset:])
                except BlockingIOError:
                    written = 0
                if written > 0:
                    offset += written
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                if selector is None:
                    selector = selectors.DefaultSelector()
                    selector.register(descriptor, selectors.EVENT_WRITE)
                selector.select(min(remaining, 0.05))
            return True
        finally:
            if selector is not None:
                selector.close()
            os.set_blocking(descriptor, was_blocking)
    except OSError as error:
        raise CaptureError("provider-stdout-write-failed") from error


def capture_command(
    writer: CaptureWriter,
    command: Sequence[str],
    timeout_seconds: int,
    cap_reasons: tuple[str, ...],
    source: BinaryIO,
    sink: BinaryIO,
    cwd: Path,
) -> Observation:
    source_fd = _source_descriptor(source)
    if source_fd is None:
        raise CaptureError("provider-stdin-invalid")
    selector = selectors.DefaultSelector()
    process: subprocess.Popen[bytes] | None = None
    try:
        with SignalDeferral():
            try:
                process = subprocess.Popen(
                    list(command),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=cwd,
                    env=_provider_environment(cwd),
                    start_new_session=True,
                    close_fds=True,
                )
            except OSError as error:
                raise CaptureError("provider-spawn-failed") from error
            if process.stdin is None or process.stdout is None or process.stderr is None:
                for pipe in (process.stdout, process.stderr):
                    if pipe is not None:
                        selector.register(pipe, selectors.EVENT_READ)
                raise CaptureError("provider-spawn-failed")
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ, b"O")
            selector.register(process.stderr, selectors.EVENT_READ, b"E")
            source_pollable = True
            try:
                selector.register(source_fd, selectors.EVENT_READ, b"R")
            except OSError as error:
                try:
                    source_mode = os.fstat(source_fd).st_mode
                except OSError as stat_error:
                    raise CaptureError("provider-stdin-invalid") from stat_error
                if not (stat.S_ISREG(source_mode) or stat.S_ISCHR(source_mode)):
                    raise CaptureError("provider-stdin-not-pollable") from error
                source_pollable = False
    except CollectorSignal as interruption:
        signal_observation = _collector_signal_observation(interruption.number)
        return_code: int | None = None
        if process is not None:
            try:
                selector.unregister(source_fd)
            except (KeyError, ValueError):
                pass
            if process.stdin is not None:
                _close_registered(selector, process.stdin, close=True)
            return_code = _terminate_and_drain(process, selector)
        selector.close()
        return Observation(
            signal_observation.reason,
            return_code if return_code is not None and return_code >= 0 else None,
            -return_code if return_code is not None and return_code < 0 else None,
            signal_observation.collector_signal,
            signal_observation.incomplete_reasons,
        )
    except BaseException:
        if process is not None:
            try:
                selector.unregister(source_fd)
            except (KeyError, ValueError):
                pass
            if process.stdin is not None:
                _close_registered(selector, process.stdin, close=True)
            _terminate_and_drain(process, selector)
        selector.close()
        raise
    pending = bytearray()
    source_eof = False
    deadline = time.monotonic() + timeout_seconds
    observation: Observation | None = None
    try:
        while selector.get_map() or process.poll() is None:
            if process.poll() is not None:
                _close_registered(selector, process.stdin, close=True)
                try:
                    selector.unregister(source_fd)
                except KeyError:
                    pass
                source_eof = True
                pending.clear()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                observation = Observation("timeout", None, None, None, ("timeout",))
                break
            if not source_pollable and not source_eof and not pending:
                try:
                    chunk = os.read(source_fd, CHUNK_BYTES)
                except OSError as error:
                    raise CaptureError("provider-stdin-read-failed") from error
                if not chunk:
                    source_eof = True
                    _close_registered(selector, process.stdin, close=True)
                else:
                    pending.extend(chunk)
                    selector.register(process.stdin, selectors.EVENT_WRITE, b"W")
            for key, _mask in selector.select(min(remaining, 0.05)):
                if key.data == b"R":
                    try:
                        chunk = os.read(source_fd, CHUNK_BYTES)
                    except OSError as error:
                        raise CaptureError("provider-stdin-read-failed") from error
                    if not chunk:
                        selector.unregister(source_fd)
                        source_eof = True
                        if not pending:
                            _close_registered(selector, process.stdin, close=True)
                    else:
                        pending.extend(chunk)
                        selector.unregister(source_fd)
                        selector.register(process.stdin, selectors.EVENT_WRITE, b"W")
                    continue
                if key.data == b"W":
                    capacity = writer.payload_capacity()
                    if capacity < 1:
                        observation = _cap_observation(cap_reasons)
                        break
                    try:
                        written = os.write(key.fd, pending[:capacity])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        written = 0
                    except OSError as error:
                        raise CaptureError("provider-stdin-write-failed") from error
                    if written < 1:
                        pending.clear()
                        source_eof = True
                        _close_registered(selector, process.stdin, close=True)
                    else:
                        retained = writer.write_frame(b"I", bytes(pending[:written]))
                        if retained != written:
                            raise CaptureError("capture-write-failed")
                        del pending[:written]
                        if writer.at_limit:
                            observation = _cap_observation(cap_reasons)
                            break
                        if not pending:
                            selector.unregister(process.stdin)
                            if source_eof:
                                process.stdin.close()
                            elif not source_pollable:
                                pass
                            else:
                                selector.register(source_fd, selectors.EVENT_READ, b"R")
                    continue
                try:
                    chunk = os.read(key.fd, CHUNK_BYTES)
                except OSError as error:
                    raise CaptureError("provider-output-read-failed") from error
                if not chunk:
                    _close_registered(selector, key.fileobj, close=True)
                    continue
                retained = writer.write_frame(key.data, chunk)
                if key.data == b"O":
                    if not _write_sink(sink, chunk, deadline):
                        observation = Observation(
                            "timeout", None, None, None, ("timeout",)
                        )
                        break
                if retained != len(chunk) or writer.at_limit:
                    observation = _cap_observation(cap_reasons)
                    break
            if observation is not None:
                break
        if observation is None:
            return_code = process.wait()
            exit_code = return_code if return_code >= 0 else None
            provider_signal = -return_code if return_code < 0 else None
            if not _group_exists(process):
                return Observation(
                    "provider_signal" if provider_signal is not None else "provider_exit",
                    exit_code,
                    provider_signal,
                    None,
                    (),
                )
            observation = Observation(
                "descendant_process",
                exit_code,
                provider_signal,
                None,
                ("descendant_process",),
            )
    except CollectorSignal as interruption:
        observation = _collector_signal_observation(interruption.number)
    except KeyboardInterrupt:
        observation = _collector_signal_observation(signal.SIGINT)
    finally:
        try:
            if observation is not None:
                try:
                    selector.unregister(source_fd)
                except KeyError:
                    pass
                _close_registered(selector, process.stdin, close=True)
                try:
                    return_code = _terminate_and_drain(process, selector)
                except CollectorSignal as interruption:
                    observation = _collector_signal_observation(interruption.number)
                    return_code = process.wait()
                exit_code = return_code if return_code >= 0 else None
                provider_signal = -return_code if return_code < 0 else None
                observation = Observation(
                    observation.reason,
                    exit_code,
                    provider_signal,
                    observation.collector_signal,
                    observation.incomplete_reasons,
                )
            if process.poll() is None:
                cleanup_selector = selectors.DefaultSelector()
                for pipe in (process.stdout, process.stderr):
                    if pipe is not None and not pipe.closed:
                        cleanup_selector.register(pipe, selectors.EVENT_READ)
                try:
                    _terminate_and_drain(process, cleanup_selector)
                finally:
                    cleanup_selector.close()
        finally:
            selector.close()
    if observation is None:
        raise CaptureError("provider-capture-failed")
    return observation


def _write_receipt(
    root: CaptureRoot,
    capture_id: str,
    receipt: dict[str, Any],
    *,
    retry_signal: bool = True,
) -> None:
    raw = (
        json.dumps(receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")
    if len(raw) > MAX_RECEIPT_BYTES:
        raise CaptureError("capture-receipt-oversized")
    temporary_name = f"{capture_id}.receipt.tmp"
    final_name = f"{capture_id}.receipt.json"
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    temporary_identity: tuple[int, int] | None = None
    linked_identity: tuple[int, int] | None = None
    linked = False
    try:
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=root.directory_fd)
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise CaptureError("capture-receipt-unsafe")
        temporary_identity = (metadata.st_dev, metadata.st_ino)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written < 1:
                raise CaptureError("capture-receipt-write-failed")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(raw)
            or (metadata.st_dev, metadata.st_ino) != temporary_identity
            or os.pread(descriptor, len(raw) + 1, 0) != raw
        ):
            raise CaptureError("capture-receipt-changed")
        path_metadata = os.stat(
            temporary_name,
            dir_fd=root.directory_fd,
            follow_symlinks=False,
        )
        if _metadata(path_metadata) != _metadata(metadata):
            raise CaptureError("capture-receipt-changed")
        os.link(
            temporary_name,
            final_name,
            src_dir_fd=root.directory_fd,
            dst_dir_fd=root.directory_fd,
            follow_symlinks=False,
        )
        linked = True
        final_metadata = os.stat(
            final_name,
            dir_fd=root.directory_fd,
            follow_symlinks=False,
        )
        linked_identity = (final_metadata.st_dev, final_metadata.st_ino)
        temporary_metadata = os.stat(
            temporary_name,
            dir_fd=root.directory_fd,
            follow_symlinks=False,
        )
        descriptor_metadata = os.fstat(descriptor)
        if (
            (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
            != temporary_identity
            or _metadata(final_metadata) != _metadata(temporary_metadata)
            or _metadata(final_metadata) != _metadata(descriptor_metadata)
            or descriptor_metadata.st_nlink != 2
            or descriptor_metadata.st_size != len(raw)
            or stat.S_IMODE(descriptor_metadata.st_mode) != 0o600
            or descriptor_metadata.st_uid != os.getuid()
            or os.pread(descriptor, len(raw) + 1, 0) != raw
        ):
            raise CaptureError("capture-receipt-changed")
        os.fsync(root.directory_fd)
        os.unlink(temporary_name, dir_fd=root.directory_fd)
        final_metadata = os.stat(
            final_name,
            dir_fd=root.directory_fd,
            follow_symlinks=False,
        )
        descriptor_metadata = os.fstat(descriptor)
        if (
            _metadata(final_metadata) != _metadata(descriptor_metadata)
            or (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
            != temporary_identity
            or descriptor_metadata.st_nlink != 1
            or os.pread(descriptor, len(raw) + 1, 0) != raw
        ):
            raise CaptureError("capture-receipt-changed")
        os.fsync(root.directory_fd)
        os.close(descriptor)
        del descriptor
    except BaseException as error:
        if "descriptor" in locals():
            try:
                os.close(descriptor)
            except OSError:
                pass
        if linked:
            try:
                final_metadata = os.stat(
                    final_name,
                    dir_fd=root.directory_fd,
                    follow_symlinks=False,
                )
                if linked_identity is None or (
                    final_metadata.st_dev,
                    final_metadata.st_ino,
                ) == linked_identity:
                    os.unlink(final_name, dir_fd=root.directory_fd)
            except OSError:
                pass
        try:
            os.unlink(temporary_name, dir_fd=root.directory_fd)
        except OSError:
            pass
        try:
            os.fsync(root.directory_fd)
        except OSError:
            pass
        if isinstance(error, CollectorSignal) and retry_signal:
            _write_receipt(
                root,
                capture_id,
                receipt,
                retry_signal=False,
            )
            raise
        if isinstance(error, CaptureError):
            raise
        if isinstance(error, OSError):
            raise CaptureError("capture-receipt-commit-failed") from error
        raise


def _stream_receipt(writer: CaptureWriter) -> dict[str, dict[str, Any]]:
    return {
        "stdin": {
            "bytes": writer.stream_bytes[b"I"],
            "sha256": writer.stream_digests[b"I"].hexdigest(),
        },
        "stdout": {
            "bytes": writer.stream_bytes[b"O"],
            "sha256": writer.stream_digests[b"O"].hexdigest(),
        },
        "stderr": {
            "bytes": writer.stream_bytes[b"E"],
            "sha256": writer.stream_digests[b"E"].hexdigest(),
        },
    }


def _remove_owned_capture(
    root: CaptureRoot,
    capture_id: str,
    identity: tuple[int, int] | None,
) -> None:
    if identity is None:
        return
    try:
        metadata = os.stat(
            f"{capture_id}.capture",
            dir_fd=root.directory_fd,
            follow_symlinks=False,
        )
        if (metadata.st_dev, metadata.st_ino) != identity:
            return
        os.unlink(f"{capture_id}.capture", dir_fd=root.directory_fd)
        os.fsync(root.directory_fd)
    except OSError:
        pass


def _finalize_capture(
    root: CaptureRoot,
    capture_id: str,
    writer: CaptureWriter,
    identity: ExecutableIdentity,
) -> tuple[str, bool]:
    if not writer.closed:
        writer.finish()
    os.fsync(root.directory_fd)
    if not _capture_path_matches(root, capture_id, writer):
        raise CaptureError("capture-destination-changed")
    identity_changed = not _identity_matches(identity, verify_hash=True)
    if not _root_identity_matches(root):
        raise CaptureError("capture-root-changed")
    return writer.digest.hexdigest(), identity_changed


def _seal_observation(observation: Observation) -> Observation:
    state = ACTIVE_SIGNAL_STATE
    if state is None:
        return observation
    state.settling = True
    pending = state.pending
    state.pending = None
    if pending is None or observation.collector_signal is not None:
        return observation
    return _collector_signal_observation(pending)


def collect(
    spec: ProviderSpec,
    capture_root_path: Path,
    capture_id: str,
    per_capture_bytes: int,
    aggregate_bytes: int,
    timeout_seconds: int,
    provider_executable: str | None,
    stdin: BinaryIO,
    stdout: BinaryIO,
    paths: RepositoryPaths | None = None,
) -> CaptureResult:
    validate_request(capture_id, per_capture_bytes, aggregate_bytes, timeout_seconds)
    repository = repository_paths() if paths is None else paths
    root = validate_capture_root(capture_root_path, repository)
    identity: ExecutableIdentity | None = None
    capture_identity: tuple[int, int] | None = None
    writer: CaptureWriter | None = None
    receipt_committed = False
    try:
        _lock_root(root)
        initial_limit, _initial_reasons = preflight_capture(
            root,
            capture_id,
            per_capture_bytes,
            aggregate_bytes,
        )
        identity = resolve_executable(
            spec,
            provider_executable,
            PROVIDER_COMMAND_CWD,
            root,
            initial_limit,
        )
        if not _root_identity_matches(root):
            raise CaptureError("capture-root-changed")
        started_ns = time.monotonic_ns()
        try:
            with SignalDeferral():
                capture_fd, limit, cap_reasons = reserve_capture(
                    root,
                    capture_id,
                    per_capture_bytes,
                    aggregate_bytes,
                )
                if capture_fd is None:
                    writer = None
                else:
                    capture_metadata = os.fstat(capture_fd)
                    capture_identity = (
                        capture_metadata.st_dev,
                        capture_metadata.st_ino,
                    )
                    try:
                        writer = CaptureWriter(capture_fd, limit)
                        writer.start()
                    except CollectorSignal:
                        raise
                    except BaseException:
                        os.close(capture_fd)
                        raise
            if capture_fd is None:
                identity_changed = not _identity_matches(identity, verify_hash=True)
                if identity_changed:
                    raise CaptureError("provider-executable-changed")
                empty_hash = hashlib.sha256().hexdigest()
                receipt = {
                    "schema_version": SCHEMA_VERSION,
                    "capture_id": capture_id,
                    "provider": spec.name,
                    "provider_version": identity.version,
                    "source_interface": spec.source_interface,
                    "capture_status": "incomplete",
                    "provider_outcome": "unknown",
                    "incomplete_reasons": list(cap_reasons),
                    "capture_present": False,
                    "capture_bytes": 0,
                    "payload_bytes": 0,
                    "frame_count": 0,
                    "source_capture_sha256": None,
                    "executable_sha256": identity.sha256,
                    "duration_ms": 0,
                    "budgets": {
                        "per_capture_bytes": per_capture_bytes,
                        "aggregate_bytes": aggregate_bytes,
                        "capture_limit_bytes": limit,
                        "aggregate_counts": "capture_files",
                        "receipt_bytes_excluded": True,
                    },
                    "streams": {
                        stream: {"bytes": 0, "sha256": empty_hash}
                        for stream in ("stdin", "stdout", "stderr")
                    },
                    "termination": {
                        "reason": "byte_cap",
                        "exit_code": None,
                        "signal": None,
                        "collector_signal": None,
                    },
                }
                _settle_signals()
                _write_receipt(root, capture_id, receipt)
                receipt_committed = True
                return CaptureResult(
                    receipt=receipt,
                    exit_status=INCOMPLETE_EXIT,
                )
            if not _identity_matches(identity, verify_hash=True):
                raise CaptureError("provider-executable-changed")
            if not _root_identity_matches(root):
                raise CaptureError("capture-root-changed")
            if writer.at_limit:
                observation = _cap_observation(cap_reasons)
            elif spec.mode == "stdin":
                observation = capture_stdin(
                    writer, stdin, timeout_seconds, cap_reasons
                )
            else:
                if not _root_identity_matches(root):
                    raise CaptureError("capture-root-changed")
                observation = capture_command(
                    writer,
                    (str(identity.path), *spec.command),
                    timeout_seconds,
                    cap_reasons,
                    stdin,
                    stdout,
                    PROVIDER_COMMAND_CWD,
                )
            with SignalDeferral():
                capture_hash, identity_changed = _finalize_capture(
                    root, capture_id, writer, identity
                )
                observation = _seal_observation(observation)
                incomplete_reasons = list(observation.incomplete_reasons)
                if identity_changed and "executable_changed" not in incomplete_reasons:
                    incomplete_reasons.append("executable_changed")
                receipt = {
                    "schema_version": SCHEMA_VERSION,
                    "capture_id": capture_id,
                    "provider": spec.name,
                    "provider_version": identity.version,
                    "source_interface": spec.source_interface,
                    "capture_status": "incomplete"
                    if incomplete_reasons
                    else "complete",
                    "provider_outcome": "unknown",
                    "incomplete_reasons": incomplete_reasons,
                    "capture_present": True,
                    "capture_bytes": writer.capture_bytes,
                    "payload_bytes": writer.payload_bytes,
                    "frame_count": writer.sequence,
                    "source_capture_sha256": capture_hash,
                    "executable_sha256": identity.sha256,
                    "duration_ms": max(
                        (time.monotonic_ns() - started_ns) // 1_000_000,
                        0,
                    ),
                    "budgets": {
                        "per_capture_bytes": per_capture_bytes,
                        "aggregate_bytes": aggregate_bytes,
                        "capture_limit_bytes": limit,
                        "aggregate_counts": "capture_files",
                        "receipt_bytes_excluded": True,
                    },
                    "streams": _stream_receipt(writer),
                    "termination": {
                        "reason": observation.reason,
                        "exit_code": observation.exit_code,
                        "signal": observation.provider_signal,
                        "collector_signal": observation.collector_signal,
                    },
                }
                _write_receipt(root, capture_id, receipt)
                receipt_committed = True
        except CollectorSignal as interruption:
            if writer is None:
                raise
            observation = _collector_signal_observation(interruption.number)
            with SignalDeferral():
                capture_hash, identity_changed = _finalize_capture(
                    root, capture_id, writer, identity
                )
                incomplete_reasons = list(observation.incomplete_reasons)
                if identity_changed:
                    incomplete_reasons.append("executable_changed")
                receipt = {
                    "schema_version": SCHEMA_VERSION,
                    "capture_id": capture_id,
                    "provider": spec.name,
                    "provider_version": identity.version,
                    "source_interface": spec.source_interface,
                    "capture_status": "incomplete",
                    "provider_outcome": "unknown",
                    "incomplete_reasons": incomplete_reasons,
                    "capture_present": True,
                    "capture_bytes": writer.capture_bytes,
                    "payload_bytes": writer.payload_bytes,
                    "frame_count": writer.sequence,
                    "source_capture_sha256": capture_hash,
                    "executable_sha256": identity.sha256,
                    "duration_ms": max(
                        (time.monotonic_ns() - started_ns) // 1_000_000,
                        0,
                    ),
                    "budgets": {
                        "per_capture_bytes": per_capture_bytes,
                        "aggregate_bytes": aggregate_bytes,
                        "capture_limit_bytes": limit,
                        "aggregate_counts": "capture_files",
                        "receipt_bytes_excluded": True,
                    },
                    "streams": _stream_receipt(writer),
                    "termination": {
                        "reason": observation.reason,
                        "exit_code": observation.exit_code,
                        "signal": observation.provider_signal,
                        "collector_signal": observation.collector_signal,
                    },
                }
                _settle_signals()
                _write_receipt(root, capture_id, receipt)
                receipt_committed = True
    finally:
        with SignalDeferral():
            try:
                if not receipt_committed and capture_identity is not None:
                    if writer is not None and not writer.closed:
                        try:
                            os.close(writer.descriptor)
                        except OSError:
                            pass
                        writer.closed = True
                    _remove_owned_capture(root, capture_id, capture_identity)
                if isinstance(identity, ExecutableIdentity):
                    _cleanup_executable(root, identity)
            finally:
                root.close()
    if observation.collector_signal is not None:
        exit_status = 128 + observation.collector_signal
    elif identity_changed:
        exit_status = 1
    elif incomplete_reasons:
        exit_status = INCOMPLETE_EXIT
    elif observation.exit_code not in {None, 0} or observation.provider_signal is not None:
        exit_status = PROVIDER_EXIT_FAILURE
    else:
        exit_status = 0
    return CaptureResult(receipt=receipt, exit_status=exit_status)


def parse_args(spec: ProviderSpec, argv: Sequence[str]) -> argparse.Namespace:
    parser = SafeArgumentParser(
        prog=f"collect_{spec.name}_evidence.py",
        allow_abbrev=False,
    )
    parser.add_argument("--capture-root", required=True)
    parser.add_argument("--capture-id", required=True)
    parser.add_argument("--per-capture-bytes", required=True, type=positive_integer)
    parser.add_argument("--aggregate-bytes", required=True, type=positive_integer)
    parser.add_argument("--timeout-seconds", required=True, type=positive_timeout)
    parser.add_argument("--provider-executable")
    return parser.parse_args(argv)


def collector_main(provider: str, argv: Sequence[str] | None = None) -> int:
    global ACTIVE_SIGNAL_STATE
    spec = PROVIDER_SPECS[provider]
    arguments = parse_args(spec, sys.argv[1:] if argv is None else argv)
    handled_signals = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    previous_handlers = {number: signal.getsignal(number) for number in handled_signals}
    previous_signal_state = ACTIVE_SIGNAL_STATE
    ACTIVE_SIGNAL_STATE = SignalState()

    def interrupt(number: int, _frame: Any) -> None:
        state = ACTIVE_SIGNAL_STATE
        if state is not None:
            if state.settling:
                return
            if state.depth > 0:
                if state.pending is None:
                    state.pending = number
                return
        raise CollectorSignal(number)

    for number in handled_signals:
        signal.signal(number, interrupt)
    try:
        result = collect(
            spec=spec,
            capture_root_path=Path(arguments.capture_root),
            capture_id=arguments.capture_id,
            per_capture_bytes=arguments.per_capture_bytes,
            aggregate_bytes=arguments.aggregate_bytes,
            timeout_seconds=arguments.timeout_seconds,
            provider_executable=arguments.provider_executable,
            stdin=sys.stdin.buffer,
            stdout=sys.stdout.buffer,
        )
    except CaptureError as error:
        print(f"collect_{provider}_evidence: {error}", file=sys.stderr)
        return 1
    except CollectorSignal as interruption:
        return 128 + interruption.number
    except Exception:
        print(f"collect_{provider}_evidence: internal-error", file=sys.stderr)
        return 1
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
        ACTIVE_SIGNAL_STATE = previous_signal_state
    return result.exit_status
