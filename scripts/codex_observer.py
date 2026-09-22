from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import select
import stat
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

from codex_analysis import AnalysisError, CodexAnalysis, _request_key
from provider_probe import ProbeError, SafeArgumentParser, strict_message


MAX_JOURNAL_BYTES = 256 * 1024
MAX_COMMAND_BYTES = 128 * 1024
MAX_COMMANDS = 512
MAX_INPUT_BYTES = 1024 * 1024
FRESHNESS_NS = 3_000_000_000
LIFETIME_SECONDS = 90


class ObserverError(Exception):
    pass


def _encode(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def _private_directory(path: Path) -> None:
    if not path.is_absolute() or path.resolve() != path:
        raise ObserverError("private-directory-required")
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ObserverError("private-directory-required")


def _read_private(path: Path, limit: int) -> bytes:
    _private_directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not 0 < before.st_size <= limit
        ):
            raise ObserverError("private-file-invalid")
        chunks = bytearray()
        while len(chunks) <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(chunks) != before.st_size or any(
            getattr(before, field) != getattr(after, field) for field in fields
        ):
            raise ObserverError("private-file-changed")
        return bytes(chunks)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class TaskBinding:
    generation: str

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> TaskBinding:
        root = Path(environment.get("CLILANE_STATE_HOME", ""))
        socket = environment.get("CLILANE_TMUX_SOCKET", "")
        task = environment.get("CLILANE_TASK_ID", "")
        if not Path(socket).is_absolute() or re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", task
        ) is None:
            raise ObserverError("task-environment-invalid")
        _private_directory(root)
        digest = hashlib.sha256(socket.encode()).hexdigest()[:16]
        _private_directory(root / "registry")
        try:
            record = strict_message(_read_private(root / "registry" / digest / f"{task}.json", 65536))
        except FileNotFoundError as error:
            raise ObserverError("task-record-not-found-for-absolute-socket") from error
        if (
            type(record.get("schema_version")) is not int
            or record["schema_version"] != 1
            or record.get("phase") != "live"
            or record.get("socket") != socket
            or record.get("id") != task
            or record.get("session") != "agt_" + task.replace("-", "")[:12]
            or type(record.get("created")) is not str
            or not record["created"]
            or "\0" in record["created"]
        ):
            raise ObserverError("task-record-mismatch")
        material = "\0".join(record[key] for key in ("socket", "id", "created", "session"))
        return cls(hashlib.sha256(material.encode()).hexdigest())


class Journal:
    def __init__(self, path: Path, binding: TaskBinding) -> None:
        _private_directory(path.parent)
        self.descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        created = None
        try:
            created = os.fstat(self.descriptor)
            self.digest = hashlib.sha256()
            self.size = 0
            self.count = 0
            self._append({"schema_version": 1, "task_generation": binding.generation})
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            try:
                current = path.lstat()
                if created is not None and (current.st_dev, current.st_ino) == (
                    created.st_dev, created.st_ino
                ):
                    path.unlink()
            except FileNotFoundError:
                pass
            finally:
                self.close()
            raise

    def _append(self, value: dict[str, Any]) -> None:
        raw = _encode(value)
        if self.size + len(raw) > MAX_JOURNAL_BYTES:
            raise ObserverError("journal-byte-limit")
        view = memoryview(raw)
        while view:
            written = os.write(self.descriptor, view)
            if written <= 0:
                raise ObserverError("journal-write-failed")
            view = view[written:]
        os.fsync(self.descriptor)
        self.digest.update(raw)
        self.size += len(raw)

    def append(self, stream: str, observed_ns: int, message: dict[str, Any]) -> None:
        if self.count >= MAX_COMMANDS:
            raise ObserverError("journal-message-limit")
        _validate_frame(stream, observed_ns, message)
        self._append({"stream": stream, "observed_ns": observed_ns, "message": message})
        self.count += 1

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def _validate_frame(stream: Any, observed_ns: Any, message: Any) -> None:
    if (
        type(stream) is not str or stream not in {"I", "O"}
        or type(observed_ns) is not int or not 0 <= observed_ns < 1 << 63
        or type(message) is not dict or len(_encode(message)) > 65536
    ):
        raise ObserverError("invalid-observation")


class Observer:
    def __init__(self, binding: TaskBinding, clock: Callable[[], int] = time.monotonic_ns) -> None:
        self.binding = binding
        self.clock = clock
        self.instance = str(uuid.uuid4())
        self.analysis = CodexAnalysis()
        self.live_reads: set[tuple[type, str | int]] = set()
        self.proof_at: int | None = None
        self.last_observed_ns = 0
        self.ready = False
        self.expired = False
        self.replayed = 0

    def observe(self, stream: str, observed_ns: int, message: dict[str, Any], *, replay: bool) -> None:
        _validate_frame(stream, observed_ns, message)
        if observed_ns < self.last_observed_ns:
            raise ObserverError("observation-order-mismatch")
        candidate = copy.deepcopy(self.analysis)
        candidate.feed(stream, observed_ns, _encode(message))
        key = _request_key(message["id"]) if "id" in message else None
        if stream == "I" and message.get("method") == "thread/read" and not replay:
            if key not in self.analysis.client_messages:
                self.live_reads.add(key)
        if candidate.thread_reads > self.analysis.thread_reads and key in self.live_reads:
            self.proof_at = self.clock()
            self.live_reads.remove(key)
        self.analysis = candidate
        self.last_observed_ns = observed_ns

    def replay(self, path: Path, expected_sha256: str) -> None:
        if self.analysis.messages or self.ready or self.replayed:
            raise ObserverError("replay-order-mismatch")
        raw = _read_private(path, MAX_JOURNAL_BYTES)
        if hashlib.sha256(raw).hexdigest() != expected_sha256 or not raw.endswith(b"\n"):
            raise ObserverError("journal-integrity-mismatch")
        rows = raw.splitlines()
        header = strict_message(rows[0])
        if type(header.get("schema_version")) is not int or header != {
            "schema_version": 1, "task_generation": self.binding.generation
        }:
            raise ObserverError("journal-binding-mismatch")
        if len(rows) > MAX_COMMANDS + 1:
            raise ObserverError("journal-message-limit")
        candidate = copy.deepcopy(self)
        for row in rows[1:]:
            value = strict_message(row)
            if set(value) != {"stream", "observed_ns", "message"}:
                raise ObserverError("journal-frame-invalid")
            candidate.observe(value["stream"], value["observed_ns"], value["message"], replay=True)
            candidate.replayed += 1
        self.analysis = candidate.analysis
        self.last_observed_ns = candidate.last_observed_ns
        self.replayed = candidate.replayed

    def report(self) -> dict[str, Any]:
        if self.ready and (self.proof_at is None or self.clock() >= self.proof_at + FRESHNESS_NS):
            self.expired = True
        return {
            "scope": "phase0-observer-prototype",
            "qualification": "unqualified",
            "health": "healthy" if self.ready and not self.expired else "unknown",
            "state": "expired" if self.expired else "ready" if self.ready else "recovering",
            "fresh_until_monotonic_ns": self.proof_at + FRESHNESS_NS if self.ready and not self.expired else None,
            "message_count": self.analysis.messages,
            "replayed_message_count": self.replayed,
            "duplicate_count": self.analysis.duplicates,
            "thread_read_count": self.analysis.thread_reads,
            "unhandled_message_count": self.analysis.unhandled,
            "unresolved_requests": sorted(
                request.alias for request in self.analysis.requests.values() if not request.resolved
            ),
        }

    def handle(self, command: dict[str, Any]) -> dict[str, Any]:
        if command.get("task_generation") != self.binding.generation:
            raise ObserverError("stale-task-generation")
        if command.get("instance") != self.instance:
            raise ObserverError("stale-observer-instance")
        operation = command.get("op")
        fields = {"task_generation", "instance", "op"}
        extra = {"observe": {"stream", "observed_ns", "message"}, "ready": {"recovered_count"}, "status": set()}
        if type(operation) is not str or operation not in extra or set(command) != fields | extra[operation]:
            raise ObserverError("invalid-command")
        self.report()
        if operation != "status" and self.expired:
            raise ObserverError("observer-expired")
        if operation == "observe":
            self.observe(command["stream"], command["observed_ns"], command["message"], replay=False)
        elif operation == "ready":
            recovered = command["recovered_count"]
            if self.ready or type(recovered) is not int or recovered != sum(
                not request.resolved for request in self.analysis.requests.values()
            ):
                raise ObserverError("recovery-count-mismatch")
            if (
                self.proof_at is None or self.clock() >= self.proof_at + FRESHNESS_NS
                or not self.analysis.thread_response_seen or self.analysis.unhandled
            ):
                raise ObserverError("fresh-source-proof-required")
            self.ready = True
        return self.report()


def _commands(descriptor: int) -> Iterator[dict[str, Any]]:
    deadline = time.monotonic() + LIFETIME_SECONDS
    buffer = bytearray()
    total = 0
    count = 0
    while True:
        if b"\n" in buffer:
            if time.monotonic() >= deadline:
                raise ObserverError("observer-time-limit")
            end = buffer.index(b"\n")
            if end > MAX_COMMAND_BYTES or count >= MAX_COMMANDS:
                raise ObserverError("command-limit")
            raw = bytes(buffer[:end])
            del buffer[:end + 1]
            count += 1
            yield strict_message(raw)
            continue
        if len(buffer) > MAX_COMMAND_BYTES:
            raise ObserverError("command-limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
            raise ObserverError("observer-time-limit")
        chunk = os.read(descriptor, 65536)
        if not chunk:
            if buffer:
                raise ObserverError("truncated-command")
            return
        total += len(chunk)
        if total > MAX_INPUT_BYTES:
            raise ObserverError("input-byte-limit")
        buffer.extend(chunk)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        parser = SafeArgumentParser(
            prog="codex_observer.py", allow_abbrev=False,
            description="Phase0 observer for isolated tasks launched with an absolute "
            "CLILANE_TMUX_SOCKET and mode-0700 state/registry directories.",
        )
        parser.add_argument("--journal", required=True)
        parser.add_argument("--journal-sha256", required=True)
        arguments = parser.parse_args(argv)
        observer = Observer(TaskBinding.from_environment(os.environ))
        observer.replay(Path(arguments.journal), arguments.journal_sha256)
        print(json.dumps({"instance": observer.instance, "task_generation": observer.binding.generation, "report": observer.report()}), flush=True)
        for command in _commands(sys.stdin.fileno()):
            try:
                reply = {"ok": True, "report": observer.handle(command)}
            except (ObserverError, AnalysisError) as error:
                reply = {"ok": False, "error": str(error)}
            print(json.dumps(reply), flush=True)
        return 0
    except (ObserverError, AnalysisError, ProbeError) as error:
        print(f"codex_observer.py: {error}", file=sys.stderr)
    except Exception:
        print("codex_observer.py: observer-failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
