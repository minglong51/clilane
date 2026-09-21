from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any


MAX_LINE_BYTES = 64 * 1024
MAX_MESSAGES = 4096
MAX_IDENTITIES = 256
MAX_EVENTS = 1024
REQUEST_METHODS = {
    "item/commandExecution/requestApproval": "approval",
    "item/fileChange/requestApproval": "approval",
    "item/permissions/requestApproval": "approval",
    "item/tool/requestUserInput": "input",
}
IGNORED_NOTIFICATIONS = {
    "item/agentMessage/delta",
    "item/started",
    "item/completed",
    "item/reasoning/summaryTextDelta",
    "item/reasoning/summaryPartAdded",
    "item/reasoning/textDelta",
    "thread/tokenUsage/updated",
    "thread/settings/updated",
}


class AnalysisError(Exception):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AnalysisError("duplicate-json-key")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise AnalysisError("invalid-json-number")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise AnalysisError("invalid-json-number")
    return parsed


def _identifier(value: Any) -> str:
    if type(value) is not str or not value or len(value) > 256:
        raise AnalysisError("invalid-identity")
    return value


def _request_key(value: Any) -> tuple[type, str | int]:
    if type(value) is int and -(1 << 63) <= value < (1 << 63):
        return (int, value)
    return (str, _identifier(value))


def _object(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        raise AnalysisError("invalid-object")
    return value


@dataclass
class Turn:
    alias: str
    response_seen: bool = False
    started: bool = False
    status: str | None = None


@dataclass
class Request:
    alias: str
    turn_id: str
    item_id: str
    kind: str
    blocking: bool
    fingerprint: str
    resolved: bool = False


class CodexAnalysis:
    def __init__(self) -> None:
        self.buffers = {"I": bytearray(), "O": bytearray()}
        self.messages = 0
        self.duplicates = 0
        self.unhandled = 0
        self.ignored = 0
        self.warnings = 0
        self.thread_id: str | None = None
        self.session_id: str | None = None
        self.thread_response_seen = False
        self.active_turn: str | None = None
        self.pending: dict[tuple[type, str | int], str] = {}
        self.client_messages: dict[tuple[type, str | int], str] = {}
        self.responses: dict[tuple[type, str | int], str] = {}
        self.turns: dict[str, Turn] = {}
        self.requests: dict[tuple[type, str | int], Request] = {}
        self.events: list[dict[str, Any]] = []
        self.thread_state: tuple[str, tuple[str, ...]] | None = None

    def feed(self, stream: str, observed_ns: int, payload: bytes) -> None:
        if stream == "E":
            return
        if stream not in self.buffers:
            raise AnalysisError("invalid-stream")
        buffer = self.buffers[stream]
        buffer.extend(payload)
        while b"\n" in buffer:
            end = buffer.index(b"\n")
            if end > MAX_LINE_BYTES:
                raise AnalysisError("line-limit")
            raw = bytes(buffer[:end])
            del buffer[: end + 1]
            self.messages += 1
            if self.messages > MAX_MESSAGES:
                raise AnalysisError("message-limit")
            try:
                message = json.loads(
                    raw.decode("utf-8"),
                    object_pairs_hook=_unique_object,
                    parse_constant=_invalid_constant,
                    parse_float=_finite_float,
                )
                self._message(stream, observed_ns, _object(message))
            except (UnicodeDecodeError, ValueError, RecursionError) as error:
                raise AnalysisError("invalid-json") from error
        if len(buffer) > MAX_LINE_BYTES:
            raise AnalysisError("line-limit")

    def _emit(
        self,
        event: str,
        observed_ns: int,
        *,
        turn: Turn | None = None,
        request: Request | None = None,
        state: str | None = None,
        flags: tuple[str, ...] = (),
    ) -> None:
        if len(self.events) >= MAX_EVENTS:
            raise AnalysisError("event-limit")
        self.events.append(
            {
                "sequence": len(self.events) + 1,
                "observed_ms": observed_ns // 1_000_000,
                "event": event,
                "thread_id": "synthetic-codex-thread",
                "turn_id": turn.alias if turn else None,
                "request_id": request.alias if request else None,
                "request_kind": request.kind if request else None,
                "blocking": request.blocking if request else None,
                "state": state,
                "flags": list(flags),
            }
        )

    def _bind_thread(self, thread: dict[str, Any]) -> None:
        thread_id = _identifier(thread.get("id"))
        session_id = _identifier(thread.get("sessionId"))
        if self.thread_id is None:
            if "thread/start" not in self.pending.values():
                raise AnalysisError("unbound-thread")
            self.thread_id, self.session_id = thread_id, session_id
        elif (self.thread_id, self.session_id) != (thread_id, session_id):
            raise AnalysisError("thread-binding-mismatch")

    def _check_thread(self, params: dict[str, Any]) -> None:
        if self.thread_id is None or params.get("threadId") != self.thread_id:
            raise AnalysisError("thread-binding-mismatch")

    def _turn(self, turn_id: str) -> Turn:
        if turn_id not in self.turns:
            if "turn/start" not in self.pending.values():
                raise AnalysisError("unbound-turn")
            if self.active_turn is not None:
                raise AnalysisError("overlapping-turns")
            if len(self.turns) >= MAX_IDENTITIES:
                raise AnalysisError("identity-limit")
            self.turns[turn_id] = Turn(f"synthetic-codex-turn-{len(self.turns) + 1}")
            self.active_turn = turn_id
        return self.turns[turn_id]

    def _message(self, stream: str, observed_ns: int, message: dict[str, Any]) -> None:
        if "jsonrpc" in message:
            raise AnalysisError("invalid-envelope")
        method = message.get("method")
        if "method" in message:
            if type(method) is not str or not method or len(method) > 128:
                raise AnalysisError("invalid-method")
            if "result" in message or "error" in message:
                raise AnalysisError("invalid-envelope")
            params = _object(message.get("params", {}))
            if stream == "I":
                self._client(message, method, params)
            elif "id" in message:
                self._request(message["id"], method, params, observed_ns)
            else:
                self._notification(method, params, observed_ns)
        else:
            if "id" not in message or ("result" in message) == ("error" in message):
                raise AnalysisError("invalid-envelope")
            key = _request_key(message["id"])
            if stream == "I":
                if key not in self.requests:
                    raise AnalysisError("unbound-request-response")
            else:
                self._response(key, message)

    def _client(
        self, message: dict[str, Any], method: str, params: dict[str, Any]
    ) -> None:
        if method == "initialized" and "id" not in message:
            return
        if "id" not in message:
            self.unhandled += 1
            return
        key = _request_key(message["id"])
        fingerprint = hashlib.sha256(
            json.dumps(message, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if key in self.client_messages:
            if self.client_messages[key] != fingerprint:
                raise AnalysisError("conflicting-client-request")
            self.duplicates += 1
            return
        if len(self.client_messages) >= MAX_IDENTITIES:
            raise AnalysisError("identity-limit")
        if method == "thread/start":
            if self.thread_id is not None or method in self.pending.values():
                raise AnalysisError("multiple-threads")
        elif method == "turn/start":
            self._check_thread(params)
            if self.active_turn is not None or method in self.pending.values():
                raise AnalysisError("overlapping-turns")
        elif method == "turn/interrupt":
            self._check_thread(params)
            if self.active_turn is None or params.get("turnId") != self.active_turn:
                raise AnalysisError("turn-binding-mismatch")
        elif method != "initialize":
            self.unhandled += 1
        self.client_messages[key] = fingerprint
        self.pending[key] = method

    def _response(self, key: tuple[type, str | int], message: dict[str, Any]) -> None:
        fingerprint = hashlib.sha256(
            json.dumps(message, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if key in self.responses:
            if self.responses[key] != fingerprint:
                raise AnalysisError("conflicting-response")
            self.duplicates += 1
            return
        if key not in self.pending:
            raise AnalysisError("unbound-response")
        if "error" in message:
            raise AnalysisError("provider-request-failed")
        result = _object(message["result"])
        method = self.pending[key]
        if method == "thread/start":
            self._bind_thread(_object(result.get("thread")))
            self.thread_response_seen = True
        elif method == "turn/start":
            value = _object(result.get("turn"))
            turn = self._turn(_identifier(value.get("id")))
            if turn.response_seen:
                raise AnalysisError("reused-turn-identity")
            if value.get("status") != "inProgress":
                raise AnalysisError("invalid-turn-start")
            turn.response_seen = True
        self.responses[key] = fingerprint
        del self.pending[key]

    def _request(
        self, request_id: Any, method: str, params: dict[str, Any], observed_ns: int
    ) -> None:
        if method not in REQUEST_METHODS:
            raise AnalysisError("unsupported-server-request")
        self._check_thread(params)
        turn_id = _identifier(params.get("turnId"))
        item_id = _identifier(params.get("itemId"))
        kind = REQUEST_METHODS[method]
        blocking = params.get("isBlocking") if kind == "input" else True
        if type(blocking) is not bool:
            raise AnalysisError("invalid-request-blocking")
        key = _request_key(request_id)
        fingerprint = hashlib.sha256(
            json.dumps([method, params], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        existing = self.requests.get(key)
        if existing is not None:
            if existing.fingerprint != fingerprint:
                raise AnalysisError("conflicting-server-request")
            self.duplicates += 1
            return
        if turn_id != self.active_turn:
            raise AnalysisError("turn-binding-mismatch")
        if len(self.requests) >= MAX_IDENTITIES:
            raise AnalysisError("identity-limit")
        request = Request(
            f"synthetic-codex-request-{len(self.requests) + 1}",
            turn_id, item_id, kind, blocking, fingerprint,
        )
        self.requests[key] = request
        self._emit(
            "request_opened", observed_ns, turn=self.turns[turn_id], request=request
        )

    def _notification(
        self, method: str, params: dict[str, Any], observed_ns: int
    ) -> None:
        if method == "remoteControl/status/changed":
            _identifier(params.get("installationId"))
            _identifier(params.get("serverName"))
            if params.get("environmentId") is not None:
                _identifier(params["environmentId"])
            status = params.get("status")
            if type(status) is not str or status not in {
                "disabled", "connecting", "connected", "errored"
            }:
                raise AnalysisError("invalid-remote-control-status")
            if status != "disabled":
                self.unhandled += 1
                return
            self.ignored += 1
            return
        if method == "account/rateLimits/updated":
            _object(params.get("rateLimits"))
            self.ignored += 1
            return
        if method == "warning":
            if type(params.get("message")) is not str:
                raise AnalysisError("invalid-provider-warning")
            if params.get("threadId") is not None:
                self._check_thread(params)
            self.warnings += 1
            return
        if method in IGNORED_NOTIFICATIONS:
            self._check_thread(params)
            turn_id = params.get("turnId")
            if turn_id is not None and _identifier(turn_id) not in self.turns:
                raise AnalysisError("turn-binding-mismatch")
            self.ignored += 1
            return
        if method == "thread/started":
            self._bind_thread(_object(params.get("thread")))
            return
        if method not in {
            "turn/started", "turn/completed", "thread/status/changed",
            "serverRequest/resolved",
        }:
            self.unhandled += 1
            return
        self._check_thread(params)
        if method == "serverRequest/resolved":
            key = _request_key(params.get("requestId"))
            request = self.requests.get(key)
            if request is None:
                raise AnalysisError("unbound-request-resolution")
            if request.resolved:
                self.duplicates += 1
                return
            request.resolved = True
            self._emit(
                "request_resolved", observed_ns,
                turn=self.turns[request.turn_id], request=request,
            )
        elif method == "thread/status/changed":
            status = _object(params.get("status"))
            state = status.get("type")
            if type(state) is not str or state not in {
                "notLoaded", "idle", "systemError", "active"
            }:
                raise AnalysisError("invalid-thread-state")
            raw_flags = status.get("activeFlags", [])
            if (
                type(raw_flags) is not list
                or any(type(flag) is not str or flag not in {
                    "waitingOnApproval", "waitingOnUserInput"
                } for flag in raw_flags)
                or len(raw_flags) != len(set(raw_flags))
                or (state != "active" and raw_flags)
                or (state == "active" and "activeFlags" not in status)
            ):
                raise AnalysisError("invalid-thread-flags")
            flags = tuple(sorted(raw_flags))
            if self.thread_state == (state, flags):
                self.duplicates += 1
                return
            self.thread_state = (state, flags)
            self._emit("thread_state", observed_ns, state=state, flags=flags)
        else:
            value = _object(params.get("turn"))
            turn_id = _identifier(value.get("id"))
            turn = self._turn(turn_id)
            status = value.get("status")
            if method == "turn/started":
                if status != "inProgress":
                    raise AnalysisError("invalid-turn-start")
                if turn.started:
                    self.duplicates += 1
                    return
                if turn.status is not None:
                    raise AnalysisError("turn-order-mismatch")
                turn.started = True
                self._emit("turn_started", observed_ns, turn=turn, state=status)
            else:
                if type(status) is not str or status not in {
                    "completed", "interrupted", "failed"
                }:
                    raise AnalysisError("invalid-turn-completion")
                if turn.status is not None:
                    if turn.status != status:
                        raise AnalysisError("conflicting-turn-completion")
                    self.duplicates += 1
                    return
                if not turn.started or turn_id != self.active_turn:
                    raise AnalysisError("turn-order-mismatch")
                turn.status = status
                self.active_turn = None
                self._emit("turn_completed", observed_ns, turn=turn, state=status)

    def finish(self) -> dict[str, Any]:
        if any(self.buffers.values()):
            raise AnalysisError("truncated-json-line")
        unresolved = sum(not request.resolved for request in self.requests.values())
        complete = (
            self.thread_response_seen
            and bool(self.turns)
            and all(turn.response_seen and turn.started and turn.status is not None
                    for turn in self.turns.values())
            and not self.pending
            and not unresolved
            and not self.unhandled
        )
        return {
            "schema_version": 1,
            "analyzer": "codex-app-server-v1",
            "analysis_complete": complete,
            "qualification": "unqualified",
            "task_binding": "unknown",
            "source_health": "unknown",
            "session_binding": "exact" if self.thread_response_seen else "unknown",
            "session_id": "synthetic-codex-session" if self.thread_response_seen else None,
            "message_count": self.messages,
            "duplicate_count": self.duplicates,
            "ignored_notification_count": self.ignored,
            "provider_warning_count": self.warnings,
            "unhandled_message_count": self.unhandled,
            "turn_count": len(self.turns),
            "unresolved_request_count": unresolved,
            "events": self.events,
        }
