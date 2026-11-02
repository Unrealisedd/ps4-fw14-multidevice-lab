#!/usr/bin/env python3
"""Strict one-shot receiver for the PS4 firmware 14.00 kernel-dump stage."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import html.parser
import json
import mimetypes
import os
import re
import secrets
import socket
import tempfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from threading import Lock
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import parse_qs, urlsplit

STAGE_PAGE = "/fw14_kdump.html"
STAGE_QUERY = "stage=fw14-kdump&retry=0"
CANONICAL_FW14_UA = (
    "Mozilla/5.0 (PlayStation; PlayStation 4/14.00) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
)
SCHEMA = "oms.fw14-kdump.receiver.v1"
CHUNK_MAX = 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_JSON = 64 * 1024
MAX_TELEMETRY = 16 * 1024
STATIC_MANIFEST_NAME = "fw14_kdump_static.json"
SOCKET_TIMEOUT = 20.0
HEX64 = re.compile(r"0x[0-9a-f]{16}\Z")
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
IMPORT_RE = re.compile(
    r"(?:\bimport\s*(?:[^;'\"]*?\s+from\s*)?|\bexport\s+[^;'\"]*?\s+from\s*|\bimport\s*\(\s*)"
    r"['\"]([^'\"]+)['\"]"
)
WORKER_RE = re.compile(r"(?:\bnew\s+Worker\s*\(|\bimportScripts\s*\()\s*['\"]([^'\"]+)['\"]")
PROOF_FIELDS = {"marker", "readback", "restored", "reread", "scratch_rva", "scratch_address", "marker_toggled"}
PROOF_METHODS = {
    "write_path": "slow-sysctl-krw",
    "readback_path": "transient-sysent-copier",
    "restore_path": "slow-sysctl-krw",
}


class ProtocolError(Exception):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def write_all(fd: int, payload: bytes | memoryview) -> None:
    view = memoryview(payload)
    done = 0
    while done < len(view):
        count = os.write(fd, view[done:])
        if count <= 0:
            raise OSError("short write")
        done += count


def sync_directory(directory: Path) -> None:
    if os.name == "nt":
        # Windows namespace commits below use MoveFileExW(MOVEFILE_WRITE_THROUGH).
        return
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def move_namespace(source: Path, destination: Path, *, replace: bool) -> None:
    if os.name != "nt":
        if replace:
            os.replace(source, destination)
        else:
            os.link(source, destination)
            source.unlink()
        sync_directory(destination.parent)
        return
    import ctypes

    flags = 0x8 | (0x1 if replace else 0)  # WRITE_THROUGH | REPLACE_EXISTING
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.MoveFileExW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel32.MoveFileExW.restype = ctypes.c_int
    if not kernel32.MoveFileExW(str(source), str(destination), flags):
        raise ctypes.WinError(ctypes.get_last_error())



def durable_create(path: Path, payload: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".create", dir=path.parent)
    temporary = Path(name)
    try:
        write_all(fd, payload)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        move_namespace(temporary, path, replace=False)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def durable_replace(path: Path, payload: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        write_all(fd, payload)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        move_namespace(temporary, path, replace=True)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def durable_publish(path: Path, payload: bytes) -> None:
    """Atomically publish a fully durable file while refusing an existing destination."""
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".publish", dir=path.parent)
    temporary = Path(name)
    try:
        write_all(fd, payload)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        move_namespace(temporary, path, replace=False)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)

def durable_remove(path: Path) -> None:
    path.unlink()
    sync_directory(path.parent)


def reject_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def exact_keys(value: object, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProtocolError(422, f"invalid-{name}-fields", f"{name} fields must be exactly {sorted(keys)}")
    return value


def exact_uint(value: object, name: str, maximum: int = (1 << 53) - 1) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise ProtocolError(422, f"invalid-{name}", f"{name} must be an unsigned JSON integer <= {maximum}")
    return value


def parse_hex64(value: object, name: str) -> int:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise ProtocolError(422, f"invalid-{name}", f"{name} must be canonical 0x plus 16 lowercase hex digits")
    return int(value, 16)


def marker_for(challenge: bytes, kernel_base: int) -> int:
    digest = hashlib.sha256(b"OMSKEX14" + challenge + kernel_base.to_bytes(8, "little")).digest()
    return int.from_bytes(digest[:4], "little")


class _ScriptParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "script":
            values = dict(attrs)
            if values.get("src") is not None:
                self.sources.append(values["src"] or "")


def _local_dependency(parent: str, reference: str) -> str:
    parsed = urlsplit(reference)
    if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path:
        raise ValueError(f"non-local or malformed static dependency {reference!r} from {parent}")
    if parsed.path.startswith("/"):
        candidate = PurePosixPath(parsed.path)
    else:
        candidate = PurePosixPath(parent).parent / parsed.path
    normalized = "/" + str(candidate).lstrip("/")
    if ".." in PurePosixPath(normalized).parts or not normalized.endswith(".js"):
        raise ValueError(f"unsafe or non-JavaScript dependency {reference!r} from {parent}")
    return normalized


def load_static_graph(
    root: Path,
    expected_hashes: Mapping[str, str] | None = None,
    *,
    stage_page: str = STAGE_PAGE,
) -> tuple[Mapping[str, bytes], Mapping[str, str], str]:
    root = root.resolve()
    pending = [stage_page]
    payloads: dict[str, bytes] = {}
    hashes: dict[str, str] = {}
    while pending:
        request_path = pending.pop()
        if request_path in payloads:
            continue
        try:
            source = (root / request_path.removeprefix("/")).resolve(strict=True)
            source.relative_to(root)
            if not source.is_file():
                raise ValueError("not a regular file")
            payload = source.read_bytes()
        except (OSError, ValueError) as error:
            raise ValueError(
                f"required static file escapes the root or is unreadable: {request_path}: {error}"
            ) from error
        payloads[request_path] = payload
        hashes[request_path] = hashlib.sha256(payload).hexdigest()
        try:
            text = payload.decode("utf-8")
        except UnicodeError as error:
            raise ValueError(f"required static file is not UTF-8: {request_path}: {error}") from error
        if request_path == stage_page:
            parser = _ScriptParser()
            parser.feed(text)
            references = parser.sources + IMPORT_RE.findall(text) + WORKER_RE.findall(text)
            if not references:
                raise ValueError(f"{stage_page} loads no JavaScript")
        else:
            references = IMPORT_RE.findall(text) + WORKER_RE.findall(text)
        pending.extend(_local_dependency(request_path, reference) for reference in references)
    if expected_hashes is not None:
        expected = dict(expected_hashes)
        if set(expected) != set(hashes):
            raise ValueError(
                f"static manifest paths differ: expected={sorted(expected)} discovered={sorted(hashes)}"
            )
        mismatched = [
            path
            for path in sorted(hashes)
            if not hmac.compare_digest(hashes[path], expected[path])
        ]
        if mismatched:
            raise ValueError(f"static manifest hash mismatch: {mismatched}")
    manifest = hashlib.sha256(
        "".join(f"{path} {hashes[path]}\n" for path in sorted(hashes)).encode("ascii")
    ).hexdigest()
    return MappingProxyType(payloads), MappingProxyType(hashes), manifest


class DurableEventLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = Lock()

    def append(self, entry: dict[str, Any]) -> None:
        line = json_bytes({"timestamp": now(), **entry})
        with self.lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0))
            try:
                write_all(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)


class DumpRun:
    def __init__(self, output: Path, state: Path, event_log: DurableEventLog, static_manifest: str) -> None:
        self.output = output
        self.state = state
        self.active = state.with_name(state.name + ".active")
        self.abort_path = state.with_name(state.name + ".abort")
        self.event_log = event_log
        self.static_manifest = static_manifest
        self.run_id = secrets.token_hex(32)
        self.challenge = secrets.token_bytes(32)
        self.lock = Lock()
        self.phase = "armed"
        self.challenge_issued = False
        self.begin: dict[str, Any] | None = None
        self.committed = 0
        self.chunk_count = 0

    def active_record(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "status": self.phase,
            "created_at": self.created_at,
            "updated_at": now(),
            "run_id": self.run_id,
            "challenge_sha256": hashlib.sha256(self.challenge).hexdigest(),
            "challenge_issued": self.challenge_issued,
            "chunk_max": CHUNK_MAX,
            "committed": self.committed,
            "static_manifest_sha256": self.static_manifest,
            "output": str(self.output),
            "state": str(self.state),
        }

    def initialize(self) -> None:
        self.created_at = now()
        durable_create(self.active, json_bytes(self.active_record()))

    def persist_active(self) -> None:
        durable_replace(self.active, json_bytes(self.active_record()))

    def log(self, event: str, **fields: Any) -> None:
        self.event_log.append({"event": event, "run_id": self.run_id, **fields})

    def abort(self, code: str, detail: str, client: str, ua: str) -> None:
        with self.lock:
            if self.phase in {"completed", "aborted"}:
                return
            self.phase = "aborted"
            record = {
                "schema": SCHEMA,
                "status": "aborted",
                "aborted_at": now(),
                "run_id": self.run_id,
                "code": code,
                "detail": detail,
                "client": client,
                "ua": ua,
                "committed": self.committed,
                "output": str(self.output) if self.output.exists() else None,
                "static_manifest_sha256": self.static_manifest,
            }
            try:
                durable_create(self.abort_path, json_bytes(record))
                if self.active.exists():
                    durable_remove(self.active)
                self.log("aborted", code=code, detail=detail, committed=self.committed)
            except OSError:
                # Keep the active marker if durable abort recording itself fails.
                pass

    def challenge_response(self, client: str, ua: str) -> dict[str, object]:
        with self.lock:
            if self.phase == "completed":
                raise ProtocolError(409, "already-finalized", "run is complete")
            if self.phase == "aborted":
                raise ProtocolError(410, "run-aborted", "run has terminally aborted")
            if self.challenge_issued:
                raise ProtocolError(
                    409,
                    "challenge-already-issued",
                    "challenge is single-use; start a fresh server run",
                )
            self.challenge_issued = True
            self.phase = "challenged"
            self.persist_active()
            self.log("challenge-issued", client=client, ua=ua)
            return {"run_id": self.run_id, "challenge_hex": self.challenge.hex(), "chunk_max": CHUNK_MAX}

    def validate_begin(self, value: object) -> dict[str, Any]:
        begin = exact_keys(value, {"run_id", "kernel_base", "total", "link_base", "segments", "proof"}, "begin")
        if begin["run_id"] != self.run_id:
            raise ProtocolError(409, "wrong-run-id", "run_id does not match this server run")
        total = exact_uint(begin["total"], "total", MAX_TOTAL)
        if total < 1:
            raise ProtocolError(422, "invalid-total", "total must be between 1 and 64 MiB")
        kernel_base = parse_hex64(begin["kernel_base"], "kernel-base")
        link_base = parse_hex64(begin["link_base"], "link-base")
        if (kernel_base >> 48) != 0xFFFF or (link_base >> 48) != 0xFFFF:
            raise ProtocolError(422, "noncanonical-kernel-address", "kernel_base and link_base must be high-half canonical addresses")
        if kernel_base & 0x3FFF or link_base & 0xFFF:
            raise ProtocolError(422, "unaligned-kernel-address", "kernel_base must be 0x4000 aligned and link_base page aligned")
        segments_value = begin["segments"]
        if not isinstance(segments_value, list) or not 2 <= len(segments_value) <= 32:
            raise ProtocolError(422, "invalid-segments", "segments must contain 2..32 PT_LOAD descriptors")
        previous_end = 0
        segments: list[dict[str, Any]] = []
        for index, raw in enumerate(segments_value):
            segment = exact_keys(raw, {"offset", "vaddr", "filesz", "memsz", "flags"}, f"segment-{index}")
            offset = exact_uint(segment["offset"], f"segment-{index}-offset", total)
            vaddr = parse_hex64(segment["vaddr"], f"segment-{index}-vaddr")
            filesz = exact_uint(segment["filesz"], f"segment-{index}-filesz", total)
            memsz = exact_uint(segment["memsz"], f"segment-{index}-memsz", total)
            flags = exact_uint(segment["flags"], f"segment-{index}-flags", 7)
            if filesz < 1 or memsz < filesz or offset < previous_end or offset + memsz > total:
                raise ProtocolError(422, "invalid-segment-range", "segments must be sorted, nonoverlapping, nonempty, and wholly inside total")
            if vaddr != (link_base + offset) & ((1 << 64) - 1):
                raise ProtocolError(422, "invalid-segment-vaddr", "segment vaddr must equal link_base plus flat-image offset")
            previous_end = offset + memsz
            segments.append(dict(segment))
        if segments[0]["offset"] != 0 or previous_end != total:
            raise ProtocolError(422, "incomplete-segment-coverage", "PT_LOAD ranges must begin at zero and the final range must end at total")
        proof_value = begin["proof"]
        if not isinstance(proof_value, dict) or set(proof_value) != PROOF_FIELDS | set(PROOF_METHODS):
            raise ProtocolError(422, "invalid-proof-fields", "proof fields must match the exact method-annotated schema")
        proof = proof_value
        for field, expected in PROOF_METHODS.items():
            if proof[field] != expected:
                raise ProtocolError(422, "invalid-proof-method", f"{field} must be exactly {expected}")
        marker = exact_uint(proof["marker"], "proof-marker", 0xFFFFFFFF)
        readback = exact_uint(proof["readback"], "proof-readback", 0xFFFFFFFF)
        restored = exact_uint(proof["restored"], "proof-restored", 0xFFFFFFFF)
        reread = exact_uint(proof["reread"], "proof-reread", 0xFFFFFFFF)
        scratch_rva = exact_uint(proof["scratch_rva"], "proof-scratch-rva", MAX_TOTAL - 1)
        scratch_address = parse_hex64(proof["scratch_address"], "proof-scratch-address")
        toggled = proof["marker_toggled"]
        if type(toggled) is not bool:
            raise ProtocolError(422, "invalid-proof-toggle", "marker_toggled must be a JSON boolean")
        if scratch_rva + 4 > total:
            raise ProtocolError(422, "invalid-proof-address", "scratch word must be wholly inside total")
        writable_scratch = any(
            (segment["flags"] & 2) != 0
            and segment["offset"] <= scratch_rva
            and scratch_rva + 4 <= segment["offset"] + segment["memsz"]
            for segment in segments
        )
        if not writable_scratch:
            raise ProtocolError(422, "invalid-proof-address", "scratch word must lie inside a writable PT_LOAD segment")
        derived = marker_for(self.challenge, kernel_base)
        expected_marker = (derived ^ 0x80000000) if derived == restored else derived
        expected_toggled = derived == restored
        if marker != expected_marker or toggled != expected_toggled:
            raise ProtocolError(422, "invalid-proof-marker", "marker does not match the challenge-derived collision-safe value")
        if marker != readback or restored != reread or marker == restored:
            raise ProtocolError(422, "invalid-proof-transitions", "proof readback/restore invariants failed")
        if scratch_address != (kernel_base + scratch_rva) & ((1 << 64) - 1):
            raise ProtocolError(422, "invalid-proof-address", "scratch_address must equal kernel_base plus scratch_rva modulo 64 bits")
        return {**begin, "segments": segments, "proof": dict(proof)}

    def start(self, value: object) -> None:
        with self.lock:
            if self.phase != "challenged":
                raise ProtocolError(409, "begin-out-of-order", "begin requires the one-shot challenge first")
            validated = self.validate_begin(value)
            fd = os.open(self.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            sync_directory(self.output.parent)
            self.begin = validated
            self.phase = "receiving"
            self.persist_active()
            self.log("begin-accepted", total=validated["total"], kernel_base=validated["kernel_base"])

    def append(self, offset: int, total: int, body: bytes) -> None:
        with self.lock:
            if self.phase != "receiving" or self.begin is None:
                raise ProtocolError(409, "chunk-out-of-order", "chunk requires an accepted begin")
            expected_total = self.begin["total"]
            if total != expected_total:
                raise ProtocolError(422, "total-mismatch", "chunk total differs from begin total")
            if offset != self.committed:
                raise ProtocolError(409, "nonmonotonic-offset", "chunk offset must equal the exact next offset")
            if not body:
                raise ProtocolError(422, "empty-chunk", "chunk body must be nonempty")
            if len(body) > CHUNK_MAX:
                raise ProtocolError(413, "chunk-oversize", "chunk exceeds chunk_max")
            if offset + len(body) > total:
                raise ProtocolError(422, "chunk-beyond-total", "chunk extends beyond total")
            if self.output.stat().st_size != self.committed:
                raise ProtocolError(500, "output-state-diverged", "output size differs from committed byte count")
            fd = os.open(self.output, os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0))
            try:
                write_all(fd, body)
                os.fsync(fd)
            finally:
                os.close(fd)
            self.committed += len(body)
            self.chunk_count += 1
            self.persist_active()
            self.log("chunk-accepted", offset=offset, bytes=len(body), committed=self.committed)

    def finalize(self, value: object) -> dict[str, Any]:
        final = exact_keys(value, {"run_id", "total", "sha256"}, "finalize")
        with self.lock:
            if self.phase != "receiving" or self.begin is None:
                raise ProtocolError(409, "finalize-out-of-order", "finalize requires an active receive")
            if final["run_id"] != self.run_id:
                raise ProtocolError(409, "wrong-run-id", "run_id does not match this server run")
            total = exact_uint(final["total"], "total", MAX_TOTAL)
            if total != self.begin["total"] or total != self.committed:
                raise ProtocolError(409, "incomplete-dump", "final total must equal begin total and committed bytes")
            browser_digest = final["sha256"]
            if not isinstance(browser_digest, str) or HEX256.fullmatch(browser_digest) is None:
                raise ProtocolError(422, "invalid-sha256", "sha256 must be 64 lowercase hex digits")
            digest = hashlib.sha256()
            counted = 0
            with self.output.open("rb") as handle:
                while True:
                    block = handle.read(1024 * 1024)
                    if not block:
                        break
                    counted += len(block)
                    digest.update(block)
            fd = os.open(self.output, os.O_RDWR | getattr(os, "O_BINARY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            server_digest = digest.hexdigest()
            if counted != total or not hmac.compare_digest(browser_digest, server_digest):
                raise ProtocolError(422, "digest-mismatch", "browser and server SHA-256 digests do not match")
            completed = {
                "schema": SCHEMA,
                "status": "completed",
                "completed_at": now(),
                "run_id": self.run_id,
                "total": total,
                "chunks": self.chunk_count,
                "sha256": server_digest,
                "browser_sha256": browser_digest,
                "static_manifest_sha256": self.static_manifest,
                "manifest": {
                    "kernel_base": self.begin["kernel_base"],
                    "link_base": self.begin["link_base"],
                    "segments": self.begin["segments"],
                },
                "proof": self.begin["proof"],
                "output": str(self.output),
            }
            durable_publish(self.state, json_bytes(completed))
            self.phase = "completed"
            try:
                durable_remove(self.active)
            except OSError as error:
                self.log("active-remove-failed", detail=str(error))
            self.log("finalized", total=total, sha256=server_digest)
            return {"run_id": self.run_id, "total": total, "sha256": server_digest}

    def ensure_mutable(self) -> None:
        with self.lock:
            if self.phase == "completed":
                raise ProtocolError(409, "already-finalized", "completed runs reject all later mutation")
            if self.phase == "aborted":
                raise ProtocolError(410, "run-aborted", "aborted runs reject all later mutation")


class KdumpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    run: DumpRun
    static_root: Path
    static_payloads: Mapping[str, bytes]
    static_hashes: Mapping[str, str]

    def log_message(self, format: str, *args: object) -> None:
        return

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def send_json(self, status: int, value: object, close: bool = False) -> None:
        body = json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def fail(self, error: ProtocolError, terminal: bool = True) -> None:
        if terminal:
            self.run.abort(error.code, error.detail, self.client_address[0], self.headers.get("User-Agent", ""))
        self.send_json(error.status, {"error": error.code, "detail": error.detail}, close=True)

    def require_ua(self) -> None:
        values = self.headers.get_all("User-Agent", [])
        if values != [CANONICAL_FW14_UA]:
            raise ProtocolError(403, "user-agent-mismatch", "exact PS4 firmware 14.00 User-Agent required")

    def one_header(self, name: str) -> str:
        values = self.headers.get_all(name, [])
        if len(values) != 1:
            raise ProtocolError(400, "invalid-header", f"exactly one {name} header is required")
        return values[0]

    def decimal_header(self, name: str) -> int:
        text = self.one_header(name)
        if re.fullmatch(r"0|[1-9][0-9]*", text) is None:
            raise ProtocolError(400, "invalid-decimal-header", f"{name} must be canonical unsigned decimal")
        return int(text)

    def read_body(self, cap: int, *, allow_empty: bool = False) -> bytes:
        if self.headers.get("Transfer-Encoding") is not None:
            raise ProtocolError(400, "transfer-encoding-forbidden", "Content-Length framing is required")
        length = self.decimal_header("Content-Length")
        if length > cap:
            raise ProtocolError(413, "body-too-large", f"request body exceeds {cap} bytes")
        if length == 0 and not allow_empty:
            raise ProtocolError(422, "empty-body", "request body must be nonempty")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ProtocolError(400, "short-body", "body ended before Content-Length")
        return body

    def read_json(self) -> object:
        if self.one_header("Content-Type") != "application/json":
            raise ProtocolError(415, "content-type-mismatch", "Content-Type must be application/json")
        body = self.read_body(MAX_JSON)
        try:
            return json.loads(body.decode("utf-8"), object_pairs_hook=reject_duplicate_object)
        except (UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise ProtocolError(400, "invalid-json", str(error)) from error

    def verify_static(self, request_path: str) -> bytes:
        expected = self.static_hashes.get(request_path)
        if expected is None:
            raise ProtocolError(404, "static-path-refused", "only pinned stage assets are served")
        try:
            source = (
                self.static_root / request_path.removeprefix("/")
            ).resolve(strict=True)
            source.relative_to(self.static_root)
            if not source.is_file():
                raise ValueError("not a regular file")
            current = source.read_bytes()
        except (OSError, ValueError) as error:
            raise ProtocolError(
                409,
                "static-mutated",
                f"pinned static file escaped the root or became unreadable: {error}",
            ) from error
        if not hmac.compare_digest(hashlib.sha256(current).hexdigest(), expected):
            raise ProtocolError(409, "static-mutated", "pinned static file changed after startup")
        return self.static_payloads[request_path]

    def do_GET(self) -> None:
        request = urlsplit(self.path)
        try:
            self.require_ua()
            if request.path == "/kdump/challenge":
                if request.query:
                    raise ProtocolError(404, "challenge-query-refused", "challenge accepts no query")
                self.send_json(
                    200,
                    self.run.challenge_response(
                        self.client_address[0],
                        self.headers.get("User-Agent", ""),
                    ),
                )
                return
            if request.path == STAGE_PAGE:
                if request.query != STAGE_QUERY:
                    raise ProtocolError(404, "stage-query-refused", "dedicated stage query is required")
            payload = self.verify_static(request.path)
            content_type = "text/html; charset=utf-8" if request.path.endswith(".html") else "text/javascript; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except ProtocolError as error:
            self.fail(error, terminal=error.code == "static-mutated" or request.path == "/kdump/challenge")
        except OSError as error:
            self.fail(ProtocolError(500, "durable-storage-failed", str(error)))

    def do_POST(self) -> None:
        request = urlsplit(self.path)
        try:
            self.require_ua()
            self.run.ensure_mutable()
            if request.query:
                raise ProtocolError(404, "post-query-refused", "POST endpoints accept no query")
            if request.path == "/t":
                if self.one_header("Content-Type") not in {
                    "application/x-www-form-urlencoded",
                    "application/x-www-form-urlencoded;charset=UTF-8",
                }:
                    raise ProtocolError(415, "telemetry-content-type", "telemetry must be URL encoded")
                body = self.read_body(MAX_TELEMETRY)
                try:
                    text = body.decode("utf-8")
                except UnicodeError as error:
                    raise ProtocolError(400, "invalid-telemetry", str(error)) from error
                if not text.startswith("PS4-JB&"):
                    raise ProtocolError(422, "invalid-telemetry", "telemetry sentinel must be exactly PS4-JB")
                fields = parse_qs(text[len("PS4-JB&"):], keep_blank_values=True, strict_parsing=True)
                if set(fields) != {"tag", "detail"} or any(len(values) != 1 for values in fields.values()):
                    raise ProtocolError(422, "invalid-telemetry", "telemetry fields must be exactly scalar tag and detail")
                if not fields["tag"][0] or len(fields["tag"][0]) > 160 or len(fields["detail"][0]) > 12000:
                    raise ProtocolError(422, "invalid-telemetry", "telemetry tag or detail is out of bounds")
                clean = {"tag": fields["tag"][0], "detail": fields["detail"][0]}
                self.run.log("telemetry", client=self.client_address[0], fields=clean)
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if request.path == "/kdump/abort":
                value = exact_keys(
                    self.read_json(), {"run_id", "code", "detail"}, "abort"
                )
                if value["run_id"] != self.run.run_id:
                    raise ProtocolError(
                        409, "wrong-run-id", "run_id does not match this server run"
                    )
                if (
                    not isinstance(value["code"], str)
                    or not 1 <= len(value["code"]) <= 80
                    or not isinstance(value["detail"], str)
                    or len(value["detail"]) > 4096
                ):
                    raise ProtocolError(
                        422, "invalid-abort", "abort code/detail are out of bounds"
                    )
                self.run.abort(
                    value["code"],
                    value["detail"],
                    self.client_address[0],
                    self.headers.get("User-Agent", ""),
                )
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if request.path == "/kdump/begin":
                self.run.start(self.read_json())
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if request.path == "/kdump/chunk":
                if self.one_header("Content-Type") != "application/octet-stream":
                    raise ProtocolError(415, "content-type-mismatch", "chunk Content-Type must be application/octet-stream")
                run_id = self.one_header("X-Kdump-Run")
                if run_id != self.run.run_id:
                    raise ProtocolError(409, "wrong-run-id", "X-Kdump-Run does not match this server run")
                offset = self.decimal_header("X-Kdump-Offset")
                total = self.decimal_header("X-Kdump-Total")
                body = self.read_body(CHUNK_MAX)
                self.run.append(offset, total, body)
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if request.path == "/kdump/finalize":
                result = self.run.finalize(self.read_json())
                self.send_json(200, result)
                return
            raise ProtocolError(404, "post-path-refused", "unknown POST endpoint")
        except (ValueError, UnicodeError) as error:
            self.fail(ProtocolError(400, "invalid-request", str(error)))
        except ProtocolError as error:
            self.fail(error)
        except OSError as error:
            self.fail(ProtocolError(500, "durable-storage-failed", str(error)))

    def do_HEAD(self) -> None:
        self.fail(ProtocolError(405, "method-refused", "HEAD is not supported"), terminal=False)

    def do_OPTIONS(self) -> None:
        self.fail(ProtocolError(405, "method-refused", "OPTIONS is not supported"), terminal=False)


class TimeoutHTTPServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        connection.settimeout(SOCKET_TIMEOUT)
        return connection, address


def path_is_within(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def is_remote_windows_path(path: Path) -> bool:
    if os.name != "nt":
        return False
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetDriveTypeW.restype = ctypes.c_uint32
    anchor = path.anchor
    return anchor.startswith("\\\\") or not anchor or kernel32.GetDriveTypeW(anchor) == 4


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--event-log", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    output = args.output.resolve()
    state = args.state.resolve()
    event_path = args.event_log.resolve()
    active = state.with_name(state.name + ".active")
    abort_path = state.with_name(state.name + ".abort")
    if not root.is_dir():
        parser.error(f"static root is not a directory: {root}")
    paths = {output, state, event_path, active, abort_path}
    if len(paths) != 5:
        parser.error("output, state, event-log, and derived state paths must all be distinct")
    if any(path_is_within(path, root) for path in paths):
        parser.error("artifact paths must be outside the served static root")
    if any(path.exists() for path in paths):
        parser.error("refusing startup because an output, state, event-log, active, or abort path already exists")
    if any(not path.parent.is_dir() for path in paths):
        parser.error("all artifact parent directories must already exist for crash-durable creation")
    if any(is_remote_windows_path(path) for path in paths):
        parser.error("Windows artifact paths must use local storage; UNC and mapped network drives are refused")
    manifest_path = root / STATIC_MANIFEST_NAME
    try:
        manifest_document = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_object,
        )
        manifest_document = exact_keys(
            manifest_document, {"schema", "files"}, "static-manifest"
        )
        if manifest_document["schema"] != "oms.fw14-kdump.static.v1":
            raise ValueError("unsupported static manifest schema")
        expected_hashes = manifest_document["files"]
        if (
            not isinstance(expected_hashes, dict)
            or any(
                not isinstance(path, str)
                or not isinstance(digest, str)
                or HEX256.fullmatch(digest) is None
                for path, digest in expected_hashes.items()
            )
        ):
            raise ValueError("static manifest files must map paths to SHA-256")
        static_payloads, static_hashes, static_manifest = load_static_graph(
            root, expected_hashes
        )
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError, ProtocolError) as error:
        parser.error(f"invalid {manifest_path}: {error}")

    try:
        durable_create(event_path, b"")
    except OSError as error:
        parser.error(f"cannot exclusively create event log: {error}")
    event_log = DurableEventLog(event_path)
    run = DumpRun(output, state, event_log, static_manifest)
    try:
        run.initialize()
    except OSError as error:
        event_path.unlink(missing_ok=True)
        parser.error(f"cannot exclusively create active state: {error}")

    KdumpHandler.run = run
    KdumpHandler.static_root = root
    KdumpHandler.static_payloads = static_payloads
    KdumpHandler.static_hashes = static_hashes
    try:
        server = TimeoutHTTPServer((args.host, args.port), KdumpHandler)
    except OSError as error:
        run.abort("bind-failed", str(error), "server", "")
        parser.error(f"cannot bind server: {error}")
    try:
        run.log("server-ready", static_manifest_sha256=static_manifest)
        print(
            f"READY http://{args.host}:{args.port}{STAGE_PAGE}?{STAGE_QUERY} "
            f"output={output} state={state} active={active} abort={abort_path} event_log={event_path}",
            flush=True,
        )
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        run.abort("server-stopped", "receiver stopped before terminal completion", "server", "")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
