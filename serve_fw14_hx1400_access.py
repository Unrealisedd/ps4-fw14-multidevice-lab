#!/usr/bin/env python3
"""Reusable local access-code gateway for the reviewed FW14 dual-map child host."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import html
import ipaddress
import json
import os
import queue
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
from collections import OrderedDict, deque
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

try:
    from . import serve_fw14_hx1400_goldhen_dualmap as child
    from . import serve_fw14_kdump as common
except ImportError:
    import serve_fw14_hx1400_goldhen_dualmap as child
    import serve_fw14_kdump as common


REGISTRY_SCHEMA = "oms.fw14-hx1400-access.registry.v2"
LEGACY_REGISTRY_SCHEMA = "oms.fw14-hx1400-access.registry.v1"
REGISTRY_CLEANUP_PENDING_SCHEMA = "oms.fw14-hx1400-access.registry.v2-cleanup-pending"
REGISTRY_CLEANUP_KEY = "plaintext_hint_cleanup"
REGISTRY_CLEANUP_PENDING = "pending"
REGISTRY_CLEANUP_COMPLETE = "complete"
ACCESS_TEMPLATE_NAME = "fw14_hx1400_access.html"
ACCESS_TEMPLATE_SHA256 = "d7f8575dd4e636824d3734a575fa8224bfb4698e1dc17c03b238ed8882832266"
ACCESS_PLACEHOLDER = b"__OMS_ACCESS_STATUS__"
CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CODE_SYMBOLS = 16
CODE_HASH_DOMAIN = b"oms.fw14-hx1400-access.code.v1\0"
DEVICE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
HEX32_RE = re.compile(r"[0-9a-f]{32}\Z")
HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
READY_RE = re.compile(
    r"READY (?P<url>\S+) run=(?P<run>[0-9a-f]{32}) "
    r"client=(?P<client>\S+) host=(?P<host>\S+)\Z"
)
SENSITIVE_DIAGNOSTIC_HEX_RE = re.compile(r"(?i)(?:0x)?[0-9a-f]{16,}")
SENSITIVE_DIAGNOSTIC_CODE_RE = re.compile(
    r"\b[0-9A-HJKMNP-TV-Z]{4}(?:-[0-9A-HJKMNP-TV-Z]{4}){3}\b"
)
LOOPBACKS = frozenset({"127.0.0.1"})
MAX_FORM_BYTES = 256
MAX_FAILED_ATTEMPTS = 5
ATTEMPT_WINDOW_SECONDS = 60.0
MAX_LIMITER_CLIENTS = 128
DEFAULT_STATUS = "Enter a locally issued one-time code."
TERMINAL_SETTLE_SECONDS = 2.0
GATEWAY_EVENT_SCHEMA = "oms.fw14-hx1400-access.gateway-event.v1"
DIAGNOSTIC_SCHEMA = "oms.fw14-hx1400-access.diagnostic.v1"
GATEWAY_EVENTS_NAME = "gateway-events.jsonl"
DIAGNOSTIC_NAME = "diagnostic.json"



class AccessError(Exception):
    def __init__(self, status: int, code: str, public: str, *, count_failure: bool = False) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.public = public
        self.count_failure = count_failure


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime | None = None) -> str:
    return (value or utc_now()).isoformat(timespec="microseconds")


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def exact_ipv4(value: str, name: str, *, allow_unspecified: bool = False) -> str:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an exact IPv4 address") from error
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError(f"{name} must be an exact IPv4 address")
    if parsed.is_unspecified and not allow_unspecified:
        raise ValueError(f"{name} must not be unspecified")
    return value


def exact_device_id(value: str) -> str:
    if DEVICE_ID_RE.fullmatch(value) is None:
        raise ValueError("device ID must be 1..64 ASCII letters, digits, dot, underscore, or hyphen")
    return value


def device_key(device_id: str) -> str:
    return hashlib.sha256(device_id.encode("ascii")).hexdigest()[:24]


def normalize_code(value: str) -> str:
    compact = "".join(character for character in value.upper() if character not in "- \t\r\n")
    compact = compact.translate(str.maketrans({"O": "0", "I": "1", "L": "1"}))
    if len(compact) != CODE_SYMBOLS or any(character not in CODE_ALPHABET for character in compact):
        raise ValueError("invalid access-code shape")
    return compact


def format_code(value: str) -> str:
    return "-".join(value[index:index + 4] for index in range(0, CODE_SYMBOLS, 4))


def generate_code() -> str:
    value = int.from_bytes(secrets.token_bytes(10), "big")
    symbols = [CODE_ALPHABET[(value >> (5 * shift)) & 31] for shift in reversed(range(CODE_SYMBOLS))]
    return "".join(symbols)


def hash_code(value: str) -> str:
    return hashlib.sha256(CODE_HASH_DOMAIN + value.encode("ascii")).hexdigest()

def safe_error_detail(error: BaseException) -> str:
    detail = " ".join(str(error).split())
    detail = SENSITIVE_DIAGNOSTIC_CODE_RE.sub("<redacted-code>", detail)
    detail = SENSITIVE_DIAGNOSTIC_HEX_RE.sub("<redacted-hex>", detail)
    return detail[:240]


def load_access_template(root: Path) -> bytes:
    path = (root / ACCESS_TEMPLATE_NAME).resolve(strict=True)
    path.relative_to(root)
    payload = path.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(digest, ACCESS_TEMPLATE_SHA256):
        raise ValueError("access template SHA-256 mismatch")
    if payload.count(ACCESS_PLACEHOLDER) != 1:
        raise ValueError("access template must contain exactly one status placeholder")
    return payload


def render_access_page(template: bytes, message: str) -> bytes:
    escaped = html.escape(message, quote=True).encode("utf-8")
    return template.replace(ACCESS_PLACEHOLDER, escaped)

def artifact_metadata(path: Path) -> dict[str, Any] | None:
    try:
        payload = path.read_bytes()
    except FileNotFoundError:
        return None
    if not path.is_file():
        raise ValueError(f"diagnostic artifact is not a regular file: {path}")
    return {
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def load_json_artifact(path: Path) -> dict[str, Any] | None:
    try:
        payload = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    document = json.loads(payload, object_pairs_hook=common.reject_duplicate_object)
    if not isinstance(document, dict):
        raise ValueError(f"diagnostic artifact is not a JSON object: {path}")
    return document


def child_terminal_state(
    state_path: Path,
    result_path: Path,
    *,
    run_id: str,
) -> tuple[str, str, str | None] | None:
    state = load_json_artifact(state_path)
    if state is None:
        raise ValueError("child state is missing")
    if state.get("schema") != child.STATE_SCHEMA:
        raise ValueError("child state schema mismatch")
    if state.get("run_id") != run_id:
        raise ValueError("child state run ID mismatch")
    phase = state.get("phase")
    if phase not in {"armed", "claimed", "committing", "completed", "aborted", "commit-uncertain"}:
        raise ValueError("child state phase is invalid")
    if phase in {"armed", "claimed", "committing"}:
        return None
    if phase == "aborted":
        failures = {
            "browser-stage-failed": "browser stage ended without a committed result",
            "server-terminal-rejection": "authorized terminal request rejected",
        }
        code = state.get("code")
        detail = state.get("detail")
        if code not in failures or detail != failures[code]:
            raise ValueError("child aborted state is invalid")
        return "aborted", code, detail
    if phase == "commit-uncertain":
        commit_step = state.get("commit_step")
        result_sha256 = state.get("result_sha256")
        if commit_step not in {"committing-state", "result-publish", "final-state", "terminal-abort"}:
            raise ValueError("child uncertain commit step is invalid")
        if not isinstance(result_sha256, str) or HEX64_RE.fullmatch(result_sha256) is None:
            raise ValueError("child uncertain result digest is invalid")
        detail = state.get("detail")
        if not isinstance(detail, str):
            raise ValueError("child uncertain detail is invalid")
        safe_detail = safe_error_detail(RuntimeError(f"{commit_step}: {detail}"))
        return "commit-uncertain", "COMMIT_UNCERTAIN", safe_detail

    result_sha256 = state.get("result_sha256")
    if not isinstance(result_sha256, str) or HEX64_RE.fullmatch(result_sha256) is None:
        raise ValueError("completed state result digest is invalid")
    payload = result_path.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), result_sha256):
        raise ValueError("completed state result digest mismatch")
    document = json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=common.reject_duplicate_object,
    )
    validated = child.validate_result(document, run_id=run_id)
    if type(state.get("ok")) is not bool or state["ok"] is not validated["ok"]:
        raise ValueError("completed state result status mismatch")
    if state.get("code") != validated["code"]:
        raise ValueError("completed state result code mismatch")
    status = "completed" if validated["ok"] else "committed-failure"
    return status, validated["code"], None


def summarize_run_artifacts(
    run_dir: Path,
    gateway: dict[str, Any],
    *,
    tombstone: Path | None = None,
) -> dict[str, Any]:
    state_path = run_dir / "state.json"
    events_path = run_dir / "events.jsonl"
    result_path = run_dir / "result.json"
    tombstone_path_value = tombstone or (run_dir / "boot-tombstone.json")
    server_log_path = run_dir / "server.log"
    artifacts: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for name, path in (
        ("state", state_path),
        ("events", events_path),
        ("result", result_path),
        ("tombstone", tombstone_path_value),
        ("serverLog", server_log_path),
    ):
        try:
            metadata = artifact_metadata(path)
        except (OSError, ValueError) as error:
            errors[f"{name}Metadata"] = type(error).__name__
            continue
        if metadata is not None:
            artifacts[name] = metadata

    try:
        state_document = load_json_artifact(state_path)
    except (OSError, ValueError, json.JSONDecodeError, UnicodeError) as error:
        state_document = None
        errors["stateParse"] = type(error).__name__
    try:
        result_document = load_json_artifact(result_path)
    except (OSError, ValueError, json.JSONDecodeError, UnicodeError) as error:
        result_document = None
        errors["resultParse"] = type(error).__name__
    state_summary = None
    if state_document is not None:
        state_summary = {
            key: state_document[key]
            for key in (
                "run_id",
                "phase",
                "ok",
                "code",
                "launch_dispatched",
                "runtime_observed",
                "reboot_required",
                "completed_at",
            )
            if key in state_document
        }
    result_summary = None
    if result_document is not None:
        result_summary = {
            key: result_document[key]
            for key in (
                "runId",
                "phase",
                "ok",
                "code",
                "launchDispatched",
                "runtimeObserved",
                "rebootRequired",
            )
            if key in result_document
        }

    event_count = 0
    invalid_event_lines = 0
    last_event: dict[str, Any] | None = None
    last_browser_event: dict[str, Any] | None = None
    try:
        with events_path.open("r", encoding="utf-8") as events:
            for line in events:
                event_count += 1
                try:
                    event = json.loads(line, object_pairs_hook=common.reject_duplicate_object)
                    if not isinstance(event, dict):
                        raise ValueError("event must be an object")
                except (json.JSONDecodeError, ValueError):
                    invalid_event_lines += 1
                    continue
                last_event = {
                    key: event[key]
                    for key in ("timestamp", "tag", "browser_tag", "phase", "ok", "code")
                    if key in event
                }
                if event.get("tag") == "BROWSER-TELEMETRY":
                    last_browser_event = last_event
    except FileNotFoundError:
        pass
    except (OSError, UnicodeError) as error:
        errors["eventsRead"] = type(error).__name__

    terminal_status = str(gateway.get("status") or "unknown")
    result_code = gateway.get("resultCode")
    if terminal_status in {"completed", "committed-failure"}:
        boundary = "result-committed"
    elif result_document is not None:
        boundary = "result-validation"
    elif last_browser_event is not None:
        boundary = f"browser:{last_browser_event.get('browser_tag', 'unknown')}"
    elif state_summary is not None:
        boundary = f"server:{state_summary.get('phase', 'unknown')}"
    elif "serverLog" in artifacts:
        boundary = "child-startup"
    else:
        boundary = f"gateway:{terminal_status}"

    return {
        "schema": DIAGNOSTIC_SCHEMA,
        "generatedAt": timestamp(),
        "runDir": str(run_dir),
        "gateway": gateway,
        "failureBoundary": boundary,
        "resultCode": result_code,
        "state": state_summary,
        "result": result_summary,
        "events": {
            "count": event_count,
            "invalidLines": invalid_event_lines,
            "last": last_event,
            "lastBrowser": last_browser_event,
        },
        "artifacts": artifacts,
        "errors": errors,
        "secretsIncluded": False,
    }

def terminate_process(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3.0)


def child_guard(command: list[str]) -> int:
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ValueError("child guard requires a command")
    guarded = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert guarded.stdout is not None
    parent_closed = threading.Event()


    def watch_parent() -> None:
        try:
            while sys.stdin.buffer.read(4096):
                pass
        finally:
            parent_closed.set()
            terminate_process(guarded)

    monitor = threading.Thread(target=watch_parent, name="access-parent-watch", daemon=True)
    monitor.start()
    try:
        while True:
            chunk = guarded.stdout.read1(65536)
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        return 0 if parent_closed.is_set() else guarded.wait()
    finally:
        terminate_process(guarded)


def persist_run_diagnostic(
    run_dir: Path,
    gateway: dict[str, Any],
    *,
    tombstone: Path | None = None,
) -> dict[str, Any]:
    document = summarize_run_artifacts(run_dir, gateway, tombstone=tombstone)
    common.durable_replace(
        run_dir / DIAGNOSTIC_NAME,
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n",
    )
    return document


class GatewayLease:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle: Any | None = None

    def acquire(self) -> None:
        handle = self.path.open("a+b", buffering=0)
        try:
            if self.path.stat().st_size == 0:
                handle.write(b"L" + (b" " * 511))
                os.fsync(handle.fileno())
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            handle.close()
            raise RuntimeError("another gateway process owns this runs root") from error
        payload = json.dumps(
            {
                "schema": "oms.fw14-hx1400-access.gateway-lease.v1",
                "pid": os.getpid(),
                "acquiredAt": timestamp(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > 511:
            handle.close()
            raise RuntimeError("gateway lease metadata exceeds its fixed record")
        handle.seek(1)
        handle.write(payload.ljust(511, b" "))
        os.fsync(handle.fileno())
        self.handle = handle

    def release(self) -> None:
        handle = self.handle
        if handle is None:
            return
        self.handle = None
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


class AccessRegistry:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        if not self.path.parent.is_dir():
            raise ValueError(f"registry parent does not exist: {self.path.parent}")
        if self.path.exists() and not self.path.is_file():
            raise ValueError("registry path must be a regular file")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _vacuum_registry(self, connection: sqlite3.Connection) -> None:
        connection.execute("VACUUM")

    def _truncate_registry_wal(self, connection: sqlite3.Connection) -> None:
        checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint is None or checkpoint[0] != 0:
            raise RuntimeError("registry plaintext-hint migration checkpoint did not complete")

    def _initialize(self) -> None:
        database_was_new = not self.path.exists()
        cleanup_required = False
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS metadata ("
                    "key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS devices ("
                    "device_id TEXT PRIMARY KEY,"
                    "expected_client TEXT NOT NULL,"
                    "last_run_id TEXT,"
                    "reboot_required INTEGER NOT NULL DEFAULT 0 "
                    "CHECK (reboot_required IN (0, 1)),"
                    "updated_at TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS access_codes ("
                    "code_hash TEXT PRIMARY KEY CHECK (length(code_hash) = 64),"
                    "device_id TEXT NOT NULL REFERENCES devices(device_id),"
                    "expected_client TEXT NOT NULL,"
                    "issued_at TEXT NOT NULL,"
                    "expires_at TEXT NOT NULL,"
                    "status TEXT NOT NULL "
                    "CHECK (status IN ('issued','provisioning','redeemed','expired','failed')),"
                    "redeemed_at TEXT,"
                    "redeemed_client TEXT,"
                    "redemption_id TEXT UNIQUE,"
                    "run_id TEXT UNIQUE)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS runs ("
                    "redemption_id TEXT PRIMARY KEY,"
                    "code_hash TEXT NOT NULL UNIQUE REFERENCES access_codes(code_hash),"
                    "device_id TEXT NOT NULL REFERENCES devices(device_id),"
                    "client_ip TEXT NOT NULL,"
                    "status TEXT NOT NULL,"
                    "run_id TEXT UNIQUE,"
                    "run_dir TEXT UNIQUE,"
                    "ready_url TEXT,"
                    "created_at TEXT NOT NULL,"
                    "completed_at TEXT,"
                    "result_code TEXT)"
                )
                schema_row = connection.execute(
                    "SELECT value FROM metadata WHERE key = 'schema'"
                ).fetchone()
                cleanup_row = connection.execute(
                    "SELECT value FROM metadata WHERE key = ?",
                    (REGISTRY_CLEANUP_KEY,),
                ).fetchone()
                schema = None if schema_row is None else schema_row["value"]
                cleanup = None if cleanup_row is None else cleanup_row["value"]
                columns = {
                    column["name"]
                    for column in connection.execute("PRAGMA table_info(access_codes)")
                }
                legacy_hint = "code_hint" in columns

                def set_metadata(key: str, value: str) -> None:
                    connection.execute(
                        "INSERT INTO metadata(key, value) VALUES(?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (key, value),
                    )

                if schema is None:
                    if legacy_hint:
                        connection.execute("ALTER TABLE access_codes DROP COLUMN code_hint")
                        cleanup_required = True
                    elif not database_was_new:
                        cleanup_required = True
                    if cleanup_required:
                        set_metadata("schema", REGISTRY_CLEANUP_PENDING_SCHEMA)
                        set_metadata(REGISTRY_CLEANUP_KEY, REGISTRY_CLEANUP_PENDING)
                    else:
                        set_metadata("schema", REGISTRY_SCHEMA)
                        set_metadata(REGISTRY_CLEANUP_KEY, REGISTRY_CLEANUP_COMPLETE)
                elif schema == LEGACY_REGISTRY_SCHEMA:
                    if not legacy_hint:
                        raise ValueError("legacy registry is missing its expected code_hint column")
                    connection.execute("ALTER TABLE access_codes DROP COLUMN code_hint")
                    set_metadata("schema", REGISTRY_CLEANUP_PENDING_SCHEMA)
                    set_metadata(REGISTRY_CLEANUP_KEY, REGISTRY_CLEANUP_PENDING)
                    cleanup_required = True
                elif schema == REGISTRY_CLEANUP_PENDING_SCHEMA:
                    if legacy_hint:
                        connection.execute("ALTER TABLE access_codes DROP COLUMN code_hint")
                    set_metadata(REGISTRY_CLEANUP_KEY, REGISTRY_CLEANUP_PENDING)
                    cleanup_required = True
                elif schema == REGISTRY_SCHEMA:
                    if legacy_hint:
                        raise ValueError("current registry unexpectedly contains a plaintext hint column")
                    if cleanup == REGISTRY_CLEANUP_COMPLETE:
                        pass
                    elif cleanup in {None, REGISTRY_CLEANUP_PENDING}:
                        set_metadata("schema", REGISTRY_CLEANUP_PENDING_SCHEMA)
                        set_metadata(REGISTRY_CLEANUP_KEY, REGISTRY_CLEANUP_PENDING)
                        cleanup_required = True
                    else:
                        raise ValueError("access registry cleanup state mismatch")
                else:
                    raise ValueError("access registry schema mismatch")

                duplicate = connection.execute(
                    "SELECT expected_client FROM devices "
                    "GROUP BY expected_client HAVING COUNT(*) > 1 LIMIT 1"
                ).fetchone()
                if duplicate is not None:
                    raise ValueError(
                        "registry contains duplicate device bindings for "
                        f"{duplicate['expected_client']}"
                    )
                connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS devices_expected_client_unique "
                    "ON devices(expected_client)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS access_codes_device_status "
                    "ON access_codes(device_id, status)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS runs_device_created "
                    "ON runs(device_id, created_at)"
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

            if cleanup_required:
                self._vacuum_registry(connection)
                self._truncate_registry_wal(connection)
                connection.execute("BEGIN IMMEDIATE")
                try:
                    schema_row = connection.execute(
                        "SELECT value FROM metadata WHERE key = 'schema'"
                    ).fetchone()
                    cleanup_row = connection.execute(
                        "SELECT value FROM metadata WHERE key = ?",
                        (REGISTRY_CLEANUP_KEY,),
                    ).fetchone()
                    schema = None if schema_row is None else schema_row["value"]
                    cleanup = None if cleanup_row is None else cleanup_row["value"]
                    columns = {
                        column["name"]
                        for column in connection.execute("PRAGMA table_info(access_codes)")
                    }
                    if "code_hint" in columns:
                        raise RuntimeError("registry plaintext-hint column survived sanitation")
                    if schema == REGISTRY_CLEANUP_PENDING_SCHEMA:
                        connection.execute(
                            "UPDATE metadata SET value = ? WHERE key = 'schema'",
                            (REGISTRY_SCHEMA,),
                        )
                        connection.execute(
                            "UPDATE metadata SET value = ? WHERE key = ?",
                            (REGISTRY_CLEANUP_COMPLETE, REGISTRY_CLEANUP_KEY),
                        )
                    elif not (
                        schema == REGISTRY_SCHEMA
                        and cleanup == REGISTRY_CLEANUP_COMPLETE
                    ):
                        raise RuntimeError("registry sanitation state changed unexpectedly")
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise

    def issue_code(
        self,
        *,
        device_id: str,
        expected_client: str,
        ttl_minutes: int,
    ) -> tuple[str, str]:
        device_id = exact_device_id(device_id)
        expected_client = exact_ipv4(expected_client, "expected client")
        if not 1 <= ttl_minutes <= 24 * 60:
            raise ValueError("TTL minutes must be in 1..1440")
        now = utc_now()
        expires = now + timedelta(minutes=ttl_minutes)
        for _ in range(8):
            normalized = generate_code()
            code_digest = hash_code(normalized)
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    device = connection.execute(
                        "SELECT expected_client, reboot_required FROM devices WHERE device_id = ?",
                        (device_id,),
                    ).fetchone()
                    client_owner = connection.execute(
                        "SELECT device_id FROM devices WHERE expected_client = ?",
                        (expected_client,),
                    ).fetchone()
                    if client_owner is not None and client_owner["device_id"] != device_id:
                        raise ValueError("client address is registered to a different device ID")
                    if device is None:
                        connection.execute(
                            "INSERT INTO devices(device_id, expected_client, reboot_required, updated_at) "
                            "VALUES(?, ?, 0, ?)",
                            (device_id, expected_client, timestamp(now)),
                        )
                    else:
                        if device["expected_client"] != expected_client:
                            raise ValueError("device is registered to a different client address")
                        if device["reboot_required"]:
                            raise ValueError("device requires a confirmed cold reboot before another code")
                    try:
                        connection.execute(
                            "INSERT INTO access_codes("
                            "code_hash, device_id, expected_client, issued_at, expires_at, status"
                            ") VALUES(?, ?, ?, ?, ?, 'issued')",
                            (
                                code_digest,
                                device_id,
                                expected_client,
                                timestamp(now),
                                timestamp(expires),
                            ),
                        )
                    except sqlite3.IntegrityError:
                        connection.rollback()
                        continue
                    connection.commit()
                    return format_code(normalized), timestamp(expires)
                except Exception:
                    connection.rollback()
                    raise
        raise RuntimeError("could not allocate a unique access code")

    def redeem_code(self, supplied: str, client_ip: str) -> dict[str, str]:
        try:
            normalized = normalize_code(supplied)
        except ValueError as error:
            raise AccessError(
                403,
                "code-unavailable",
                "Code unavailable or expired. Ask the operator for a new code.",
                count_failure=True,
            ) from error
        code_digest = hash_code(normalized)
        now = utc_now()
        redemption_id = secrets.token_hex(16)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT c.*, d.reboot_required, d.expected_client AS device_client "
                    "FROM access_codes AS c JOIN devices AS d ON d.device_id = c.device_id "
                    "WHERE c.code_hash = ?",
                    (code_digest,),
                ).fetchone()
                unavailable = AccessError(
                    403,
                    "code-unavailable",
                    "Code unavailable or expired. Ask the operator for a new code.",
                    count_failure=True,
                )
                if row is None or row["status"] != "issued":
                    raise unavailable
                if parse_timestamp(row["expires_at"]) <= now:
                    connection.execute(
                        "UPDATE access_codes SET status = 'expired' WHERE code_hash = ? AND status = 'issued'",
                        (code_digest,),
                    )
                    connection.commit()
                    raise unavailable
                if row["expected_client"] != client_ip or row["device_client"] != client_ip:
                    raise unavailable
                if row["reboot_required"]:
                    raise AccessError(
                        409,
                        "reboot-required",
                        "This device is locked until the operator confirms a full cold reboot.",
                    )
                changed = connection.execute(
                    "UPDATE access_codes SET status = 'provisioning', redeemed_at = ?, "
                    "redeemed_client = ?, redemption_id = ? "
                    "WHERE code_hash = ? AND status = 'issued'",
                    (timestamp(now), client_ip, redemption_id, code_digest),
                ).rowcount
                if changed != 1:
                    raise unavailable
                connection.execute(
                    "INSERT INTO runs(" 
                    "redemption_id, code_hash, device_id, client_ip, status, created_at" 
                    ") VALUES(?, ?, ?, ?, 'provisioning', ?)",
                    (redemption_id, code_digest, row["device_id"], client_ip, timestamp(now)),
                )
                connection.commit()
                return {
                    "redemption_id": redemption_id,
                    "code_hash": code_digest,
                    "device_id": row["device_id"],
                    "client_ip": client_ip,
                }
            except AccessError:
                if connection.in_transaction:
                    connection.rollback()
                raise
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise

    def mark_armed(
        self,
        *,
        redemption_id: str,
        run_id: str,
        run_dir: Path,
        ready_url: str,
    ) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                changed = connection.execute(
                    "UPDATE runs SET status = 'armed', run_id = ?, run_dir = ?, ready_url = ? "
                    "WHERE redemption_id = ? AND status = 'provisioning'",
                    (run_id, str(run_dir), ready_url, redemption_id),
                ).rowcount
                code_changed = connection.execute(
                    "UPDATE access_codes SET status = 'redeemed', run_id = ? "
                    "WHERE redemption_id = ? AND status = 'provisioning'",
                    (run_id, redemption_id),
                ).rowcount
                if changed != 1 or code_changed != 1:
                    raise RuntimeError("provisioning row changed before arm commit")
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def mark_failed(self, redemption_id: str, status: str, result_code: str) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "UPDATE runs SET status = ?, result_code = ?, completed_at = ? "
                    "WHERE redemption_id = ?",
                    (status, result_code, timestamp(), redemption_id),
                )
                connection.execute(
                    "UPDATE access_codes SET status = 'failed' "
                    "WHERE redemption_id = ? AND status = 'provisioning'",
                    (redemption_id,),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def mark_claimed(self, *, device_id: str, run_id: str, redemption_id: str) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "UPDATE devices SET last_run_id = ?, reboot_required = 1, updated_at = ? "
                    "WHERE device_id = ?",
                    (run_id, timestamp(), device_id),
                )
                connection.execute(
                    "UPDATE runs SET status = 'claimed' "
                    "WHERE redemption_id = ? AND status = 'armed'",
                    (redemption_id,),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def mark_terminal(
        self,
        *,
        redemption_id: str,
        status: str,
        result_code: str,
    ) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "UPDATE runs SET status = ?, result_code = ?, completed_at = ? "
                    "WHERE redemption_id = ?",
                    (status, result_code, timestamp(), redemption_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def reconcile_devices(self, runs_root: Path) -> None:
        with closing(self._connect()) as connection:
            devices = connection.execute(
                "SELECT device_id, last_run_id, reboot_required FROM devices"
            ).fetchall()
        for device in devices:
            tombstone = tombstone_path(runs_root, device["device_id"])
            if not tombstone.exists():
                continue
            try:
                document = child.load_boot_tombstone(tombstone)
            except (OSError, ValueError):
                continue
            if document["blocked"]:
                with closing(self._connect()) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        connection.execute(
                            "UPDATE devices SET last_run_id = ?, reboot_required = 1, updated_at = ? "
                            "WHERE device_id = ?",
                            (document["run_id"], timestamp(), device["device_id"]),
                        )
                        connection.commit()
                    except Exception:
                        connection.rollback()
                        raise

    def recover_interrupted_runs(self) -> list[dict[str, Any]]:
        recovered: list[dict[str, Any]] = []
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    "SELECT redemption_id, device_id, client_ip, status, run_id, run_dir "
                    "FROM runs WHERE completed_at IS NULL "
                    "AND status IN ('provisioning','armed','claimed') "
                    "ORDER BY created_at"
                ).fetchall()
                for row in rows:
                    changed = connection.execute(
                        "UPDATE runs SET status = 'gateway-recovered', "
                        "result_code = 'GATEWAY_RESTARTED', completed_at = ? "
                        "WHERE redemption_id = ? AND completed_at IS NULL",
                        (timestamp(), row["redemption_id"]),
                    ).rowcount
                    if changed != 1:
                        raise RuntimeError("interrupted run changed during recovery")
                    connection.execute(
                        "UPDATE access_codes SET status = 'failed' "
                        "WHERE redemption_id = ? AND status = 'provisioning'",
                        (row["redemption_id"],),
                    )
                    recovered.append(dict(row))
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return recovered

    def confirm_reboot(
        self,
        *,
        runs_root: Path,
        device_id: str,
        after_run: str,
        expected_client: str | None,
    ) -> str:
        device_id = exact_device_id(device_id)
        if HEX32_RE.fullmatch(after_run) is None:
            raise ValueError("after-run must be an exact 32-character lowercase run ID")
        if expected_client is not None:
            expected_client = exact_ipv4(expected_client, "expected client")
        tombstone = tombstone_path(runs_root, device_id)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT expected_client, last_run_id, reboot_required FROM devices WHERE device_id = ?",
                    (device_id,),
                ).fetchone()
                if row is None:
                    raise ValueError("unknown device ID")
                if not row["reboot_required"] or row["last_run_id"] != after_run:
                    raise ValueError("device lock does not match the confirmed prior run")
                next_client = expected_client or row["expected_client"]
                client_owner = connection.execute(
                    "SELECT device_id FROM devices WHERE expected_client = ?",
                    (next_client,),
                ).fetchone()
                if client_owner is not None and client_owner["device_id"] != device_id:
                    raise ValueError("client address is registered to a different device ID")
                child.prepare_boot_tombstone(tombstone, after_run)
                connection.execute(
                    "UPDATE devices SET expected_client = ?, reboot_required = 0, updated_at = ? "
                    "WHERE device_id = ?",
                    (next_client, timestamp(), device_id),
                )
                connection.commit()
                return next_client
            except Exception:
                connection.rollback()
                raise

    def status(self) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            devices = [dict(row) for row in connection.execute(
                "SELECT device_id, expected_client, last_run_id, reboot_required, updated_at "
                "FROM devices ORDER BY device_id"
            )]
            codes = [dict(row) for row in connection.execute(
                "SELECT device_id, expected_client, issued_at, expires_at, status, run_id "
                "FROM access_codes ORDER BY issued_at DESC"
            )]
            runs = [dict(row) for row in connection.execute(
                "SELECT redemption_id, device_id, client_ip, status, run_id, run_dir, "
                "created_at, completed_at, result_code FROM runs ORDER BY created_at DESC"
            )]
        return {
            "schema": REGISTRY_SCHEMA,
            "devices": devices,
            "codes": codes,
            "runs": runs,
        }


class AttemptLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: OrderedDict[str, deque[float]] = OrderedDict()

    def allowed(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            entries = self._failures.get(client)
            if entries is None:
                return True
            while entries and now - entries[0] >= ATTEMPT_WINDOW_SECONDS:
                entries.popleft()
            if not entries:
                self._failures.pop(client, None)
                return True
            self._failures.move_to_end(client)
            return len(entries) < MAX_FAILED_ATTEMPTS

    def record_failure(self, client: str) -> None:
        now = time.monotonic()
        with self._lock:
            entries = self._failures.setdefault(client, deque())
            while entries and now - entries[0] >= ATTEMPT_WINDOW_SECONDS:
                entries.popleft()
            entries.append(now)
            self._failures.move_to_end(client)
            while len(self._failures) > MAX_LIMITER_CLIENTS:
                self._failures.popitem(last=False)

    def clear(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)


@dataclass
class ActiveRun:
    redemption_id: str
    device_id: str
    client_ip: str
    run_id: str
    run_dir: Path
    tombstone: Path
    result: Path
    process: subprocess.Popen[str]
    log_thread: threading.Thread
    finish_lock: threading.Lock = field(default_factory=threading.Lock)
    finalized: bool = False
    claimed: bool = False


def tombstone_path(runs_root: Path, device_id: str) -> Path:
    return runs_root / "devices" / device_key(device_id) / "boot-tombstone.json"


class RunCoordinator:
    def __init__(
        self,
        *,
        registry: AccessRegistry,
        runs_root: Path,
        static_root: Path,
        hen_path: Path,
        host: str,
        public_host: str,
        child_port: int,
        startup_timeout: float,
        run_timeout: float,
    ) -> None:
        self.registry = registry
        self.runs_root = runs_root.resolve()
        self.static_root = static_root.resolve(strict=True)
        self.hen_path = hen_path.resolve(strict=True)
        self.host = host
        self.public_host = public_host
        self.child_port = child_port
        self.startup_timeout = startup_timeout
        self.run_timeout = run_timeout
        self.lock = threading.Lock()
        self.active: ActiveRun | None = None
        self.shutdown_lock = threading.Lock()
        self.stopping = False
        self.stopped = False
        self.terminal_settle_seconds = TERMINAL_SETTLE_SECONDS
        (self.runs_root / "runs").mkdir(parents=True, exist_ok=True)
        (self.runs_root / "devices").mkdir(parents=True, exist_ok=True)
        self.lease = GatewayLease(self.runs_root / "gateway.lock")
        self.lease.acquire()
        try:
            gateway_events_path = self.runs_root / GATEWAY_EVENTS_NAME
            try:
                common.durable_create(gateway_events_path, b"")
            except FileExistsError:
                if not gateway_events_path.is_file():
                    raise ValueError("gateway event log is not a regular file")
            self.gateway_events = common.DurableEventLog(gateway_events_path)
            self.registry.reconcile_devices(self.runs_root)
            recovered = self.registry.recover_interrupted_runs()
            self._event(
                "GATEWAY-INITIALIZED",
                host=self.host,
                public_host=self.public_host,
                child_port=self.child_port,
                recovered_runs=len(recovered),
            )
            allowed_runs = (self.runs_root / "runs").resolve()
            for run in recovered:
                run_dir = (
                    Path(run["run_dir"]).resolve()
                    if run["run_dir"]
                    else (allowed_runs / run["redemption_id"]).resolve()
                )
                try:
                    run_dir.relative_to(allowed_runs)
                except ValueError as error:
                    raise ValueError("recovered run directory escapes the runs root") from error
                if run_dir.is_dir():
                    self._persist_diagnostic_safely(
                        run_dir,
                        {
                            "redemptionId": run["redemption_id"],
                            "deviceId": run["device_id"],
                            "clientIp": run["client_ip"],
                            "runId": run["run_id"],
                            "status": "gateway-recovered",
                            "resultCode": "GATEWAY_RESTARTED",
                            "observedChildExit": None,
                            "finalChildExit": None,
                        },
                        tombstone_path(self.runs_root, run["device_id"]),
                    )
                self._event_safely(
                    "RUN-RECOVERED",
                    redemption_id=run["redemption_id"],
                    device_id=run["device_id"],
                    client_ip=run["client_ip"],
                    run_id=run["run_id"],
                    prior_status=run["status"],
                    status="gateway-recovered",
                    result_code="GATEWAY_RESTARTED",
                )
        except Exception:
            self.lease.release()
            raise

    def _event(self, tag: str, **fields: Any) -> None:
        self.gateway_events.append({
            "schema": GATEWAY_EVENT_SCHEMA,
            "tag": tag,
            **fields,
        })

    def _event_safely(self, tag: str, **fields: Any) -> None:
        try:
            self._event(tag, **fields)
        except OSError as error:
            print(
                f"DIAGNOSTIC ERROR event={tag} error={type(error).__name__}",
                file=sys.stderr,
                flush=True,
            )

    def _persist_diagnostic_safely(
        self,
        run_dir: Path,
        gateway: dict[str, Any],
        tombstone: Path,
    ) -> dict[str, Any] | None:
        try:
            return persist_run_diagnostic(run_dir, gateway, tombstone=tombstone)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(
                f"DIAGNOSTIC ERROR run={gateway.get('runId')} error={type(error).__name__}",
                file=sys.stderr,
                flush=True,
            )
            return None

    def _terminate(self, process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        stdin = getattr(process, "stdin", None)
        if stdin is not None and not stdin.closed:
            stdin.close()
            try:
                process.wait(timeout=3.0)
                return
            except subprocess.TimeoutExpired:
                pass
        terminate_process(process)

    def _spawn(self, provision: dict[str, str], run_dir: Path, tombstone: Path) -> tuple[ActiveRun, str]:
        state_path = run_dir / "state.json"
        events_path = run_dir / "events.jsonl"
        result_path = run_dir / "result.json"
        log_path = run_dir / "server.log"
        child_command = [
            sys.executable,
            "-u",
            "-B",
            str(Path(child.__file__).resolve()),
            "--host",
            self.host,
            "--public-host",
            self.public_host,
            "--port",
            str(self.child_port),
            "--root",
            str(self.static_root),
            "--expected-client",
            provision["client_ip"],
            "--state",
            str(state_path),
            "--events",
            str(events_path),
            "--result",
            str(result_path),
            "--boot-tombstone",
            str(tombstone),
            "--hen",
            str(self.hen_path),
            "--hen-sha256",
            child.HEN_SHA256,
            "--trusted-isolated-network",
        ]
        command = [
            sys.executable,
            "-u",
            "-B",
            str(Path(__file__).resolve()),
            "_child-guard",
            "--",
            *child_command,
        ]
        process = subprocess.Popen(
            command,
            cwd=self.static_root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert process.stdout is not None
        lines: queue.Queue[str | None] = queue.Queue()

        def pump() -> None:
            with log_path.open("x", encoding="utf-8", newline="\n") as log:
                for line in process.stdout:
                    log.write(line)
                    log.flush()
                    os.fsync(log.fileno())
                    lines.put(line.rstrip("\r\n"))
            lines.put(None)

        log_thread = threading.Thread(target=pump, name=f"access-log-{provision['redemption_id']}", daemon=True)
        log_thread.start()
        deadline = time.monotonic() + self.startup_timeout
        ready_match: re.Match[str] | None = None
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                line = lines.get(timeout=max(0.01, remaining))
            except queue.Empty:
                break
            if line is None:
                break
            candidate = READY_RE.fullmatch(line)
            if candidate is not None:
                ready_match = candidate
                break
        if ready_match is None:
            self._terminate(process)
            raise RuntimeError(f"child did not become ready; exit={process.poll()}")
        run_id = ready_match.group("run")
        ready_url = ready_match.group("url")
        expected_authority = self.public_host if self.child_port == 80 else f"{self.public_host}:{self.child_port}"
        parsed = urlsplit(ready_url)
        expected_query = (
            f"stage={child.STAGE_NAME}&retry=0&slots={child.STABLE_SLOTS}"
            f"&g={child.STABLE_G}&intent="
        )
        if not (
            parsed.scheme == "http"
            and parsed.netloc == expected_authority
            and parsed.path == child.STAGE_PAGE
            and parsed.query.startswith(expected_query)
            and HEX64_RE.fullmatch(parsed.query.removeprefix(expected_query)) is not None
            and ready_match.group("client") == provision["client_ip"]
            and ready_match.group("host") == expected_authority
        ):
            self._terminate(process)
            raise RuntimeError("child READY binding mismatch")
        active = ActiveRun(
            redemption_id=provision["redemption_id"],
            device_id=provision["device_id"],
            client_ip=provision["client_ip"],
            run_id=run_id,
            run_dir=run_dir,
            tombstone=tombstone,
            result=result_path,
            process=process,
            log_thread=log_thread,
        )
        return active, ready_url

    def launch(self, supplied_code: str, client_ip: str) -> str:
        with self.lock:
            if self.stopping:
                raise AccessError(
                    503,
                    "gateway-stopping",
                    "Gateway is stopping; your code was not consumed.",
                )
            if self.active is not None and self.active.process.poll() is None:
                raise AccessError(
                    409,
                    "run-active",
                    "Another device run is active. Wait for it to finish; your code was not consumed.",
                )
            self.active = None
            provision = self.registry.redeem_code(supplied_code, client_ip)
            run_dir = self.runs_root / "runs" / provision["redemption_id"]
            tombstone = tombstone_path(self.runs_root, provision["device_id"])
            active: ActiveRun | None = None
            try:
                run_dir.mkdir(mode=0o700)
                tombstone.parent.mkdir(parents=True, exist_ok=True)
                self._event(
                    "CODE-REDEEMED",
                    redemption_id=provision["redemption_id"],
                    device_id=provision["device_id"],
                    client_ip=provision["client_ip"],
                )
                active, ready_url = self._spawn(provision, run_dir, tombstone)
                self.registry.mark_armed(
                    redemption_id=provision["redemption_id"],
                    run_id=active.run_id,
                    run_dir=run_dir,
                    ready_url=ready_url,
                )
                self._event_safely(
                    "CHILD-READY",
                    redemption_id=active.redemption_id,
                    device_id=active.device_id,
                    client_ip=active.client_ip,
                    run_id=active.run_id,
                )
            except Exception as error:
                error_detail = safe_error_detail(error)
                observed_child_exit = None
                final_child_exit = None
                run_id = None
                if active is not None:
                    run_id = active.run_id
                    observed_child_exit = active.process.poll()
                    self._terminate(active.process)
                    active.log_thread.join(timeout=2.0)
                    final_child_exit = active.process.poll()
                self.registry.mark_failed(
                    provision["redemption_id"],
                    "provision-failed",
                    type(error).__name__,
                )
                if run_dir.is_dir():
                    self._persist_diagnostic_safely(
                        run_dir,
                        {
                            "redemptionId": provision["redemption_id"],
                            "deviceId": provision["device_id"],
                            "clientIp": provision["client_ip"],
                            "runId": run_id,
                            "status": "provision-failed",
                            "resultCode": type(error).__name__,
                            "errorType": type(error).__name__,
                            "errorDetail": error_detail,
                            "observedChildExit": observed_child_exit,
                            "finalChildExit": final_child_exit,
                        },
                        tombstone,
                    )
                self._event_safely(
                    "CHILD-PROVISION-FAILED",
                    redemption_id=provision["redemption_id"],
                    device_id=provision["device_id"],
                    client_ip=provision["client_ip"],
                    run_id=run_id,
                    error_type=type(error).__name__,
                    error_detail=error_detail,
                )
                raise AccessError(
                    503,
                    "provision-failed",
                    "Run provisioning failed; this code is consumed. Contact the operator.",
                ) from error
            self.active = active
            watcher = threading.Thread(
                target=self._watch,
                args=(active,),
                name=f"access-watch-{active.run_id}",
                daemon=True,
            )
            try:
                watcher.start()
            except Exception as error:
                error_detail = safe_error_detail(error)
                self.active = None
                observed_child_exit = active.process.poll()
                self._terminate(active.process)
                active.log_thread.join(timeout=2.0)
                self.registry.mark_terminal(
                    redemption_id=active.redemption_id,
                    status="provision-failed",
                    result_code=type(error).__name__,
                )
                self._persist_diagnostic_safely(
                    active.run_dir,
                    {
                        "redemptionId": active.redemption_id,
                        "deviceId": active.device_id,
                        "clientIp": active.client_ip,
                        "runId": active.run_id,
                        "status": "provision-failed",
                        "resultCode": type(error).__name__,
                        "errorType": type(error).__name__,
                        "errorDetail": error_detail,
                        "observedChildExit": observed_child_exit,
                        "finalChildExit": active.process.poll(),
                    },
                    active.tombstone,
                )
                self._event_safely(
                    "CHILD-PROVISION-FAILED",
                    redemption_id=active.redemption_id,
                    device_id=active.device_id,
                    client_ip=active.client_ip,
                    run_id=active.run_id,
                    error_type=type(error).__name__,
                    error_detail=error_detail,
                )
                raise AccessError(
                    503,
                    "provision-failed",
                    "Run provisioning failed; this code is consumed. Contact the operator.",
                ) from error
            return ready_url

    def _tombstone_blocked(self, active: ActiveRun) -> bool:
        if not active.tombstone.exists():
            return False
        try:
            document = child.load_boot_tombstone(active.tombstone)
        except (OSError, ValueError):
            return False
        return bool(document["blocked"] and document["run_id"] == active.run_id)

    def _finalize(
        self,
        active: ActiveRun,
        status: str,
        result_code: str,
        error_detail: str | None = None,
    ) -> None:
        with active.finish_lock:
            if active.finalized:
                return
            active.finalized = True
            try:
                observed_child_exit = active.process.poll()
                self._terminate(active.process)
                active.log_thread.join(timeout=2.0)
                if not active.claimed and self._tombstone_blocked(active):
                    self.registry.mark_claimed(
                        device_id=active.device_id,
                        run_id=active.run_id,
                        redemption_id=active.redemption_id,
                    )
                    active.claimed = True
                    self._event_safely(
                        "CHILD-CLAIMED",
                        redemption_id=active.redemption_id,
                        device_id=active.device_id,
                        client_ip=active.client_ip,
                        run_id=active.run_id,
                    )
                self.registry.mark_terminal(
                    redemption_id=active.redemption_id,
                    status=status,
                    result_code=result_code,
                )
                diagnostic = self._persist_diagnostic_safely(
                    active.run_dir,
                    {
                        "redemptionId": active.redemption_id,
                        "deviceId": active.device_id,
                        "clientIp": active.client_ip,
                        "runId": active.run_id,
                        "status": status,
                        "resultCode": result_code,
                        "errorDetail": error_detail,
                        "observedChildExit": observed_child_exit,
                        "finalChildExit": active.process.poll(),
                    },
                    active.tombstone,
                )
                self._event_safely(
                    "RUN-TERMINAL",
                    redemption_id=active.redemption_id,
                    device_id=active.device_id,
                    client_ip=active.client_ip,
                    run_id=active.run_id,
                    status=status,
                    result_code=result_code,
                    error_detail=error_detail,
                    failure_boundary=(
                        diagnostic["failureBoundary"]
                        if diagnostic is not None
                        else "diagnostic-unavailable"
                    ),
                )
            finally:
                with self.lock:
                    if self.active is active:
                        self.active = None

    def _watch(self, active: ActiveRun) -> None:
        deadline = time.monotonic() + self.run_timeout
        terminal_status = "child-exited"
        terminal_code = "NO_COMMITTED_RESULT"
        terminal_detail: str | None = None
        pending_terminal: tuple[str, str, str | None] | None = None
        terminal_seen_at: float | None = None
        try:
            while True:
                if not active.claimed and self._tombstone_blocked(active):
                    self.registry.mark_claimed(
                        device_id=active.device_id,
                        run_id=active.run_id,
                        redemption_id=active.redemption_id,
                    )
                    active.claimed = True
                    self._event_safely(
                        "CHILD-CLAIMED",
                        redemption_id=active.redemption_id,
                        device_id=active.device_id,
                        client_ip=active.client_ip,
                        run_id=active.run_id,
                    )
                try:
                    terminal = child_terminal_state(
                        active.run_dir / "state.json",
                        active.result,
                        run_id=active.run_id,
                    )
                except (OSError, UnicodeError, ValueError, common.ProtocolError) as error:
                    terminal_status = "evidence-invalid"
                    terminal_code = type(error).__name__
                    terminal_detail = safe_error_detail(error)
                    break
                now = time.monotonic()
                if terminal is not None:
                    if pending_terminal is None:
                        pending_terminal = terminal
                        terminal_seen_at = now
                    elif terminal != pending_terminal:
                        terminal_status = "evidence-invalid"
                        terminal_code = "TERMINAL_STATE_CHANGED"
                        terminal_detail = "child terminal state changed during settling"
                        break
                    assert terminal_seen_at is not None
                    if now - terminal_seen_at >= self.terminal_settle_seconds:
                        terminal_status, terminal_code, terminal_detail = pending_terminal
                        break
                elif pending_terminal is not None:
                    terminal_status = "evidence-invalid"
                    terminal_code = "TERMINAL_STATE_REGRESSED"
                    terminal_detail = "child terminal state regressed during settling"
                    break
                return_code = active.process.poll()
                if return_code is not None:
                    if pending_terminal is not None:
                        terminal_status, terminal_code, terminal_detail = pending_terminal
                    else:
                        terminal_code = f"CHILD_EXIT_{return_code}"
                    break
                if pending_terminal is None and now >= deadline:
                    terminal_status = "timed-out"
                    terminal_code = "RUN_TIMEOUT"
                    break
                time.sleep(0.1)
        finally:
            self._finalize(active, terminal_status, terminal_code, terminal_detail)

    def begin_shutdown(self) -> None:
        changed = False
        with self.lock:
            if not self.stopping and not self.stopped:
                self.stopping = True
                changed = True
        if changed:
            self._event_safely("GATEWAY-STOPPING")

    def shutdown(self) -> None:
        with self.shutdown_lock:
            if self.stopped:
                return
            self.begin_shutdown()
            try:
                with self.lock:
                    active = self.active
                if active is not None:
                    self._finalize(active, "gateway-stopped", "GATEWAY_STOPPED")
                self._event_safely("GATEWAY-STOPPED")
            finally:
                with self.lock:
                    self.stopped = True
                self.lease.release()



class AccessServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        address: tuple[str, int],
        *,
        coordinator: RunCoordinator,
        template: bytes,
        authority: str,
        client_network: ipaddress.IPv4Network,
    ) -> None:
        self.coordinator = coordinator
        self.template = template
        self.authority = authority
        self.client_network = client_network
        self.limiter = AttemptLimiter()
        super().__init__(address, AccessHandler)


class AccessHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: AccessServer

    def log_message(self, format: str, *args: object) -> None:
        return

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        super().end_headers()

    def one_header(self, name: str) -> str:
        values = self.headers.get_all(name, [])
        if len(values) != 1:
            raise AccessError(400, "invalid-header", "Request refused.")
        return values[0]

    def require_base(self) -> str:
        client = self.client_address[0]
        try:
            parsed = ipaddress.ip_address(client)
        except ValueError as error:
            raise AccessError(403, "client-refused", "Request refused.") from error
        if parsed.version != 4 or parsed not in self.server.client_network:
            raise AccessError(403, "client-refused", "Request refused.")
        if self.headers.get_all("User-Agent", []) != [common.CANONICAL_FW14_UA]:
            raise AccessError(403, "user-agent-refused", "Firmware 14.00 browser identity required.")
        if not hmac.compare_digest(self.one_header("Host"), self.server.authority):
            raise AccessError(403, "host-refused", "Request refused.")
        return client

    def send_page(self, status: int, message: str) -> None:
        payload = render_access_page(self.server.template, message)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def send_empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def read_form(self) -> str:
        if self.headers.get("Transfer-Encoding") is not None:
            raise AccessError(400, "transfer-encoding-refused", "Request refused.")
        content_type = self.one_header("Content-Type").lower().replace(" ", "")
        if content_type not in {
            "application/x-www-form-urlencoded",
            "application/x-www-form-urlencoded;charset=utf-8",
        }:
            raise AccessError(415, "content-type-refused", "Request refused.")
        length_text = self.one_header("Content-Length")
        if re.fullmatch(r"0|[1-9][0-9]*", length_text) is None:
            raise AccessError(400, "content-length-refused", "Request refused.")
        length = int(length_text)
        if length <= 0 or length > MAX_FORM_BYTES:
            raise AccessError(413 if length > MAX_FORM_BYTES else 422, "form-size-refused", "Request refused.")
        body = self.rfile.read(length)
        if len(body) != length:
            raise AccessError(400, "short-body", "Request refused.")
        try:
            values = parse_qs(
                body.decode("ascii"),
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=1,
            )
        except (UnicodeError, ValueError) as error:
            raise AccessError(400, "invalid-form", "Request refused.") from error
        if set(values) != {"access_code"} or len(values["access_code"]) != 1:
            raise AccessError(400, "invalid-form", "Request refused.")
        return values["access_code"][0]

    def do_GET(self) -> None:
        request = urlsplit(self.path)
        try:
            self.require_base()
            if request.path != "/" or request.query or request.fragment:
                raise AccessError(404, "path-refused", "Request refused.")
            self.send_page(200, DEFAULT_STATUS)
        except AccessError as error:
            self.send_page(error.status, error.public)

    def do_POST(self) -> None:
        request = urlsplit(self.path)
        client = self.client_address[0]
        try:
            client = self.require_base()
            if request.path != "/redeem" or request.query or request.fragment:
                raise AccessError(404, "path-refused", "Request refused.")
            if not self.server.limiter.allowed(client):
                raise AccessError(429, "rate-limited", "Too many rejected codes. Wait one minute.")
            supplied = self.read_form()
            ready_url = self.server.coordinator.launch(supplied, client)
            self.server.limiter.clear(client)
            self.send_response(303)
            self.send_header("Location", ready_url)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
        except AccessError as error:
            if error.count_failure:
                self.server.limiter.record_failure(client)
            self.send_page(error.status, error.public)
        except (OSError, sqlite3.Error):
            self.send_page(500, "Durable access state failed. Contact the operator.")

    def do_HEAD(self) -> None:
        self.send_empty(405)

    def do_OPTIONS(self) -> None:
        self.send_empty(405)

    def do_PUT(self) -> None:
        self.send_empty(405)

    def do_DELETE(self) -> None:
        self.send_empty(405)


@dataclass(frozen=True)
class ReleaseInputs:
    root: Path
    hen_path: Path
    template: bytes
    static_graph: str
    hen_meta: dict[str, Any]


def summarize_gateway_events(path: Path, redemption_id: str) -> dict[str, Any]:
    matching = 0
    invalid = 0
    last: dict[str, Any] | None = None
    try:
        with path.open("r", encoding="utf-8") as events:
            for line in events:
                try:
                    event = json.loads(line, object_pairs_hook=common.reject_duplicate_object)
                    if not isinstance(event, dict):
                        raise ValueError("gateway event must be an object")
                except (json.JSONDecodeError, ValueError):
                    invalid += 1
                    continue
                if event.get("redemption_id") != redemption_id:
                    continue
                matching += 1
                last = {
                    key: event[key]
                    for key in (
                        "timestamp",
                        "tag",
                        "run_id",
                        "status",
                        "result_code",
                        "error_type",
                        "failure_boundary",
                    )
                    if key in event
                }
    except FileNotFoundError:
        return {"matching": 0, "invalidLines": 0, "last": None, "readError": "FileNotFoundError"}
    except (OSError, UnicodeError) as error:
        return {"matching": matching, "invalidLines": invalid, "last": last, "readError": type(error).__name__}
    return {"matching": matching, "invalidLines": invalid, "last": last, "readError": None}


def diagnose_run(
    registry: AccessRegistry,
    runs_root: Path,
    selector: str | None,
) -> dict[str, Any]:
    status = registry.status()
    selected = None
    for run in status["runs"]:
        if selector is None or selector in {run["run_id"], run["redemption_id"]}:
            selected = run
            break
    if selected is None:
        if selector is None:
            raise ValueError("no runs are recorded")
        raise ValueError("run ID or redemption ID was not found")

    allowed_root = (runs_root / "runs").resolve()
    if selected["run_dir"]:
        run_dir = Path(selected["run_dir"]).resolve()
    else:
        run_dir = (allowed_root / selected["redemption_id"]).resolve()
    try:
        run_dir.relative_to(allowed_root)
    except ValueError as error:
        raise ValueError("recorded run directory escapes the runs root") from error

    gateway = {
        "redemptionId": selected["redemption_id"],
        "deviceId": selected["device_id"],
        "clientIp": selected["client_ip"],
        "runId": selected["run_id"],
        "status": selected["status"],
        "resultCode": selected["result_code"],
        "createdAt": selected["created_at"],
        "completedAt": selected["completed_at"],
    }
    document = summarize_run_artifacts(
        run_dir,
        gateway,
        tombstone=tombstone_path(runs_root, selected["device_id"]),
    )
    document["gatewayEvents"] = summarize_gateway_events(
        runs_root / GATEWAY_EVENTS_NAME,
        selected["redemption_id"],
    )
    persisted = artifact_metadata(run_dir / DIAGNOSTIC_NAME)
    document["persistedDiagnostic"] = persisted
    return document


def validate_release(root: Path, hen_path: Path, expected_hen_hash: str) -> ReleaseInputs:
    root = root.resolve(strict=True)
    template = load_access_template(root)
    _payloads, _hashes, static_graph = child.load_manifest(root)
    hen_path = hen_path.resolve(strict=True)
    hen_bytes = hen_path.read_bytes()
    if not hmac.compare_digest(expected_hen_hash, child.HEN_SHA256):
        raise ValueError("HEN SHA-256 does not match the reviewed image")
    hen_meta = child.validate_hen(hen_bytes, expected_hen_hash)
    return ReleaseInputs(root, hen_path, template, static_graph, hen_meta)


def add_release_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--hen", type=Path, required=True)
    parser.add_argument("--hen-sha256", required=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    check_parser = commands.add_parser("check", help="validate release bytes without mutation or bind")
    add_release_args(check_parser)

    serve_parser = commands.add_parser("serve", help="run the reusable local access gateway")
    add_release_args(serve_parser)
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--public-host")
    serve_parser.add_argument("--port", type=int, default=80)
    serve_parser.add_argument("--child-port", type=int, default=8080)
    serve_parser.add_argument("--client-cidr", default="127.0.0.0/8")
    serve_parser.add_argument("--registry", type=Path, required=True)
    serve_parser.add_argument("--runs-root", type=Path, required=True)
    serve_parser.add_argument("--startup-timeout", type=float, default=30.0)
    serve_parser.add_argument("--run-timeout", type=float, default=1800.0)
    serve_parser.add_argument("--trusted-isolated-network", action="store_true")

    issue_parser = commands.add_parser("issue", help="issue one code locally; never exposed over HTTP")
    issue_parser.add_argument("--registry", type=Path, required=True)
    issue_parser.add_argument("--runs-root", type=Path, required=True)
    issue_parser.add_argument("--device-id", required=True)
    issue_parser.add_argument("--expected-client", required=True)
    issue_parser.add_argument("--ttl-minutes", type=int, default=30)

    reboot_parser = commands.add_parser("confirm-reboot", help="clear one exact device lock after a real cold boot")
    reboot_parser.add_argument("--registry", type=Path, required=True)
    reboot_parser.add_argument("--runs-root", type=Path, required=True)
    reboot_parser.add_argument("--device-id", required=True)
    reboot_parser.add_argument("--after-run", required=True)
    reboot_parser.add_argument("--expected-client")

    status_parser = commands.add_parser("status", help="show hashed-code/device/run state")
    status_parser.add_argument("--registry", type=Path, required=True)

    diagnose_parser = commands.add_parser(
        "diagnose",
        help="show the exact last recorded phase and crash/failure boundary for one run",
    )
    diagnose_parser.add_argument("--registry", type=Path, required=True)
    diagnose_parser.add_argument("--runs-root", type=Path, required=True)
    diagnose_parser.add_argument("--run-id")

    guard_parser = commands.add_parser("_child-guard", help=argparse.SUPPRESS)
    guard_parser.add_argument("child_args", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)
    if args.command in {"check", "serve"}:
        if HEX64_RE.fullmatch(args.hen_sha256 or "") is None:
            parser.error("--hen-sha256 must be exact lowercase SHA-256")
    if args.command == "serve":
        if not 1 <= args.port <= 65535 or not 1 <= args.child_port <= 65535:
            parser.error("ports must be in 1..65535")
        if args.port == args.child_port:
            parser.error("access and child ports must differ")
        try:
            exact_ipv4(args.host, "--host", allow_unspecified=True)
            args.public_host = args.public_host or args.host
            exact_ipv4(args.public_host, "--public-host")
            network = ipaddress.ip_network(args.client_cidr, strict=True)
            if network.version != 4:
                raise ValueError("--client-cidr must be IPv4")
            args.client_network = network
        except ValueError as error:
            parser.error(str(error))
        if (
            args.host not in LOOPBACKS
            or args.public_host not in LOOPBACKS
            or not args.client_network.is_loopback
        ) and not args.trusted_isolated_network:
            parser.error("non-loopback serving requires --trusted-isolated-network")
        if args.startup_timeout <= 0 or args.run_timeout <= 0:
            parser.error("timeouts must be positive")
    if args.command == "diagnose" and args.run_id is not None:
        if HEX32_RE.fullmatch(args.run_id) is None:
            parser.error("--run-id must be an exact 32-character lowercase run or redemption ID")
    return args


def ensure_state_paths(root: Path, registry_path: Path, runs_root: Path) -> tuple[Path, Path]:
    registry_path = registry_path.resolve()
    runs_root = runs_root.resolve()
    for path in (registry_path, runs_root):
        try:
            path.relative_to(root)
        except ValueError:
            pass
        else:
            raise ValueError(f"mutable path must be outside static root: {path}")
    if not registry_path.parent.is_dir():
        raise ValueError(f"registry parent does not exist: {registry_path.parent}")
    if not runs_root.parent.is_dir():
        raise ValueError(f"runs-root parent does not exist: {runs_root.parent}")
    runs_root.mkdir(exist_ok=True)
    return registry_path, runs_root


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "_child-guard":
        try:
            return child_guard(args.child_args)
        except ValueError as error:
            raise SystemExit(str(error)) from error

    if args.command == "check":
        release = validate_release(args.root, args.hen, args.hen_sha256)
        print(
            f"CHECK PASS access={ACCESS_TEMPLATE_SHA256} childGraph={release.static_graph} "
            f"hen={release.hen_meta['sha256']} registryMutated=false "
            "serverConstructed=false bound=false"
        )
        return 0

    if args.command == "status":
        registry = AccessRegistry(args.registry)
        print(json.dumps(registry.status(), indent=2, sort_keys=True))
        return 0

    if args.command == "diagnose":
        runs_root = args.runs_root.resolve()
        if not runs_root.is_dir():
            raise SystemExit(f"runs-root does not exist: {runs_root}")
        registry = AccessRegistry(args.registry)
        try:
            document = diagnose_run(registry, runs_root, args.run_id)
        except ValueError as error:
            raise SystemExit(str(error)) from error
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0

    if args.command in {"issue", "confirm-reboot"}:
        runs_root = args.runs_root.resolve()
        if not runs_root.is_dir():
            raise SystemExit(f"runs-root does not exist: {runs_root}")
        registry = AccessRegistry(args.registry)
        registry.reconcile_devices(runs_root)
        if args.command == "issue":
            code, expires = registry.issue_code(
                device_id=args.device_id,
                expected_client=args.expected_client,
                ttl_minutes=args.ttl_minutes,
            )
            print(
                json.dumps(
                    {
                        "accessCode": code,
                        "deviceId": args.device_id,
                        "expectedClient": args.expected_client,
                        "expiresAt": expires,
                        "storedPlaintext": False,
                    },
                    separators=(",", ":"),
                )
            )
            return 0
        next_client = registry.confirm_reboot(
            runs_root=runs_root,
            device_id=args.device_id,
            after_run=args.after_run,
            expected_client=args.expected_client,
        )
        print(
            json.dumps(
                {
                    "deviceId": args.device_id,
                    "confirmedAfterRun": args.after_run,
                    "expectedClient": next_client,
                    "rebootRequired": False,
                },
                separators=(",", ":"),
            )
        )
        return 0

    release = validate_release(args.root, args.hen, args.hen_sha256)
    registry_path, runs_root = ensure_state_paths(release.root, args.registry, args.runs_root)
    registry = AccessRegistry(registry_path)
    coordinator = RunCoordinator(
        registry=registry,
        runs_root=runs_root,
        static_root=release.root,
        hen_path=release.hen_path,
        host=args.host,
        public_host=args.public_host,
        child_port=args.child_port,
        startup_timeout=args.startup_timeout,
        run_timeout=args.run_timeout,
    )
    authority = args.public_host if args.port == 80 else f"{args.public_host}:{args.port}"
    server: AccessServer | None = None
    try:
        server = AccessServer(
            (args.host, args.port),
            coordinator=coordinator,
            template=release.template,
            authority=authority,
            client_network=args.client_network,
        )
        coordinator._event(
            "GATEWAY-READY",
            authority=authority,
            client_cidr=str(args.client_network),
        )
    except Exception:
        coordinator.begin_shutdown()
        try:
            if server is not None:
                server.server_close()
        finally:
            coordinator.shutdown()
        raise
    print(
        f"CHECK PASS access={ACCESS_TEMPLATE_SHA256} childGraph={release.static_graph} "
        f"hen={release.hen_meta['sha256']} registry={registry.path}"
    )
    print(
        f"READY http://{authority}/ child=http://{args.public_host}:{args.child_port}/ "
        f"clientCidr={args.client_network}",
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        coordinator.begin_shutdown()
        try:
            server.server_close()
        finally:
            coordinator.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
