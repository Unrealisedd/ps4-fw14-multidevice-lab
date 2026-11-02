from __future__ import annotations

import ctypes
import hashlib
import http.client
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import closing
from datetime import timedelta
from ipaddress import ip_network
from pathlib import Path
from unittest import mock

import serve_fw14_hx1400_access as access
import serve_fw14_hx1400_goldhen_dualmap as child
import serve_fw14_kdump as common


CLIENT = "192.168.1.106"
OTHER_CLIENT = "192.168.1.107"
RUN_ID = "1" * 32


class RegistryCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.runs_root = self.base / "runs-root"
        self.runs_root.mkdir()
        self.registry_path = self.base / "access.sqlite3"
        self.registry = access.AccessRegistry(self.registry_path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def issue(self, *, device: str = "lab-ps4-01", client: str = CLIENT, ttl: int = 30) -> str:
        code, _expires = self.registry.issue_code(
            device_id=device,
            expected_client=client,
            ttl_minutes=ttl,
        )
        return code

    def provision(self, *, device: str = "lab-ps4-01", client: str = CLIENT) -> tuple[str, dict[str, str]]:
        code = self.issue(device=device, client=client)
        return code, self.registry.redeem_code(code, client)

    def create_blocked_tombstone(self, device: str, run_id: str = RUN_ID) -> Path:
        path = access.tombstone_path(self.runs_root, device)
        path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "schema": child.BOOT_TOMBSTONE_SCHEMA,
            "blocked": True,
            "run_id": run_id,
            "client": CLIENT,
            "claimed_at": access.timestamp(),
            "reset_at": None,
            "confirm_cold_reboot_after": None,
            "reboot_required": True,
            "launch_dispatched": None,
            "runtime_observed": False,
        }
        common.durable_create(
            path,
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        return path


class CodeTests(unittest.TestCase):
    def test_generated_codes_have_eighty_bits_of_shape_and_round_trip(self) -> None:
        codes = {access.generate_code() for _ in range(128)}
        self.assertEqual(len(codes), 128)
        for code in codes:
            self.assertEqual(len(code), access.CODE_SYMBOLS)
            self.assertTrue(set(code) <= set(access.CODE_ALPHABET))
            self.assertEqual(access.normalize_code(access.format_code(code).lower()), code)

    def test_normalization_accepts_crockford_ambiguity_but_rejects_bad_shape(self) -> None:
        self.assertEqual(access.normalize_code("0000-1111-ABCD-EFGH"), "00001111ABCDEFGH")
        self.assertEqual(access.normalize_code("OOOO-ILLI-ABCD-EFGH"), "00001111ABCDEFGH")
        for value in ("", "AAAA", "AAAA-AAAA-AAAA-AAAA-X", "AAAA-AAAA-AAAA-AAAU", "💥" * 16):
            with self.subTest(value=value), self.assertRaises(ValueError):
                access.normalize_code(value)

    def test_hash_is_domain_separated_and_plaintext_independent(self) -> None:
        normalized = "0123456789ABCDEF"
        digest = access.hash_code(normalized)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertNotEqual(digest, __import__("hashlib").sha256(normalized.encode()).hexdigest())

    def test_diagnostic_error_detail_redacts_code_addresses_and_long_tokens(self) -> None:
        detail = access.safe_error_detail(
            RuntimeError(
                "code=0123-4567-89AB-CDEF ptr=0xffff800012345678 "
                "intent=" + ("a" * 64)
            )
        )
        self.assertNotIn("0123-4567-89AB-CDEF", detail)
        self.assertNotIn("ffff800012345678", detail)
        self.assertNotIn("a" * 64, detail)
        self.assertIn("<redacted-code>", detail)
        self.assertIn("<redacted-hex>", detail)


class RegistryTests(RegistryCase):
    def test_issue_stores_hash_only_and_status_never_returns_plaintext(self) -> None:
        code = self.issue()
        normalized = access.normalize_code(code)
        status = self.registry.status()
        self.assertNotIn("code_hint", status["codes"][0])
        self.assertNotIn("accessCode", json.dumps(status))
        with closing(sqlite3.connect(self.registry_path)) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(access_codes)")}
        self.assertNotIn("code_hint", columns)
        for path in self.base.glob("access.sqlite3*"):
            if path.is_file():
                self.assertNotIn(normalized.encode("ascii"), path.read_bytes())

    def test_wrong_client_does_not_consume_code_and_right_client_redeems_once(self) -> None:
        code = self.issue()
        with self.assertRaises(access.AccessError) as caught:
            self.registry.redeem_code(code, OTHER_CLIENT)
        self.assertEqual(caught.exception.code, "code-unavailable")
        self.assertEqual(self.registry.status()["codes"][0]["status"], "issued")
        provision = self.registry.redeem_code(code, CLIENT)
        self.assertEqual(provision["client_ip"], CLIENT)
        with self.assertRaises(access.AccessError):
            self.registry.redeem_code(code, CLIENT)
        self.assertEqual(self.registry.status()["codes"][0]["status"], "provisioning")

    def test_expired_code_is_consumed_as_expired(self) -> None:
        code = self.issue()
        with closing(sqlite3.connect(self.registry_path)) as connection:
            connection.execute(
                "UPDATE access_codes SET expires_at = ?",
                (access.timestamp(access.utc_now() - timedelta(seconds=1)),),
            )
            connection.commit()
        with self.assertRaises(access.AccessError):
            self.registry.redeem_code(code, CLIENT)
        self.assertEqual(self.registry.status()["codes"][0]["status"], "expired")

    def test_concurrent_redemption_has_exactly_one_winner(self) -> None:
        code = self.issue()
        barrier = threading.Barrier(3)
        outcomes: list[str] = []
        lock = threading.Lock()

        def redeem() -> None:
            barrier.wait()
            try:
                self.registry.redeem_code(code, CLIENT)
                outcome = "won"
            except access.AccessError:
                outcome = "lost"
            with lock:
                outcomes.append(outcome)

        threads = [threading.Thread(target=redeem) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["lost", "won"])
        self.assertEqual(len(self.registry.status()["runs"]), 1)

    def test_device_lock_blocks_issuance_until_exact_tombstone_reset(self) -> None:
        _code, provision = self.provision()
        run_dir = self.runs_root / "run"
        self.registry.mark_armed(
            redemption_id=provision["redemption_id"],
            run_id=RUN_ID,
            run_dir=run_dir,
            ready_url="http://192.168.1.83:8080/run",
        )
        self.registry.mark_claimed(
            device_id=provision["device_id"],
            run_id=RUN_ID,
            redemption_id=provision["redemption_id"],
        )
        tombstone = self.create_blocked_tombstone(provision["device_id"])
        with self.assertRaisesRegex(ValueError, "confirmed cold reboot"):
            self.issue()
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.registry.confirm_reboot(
                runs_root=self.runs_root,
                device_id=provision["device_id"],
                after_run="2" * 32,
                expected_client=None,
            )
        next_client = self.registry.confirm_reboot(
            runs_root=self.runs_root,
            device_id=provision["device_id"],
            after_run=RUN_ID,
            expected_client=OTHER_CLIENT,
        )
        self.assertEqual(next_client, OTHER_CLIENT)
        reset = child.load_boot_tombstone(tombstone)
        self.assertFalse(reset["blocked"])
        self.assertEqual(reset["confirm_cold_reboot_after"], RUN_ID)
        code, _ = self.registry.issue_code(
            device_id=provision["device_id"],
            expected_client=OTHER_CLIENT,
            ttl_minutes=30,
        )
        self.assertRegex(code, r"^[0-9A-Z]{4}(?:-[0-9A-Z]{4}){3}$")

    def test_reconcile_restores_fail_closed_device_lock(self) -> None:
        self.issue()
        self.create_blocked_tombstone("lab-ps4-01")
        self.registry.reconcile_devices(self.runs_root)
        device = self.registry.status()["devices"][0]
        self.assertEqual(device["reboot_required"], 1)
        self.assertEqual(device["last_run_id"], RUN_ID)

    def test_client_address_has_one_canonical_device_identity(self) -> None:
        self.issue(device="lab-ps4-01", client=CLIENT)
        with self.assertRaisesRegex(ValueError, "different device ID"):
            self.issue(device="mistyped-alias", client=CLIENT)
        devices = self.registry.status()["devices"]
        self.assertEqual([device["device_id"] for device in devices], ["lab-ps4-01"])

    def test_reboot_confirmation_cannot_move_binding_onto_another_device(self) -> None:
        code = self.issue(device="lab-ps4-01", client=CLIENT)
        provision = self.registry.redeem_code(code, CLIENT)
        self.issue(device="lab-ps4-02", client=OTHER_CLIENT)
        self.registry.mark_armed(
            redemption_id=provision["redemption_id"],
            run_id=RUN_ID,
            run_dir=self.runs_root / "run",
            ready_url="http://192.168.1.83:8080/run",
        )
        self.registry.mark_claimed(
            device_id=provision["device_id"],
            run_id=RUN_ID,
            redemption_id=provision["redemption_id"],
        )
        tombstone = self.create_blocked_tombstone(provision["device_id"])
        with self.assertRaisesRegex(ValueError, "different device ID"):
            self.registry.confirm_reboot(
                runs_root=self.runs_root,
                device_id=provision["device_id"],
                after_run=RUN_ID,
                expected_client=OTHER_CLIENT,
            )
        self.assertTrue(child.load_boot_tombstone(tombstone)["blocked"])

    def make_legacy_registry(self, path: Path, normalized: str) -> None:
        with closing(sqlite3.connect(path)) as connection:
            connection.executescript(
                """
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE devices (
                    device_id TEXT PRIMARY KEY,
                    expected_client TEXT NOT NULL,
                    last_run_id TEXT,
                    reboot_required INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE access_codes (
                    code_hash TEXT PRIMARY KEY,
                    code_hint TEXT NOT NULL,
                    device_id TEXT NOT NULL REFERENCES devices(device_id),
                    expected_client TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    redeemed_at TEXT,
                    redeemed_client TEXT,
                    redemption_id TEXT UNIQUE,
                    run_id TEXT UNIQUE
                );
                CREATE TABLE runs (
                    redemption_id TEXT PRIMARY KEY,
                    code_hash TEXT NOT NULL UNIQUE REFERENCES access_codes(code_hash),
                    device_id TEXT NOT NULL REFERENCES devices(device_id),
                    client_ip TEXT NOT NULL,
                    status TEXT NOT NULL,
                    run_id TEXT UNIQUE,
                    run_dir TEXT UNIQUE,
                    ready_url TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    result_code TEXT
                );
                """
            )
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES('schema', ?)",
                (access.LEGACY_REGISTRY_SCHEMA,),
            )
            connection.execute(
                "INSERT INTO devices(device_id, expected_client, updated_at) VALUES(?, ?, ?)",
                ("legacy-device", CLIENT, access.timestamp()),
            )
            connection.execute(
                "INSERT INTO access_codes("
                "code_hash, code_hint, device_id, expected_client, issued_at, expires_at, status"
                ") VALUES(?, ?, ?, ?, ?, ?, 'issued')",
                (
                    access.hash_code(normalized),
                    normalized[-4:],
                    "legacy-device",
                    CLIENT,
                    access.timestamp(),
                    access.timestamp(access.utc_now() + timedelta(minutes=30)),
                ),
            )
            connection.commit()

    def assert_registry_sanitized(self, path: Path, suffix: str) -> None:
        with closing(sqlite3.connect(path)) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(access_codes)")}
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        self.assertNotIn("code_hint", columns)
        self.assertEqual(metadata["schema"], access.REGISTRY_SCHEMA)
        self.assertEqual(
            metadata[access.REGISTRY_CLEANUP_KEY],
            access.REGISTRY_CLEANUP_COMPLETE,
        )
        for candidate in path.parent.glob(f"{path.name}*"):
            if candidate.is_file():
                self.assertNotIn(suffix.encode("ascii"), candidate.read_bytes())

    def assert_registry_cleanup_pending(self, path: Path) -> None:
        with closing(sqlite3.connect(path)) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(access_codes)")}
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        self.assertNotIn("code_hint", columns)
        self.assertEqual(metadata["schema"], access.REGISTRY_CLEANUP_PENDING_SCHEMA)
        self.assertEqual(
            metadata[access.REGISTRY_CLEANUP_KEY],
            access.REGISTRY_CLEANUP_PENDING,
        )

    def test_v1_registry_migration_removes_plaintext_hint_column(self) -> None:
        legacy_path = self.base / "legacy.sqlite3"
        normalized = "0123456789ABCDEF"
        self.make_legacy_registry(legacy_path, normalized)
        migrated = access.AccessRegistry(legacy_path)
        self.assertEqual(migrated.status()["schema"], access.REGISTRY_SCHEMA)
        self.assert_registry_sanitized(legacy_path, normalized[-4:])

    def test_v1_migration_retries_after_vacuum_failure(self) -> None:
        legacy_path = self.base / "vacuum-failure.sqlite3"
        normalized = "0123456789ABCDEF"
        self.make_legacy_registry(legacy_path, normalized)
        with (
            mock.patch.object(
                access.AccessRegistry,
                "_vacuum_registry",
                side_effect=OSError("simulated vacuum failure"),
            ),
            self.assertRaisesRegex(OSError, "simulated vacuum failure"),
        ):
            access.AccessRegistry(legacy_path)
        self.assert_registry_cleanup_pending(legacy_path)
        access.AccessRegistry(legacy_path)
        self.assert_registry_sanitized(legacy_path, normalized[-4:])

    def test_v1_migration_retries_after_checkpoint_failure(self) -> None:
        legacy_path = self.base / "checkpoint-failure.sqlite3"
        normalized = "0123456789ABCDEF"
        self.make_legacy_registry(legacy_path, normalized)
        with (
            mock.patch.object(
                access.AccessRegistry,
                "_truncate_registry_wal",
                side_effect=RuntimeError("simulated checkpoint failure"),
            ),
            self.assertRaisesRegex(RuntimeError, "simulated checkpoint failure"),
        ):
            access.AccessRegistry(legacy_path)
        self.assert_registry_cleanup_pending(legacy_path)
        access.AccessRegistry(legacy_path)
        self.assert_registry_sanitized(legacy_path, normalized[-4:])

    def test_v2_registry_without_cleanup_marker_is_sanitized_before_use(self) -> None:
        markerless_path = self.base / "markerless.sqlite3"
        access.AccessRegistry(markerless_path)
        with closing(sqlite3.connect(markerless_path)) as connection:
            connection.execute(
                "DELETE FROM metadata WHERE key = ?",
                (access.REGISTRY_CLEANUP_KEY,),
            )
            connection.commit()
        access.AccessRegistry(markerless_path)
        with closing(sqlite3.connect(markerless_path)) as connection:
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        self.assertEqual(metadata["schema"], access.REGISTRY_SCHEMA)
        self.assertEqual(
            metadata[access.REGISTRY_CLEANUP_KEY],
            access.REGISTRY_CLEANUP_COMPLETE,
        )


class LimiterTests(unittest.TestCase):
    def test_failure_budget_is_bounded_per_client_and_globally(self) -> None:
        limiter = access.AttemptLimiter()
        for _ in range(access.MAX_FAILED_ATTEMPTS):
            self.assertTrue(limiter.allowed(CLIENT))
            limiter.record_failure(CLIENT)
        self.assertFalse(limiter.allowed(CLIENT))
        limiter.clear(CLIENT)
        self.assertTrue(limiter.allowed(CLIENT))
        for index in range(access.MAX_LIMITER_CLIENTS + 5):
            limiter.record_failure(f"192.168.1.{index % 255}")
        self.assertLessEqual(len(limiter._failures), access.MAX_LIMITER_CLIENTS)


class TemplateTests(unittest.TestCase):
    def test_checked_template_is_original_static_form_and_escapes_status(self) -> None:
        root = Path(__file__).resolve().parent
        template = access.load_access_template(root)
        self.assertEqual(template.count(access.ACCESS_PLACEHOLDER), 1)
        self.assertNotIn(b"sentrix", template.lower())
        rendered = access.render_access_page(template, '<script>alert("x")</script>')
        self.assertNotIn(b"<script>alert", rendered)
        self.assertIn(b"&lt;script&gt;", rendered)
        self.assertIn(b'action="/redeem"', rendered)
        self.assertNotIn(access.ACCESS_PLACEHOLDER, rendered)


class FakeCoordinator:
    def __init__(self, location: str) -> None:
        self.location = location
        self.calls: list[tuple[str, str]] = []

    def launch(self, supplied_code: str, client_ip: str) -> str:
        self.calls.append((supplied_code, client_ip))
        return self.location


class HandlerTests(unittest.TestCase):
    def setUp(self) -> None:
        template = access.load_access_template(Path(__file__).resolve().parent)
        self.coordinator = FakeCoordinator("http://127.0.0.1:8080/stage")
        self.server = access.AccessServer(
            ("127.0.0.1", 0),
            coordinator=self.coordinator,  # type: ignore[arg-type]
            template=template,
            authority="placeholder",
            client_network=ip_network("127.0.0.0/8"),
        )
        self.server.authority = f"127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, method: str, path: str, *, body: str | None = None, ua: str = common.CANONICAL_FW14_UA) -> http.client.HTTPResponse:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {"Host": self.server.authority, "User-Agent": ua}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(body.encode("ascii")))
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response.body = response.read()  # type: ignore[attr-defined]
        connection.close()
        return response

    def test_actual_root_and_redeem_surface(self) -> None:
        root = self.request("GET", "/")
        self.assertEqual(root.status, 200)
        self.assertIn(b"FW14 Device Gate", root.body)  # type: ignore[attr-defined]
        self.assertNotIn(access.ACCESS_PLACEHOLDER, root.body)  # type: ignore[attr-defined]
        self.assertEqual(root.getheader("Cache-Control"), "no-store, no-cache, must-revalidate")
        redeem = self.request("POST", "/redeem", body="access_code=ABCD-EFGH-JKMP-QRST")
        self.assertEqual(redeem.status, 303)
        self.assertEqual(redeem.getheader("Location"), self.coordinator.location)
        self.assertEqual(self.coordinator.calls, [("ABCD-EFGH-JKMP-QRST", "127.0.0.1")])

    def test_non_ps4_and_admin_shaped_routes_are_refused(self) -> None:
        wrong_ua = self.request("GET", "/", ua="desktop")
        self.assertEqual(wrong_ua.status, 403)
        self.assertEqual(self.request("GET", "/issue").status, 404)
        self.assertEqual(self.request("POST", "/issue", body="access_code=x").status, 404)


class FakeProcess:
    def __init__(self, output: str) -> None:
        self.stdout = io.StringIO(output)
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = -15

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class CoordinatorTests(RegistryCase):
    def tearDown(self) -> None:
        for coordinator in reversed(getattr(self, "coordinators", [])):
            coordinator.shutdown()
        super().tearDown()

    def make_coordinator(self) -> access.RunCoordinator:
        static_root = Path(__file__).resolve().parent
        hen = self.base / "hen.bin"
        hen.write_bytes(b"hen")
        coordinator = access.RunCoordinator(
            registry=self.registry,
            runs_root=self.runs_root,
            static_root=static_root,
            hen_path=hen,
            host="127.0.0.1",
            public_host="127.0.0.1",
            child_port=8080,
            startup_timeout=2.0,
            run_timeout=10.0,
        )
        if not hasattr(self, "coordinators"):
            self.coordinators: list[access.RunCoordinator] = []
        self.coordinators.append(coordinator)
        return coordinator

    def make_failure_result(self, run_id: str) -> dict[str, object]:
        value: dict[str, object] = {}
        for key in child.RESULT_KEYS:
            if key in child.BOOL_KEYS:
                value[key] = False
            elif key in child.UINT_KEYS:
                value[key] = 0
            elif key in child.NULLABLE_INT_KEYS:
                value[key] = None
            elif key in {"kvaSearchOutcome", "rotationError", "oracleCode", "leaseStatus"}:
                value[key] = None
            elif key == "armRecords":
                value[key] = []
            elif key in {
                "schema",
                "code",
                "runId",
                "oracleDiagnosticPhase",
                "oracleDiagnosticReason",
            }:
                value[key] = ""
            else:
                raise AssertionError(f"unhandled result key {key}")
        value.update({
            "schema": child.RESULT_SCHEMA,
            "code": "THREW",
            "runId": run_id,
            "maxArms": child.MAX_ARMS,
            "armRecords": [],
            "oracleDiagnosticPhase": "not-started",
            "oracleDiagnosticReason": "none",
            "aioCleanupVerified": True,
            "rebootRequired": True,
        })
        return value

    def make_watched_run(
        self,
        state: dict[str, object],
        result: bytes | None = None,
    ) -> tuple[access.RunCoordinator, access.ActiveRun, FakeProcess]:
        coordinator = self.make_coordinator()
        coordinator.terminal_settle_seconds = 0.0
        _code, provision = self.provision()
        run_dir = self.runs_root / "runs" / provision["redemption_id"]
        run_dir.mkdir(parents=True)
        common.durable_create(run_dir / "state.json", common.json_bytes(state))
        result_path = run_dir / "result.json"
        if result is not None:
            common.durable_create(result_path, result)
        process = FakeProcess("")
        log_thread = mock.Mock()
        active = access.ActiveRun(
            redemption_id=provision["redemption_id"],
            device_id=provision["device_id"],
            client_ip=provision["client_ip"],
            run_id=RUN_ID,
            run_dir=run_dir,
            tombstone=access.tombstone_path(self.runs_root, provision["device_id"]),
            result=result_path,
            process=process,  # type: ignore[arg-type]
            log_thread=log_thread,
        )
        self.registry.mark_armed(
            redemption_id=provision["redemption_id"],
            run_id=RUN_ID,
            run_dir=run_dir,
            ready_url="http://127.0.0.1:8080/stage",
        )
        coordinator.active = active
        return coordinator, active, process

    def test_spawn_accepts_only_exact_child_ready_binding(self) -> None:
        coordinator = self.make_coordinator()
        provision = {
            "redemption_id": "a" * 32,
            "device_id": "lab-ps4-01",
            "client_ip": "127.0.0.1",
        }
        run_dir = self.runs_root / "spawn"
        run_dir.mkdir()
        tombstone = access.tombstone_path(self.runs_root, provision["device_id"])
        tombstone.parent.mkdir(parents=True)
        intent = "b" * 64
        ready = (
            "CHECK PASS files=12\n"
            "READY http://127.0.0.1:8080/fw14_hx1400_goldhen_dualmap.html"
            f"?stage={child.STAGE_NAME}&retry=0&slots={child.STABLE_SLOTS}&g={child.STABLE_G}&intent={intent} "
            f"run={RUN_ID} client=127.0.0.1 host=127.0.0.1:8080\n"
        )
        fake = FakeProcess(ready)
        with mock.patch.object(access.subprocess, "Popen", return_value=fake) as popen:
            active, url = coordinator._spawn(provision, run_dir, tombstone)
        self.assertEqual(active.run_id, RUN_ID)
        self.assertTrue(url.endswith(intent))
        command = popen.call_args.args[0]
        self.assertIn("--expected-client", command)
        self.assertIn("127.0.0.1", command)
        self.assertIn("--boot-tombstone", command)
        coordinator._terminate(fake)  # type: ignore[arg-type]

    def test_watcher_finalizes_aborted_child_without_waiting_for_exit(self) -> None:
        coordinator, active, process = self.make_watched_run({
            "schema": child.STATE_SCHEMA,
            "run_id": RUN_ID,
            "phase": "aborted",
            "code": "browser-stage-failed",
            "detail": "browser stage ended without a committed result",
        })
        coordinator._watch(active)
        run = self.registry.status()["runs"][0]
        self.assertEqual(run["status"], "aborted")
        self.assertEqual(run["result_code"], "browser-stage-failed")
        self.assertIsNotNone(process.returncode)

    def test_watcher_never_accepts_result_from_uncertain_commit(self) -> None:
        result = common.json_bytes(self.make_failure_result(RUN_ID))
        coordinator, active, _process = self.make_watched_run(
            {
                "schema": child.STATE_SCHEMA,
                "run_id": RUN_ID,
                "phase": "commit-uncertain",
                "commit_step": "final-state",
                "result_sha256": hashlib.sha256(result).hexdigest(),
                "detail": "durable commit outcome is unknown",
            },
            result,
        )
        coordinator._watch(active)
        run = self.registry.status()["runs"][0]
        self.assertEqual(run["status"], "commit-uncertain")
        self.assertEqual(run["result_code"], "COMMIT_UNCERTAIN")

    def test_watcher_rejects_completed_state_with_wrong_result_digest(self) -> None:
        result = common.json_bytes(self.make_failure_result(RUN_ID))
        coordinator, active, _process = self.make_watched_run(
            {
                "schema": child.STATE_SCHEMA,
                "run_id": RUN_ID,
                "phase": "completed",
                "result_sha256": "0" * 64,
                "ok": False,
                "code": "THREW",
            },
            result,
        )
        coordinator._watch(active)
        run = self.registry.status()["runs"][0]
        self.assertEqual(run["status"], "evidence-invalid")
        self.assertEqual(run["result_code"], "ValueError")

    def test_watcher_accepts_only_matching_completed_result(self) -> None:
        result = common.json_bytes(self.make_failure_result(RUN_ID))
        coordinator, active, _process = self.make_watched_run(
            {
                "schema": child.STATE_SCHEMA,
                "run_id": RUN_ID,
                "phase": "completed",
                "result_sha256": hashlib.sha256(result).hexdigest(),
                "ok": False,
                "code": "THREW",
            },
            result,
        )
        coordinator._watch(active)
        run = self.registry.status()["runs"][0]
        self.assertEqual(run["status"], "committed-failure")
        self.assertEqual(run["result_code"], "THREW")

    def test_watcher_allows_terminal_event_to_flush_before_child_stop(self) -> None:
        result = common.json_bytes(self.make_failure_result(RUN_ID))
        coordinator, active, process = self.make_watched_run(
            {
                "schema": child.STATE_SCHEMA,
                "run_id": RUN_ID,
                "phase": "completed",
                "result_sha256": hashlib.sha256(result).hexdigest(),
                "ok": False,
                "code": "THREW",
            },
            result,
        )
        coordinator.terminal_settle_seconds = 0.2
        observed_terminal = threading.Event()
        original = access.child_terminal_state

        def observe_terminal(*args: object, **kwargs: object) -> object:
            terminal = original(*args, **kwargs)  # type: ignore[arg-type]
            if terminal is not None:
                observed_terminal.set()
            return terminal

        with mock.patch.object(access, "child_terminal_state", side_effect=observe_terminal):
            watcher = threading.Thread(target=coordinator._watch, args=(active,))
            watcher.start()
            self.assertTrue(observed_terminal.wait(timeout=1.0))
            self.assertFalse(active.finalized)
            common.durable_create(
                active.run_dir / "events.jsonl",
                b'{"tag":"RESULT-COMMITTED"}\n',
            )
            watcher.join(timeout=2.0)
        self.assertFalse(watcher.is_alive())
        self.assertTrue(active.finalized)
        self.assertIsNotNone(process.returncode)
        self.assertIn(
            b"RESULT-COMMITTED",
            (active.run_dir / "events.jsonl").read_bytes(),
        )

    def test_provision_failure_consumes_code_without_device_reboot_lock(self) -> None:
        code = self.issue(device="loopback", client="127.0.0.1")
        coordinator = self.make_coordinator()
        with mock.patch.object(coordinator, "_spawn", side_effect=RuntimeError("no child")):
            with self.assertRaises(access.AccessError) as caught:
                coordinator.launch(code, "127.0.0.1")
        self.assertEqual(caught.exception.code, "provision-failed")
        status = self.registry.status()
        self.assertEqual(status["codes"][0]["status"], "failed")
        self.assertEqual(status["runs"][0]["status"], "provision-failed")
        self.assertEqual(status["devices"][0]["reboot_required"], 0)
        run = status["runs"][0]
        diagnostic_path = Path(run["run_dir"] or self.runs_root / "runs" / run["redemption_id"]) / access.DIAGNOSTIC_NAME
        diagnostic = json.loads(diagnostic_path.read_text(encoding="utf-8"))
        self.assertEqual(diagnostic["failureBoundary"], "gateway:provision-failed")
        self.assertFalse(diagnostic["secretsIncluded"])
        gateway_log = (self.runs_root / access.GATEWAY_EVENTS_NAME).read_text(encoding="utf-8")
        self.assertIn("CHILD-PROVISION-FAILED", gateway_log)
        self.assertNotIn(code, gateway_log)
        self.assertNotIn(access.normalize_code(code), gateway_log)

    def test_post_spawn_registry_failure_terminates_child_and_joins_log(self) -> None:
        code = self.issue(device="loopback", client="127.0.0.1")
        coordinator = self.make_coordinator()
        created: dict[str, object] = {}

        def spawn(
            provision: dict[str, str],
            run_dir: Path,
            tombstone: Path,
        ) -> tuple[access.ActiveRun, str]:
            process = FakeProcess("")
            log_thread = mock.Mock()
            active = access.ActiveRun(
                redemption_id=provision["redemption_id"],
                device_id=provision["device_id"],
                client_ip=provision["client_ip"],
                run_id=RUN_ID,
                run_dir=run_dir,
                tombstone=tombstone,
                result=run_dir / "result.json",
                process=process,  # type: ignore[arg-type]
                log_thread=log_thread,
            )
            created.update(process=process, log_thread=log_thread)
            return active, "http://127.0.0.1:8080/stage"

        with (
            mock.patch.object(coordinator, "_spawn", side_effect=spawn),
            mock.patch.object(self.registry, "mark_armed", side_effect=sqlite3.OperationalError("disk")),
            self.assertRaises(access.AccessError),
        ):
            coordinator.launch(code, "127.0.0.1")
        process = created["process"]
        self.assertIsNotNone(process.poll())  # type: ignore[union-attr]
        created["log_thread"].join.assert_called_once_with(timeout=2.0)  # type: ignore[union-attr]
        self.assertEqual(self.registry.status()["runs"][0]["status"], "provision-failed")

    def test_child_ready_log_failure_does_not_orphan_armed_child(self) -> None:
        code = self.issue(device="loopback", client="127.0.0.1")
        coordinator = self.make_coordinator()
        process = FakeProcess("")
        log_thread = mock.Mock()

        def spawn(
            provision: dict[str, str],
            run_dir: Path,
            tombstone: Path,
        ) -> tuple[access.ActiveRun, str]:
            return (
                access.ActiveRun(
                    redemption_id=provision["redemption_id"],
                    device_id=provision["device_id"],
                    client_ip=provision["client_ip"],
                    run_id=RUN_ID,
                    run_dir=run_dir,
                    tombstone=tombstone,
                    result=run_dir / "result.json",
                    process=process,  # type: ignore[arg-type]
                    log_thread=log_thread,
                ),
                "http://127.0.0.1:8080/stage",
            )

        original_event = coordinator._event

        def event(tag: str, **fields: object) -> None:
            if tag == "CHILD-READY":
                raise OSError("simulated log failure")
            original_event(tag, **fields)

        with (
            mock.patch.object(coordinator, "_spawn", side_effect=spawn),
            mock.patch.object(coordinator, "_event", side_effect=event),
            mock.patch("sys.stderr", new=io.StringIO()),
        ):
            ready = coordinator.launch(code, "127.0.0.1")
            self.assertEqual(ready, "http://127.0.0.1:8080/stage")
            self.assertIs(coordinator.active.process, process)  # type: ignore[union-attr]
            coordinator.shutdown()
        self.assertIsNotNone(process.poll())
        log_thread.join.assert_called()

    def test_runs_root_has_one_live_gateway_owner(self) -> None:
        first = self.make_coordinator()
        with self.assertRaisesRegex(RuntimeError, "another gateway process"):
            access.RunCoordinator(
                registry=self.registry,
                runs_root=self.runs_root,
                static_root=Path(__file__).resolve().parent,
                hen_path=self.base / "hen.bin",
                host="127.0.0.1",
                public_host="127.0.0.1",
                child_port=8080,
                startup_timeout=2.0,
                run_timeout=10.0,
            )
        first.shutdown()
        second = self.make_coordinator()
        self.assertIsNotNone(second.lease.handle)

    def test_shutdown_gate_rejects_paused_request_before_code_redemption(self) -> None:
        code = self.issue(device="loopback", client="127.0.0.1")
        coordinator = self.make_coordinator()
        accepted = threading.Event()
        resume = threading.Event()
        outcomes: list[str] = []

        def delayed_launch() -> None:
            accepted.set()
            resume.wait(timeout=2.0)
            try:
                coordinator.launch(code, "127.0.0.1")
            except access.AccessError as error:
                outcomes.append(error.code)

        with mock.patch.object(coordinator, "_spawn") as spawn:
            request = threading.Thread(target=delayed_launch)
            request.start()
            self.assertTrue(accepted.wait(timeout=1.0))
            coordinator.begin_shutdown()
            self.assertIsNotNone(coordinator.lease.handle)
            resume.set()
            request.join(timeout=2.0)
        self.assertFalse(request.is_alive())
        self.assertEqual(outcomes, ["gateway-stopping"])
        spawn.assert_not_called()
        status = self.registry.status()
        self.assertEqual(status["codes"][0]["status"], "issued")
        self.assertEqual(status["runs"], [])
        coordinator.shutdown()
        self.assertIsNone(coordinator.lease.handle)

    def test_startup_recovers_interrupted_run_with_diagnostic_boundary(self) -> None:
        code = self.issue(device="loopback", client="127.0.0.1")
        provision = self.registry.redeem_code(code, "127.0.0.1")
        run_dir = self.runs_root / "runs" / provision["redemption_id"]
        run_dir.mkdir(parents=True)
        (run_dir / "state.json").write_text(
            json.dumps({"run_id": RUN_ID, "phase": "armed"}),
            encoding="utf-8",
        )
        self.registry.mark_armed(
            redemption_id=provision["redemption_id"],
            run_id=RUN_ID,
            run_dir=run_dir,
            ready_url="http://127.0.0.1:8080/stage",
        )
        coordinator = self.make_coordinator()
        self.assertIsNone(coordinator.active)
        recovered = self.registry.status()["runs"][0]
        self.assertEqual(recovered["status"], "gateway-recovered")
        self.assertEqual(recovered["result_code"], "GATEWAY_RESTARTED")
        diagnostic = json.loads(
            (run_dir / access.DIAGNOSTIC_NAME).read_text(encoding="utf-8")
        )
        self.assertEqual(diagnostic["gateway"]["status"], "gateway-recovered")
        self.assertEqual(diagnostic["failureBoundary"], "server:armed")
        gateway_log = (self.runs_root / access.GATEWAY_EVENTS_NAME).read_text(encoding="utf-8")
        self.assertIn("RUN-RECOVERED", gateway_log)



class DiagnosticTests(RegistryCase):
    def test_diagnose_reports_last_browser_phase_and_artifact_hashes(self) -> None:
        code, provision = self.provision()
        del code
        run_dir = self.runs_root / "runs" / provision["redemption_id"]
        run_dir.mkdir(parents=True)
        self.registry.mark_armed(
            redemption_id=provision["redemption_id"],
            run_id=RUN_ID,
            run_dir=run_dir,
            ready_url="http://127.0.0.1:8080/stage",
        )
        self.registry.mark_terminal(
            redemption_id=provision["redemption_id"],
            status="timed-out",
            result_code="RUN_TIMEOUT",
        )
        (run_dir / "state.json").write_text(
            json.dumps({"run_id": RUN_ID, "phase": "claimed"}),
            encoding="utf-8",
        )
        (run_dir / "events.jsonl").write_text(
            json.dumps(
                {
                    "timestamp": access.timestamp(),
                    "tag": "BROWSER-TELEMETRY",
                    "browser_tag": "HX-KVA-SEARCH",
                    "phase": "claimed",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        document = access.diagnose_run(self.registry, self.runs_root, RUN_ID)
        self.assertEqual(document["failureBoundary"], "browser:HX-KVA-SEARCH")
        self.assertEqual(document["events"]["lastBrowser"]["browser_tag"], "HX-KVA-SEARCH")
        self.assertRegex(document["artifacts"]["events"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(document["secretsIncluded"])

    def test_diagnostics_survive_truncated_state_and_event_files(self) -> None:
        run_dir = self.runs_root / "runs" / ("a" * 32)
        run_dir.mkdir(parents=True)
        (run_dir / "state.json").write_text("{", encoding="utf-8")
        (run_dir / "events.jsonl").write_bytes(b"{\n\xff")
        document = access.summarize_run_artifacts(
            run_dir,
            {"status": "child-exited", "resultCode": "CHILD_EXIT_1"},
        )
        self.assertIn("stateParse", document["errors"])
        self.assertIn("eventsRead", document["errors"])
        self.assertEqual(document["failureBoundary"], "gateway:child-exited")


class ChildGuardTests(unittest.TestCase):
    @staticmethod
    def process_is_alive(process_id: int) -> bool:
        if os.name != "nt":
            try:
                os.kill(process_id, 0)
            except ProcessLookupError:
                return False
            return True
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(0x1000, False, process_id)
        if not handle:
            return False
        try:
            exit_code = ctypes.c_uint32()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return exit_code.value == 259
        finally:
            kernel32.CloseHandle(handle)

    @staticmethod
    def terminate_process_id(process_id: int) -> None:
        if os.name != "nt":
            try:
                os.kill(process_id, 9)
            except ProcessLookupError:
                pass
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(0x0001, False, process_id)
        if handle:
            try:
                kernel32.TerminateProcess(handle, 1)
            finally:
                kernel32.CloseHandle(handle)

    def test_parent_pipe_eof_terminates_guarded_child(self) -> None:
        script = Path(access.__file__).resolve()
        child_code = "import os,time;print(os.getpid(),flush=True);time.sleep(30)"
        guard = subprocess.Popen(
            [
                sys.executable,
                "-B",
                str(script),
                "_child-guard",
                "--",
                sys.executable,
                "-u",
                "-c",
                child_code,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        process_id = 0
        try:
            assert guard.stdout is not None
            process_id = int(guard.stdout.readline().strip())
            self.assertTrue(self.process_is_alive(process_id))
            assert guard.stdin is not None
            guard.stdin.close()
            self.assertEqual(guard.wait(timeout=5), 0)
            self.assertFalse(self.process_is_alive(process_id))
        finally:
            if guard.poll() is None:
                guard.kill()
                guard.wait(timeout=3)
            if process_id and self.process_is_alive(process_id):
                self.terminate_process_id(process_id)
            for stream in (guard.stdout, guard.stderr):
                if stream is not None:
                    stream.close()


class CliTests(unittest.TestCase):
    def test_nonloopback_serve_requires_explicit_isolated_network_flag(self) -> None:
        argv = [
            "serve", "--root", ".", "--hen", "hen.bin", "--hen-sha256", child.HEN_SHA256,
            "--host", "192.168.1.83", "--public-host", "192.168.1.83",
            "--client-cidr", "192.168.1.0/24", "--registry", "state/access.sqlite3",
            "--runs-root", "state/runs",
        ]
        with mock.patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit):
            access.parse_args(argv)
        parsed = access.parse_args(argv + ["--trusted-isolated-network"])
        self.assertEqual(str(parsed.client_network), "192.168.1.0/24")


if __name__ == "__main__":
    unittest.main()
