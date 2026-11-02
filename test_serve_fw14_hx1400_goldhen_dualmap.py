from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import serve_fw14_hx1400_goldhen_dualmap as target
import serve_fw14_kdump as common


class GoldhenDualmapServerTests(unittest.TestCase):
    def make_failure_result(self, run_id: str) -> dict[str, object]:
        value: dict[str, object] = {}
        for key in target.RESULT_KEYS:
            if key in target.BOOL_KEYS:
                value[key] = False
            elif key in target.UINT_KEYS:
                value[key] = 0
            elif key in target.NULLABLE_INT_KEYS:
                value[key] = None
            elif key in {"kvaSearchOutcome", "rotationError", "oracleCode", "leaseStatus"}:
                value[key] = None
            elif key == "armRecords":
                value[key] = []
            elif key in {
                "schema", "code", "runId", "oracleDiagnosticPhase",
                "oracleDiagnosticReason",
            }:
                value[key] = ""
            else:
                raise AssertionError(f"unhandled result key {key}")
        value.update({
            "schema": target.RESULT_SCHEMA,
            "code": "THREW",
            "runId": run_id,
            "maxArms": target.MAX_ARMS,
            "armRecords": [],
            "oracleDiagnosticPhase": "not-started",
            "oracleDiagnosticReason": "none",
            "aioCleanupVerified": True,
            "rebootRequired": True,
        })
        return value

    def make_paired_arm(self) -> dict[str, object]:
        return {
            "sequence": 1, "sprayCount": target.SPRAY_MAX, "round": 1,
            "candidateIndex": target.CANDIDATES[0], "candidateFd": 131,
            "dceFd": 16, "evAddRc": 0, "scanOk": target.SPRAY_MAX - 1,
            "scanErrors": 0, "nonStockOptions": 0, "matches": 1,
            "targetIndex": 0, "targetFd": 3, "evDeleteRc": 0,
            "candidateRestoreRc": 0, "repairFailures": 0,
            "dceCloseOk": None, "outcome": "paired",
        }

    def make_success_result(self, run_id: str = "run-1") -> dict[str, object]:
        value = self.make_failure_result(run_id)
        value.update({
            "ok": True,
            "code": target.SUCCESS_CODE,
            "kbaseValidated": True,
            "armsAttempted": 1,
            "armRecords": [self.make_paired_arm()],
            "pairEstablished": True,
            "pairRound": 1,
            "pairCandidateIndex": target.CANDIDATES[0],
            "pairCandidateFd": 131,
            "pairTargetIndex": 0,
            "pairTargetFd": 3,
            "kvaSearchOutcome": "accepted",
            "kvaSearchAttempts": 1,
            "kvaSearchFd": 4,
            "kvaSearchRc": 0,
            "kvaSearchRef": 2,
            "kvaSearchTreeAccepted": True,
            "rotationAttempted": True,
            "rotationRc": 0,
            "rotationExpectedOpsMatch": True,
            "rotationPredicateMask": 0x3FF,
            "kernelRwProved": True,
            "challengeWriteAttempted": True,
            "challengeWritten": True,
            "challengeRestored": True,
            "lowMapPolicyValidated": True,
            "lowMapMapped": True,
            "lowMapLeaseAcquired": True,
            "lowMapUnmapped": True,
            "lowMapLeaseRevoked": True,
            "oracleAttempted": True,
            "oracleCode": "OK_CURRENT_OWNER",
            "oracleCleanup": True,
            "oracleExecutions": 2,
            "oracleSignatureVerified": True,
            "oracleRopReadOnly": True,
            "oracleAuthorityConsumed": True,
            "oracleDiagnosticPhase": "oracle-complete",
            "oracleDiagnosticReason": "none",
            "oracleSignatureChecks": 4,
            "oracleRoundsStarted": 2,
            "oracleRoundsCompleted": 2,
            "currentObjectsAuthenticated": True,
            "handlerSemanticAttested": True,
            "mmapCapabilityRecheckAttested": True,
            "dwordGadgetAttested": True,
            "ownerRevalidated": True,
            "writerIsolationVerified": True,
            "leaseStatus": "OK",
            "leaseWrites": 4,
            "leaseCreateCalls": 1,
            "leaseMapCalls": 1,
            "leaseWriteArmConfirmed": True,
            "leaseWriteRestoreConfirmed": True,
            "leaseExecuteArmConfirmed": True,
            "leaseExecuteRestoreConfirmed": True,
            "leaseBorrowedBitsCleared": True,
            "leaseTerminalMatchesOriginal": True,
            "jitDescriptorCreated": True,
            "jitDescriptorReleased": True,
            "jitWritableMappingCreated": True,
            "jitExecutableMappingCreated": True,
            "jitMappingsCapabilityBound": True,
            "jitMappingsReleased": True,
            "wxPatchMappingVerified": True,
            "crossViewPatchVerified": True,
            "patchCopyVerified": True,
            "stockGuardsVerified": 24,
            "patchedGuardsVerified": 24,
            "patchExecutionAttempted": True,
            "bridgeCallbackRestored": True,
            "sysent11Restored": True,
            "exploitRetired": True,
            "henRwxMapCreated": True,
            "henCopyVerified": True,
            "bssTailVerified": True,
            "goldhenLaunchAttempted": True,
            "goldhenLaunchDispatched": True,
            "henMappingRetained": True,
            "aioCleanupVerified": True,
            "stageCleanupVerified": True,
            "hostCleanupVerified": True,
            "cleanupVerified": True,
            "rebootRequired": True,
        })
        return value

    def make_lease_failure(
        self,
        status: str,
        *,
        clean: bool,
        run_id: str = "run-1",
    ) -> dict[str, object]:
        value = self.make_success_result(run_id)
        value.update({
            "ok": False,
            "code": "JIT_LEASE_FAILED",
            "leaseStatus": status,
            "oracleDiagnosticPhase": "authority-consumed",
            "leaseWrites": 2 if status == "ERROR" and clean else 0,
            "leaseCreateCalls": 1 if status == "ERROR" and clean else 0,
            "leaseMapCalls": 0,
            "leaseWriteArmConfirmed": status == "ERROR" and clean,
            "leaseWriteRestoreConfirmed": status == "ERROR" and clean,
            "leaseExecuteArmConfirmed": False,
            "leaseExecuteRestoreConfirmed": False,
            "leaseBorrowedBitsCleared": status == "ERROR" and clean,
            "leaseTerminalMatchesOriginal": status == "ERROR" and clean,
            "jitDescriptorCreated": False,
            "jitDescriptorReleased": False,
            "jitWritableMappingCreated": False,
            "jitExecutableMappingCreated": False,
            "jitMappingsCapabilityBound": False,
            "jitMappingsReleased": False,
            "wxPatchMappingVerified": False,
            "crossViewPatchVerified": False,
            "patchCopyVerified": False,
            "patchedGuardsVerified": 0,
            "patchExecutionAttempted": False,
            "bridgeCallbackRestored": False,
            "sysent11Restored": False,
            "henRwxMapCreated": False,
            "henCopyVerified": False,
            "bssTailVerified": False,
            "henMappingRetained": False,
            "goldhenLaunchAttempted": False,
            "goldhenLaunchDispatched": False,
            "goldhenRuntimeObserved": False,
            "exploitRetired": clean,
            "quarantined": not clean,
            "stageCleanupVerified": clean,
            "hostCleanupVerified": clean,
            "cleanupVerified": clean,
            "rebootRequired": True,
        })
        return value

    def make_run(
        self,
        root: Path,
        tombstone: Path,
        suffix: str,
    ) -> target.GoldhenDualmapRun:
        events = root / f"events-{suffix}.jsonl"
        common.durable_create(events, b"")
        return target.GoldhenDualmapRun(
            state_path=root / f"state-{suffix}.json",
            result_path=root / f"result-{suffix}.json",
            boot_tombstone=tombstone,
            event_log=common.DurableEventLog(events),
            static_manifest="0" * 64,
            expected_client="127.0.0.1",
            expected_host="127.0.0.1:8080",
            hen_meta={
                "sha256": target.HEN_SHA256,
                "size": target.HEN_SIZE,
                "offset": 0x4000,
                "head": target.HEN_HEAD.hex(),
                "entry": target.HEN_ENTRY,
            },
        )

    def assert_rejected(self, result: dict[str, object], code: str | None = None) -> None:
        with self.assertRaises(common.ProtocolError) as caught:
            target.validate_result(copy.deepcopy(result), run_id=str(result["runId"]))
        if code is not None:
            self.assertEqual(caught.exception.code, code)

    def test_exact_route_identity_and_manifest_graph(self) -> None:
        self.assertEqual(target.STAGE_PAGE, "/fw14_hx1400_goldhen_dualmap.html")
        self.assertEqual(target.STAGE_NAME, "fw14-hx1400-goldhen-dualmap")
        self.assertEqual(target.STABLE_SLOTS, "9100000")
        self.assertEqual(target.STABLE_G, "drain:12")
        self.assertEqual(target.INTENT_HEADER, "X-Hx1400-Goldhen-Dualmap-Intent")
        self.assertEqual(target.CLAIM_SCHEMA, "oms.fw14-hx1400-goldhen-dualmap.claim.v1")
        self.assertEqual(target.RESULT_SCHEMA, "oms.fw14-hx1400-goldhen-dualmap.result.v1")
        self.assertEqual(target.STATE_SCHEMA, "oms.fw14-hx1400-goldhen-dualmap.state.v1")
        self.assertEqual(target.STATIC_SCHEMA, "oms.fw14-hx1400-goldhen-dualmap.static.v1")
        self.assertEqual(target.AUDIT_SCHEMA, "oms.fw14-hx1400-goldhen-dualmap.audit.v1")
        self.assertEqual(
            target.BOOT_TOMBSTONE_SCHEMA,
            "oms.fw14-hx1400-goldhen-dualmap.boot.v1",
        )
        self.assertEqual(target.SUCCESS_CODE, "OK_GOLDHEN_DUALMAP_LAUNCH_DISPATCHED_REBOOT_REQUIRED")
        payloads, hashes, digest = target.load_manifest(Path(__file__).resolve().parent)
        self.assertEqual(set(payloads), set(hashes))
        self.assertEqual(digest, target.EXPECTED_STATIC_GRAPH_SHA256)
        self.assertIn("/hx1400_jit_dualmap_lease.js", payloads)
        self.assertNotIn("/hx1400_jit_capability_lease.js", payloads)

    def test_browser_and_page_use_only_dualmap_endpoint_and_storage_identity(self) -> None:
        root = Path(__file__).resolve().parent
        client = (root / "jb_hx1400_goldhen_dualmap.js").read_text(encoding="utf-8")
        page = (root / "fw14_hx1400_goldhen_dualmap.html").read_text(encoding="utf-8")
        host = (root / "serve_fw14_hx1400_goldhen_dualmap.py").read_text(encoding="utf-8")
        for endpoint in ("claim", "hen", "result", "abort", "telemetry"):
            self.assertIn(f"/hx1400-goldhen-dualmap/{endpoint}", client)
        self.assertIn("X-Hx1400-Goldhen-Dualmap-Intent", client)
        self.assertIn("oms.fw14-hx1400-goldhen-dualmap.claim.v1", client)
        self.assertIn("oms.fw14-hx1400-goldhen-dualmap.result.v1", client)
        self.assertIn("fw14-hx1400-goldhen-dualmap", page)
        self.assertIn("hx1400-goldhen-dualmap-1", page)
        for source in (client, page):
            self.assertIn('params.get("slots") === "9100000"', source)
            self.assertIn('params.get("g") === "drain:12"', source)
        self.assertIn("&slots={STABLE_SLOTS}&g={STABLE_G}&intent=", host)
        for key in (
            "jb-fw14-hx1400-goldhen-dualmap-page-attempted",
            "jb-fw14-hx1400-goldhen-dualmap-arm-attempted",
            "jb-fw14-hx1400-goldhen-dualmap-click-token",
            "jb-fw14-hx1400-goldhen-dualmap-read-retry",
        ):
            self.assertIn(key, page + client)
        self.assertNotIn("/hx1400-goldhen/", client)
        self.assertNotIn("X-Hx1400-Goldhen-Intent", client)

    def test_complete_success_contract_is_accepted(self) -> None:
        result = self.make_success_result()
        self.assertEqual(target.validate_result(copy.deepcopy(result), run_id="run-1"), result)

    def test_success_rejects_every_incomplete_lease_component(self) -> None:
        mutations = {
            "leaseWrites": 3,
            "leaseCreateCalls": 0,
            "leaseMapCalls": 0,
            "leaseWriteArmConfirmed": False,
            "leaseWriteRestoreConfirmed": False,
            "leaseExecuteArmConfirmed": False,
            "leaseExecuteRestoreConfirmed": False,
            "leaseBorrowedBitsCleared": False,
            "leaseTerminalMatchesOriginal": False,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                result = self.make_success_result()
                result[field] = replacement
                self.assert_rejected(result, "lease-success-incomplete")

    def test_lease_requires_exact_completed_semantic_oracle_proof(self) -> None:
        mutations = {
            "oracleDiagnosticPhase": "authority-consumed",
            "oracleDiagnosticReason": "unknown",
            "oracleKernelMutated": True,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                result = self.make_success_result()
                result[field] = replacement
                self.assert_rejected(result)

    def test_patch_execution_rejects_missing_wx_alias_or_cross_view_proof(self) -> None:
        for field in (
            "jitWritableMappingCreated", "jitExecutableMappingCreated",
            "jitMappingsCapabilityBound", "wxPatchMappingVerified",
            "crossViewPatchVerified", "patchCopyVerified",
        ):
            with self.subTest(field=field):
                result = self.make_success_result()
                result[field] = False
                self.assert_rejected(result)

    def test_rwx_hen_mapping_is_rejected_before_every_patch_completion_boundary(self) -> None:
        cases = {
            "patchedGuardsVerified": 23,
            "sysent11Restored": False,
            "jitMappingsReleased": False,
            "jitDescriptorReleased": False,
            "exploitRetired": False,
        }
        for field, replacement in cases.items():
            with self.subTest(field=field):
                result = self.make_success_result()
                result[field] = replacement
                result["ok"] = False
                result["code"] = "HEN_MMAP"
                result["goldhenLaunchAttempted"] = False
                result["goldhenLaunchDispatched"] = False
                result["henMappingRetained"] = False
                result["stageCleanupVerified"] = False
                result["hostCleanupVerified"] = False
                result["cleanupVerified"] = False
                result["quarantined"] = True
                self.assert_rejected(result)

    def test_success_requires_released_patch_resources_and_only_hen_retained(self) -> None:
        for field in (
            "jitMappingsReleased", "jitDescriptorReleased",
            "aioCleanupVerified", "henMappingRetained",
        ):
            with self.subTest(field=field):
                result = self.make_success_result()
                result[field] = False
                self.assert_rejected(result)

    def test_failed_hen_copy_or_launch_cannot_be_presented_as_success(self) -> None:
        for field in ("henRwxMapCreated", "henCopyVerified", "bssTailVerified", "goldhenLaunchDispatched"):
            with self.subTest(field=field):
                result = self.make_success_result()
                result[field] = False
                if field == "goldhenLaunchDispatched":
                    result["henMappingRetained"] = False
                with self.assertRaises(common.ProtocolError):
                    target.validate_result(result, run_id="run-1")

    def test_browser_and_python_result_keys_have_exact_93_key_parity(self) -> None:
        client = (
            Path(__file__).resolve().parent / "jb_hx1400_goldhen_dualmap.js"
        ).read_text(encoding="utf-8")
        match = re.search(r"const resultKeys = \[(.*?)\n\s*\];", client, re.DOTALL)
        self.assertIsNotNone(match)
        browser_keys = re.findall(r'"([^"]+)"', match.group(1))
        self.assertEqual(len(browser_keys), 93)
        self.assertEqual(len(set(browser_keys)), 93)
        self.assertEqual(set(browser_keys), target.RESULT_KEYS)
        self.assertIn("hxResult.aioCleanupVerified", client)
        self.assertIn("goldhenConsumedSemanticProof", client)

    def test_refused_lease_requires_an_all_zero_activity_resource_tuple(self) -> None:
        refused = self.make_lease_failure("REFUSED", clean=True)
        self.assertEqual(
            target.validate_result(copy.deepcopy(refused), run_id="run-1"),
            refused,
        )
        refused["leaseWrites"] = 1
        self.assert_rejected(refused, "lease-refused-activity")

    def test_refused_and_error_require_consumed_semantic_owner_proof(self) -> None:
        for status in ("REFUSED", "ERROR"):
            with self.subTest(status=status):
                result = self.make_lease_failure(status, clean=True)
                result["oracleDiagnosticReason"] = "unknown"
                self.assert_rejected(result, "lease-attempt-order")

    def test_error_is_clean_only_with_exact_reached_restore_and_releases(self) -> None:
        clean = self.make_lease_failure("ERROR", clean=True)
        self.assertEqual(
            target.validate_result(copy.deepcopy(clean), run_id="run-1"),
            clean,
        )
        all_zero = self.make_lease_failure("REFUSED", clean=True)
        all_zero["leaseStatus"] = "ERROR"
        self.assert_rejected(all_zero, "lease-error-cleanup-underclaim")

        descriptor_only = self.make_lease_failure("ERROR", clean=True)
        descriptor_only.update({
            "leaseCreateCalls": 1,
            "jitDescriptorCreated": True,
            "jitDescriptorReleased": True,
        })
        self.assertEqual(
            target.validate_result(
                copy.deepcopy(descriptor_only),
                run_id="run-1",
            ),
            descriptor_only,
        )
        quarantined_descriptor_only = self.make_lease_failure(
            "QUARANTINED",
            clean=False,
        )
        quarantined_descriptor_only.update({
            "leaseWrites": 2,
            "leaseCreateCalls": 1,
            "leaseWriteArmConfirmed": True,
            "leaseWriteRestoreConfirmed": True,
            "leaseBorrowedBitsCleared": True,
            "leaseTerminalMatchesOriginal": True,
            "jitDescriptorCreated": True,
            "jitDescriptorReleased": True,
        })
        self.assertEqual(
            target.validate_result(
                copy.deepcopy(quarantined_descriptor_only),
                run_id="run-1",
            ),
            quarantined_descriptor_only,
        )
        client = (
            Path(__file__).resolve().parent / "jb_hx1400_goldhen_dualmap.js"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'hxResult.leaseStatus === "ERROR" &&\n'
            "        writeLeasePhaseReached &&",
            client,
        )
        clean_with_resources = self.make_lease_failure("ERROR", clean=True)
        clean_with_resources.update({
            "leaseCreateCalls": 1,
            "jitDescriptorCreated": True,
            "jitDescriptorReleased": True,
            "jitWritableMappingCreated": True,
            "jitMappingsReleased": True,
        })
        self.assertEqual(
            target.validate_result(copy.deepcopy(clean_with_resources), run_id="run-1"),
            clean_with_resources,
        )
        for field in (
            "leaseWriteRestoreConfirmed",
            "leaseBorrowedBitsCleared",
            "leaseTerminalMatchesOriginal",
            "jitDescriptorReleased",
            "jitMappingsReleased",
        ):
            with self.subTest(field=field):
                dirty = copy.deepcopy(clean_with_resources)
                dirty[field] = False
                self.assert_rejected(dirty)
        self.assertNotIn("FW14-HX1400-GOLDHEN-COMPLETE", client)
        self.assertNotIn("FW14-HX1400-GOLDHEN-STOP", client)

    def test_unproved_partial_activity_is_coherent_only_when_quarantined(self) -> None:
        dirty = self.make_lease_failure("ERROR", clean=False)
        dirty["leaseWrites"] = 1
        self.assertEqual(
            target.validate_result(copy.deepcopy(dirty), run_id="run-1"),
            dirty,
        )
        for field in (
            "quarantined",
            "stageCleanupVerified",
            "hostCleanupVerified",
            "cleanupVerified",
        ):
            with self.subTest(field=field):
                incoherent = copy.deepcopy(dirty)
                incoherent[field] = field != "quarantined"
                self.assert_rejected(incoherent)

    def test_stage_cleanup_releases_every_created_jit_resource_prepatch(self) -> None:
        result = self.make_lease_failure("ERROR", clean=True)
        result.update({
            "leaseCreateCalls": 1,
            "jitDescriptorCreated": True,
            "jitDescriptorReleased": True,
            "jitWritableMappingCreated": True,
            "jitMappingsReleased": True,
        })
        for field in ("jitDescriptorReleased", "jitMappingsReleased"):
            with self.subTest(field=field):
                incomplete = copy.deepcopy(result)
                incomplete[field] = False
                self.assert_rejected(incomplete)

    def test_hen_mapping_without_dispatch_is_quarantined_and_unverified(self) -> None:
        result = self.make_success_result()
        result.update({
            "ok": False,
            "code": "PTHREAD_CREATE",
            "goldhenLaunchAttempted": True,
            "goldhenLaunchDispatched": False,
            "henMappingRetained": False,
            "quarantined": True,
            "stageCleanupVerified": False,
            "hostCleanupVerified": False,
            "cleanupVerified": False,
        })
        self.assertEqual(
            target.validate_result(copy.deepcopy(result), run_id="run-1"),
            result,
        )
        for field in (
            "quarantined",
            "stageCleanupVerified",
            "hostCleanupVerified",
            "cleanupVerified",
        ):
            with self.subTest(field=field):
                incoherent = copy.deepcopy(result)
                incoherent[field] = field != "quarantined"
                self.assert_rejected(incoherent)

    def test_boot_tombstone_blocks_cross_run_until_exact_cold_reboot_reset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tombstone = root / "boot.json"
            first = self.make_run(root, tombstone, "first")
            first.claim("127.0.0.1")
            blocked = target.load_boot_tombstone(tombstone)
            self.assertTrue(blocked["blocked"])
            self.assertEqual(blocked["run_id"], first.run_id)
            self.assertTrue(blocked["reboot_required"])
            self.assertFalse(blocked["runtime_observed"])
            self.assertIsNone(blocked["launch_dispatched"])
            with self.assertRaises(ValueError):
                target.prepare_boot_tombstone(tombstone, None)
            with self.assertRaises(ValueError):
                target.prepare_boot_tombstone(tombstone, "wrong-run")
            reset = target.prepare_boot_tombstone(tombstone, first.run_id)
            self.assertFalse(reset["blocked"])
            self.assertEqual(reset["confirm_cold_reboot_after"], first.run_id)
            second = self.make_run(root, tombstone, "second")
            second.claim("127.0.0.1")
            blocked_again = target.load_boot_tombstone(tombstone)
            self.assertTrue(blocked_again["blocked"])
            self.assertEqual(blocked_again["run_id"], second.run_id)
            third = self.make_run(root, tombstone, "third")
            with self.assertRaises(common.ProtocolError) as caught:
                third.claim("127.0.0.1")
            self.assertEqual(caught.exception.code, "cold-reboot-required")
            for event_path in (
                root / "events-first.jsonl",
                root / "events-second.jsonl",
                root / "events-third.jsonl",
            ):
                events = [
                    json.loads(line)
                    for line in event_path.read_text(encoding="utf-8").splitlines()
                ]
                self.assertTrue(events)
                self.assertTrue(
                    all(event["schema"] == target.AUDIT_SCHEMA for event in events)
                )

    def test_check_mode_never_changes_boot_tombstone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hen = root / "hen.bin"
            hen.write_bytes(b"")
            tombstone = root / "boot.json"
            tombstone.write_text("sentinel", encoding="utf-8")
            with (
                patch.object(target, "load_manifest", return_value=({}, {}, "0" * 64)),
                patch.object(
                    target,
                    "validate_hen",
                    return_value={
                        "sha256": target.HEN_SHA256,
                        "size": target.HEN_SIZE,
                        "offset": 0x4000,
                        "head": target.HEN_HEAD.hex(),
                        "entry": target.HEN_ENTRY,
                    },
                ),
                patch("builtins.print"),
            ):
                self.assertEqual(target.main([
                    "--check",
                    "--hen", str(hen),
                    "--hen-sha256", target.HEN_SHA256,
                    "--boot-tombstone", str(tombstone),
                ]), 0)
            self.assertEqual(tombstone.read_text(encoding="utf-8"), "sentinel")

    def test_ipv4_loopback_default_and_explicit_trusted_lan_only(self) -> None:
        base = ["--check", "--hen", "hen.bin", "--hen-sha256", target.HEN_SHA256]
        self.assertEqual(target.parse_args(base).host, "127.0.0.1")
        with self.assertRaises(SystemExit):
            target.parse_args([
                "--hen", "hen.bin",
                "--hen-sha256", target.HEN_SHA256,
                "--state", "state.json",
                "--events", "events.jsonl",
                "--result", "result.json",
            ])
        for unsupported in ("::1", "localhost"):
            with self.subTest(unsupported=unsupported), self.assertRaises(SystemExit):
                target.parse_args(base + ["--host", unsupported])
        lan = target.parse_args(base + [
            "--host", "192.168.1.20",
            "--public-host", "192.168.1.20",
            "--expected-client", "192.168.1.30",
            "--trusted-isolated-network",
        ])
        self.assertEqual(lan.host, "192.168.1.20")

    def test_claimed_abort_is_durably_reboot_required_and_unobserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self.make_run(root, root / "boot.json", "abort")
            run.claim("127.0.0.1")
            run.abort(
                "browser-stage-failed",
                "browser stage ended without a committed result",
                "127.0.0.1",
            )
            state = json.loads(run.state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["phase"], "aborted")
            self.assertTrue(state["reboot_required"])
            self.assertFalse(state["runtime_observed"])
            self.assertIsNone(state["launch_dispatched"])

    def test_commit_failures_are_terminal_commit_uncertain(self) -> None:
        for failure in ("before-publish", "after-publish", "final-state"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run = self.make_run(root, root / "boot.json", failure)
                run.claim("127.0.0.1")
                result = self.make_success_result(run.run_id)
                original_replace = common.durable_replace
                original_publish = common.durable_publish

                def replace(path: Path, payload: bytes) -> None:
                    document = json.loads(payload)
                    phase = document.get("phase")
                    if (
                        (failure == "before-publish" and phase == "committing")
                        or (failure == "final-state" and phase == "completed")
                    ):
                        raise OSError(f"injected {failure}")
                    original_replace(path, payload)

                def publish(path: Path, payload: bytes) -> None:
                    original_publish(path, payload)
                    raise OSError("injected after-publish")

                if failure == "after-publish":
                    context = patch.object(common, "durable_publish", side_effect=publish)
                else:
                    context = patch.object(common, "durable_replace", side_effect=replace)
                with context, self.assertRaises(OSError):
                    run.complete(result, "127.0.0.1")
                state = json.loads(run.state_path.read_text(encoding="utf-8"))
                self.assertEqual(state["phase"], "commit-uncertain")
                self.assertTrue(state["reboot_required"])
                self.assertFalse(state["runtime_observed"])
                self.assertIsNone(state["launch_dispatched"])
                self.assertEqual(
                    run.result_path.exists(),
                    failure in {"after-publish", "final-state"},
                )

    def test_obsolete_generation6_mapping_keys_are_rejected(self) -> None:
        for obsolete in (
            "jitMappingCreated", "jitMappingCapabilityBound", "jitMappingRetained",
            "unifiedMappingVerified", "jitDescriptorRetained", "leaseBorrowedBitCleared",
        ):
            with self.subTest(obsolete=obsolete):
                result = self.make_success_result()
                result[obsolete] = True
                with self.assertRaises(common.ProtocolError):
                    target.validate_result(result, run_id="run-1")


if __name__ == "__main__":
    unittest.main()
