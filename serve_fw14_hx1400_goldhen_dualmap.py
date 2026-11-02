#!/usr/bin/env python3
"""Strict one-shot live host for the PS4 FW14 Hx1400 GoldHEN dual-map successor."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import Any, Iterator, Mapping
from urllib.parse import parse_qs, urlsplit

try:
    from . import serve_fw14_kdump as common
    from . import serve_fw14_hx1400_current_rop as predecessor
except ImportError:
    import serve_fw14_kdump as common
    import serve_fw14_hx1400_current_rop as predecessor
# The pinned predecessor validator references this intended phase set but its
# immutable module never defined it. Supply the one missing derived constant
# without changing the reviewed predecessor bytes.
predecessor.POST_ROTATION_CODES = frozenset(
    predecessor.ACCEPTED_KVA_CODES - {"RB_GADGET", "THREW"}
)


STAGE_PAGE = "/fw14_hx1400_goldhen_dualmap.html"
STAGE_NAME = "fw14-hx1400-goldhen-dualmap"
STABLE_SLOTS = "9100000"
STABLE_G = "drain:12"
STATIC_MANIFEST_NAME = "fw14_hx1400_goldhen_dualmap_static.json"
CLAIM_SCHEMA = "oms.fw14-hx1400-goldhen-dualmap.claim.v1"
RESULT_SCHEMA = "oms.fw14-hx1400-goldhen-dualmap.result.v1"
STATE_SCHEMA = "oms.fw14-hx1400-goldhen-dualmap.state.v1"
STATIC_SCHEMA = "oms.fw14-hx1400-goldhen-dualmap.static.v1"
AUDIT_SCHEMA = "oms.fw14-hx1400-goldhen-dualmap.audit.v1"
BOOT_TOMBSTONE_SCHEMA = "oms.fw14-hx1400-goldhen-dualmap.boot.v1"
# Reviewed hardened static graph aggregate, recomputed after fail-closed source
# and manifest review.
EXPECTED_STATIC_GRAPH_SHA256 = "76451f8bc1229c01ab738716efd7af633285d765e5b444b2ff8b9a74cd4254fe"
INTENT_HEADER = "X-Hx1400-Goldhen-Dualmap-Intent"
HEN_SIZE = 0x89440
HEN_SHA256 = "29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06"
HEN_HEAD = bytes.fromhex("e9a64a0000")
HEN_ENTRY = 0x4AAB
PATCH_SIZE = 632
PATCH_SHA256 = "165d2ad966b3829d1fbcb53d5e7ecbc20563de4a6a49ee70d8126d0256a49c02"
MAX_ARMS = 32
KVA_SEARCH_LIMIT = 192
PREDECESSOR_KVA_SEARCH_LIMIT = 96
MAX_JSON = 64 * 1024
MAX_TELEMETRY = 16 * 1024
MAX_TELEMETRY_EVENTS = 64
MAX_TELEMETRY_BYTES = 32 * 1024
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
ADDRESS_TEXT = re.compile(r"0x[0-9a-f]{8,16}", re.IGNORECASE)
TELEMETRY_TAG = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\Z")
LOOPBACKS = frozenset({"127.0.0.1"})
SPRAY_MIN = 128
SPRAY_MAX = 144
CANDIDATES = (
    128, 96, 160, 64, 192, 32, 224, 120, 136, 88, 104, 152, 168, 56, 72,
    184, 200, 24, 40, 216, 232, 8, 16, 48, 80, 112, 144, 176, 208, 240,
)
ARM_KEYS = {
    "sequence", "sprayCount", "round", "candidateIndex", "candidateFd", "dceFd",
    "evAddRc", "scanOk", "scanErrors", "nonStockOptions", "matches",
    "targetIndex", "targetFd", "evDeleteRc", "candidateRestoreRc",
    "repairFailures", "dceCloseOk", "outcome",
}
ARM_OUTCOMES = frozenset({
    "interrupted", "paired", "evadd-failed", "no-match", "scan-incomplete",
    "ambiguous", "event-delete-failed", "pair-delete-failed",
    "candidate-restore-failed", "cleanup-failed",
})


RESULT_KEYS = {
    "schema","ok","code","runId","kbaseValidated","maxArms","armsAttempted",
    "possibleBlindWrites","armRecords","pairEstablished","pairRound",
    "pairCandidateIndex","pairCandidateFd","pairTargetIndex","pairTargetFd",
    "kvaSearchOutcome","kvaSearchAttempts","kvaSearchFd","kvaSearchRc",
    "kvaSearchRef","kvaSearchTreeAccepted","rotationAttempted","rotationError",
    "rotationRc","rotationExpectedOpsMatch","rotationPredicateMask","kernelRwProved",
    "challengeWriteAttempted","challengeWritten","challengeRestored",
    "lowMapPolicyValidated","lowMapMapped","lowMapLeaseAcquired","lowMapUnmapped",
    "lowMapLeaseRevoked","oracleAttempted","oracleCode","oracleKernelMutated",
    "oracleCleanup","oracleRebootRequired","oracleExecutions","oracleSignatureVerified",
    "oracleRopReadOnly","oracleAuthorityConsumed","oracleDiagnosticPhase",
    "oracleDiagnosticReason","oracleSignatureChecks","oracleRoundsStarted",
    "oracleRoundsCompleted","currentObjectsAuthenticated","handlerSemanticAttested",
    "mmapCapabilityRecheckAttested","dwordGadgetAttested","ownerRevalidated",
    "writerIsolationVerified","leaseStatus","leaseWrites","leaseCreateCalls",
    "leaseMapCalls","leaseWriteArmConfirmed","leaseWriteRestoreConfirmed",
    "leaseExecuteArmConfirmed","leaseExecuteRestoreConfirmed",
    "leaseBorrowedBitsCleared","leaseTerminalMatchesOriginal",
    "jitDescriptorCreated","jitDescriptorReleased","jitWritableMappingCreated",
    "jitExecutableMappingCreated","jitMappingsCapabilityBound","jitMappingsReleased",
    "wxPatchMappingVerified","crossViewPatchVerified","patchCopyVerified",
    "henRwxMapCreated","henCopyVerified","bssTailVerified","henMappingRetained",
    "stockGuardsVerified","patchedGuardsVerified","patchExecutionAttempted",
    "bridgeCallbackRestored","sysent11Restored","goldhenLaunchAttempted",
    "goldhenLaunchDispatched","goldhenRuntimeObserved","exploitRetired",
    "aioCleanupVerified","quarantined","stageCleanupVerified",
    "hostCleanupVerified","cleanupVerified","rebootRequired",
}
BOOL_KEYS = {
    "ok","kbaseValidated","pairEstablished","kvaSearchTreeAccepted","rotationAttempted",
    "rotationExpectedOpsMatch","kernelRwProved","challengeWriteAttempted","challengeWritten",
    "challengeRestored","lowMapPolicyValidated","lowMapMapped","lowMapLeaseAcquired",
    "lowMapUnmapped","lowMapLeaseRevoked","oracleAttempted","oracleKernelMutated",
    "oracleCleanup","oracleRebootRequired","oracleSignatureVerified","oracleRopReadOnly",
    "oracleAuthorityConsumed","currentObjectsAuthenticated","handlerSemanticAttested",
    "mmapCapabilityRecheckAttested","dwordGadgetAttested","ownerRevalidated",
    "writerIsolationVerified","leaseWriteArmConfirmed","leaseWriteRestoreConfirmed",
    "leaseExecuteArmConfirmed","leaseExecuteRestoreConfirmed",
    "leaseBorrowedBitsCleared","leaseTerminalMatchesOriginal",
    "jitDescriptorCreated","jitDescriptorReleased","jitWritableMappingCreated",
    "jitExecutableMappingCreated","jitMappingsCapabilityBound","jitMappingsReleased",
    "wxPatchMappingVerified","crossViewPatchVerified","patchCopyVerified",
    "henRwxMapCreated","henCopyVerified","bssTailVerified","henMappingRetained",
    "patchExecutionAttempted","bridgeCallbackRestored","sysent11Restored",
    "goldhenLaunchAttempted","goldhenLaunchDispatched","goldhenRuntimeObserved",
    "exploitRetired","aioCleanupVerified","quarantined","stageCleanupVerified",
    "hostCleanupVerified","cleanupVerified","rebootRequired",
}
UINT_KEYS = {
    "maxArms": MAX_ARMS,"armsAttempted": MAX_ARMS,"possibleBlindWrites": MAX_ARMS,
    "kvaSearchAttempts": 0x10000,"kvaSearchRef": 0xffffffff,"oracleExecutions": 2,
    "oracleSignatureChecks": 4,"oracleRoundsStarted": 2,"oracleRoundsCompleted": 2,
    "leaseWrites": 4,"leaseCreateCalls": 1,"leaseMapCalls": 1,
    "stockGuardsVerified": 24,"patchedGuardsVerified": 24,
}
NULLABLE_INT_KEYS = {
    "pairRound","pairCandidateIndex","pairCandidateFd","pairTargetIndex","pairTargetFd",
    "kvaSearchFd","kvaSearchRc","rotationRc","rotationPredicateMask",
}
ORACLE_PHASE_COUNTS = {
    "not-started": (0, 0, 0), "oracle-entered": (0, 0, 0),
    "round-1-request-validated": (0, 0, 0),
    "round-1-signature-before-ok": (1, 0, 0),
    "round-1-chain-built": (1, 1, 0), "round-1-bridge-returned": (1, 1, 0),
    "round-1-signature-after-ok": (2, 1, 0), "round-1-complete": (2, 1, 1),
    "round-2-request-validated": (2, 1, 1),
    "round-2-signature-before-ok": (3, 1, 1),
    "round-2-chain-built": (3, 2, 1), "round-2-bridge-returned": (3, 2, 1),
    "round-2-signature-after-ok": (4, 2, 1), "round-2-complete": (4, 2, 2),
    "authority-consumed": (4, 2, 2), "oracle-complete": (4, 2, 2),
}
ORACLE_REASONS = {
    "none", "request-validation", "signature-read", "signature-mismatch",
    "chain-build", "bridge-failed", "capture", "oracle-module-quarantine", "unknown",
}

KVA_SEARCH_OUTCOMES = predecessor.KVA_SEARCH_OUTCOMES
ROTATION_ERRORS = predecessor.ROTATION_ERRORS
ORACLE_CODES = predecessor.ORACLE_FAILURE_CODES | {
    predecessor.ORACLE_SUCCESS_CODE, "OK_CURRENT_OWNER", "ERR_REENTRY",
    "ERR_GENERATION_CLOSED", "ERR_CONTEXT", "ERR_EXECUTOR", "ERR_VALIDATION",
    "ERR_OWNER_DRIFT", "ERR_ATTEST_CONTEXT", "ERR_LIVE_SEMANTICS",
}
LEASE_STATUSES = frozenset({"OK", "REFUSED", "QUARANTINED", "ERROR"})
SUCCESS_CODE = "OK_GOLDHEN_DUALMAP_LAUNCH_DISPATCHED_REBOOT_REQUIRED"
GOLDHEN_TERMINAL_CODES = (
    predecessor.ACCEPTED_KVA_CODES
    | set(predecessor.NO_KVA_CODES.values())
    | {
        SUCCESS_CODE, "LOWMAP_RANGE", "FAKE_MMAP", "LOWMAP_LEASE_INVALID",
        "BRIDGE_STACK_ENCODING", "ANCHOR_JOIN", "TARGET_FREE", "VICTIM_JOIN",
        "LEAK_EV_ADD", "NO_KVA_REJECTED_TREE", "ROP_TOO_LONG",
        "ROP_STACK_UNMAPPED", "GUARD_WIDTH", "DWRITE_REENTRY", "DWRITE_BRIDGE",
        "BAD_CONTEXT", "MISSING_SYSCALL", "PATCH_SHA256", "HEN_SIZE",
        "HEN_SHA256", "HEN_ENTRY", "ROUTE_CLOSED", "AFFINITY_GET",
        "AFFINITY_EMPTY", "AFFINITY_SET", "AFFINITY_READBACK", "AIO_SUBMIT",
        "AIO_ZERO_ID", "AIO_CLEANUP_STUCK", "NO_KBASE",
        "AFFINITY_RESTORE_AFTER_LEAK", "AFFINITY_REPIN",
        "AFFINITY_REPIN_READBACK", "ANCHOR_SOCKET", "VICTIM_COUNT", "DCE_OPEN",
        "DCE_FSTAT", "DCE_INODE", "DCE_CLOSE", "DCE_CENSUS_OWNERSHIP",
        "DCE_CENSUS_CHANGED", "DCE_CENSUS_CLOSE", "DCE_PLUG_PROBE_CLOSE",
        "DCE_PLUG_DEVICE", "DCE_PLUG_OPEN", "DCE_PLUG_FD", "DCE_WARM_CLOSE",
        "SPRAY_COUNT", "EXPLOIT_KQUEUE", "ROUND_CLEAR_FAILED",
        "ROUND_REPACK_FAILED", "DCE_OPEN_RESTORE_FAILED", "ARM_CLEANUP_FAILED",
        "ARM_DELETE_FAILED", "SCAN_INCOMPLETE", "AMBIGUOUS_PAIR",
        "CANDIDATE_RESTORE_FAILED", "NO_PAIR", "PATCH_DISPATCH",
        "SYSENT11_READBACK", "STOCK_GUARD_MISMATCH", "PATCH_GUARD_READBACK",
        "PATCH_COPY_READBACK", "JIT_MMAP", "JIT_RELEASE", "HEN_MMAP",
        "HEN_COPY_READBACK", "PTHREAD_CREATE", "PTHREAD_HANDLE_ZERO",
        "JIT_LEASE_FAILED", "GOLDHEN_ORACLE_FAILED", "HX_GOLDHEN_CONSTANTS",
        "HX_KBASE", "ERR_WRITER_ISOLATION", "ERR_OWNER_DRIFT",
        "ERR_ATTEST_CONTEXT", "ERR_LIVE_SEMANTICS", "ERR_OWNER_OPERATION",
        "ERR_OWNER_REENTRY", "ERR_OWNER_TOKEN", "ERR_REENTRY", "ERR_PRE_READ",
        "ERR_GENERATION_CLOSED", "ERR_CONTEXT", "ERR_EXECUTOR", "ERR_VALIDATION",
        "ERR_UNSTABLE_PRE_READ", "ERR_PREAUTHORIZED", "ERR_WRITE_ARM_WRITE",
        "ERR_WRITE_ARM_READBACK", "ERR_WRITE_POST_READ", "ERR_WRITE_POST_STATE",
        "ERR_WRITE_RESTORE_WRITE", "ERR_WRITE_RESTORE_READ",
        "ERR_WRITE_RESTORE_UNSTABLE", "ERR_WRITE_RESTORE_STATE",
        "ERR_JIT_CREATE_CALLBACK", "ERR_JIT_CREATE", "ERR_EXECUTE_ARM_WRITE",
        "ERR_EXECUTE_ARM_READBACK", "ERR_EXECUTE_POST_READ",
        "ERR_EXECUTE_POST_STATE", "ERR_EXECUTE_RESTORE_WRITE",
        "ERR_EXECUTE_RESTORE_READ", "ERR_EXECUTE_RESTORE_UNSTABLE",
        "ERR_EXECUTE_RESTORE_STATE", "ERR_JIT_MAP_CALLBACK", "ERR_JIT_MAP",
        "ERR_DISPOSE", "ERR_INTERNAL",
    }
)

BOOT_TOMBSTONE_KEYS = frozenset({
    "schema", "blocked", "run_id", "client", "claimed_at", "reset_at",
    "confirm_cold_reboot_after", "reboot_required", "runtime_observed",
    "launch_dispatched",
})


def _exact_ipv4(value: str, name: str, *, allow_unspecified: bool = False) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError(f"{name} must be an exact IPv4 address") from error
    if str(address) != value:
        raise ValueError(f"{name} must use canonical IPv4 spelling")
    if address.is_multicast or address.is_reserved or (
        address.is_unspecified and not allow_unspecified
    ):
        raise ValueError(f"{name} is not a supported IPv4 address")
    return value


@contextmanager
def _boot_tombstone_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ValueError(f"boot tombstone is locked; refusing: {lock_path}") from error
    try:
        yield
    finally:
        os.close(descriptor)
        lock_path.unlink(missing_ok=True)


def load_boot_tombstone(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=common.reject_duplicate_object,
        )
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid boot tombstone: {error}") from error
    if not isinstance(value, dict) or set(value) != BOOT_TOMBSTONE_KEYS:
        raise ValueError("boot tombstone fields do not match the exact schema")
    if value["schema"] != BOOT_TOMBSTONE_SCHEMA or type(value["blocked"]) is not bool:
        raise ValueError("boot tombstone schema or blocked state is invalid")
    if (
        not isinstance(value["run_id"], str)
        or not 1 <= len(value["run_id"]) <= 128
        or not isinstance(value["client"], str)
        or not value["client"]
        or not isinstance(value["claimed_at"], str)
        or not value["claimed_at"]
        or value["runtime_observed"] is not False
        or value["launch_dispatched"] is not None
    ):
        raise ValueError("boot tombstone identity or observation state is invalid")
    if value["blocked"]:
        if (
            value["reset_at"] is not None
            or value["confirm_cold_reboot_after"] is not None
            or value["reboot_required"] is not True
        ):
            raise ValueError("blocked boot tombstone must require an unconfirmed reboot")
    elif (
        not isinstance(value["reset_at"], str)
        or not value["reset_at"]
        or value["confirm_cold_reboot_after"] != value["run_id"]
        or value["reboot_required"] is not False
    ):
        raise ValueError("reset boot tombstone lacks exact cold-reboot confirmation")
    return value


def prepare_boot_tombstone(
    path: Path,
    confirm_cold_reboot_after: str | None,
) -> dict[str, Any] | None:
    with _boot_tombstone_lock(path):
        value = load_boot_tombstone(path)
        if value is None:
            if confirm_cold_reboot_after is not None:
                raise ValueError("--confirm-cold-reboot-after has no prior run to confirm")
            return None
        if not value["blocked"]:
            if (
                confirm_cold_reboot_after is not None
                and confirm_cold_reboot_after != value["run_id"]
            ):
                raise ValueError("--confirm-cold-reboot-after does not match the recorded run")
            return value
        if confirm_cold_reboot_after != value["run_id"]:
            raise ValueError(
                "boot tombstone is blocked; pass --confirm-cold-reboot-after with its exact prior run ID only after a cold reboot"
            )
        reset = dict(value)
        reset.update({
            "blocked": False,
            "reset_at": common.now(),
            "confirm_cold_reboot_after": value["run_id"],
            "reboot_required": False,
        })
        common.durable_replace(path, common.json_bytes(reset))
        return reset



def exact_signed(value: object, name: str) -> int:
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise common.ProtocolError(
            422, f"invalid-{name}", f"{name} must be a signed 32-bit integer",
        )
    return value


def exact_nullable_uint(value: object, name: str, maximum: int) -> int | None:
    if value is None:
        return None
    return common.exact_uint(value, name, maximum)


def exact_nullable_signed(value: object, name: str) -> int | None:
    if value is None:
        return None
    return exact_signed(value, name)


def validate_arm_record(value: object, sequence: int) -> dict[str, Any]:
    record = common.exact_keys(value, ARM_KEYS, "arm-record")
    if common.exact_uint(record["sequence"], "arm-sequence", MAX_ARMS) != sequence:
        raise common.ProtocolError(
            422, "invalid-arm-sequence", "arm records must be contiguous and ordered",
        )
    spray_count = common.exact_uint(record["sprayCount"], "spray-count", SPRAY_MAX)
    if spray_count < SPRAY_MIN:
        raise common.ProtocolError(
            422, "invalid-spray-count", "armed sweep requires 128..144 spray sockets",
        )
    round_number = common.exact_uint(record["round"], "arm-round", 6)
    if round_number < 1:
        raise common.ProtocolError(
            422, "invalid-arm-round", "arm round must be in 1..6",
        )
    candidate = common.exact_uint(
        record["candidateIndex"], "candidate-index", 0x10000,
    )
    if candidate not in CANDIDATES or candidate >= spray_count:
        raise common.ProtocolError(
            422, "invalid-candidate-index",
            "candidate must be in the recovered order and inside the spray",
        )
    common.exact_uint(record["candidateFd"], "candidate-fd", 0x7fffffff)
    common.exact_uint(record["dceFd"], "dce-fd", 0x7fffffff)
    ev_add = exact_nullable_signed(record["evAddRc"], "ev-add-rc")
    scan_ok = common.exact_uint(record["scanOk"], "scan-ok", SPRAY_MAX)
    scan_errors = common.exact_uint(record["scanErrors"], "scan-errors", SPRAY_MAX)
    non_stock = common.exact_uint(
        record["nonStockOptions"], "non-stock-options", SPRAY_MAX,
    )
    matches = common.exact_uint(record["matches"], "matches", SPRAY_MAX)
    repair_failures = common.exact_uint(
        record["repairFailures"], "repair-failures", SPRAY_MAX,
    )
    if scan_ok + scan_errors > spray_count - 1:
        raise common.ProtocolError(
            422, "arm-scan-count-mismatch",
            "scan counters exceed all non-candidate sockets",
        )
    if matches + non_stock > scan_ok:
        raise common.ProtocolError(
            422, "arm-scan-counter-mismatch",
            "match and non-stock counters exceed successful scans",
        )
    target_index = exact_nullable_uint(
        record["targetIndex"], "target-index", SPRAY_MAX - 1,
    )
    target_fd = exact_nullable_uint(record["targetFd"], "target-fd", 0x7fffffff)
    if (target_index is None) != (target_fd is None):
        raise common.ProtocolError(
            422, "invalid-arm-target",
            "target index and descriptor must be jointly null or present",
        )
    if target_index is not None and (
        target_index >= spray_count or target_index == candidate
    ):
        raise common.ProtocolError(
            422, "invalid-arm-target",
            "target must be a distinct socket inside the recorded spray",
        )
    ev_delete = exact_nullable_signed(record["evDeleteRc"], "ev-delete-rc")
    candidate_restore = exact_nullable_signed(
        record["candidateRestoreRc"], "candidate-restore-rc",
    )
    dce_close = record["dceCloseOk"]
    if dce_close is not None and type(dce_close) is not bool:
        raise common.ProtocolError(
            422, "invalid-dce-close", "dceCloseOk must be null or boolean",
        )
    outcome = record["outcome"]
    if not isinstance(outcome, str) or outcome not in ARM_OUTCOMES:
        raise common.ProtocolError(
            422, "invalid-arm-outcome", "unknown arm outcome",
        )

    scanned = scan_ok + scan_errors
    target_recorded = target_index is not None
    if outcome == "interrupted":
        if ev_add is None:
            progression_ok = (
                scanned == 0 and non_stock == 0 and matches == 0
                and not target_recorded and ev_delete is None
            )
        elif ev_add == 0:
            progression_ok = (
                (
                    scanned < spray_count - 1
                    and not target_recorded
                    and ev_delete is None
                )
                or (
                    scanned == spray_count - 1
                    and target_recorded == (matches == 1)
                )
            )
        else:
            progression_ok = False
        if not (
            progression_ok
            and candidate_restore is None
            and repair_failures == 0
            and dce_close is None
        ):
            raise common.ProtocolError(
                422, "arm-outcome-mismatch",
                "interrupted arm fields violate producer progression",
            )
        return record

    if ev_add is None:
        raise common.ProtocolError(
            422, "arm-outcome-mismatch", "completed arm requires an EV_ADD result",
        )
    if ev_add != 0:
        if (
            scanned != 0 or non_stock != 0 or matches != 0 or target_recorded
            or ev_delete is not None or candidate_restore is not None
        ):
            raise common.ProtocolError(
                422, "arm-outcome-mismatch",
                "failed EV_ADD cannot report a victim scan",
            )
    else:
        if scanned != spray_count - 1:
            raise common.ProtocolError(
                422, "arm-scan-count-mismatch",
                "completed EV_ADD requires a complete victim scan",
            )
        if target_recorded != (matches == 1):
            raise common.ProtocolError(
                422, "arm-target-count-mismatch",
                "target metadata requires exactly one marker match",
            )
        pair_scan = matches == 1 and scan_errors == 0
        if pair_scan:
            if ev_delete is None or candidate_restore is None:
                raise common.ProtocolError(
                    422, "arm-outcome-mismatch",
                    "unique complete scan requires delete and restore results",
                )
        elif ev_delete is None or candidate_restore is not None:
            raise common.ProtocolError(
                422, "arm-outcome-mismatch",
                "non-pair scan requires only an event-delete result",
            )

    cleanup_ok = repair_failures == 0 and dce_close is True
    cleanup_failed = (
        dce_close is not None and (repair_failures != 0 or dce_close is False)
    )
    pair_scan = ev_add == 0 and matches == 1 and scan_errors == 0
    outcome_ok = {
        "paired": (
            pair_scan and ev_delete == 0 and candidate_restore == 0
            and repair_failures == 0 and dce_close is None
        ),
        "evadd-failed": ev_add != 0 and cleanup_ok,
        "no-match": (
            ev_add == 0 and scan_errors == 0 and matches == 0
            and ev_delete == 0 and candidate_restore is None and cleanup_ok
        ),
        "scan-incomplete": (
            ev_add == 0 and scan_errors > 0 and ev_delete == 0
            and candidate_restore is None and cleanup_ok
        ),
        "ambiguous": (
            ev_add == 0 and scan_errors == 0 and matches > 1
            and ev_delete == 0 and candidate_restore is None and cleanup_ok
        ),
        "event-delete-failed": (
            ev_add == 0 and not pair_scan and ev_delete is not None
            and ev_delete != 0 and candidate_restore is None and cleanup_ok
        ),
        "pair-delete-failed": (
            pair_scan and ev_delete is not None and ev_delete != 0
            and candidate_restore is not None and cleanup_ok
        ),
        "candidate-restore-failed": (
            pair_scan and ev_delete == 0 and candidate_restore is not None
            and candidate_restore != 0 and cleanup_ok
        ),
        "cleanup-failed": (
            cleanup_failed
            and not (pair_scan and ev_delete == 0 and candidate_restore == 0)
        ),
    }.get(outcome, False)
    if not outcome_ok:
        raise common.ProtocolError(
            422, "arm-outcome-mismatch",
            "arm fields do not match the reported terminal state",
        )
    return record


def validate_hen(image: bytes, expected_hash: str) -> dict[str, Any]:
    if len(image) != HEN_SIZE:
        raise ValueError(f"HEN size mismatch: {len(image)}")
    digest = hashlib.sha256(image).hexdigest()
    if not hmac.compare_digest(digest, expected_hash) or not hmac.compare_digest(digest, HEN_SHA256):
        raise ValueError("HEN SHA-256 mismatch")
    if image[:5] != HEN_HEAD:
        raise ValueError("HEN head mismatch")
    entry = 5 + int.from_bytes(image[1:5], "little", signed=True)
    if entry != HEN_ENTRY:
        raise ValueError(f"HEN E9 target mismatch: 0x{entry:x}")
    return {"sha256": digest, "size": len(image), "offset": 0x4000, "head": image[:5].hex(), "entry": entry}


def _validate_kva_attempt_window(result: dict[str, Any]) -> None:
    attempts = result["kvaSearchAttempts"]
    outcome = result["kvaSearchOutcome"]
    if outcome is None:
        if attempts != 0:
            raise common.ProtocolError(
                422, "kva-search-before-start",
                "unstarted KVA search requires zero attempts",
            )
        return
    if not 1 <= attempts <= KVA_SEARCH_LIMIT:
        raise common.ProtocolError(
            422, "invalid-kva-search-attempts",
            f"GoldHEN KVA search attempts must be in 1..{KVA_SEARCH_LIMIT}",
        )
    if outcome in {"exhausted", "setsockopt-error"} and attempts != KVA_SEARCH_LIMIT:
        raise common.ProtocolError(
            422, "kva-search-outcome-mismatch",
            f"{outcome} requires all {KVA_SEARCH_LIMIT} GoldHEN victims",
        )


def _validate_inherited(result: dict[str, Any], run_id: str) -> None:
    base = {key: result[key] for key in predecessor.RESULT_KEYS}
    base["schema"] = predecessor.RESULT_SCHEMA
    if base["kvaSearchAttempts"] > PREDECESSOR_KVA_SEARCH_LIMIT:
        base["kvaSearchAttempts"] = PREDECESSOR_KVA_SEARCH_LIMIT
    if result["currentObjectsAuthenticated"]:
        base.update({
            "ok": True,
            "code": "OK_CURRENT_OBJECTS_REBOOT_REQUIRED",
            "oracleCode": predecessor.ORACLE_SUCCESS_CODE,
            "oracleAuthorityConsumed": True,
            "oracleDiagnosticPhase": "oracle-complete",
            "oracleDiagnosticReason": "none",
            "lowMapUnmapped": True,
            "lowMapLeaseRevoked": True,
            "quarantined": False,
            "stageCleanupVerified": True,
            "hostCleanupVerified": True,
            "cleanupVerified": True,
        })
    else:
        oracle_code = result["oracleCode"]
        mapped_oracle = {
            "ERR_OWNER_DRIFT": "ERR_ORACLE_DRIFT",
            "ERR_REENTRY": "ERR_REENTRANT",
        }.get(oracle_code, oracle_code)
        if mapped_oracle not in predecessor.ORACLE_FAILURE_CODES | {
            predecessor.ORACLE_SUCCESS_CODE, None
        }:
            mapped_oracle = "ERR_VALIDATION"
        base["oracleCode"] = mapped_oracle
        if result["code"] in {"STAGE_CLEANUP_UNVERIFIED", "HOST_CLEANUP_UNVERIFIED"}:
            base["code"] = result["code"]
        elif result["oracleAttempted"] and result["code"] not in predecessor.ACCEPTED_KVA_CODES:
            base["code"] = mapped_oracle
    predecessor.validate_result(base, run_id=run_id)


def validate_result(value: object, *, run_id: str) -> dict[str, Any]:
    result = common.exact_keys(value, RESULT_KEYS, "result")
    serialized = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if ADDRESS_TEXT.search(serialized):
        raise common.ProtocolError(422, "serialized-address", "result must not serialize an address")
    if result["schema"] != RESULT_SCHEMA or result["runId"] != run_id:
        raise common.ProtocolError(409, "result-identity-mismatch", "result schema or run ID mismatch")
    if type(result["ok"]) is not bool:
        raise common.ProtocolError(422, "invalid-result-boolean", "ok must be boolean")
    if not isinstance(result["code"], str) or result["code"] not in GOLDHEN_TERMINAL_CODES:
        raise common.ProtocolError(422, "invalid-result-code", "result code is outside the terminal vocabulary")
    if result["ok"] != (result["code"] == SUCCESS_CODE):
        raise common.ProtocolError(422, "result-status-mismatch", "ok must exactly match the reserved success code")
    for name in BOOL_KEYS:
        if type(result[name]) is not bool:
            raise common.ProtocolError(422, "invalid-result-boolean", f"{name} must be boolean")
    for name, maximum in UINT_KEYS.items():
        common.exact_uint(result[name], name, maximum)
    if result["maxArms"] != MAX_ARMS:
        raise common.ProtocolError(422, "invalid-max-arms", "maxArms must remain 32")
    exact_nullable_uint(result["pairRound"], "pair-round", 6)
    exact_nullable_uint(result["pairCandidateIndex"], "pair-candidate-index", SPRAY_MAX - 1)
    exact_nullable_signed(result["pairCandidateFd"], "pair-candidate-fd")
    exact_nullable_uint(result["pairTargetIndex"], "pair-target-index", SPRAY_MAX - 1)
    exact_nullable_signed(result["pairTargetFd"], "pair-target-fd")
    exact_nullable_signed(result["kvaSearchFd"], "kva-search-fd")
    exact_nullable_signed(result["kvaSearchRc"], "kva-search-rc")
    exact_nullable_signed(result["rotationRc"], "rotation-rc")
    exact_nullable_uint(result["rotationPredicateMask"], "rotation-predicate-mask", 0xffffffff)
    vocabularies = {
        "kvaSearchOutcome": KVA_SEARCH_OUTCOMES,
        "rotationError": ROTATION_ERRORS,
        "oracleCode": ORACLE_CODES,
        "leaseStatus": LEASE_STATUSES,
    }
    for name, vocabulary in vocabularies.items():
        if result[name] is not None and (
            not isinstance(result[name], str) or result[name] not in vocabulary
        ):
            raise common.ProtocolError(422, f"invalid-{name}", f"{name} is outside the exact vocabulary")
    phase = result["oracleDiagnosticPhase"]
    reason = result["oracleDiagnosticReason"]
    if phase not in ORACLE_PHASE_COUNTS or reason not in ORACLE_REASONS:
        raise common.ProtocolError(422, "invalid-oracle-diagnostic", "oracle diagnostics are outside the exact vocabulary")
    checks, started, completed = ORACLE_PHASE_COUNTS[phase]
    if (
        result["oracleSignatureChecks"] != checks
        or result["oracleRoundsStarted"] != started
        or result["oracleRoundsCompleted"] != completed
        or result["oracleExecutions"] != completed
        or result["oracleSignatureVerified"] != (checks == 4 and completed == 2)
        or result["oracleRopReadOnly"] != (started > 0 and started == completed)
        or result["oracleAuthorityConsumed"] != (phase in {"authority-consumed", "oracle-complete"})
        or (result["oracleAttempted"] and phase == "not-started")
    ):
        raise common.ProtocolError(422, "oracle-diagnostic-relation", "oracle diagnostic relation mismatch")
    if phase == "oracle-complete" and not (
        result["oracleCode"] == "OK_CURRENT_OWNER"
        and result["oracleCleanup"]
        and not result["oracleRebootRequired"]
        and result["currentObjectsAuthenticated"]
        and result["oracleAuthorityConsumed"]
    ):
        raise common.ProtocolError(422, "oracle-completion-relation", "oracle completion proof is incomplete")
    if not result["oracleAttempted"] and (
        result["oracleCode"] is not None
        or result["oracleKernelMutated"]
        or result["oracleCleanup"]
        or result["oracleRebootRequired"]
        or result["oracleExecutions"] != 0
        or result["oracleSignatureVerified"]
        or result["oracleRopReadOnly"]
        or result["oracleAuthorityConsumed"]
        or result["currentObjectsAuthenticated"]
        or phase != "not-started"
        or reason != "none"
    ):
        raise common.ProtocolError(422, "oracle-not-attempted-relation", "unattempted oracle fields must remain empty")
    if result["quarantined"] and result["oracleAttempted"] and not result["oracleCleanup"] and reason == "none":
        raise common.ProtocolError(422, "oracle-quarantine-reason", "quarantined oracle failure requires a reason")

    if not isinstance(result["armRecords"], list) or len(result["armRecords"]) != result["armsAttempted"]:
        raise common.ProtocolError(422, "invalid-arm-records", "arm records must match attempted count")
    result["armRecords"] = [
        validate_arm_record(record, index + 1)
        for index, record in enumerate(result["armRecords"])
    ]

    _validate_kva_attempt_window(result)
    _validate_inherited(result, run_id)
    lowmap_incomplete = (
        (result["lowMapMapped"] and not result["lowMapUnmapped"])
        or (result["lowMapLeaseAcquired"] and not result["lowMapLeaseRevoked"])
    )
    if result["lowMapUnmapped"] and not result["lowMapMapped"]:
        raise common.ProtocolError(422, "lowmap-unmap-without-map", "unmap requires a mapped page")
    if result["lowMapLeaseRevoked"] and not (
        result["lowMapLeaseAcquired"] and result["lowMapUnmapped"]
    ):
        raise common.ProtocolError(422, "lowmap-revoke-order", "lease revocation requires a successful unmap")
    if lowmap_incomplete and (
        not result["quarantined"]
        or result["stageCleanupVerified"]
        or result["cleanupVerified"]
    ):
        raise common.ProtocolError(422, "lowmap-quarantine-underclaim", "a retained low map requires quarantine")


    authenticated = result["currentObjectsAuthenticated"]
    semantic_owner_proof = (
        authenticated
        and result["oracleAttempted"]
        and result["oracleCode"] == "OK_CURRENT_OWNER"
        and not result["oracleKernelMutated"]
        and result["oracleCleanup"]
        and not result["oracleRebootRequired"]
        and result["oracleExecutions"] == 2
        and result["oracleSignatureVerified"]
        and result["oracleRopReadOnly"]
        and result["oracleAuthorityConsumed"]
        and result["oracleDiagnosticPhase"] in {"authority-consumed", "oracle-complete"}
        and result["oracleDiagnosticReason"] == "none"
        and result["oracleSignatureChecks"] == 4
        and result["oracleRoundsStarted"] == 2
        and result["oracleRoundsCompleted"] == 2
        and result["handlerSemanticAttested"]
        and result["mmapCapabilityRecheckAttested"]
        and result["dwordGadgetAttested"]
    )
    if (
        result["handlerSemanticAttested"] != authenticated
        or result["mmapCapabilityRecheckAttested"] != authenticated
        or result["dwordGadgetAttested"] != authenticated
    ):
        raise common.ProtocolError(422, "semantic-attestation-relation", "semantic attestation must exactly match authenticated current objects")
    if result["ownerRevalidated"] and not (
        authenticated and result["writerIsolationVerified"] and result["leaseStatus"] is not None
    ):
        raise common.ProtocolError(422, "owner-revalidation-order", "owner revalidation requires an authenticated lease attempt")
    if result["stockGuardsVerified"] and not authenticated:
        raise common.ProtocolError(422, "stock-guard-order", "stock guard proof requires authenticated current objects")
    if result["writerIsolationVerified"] and not (
        authenticated and result["stockGuardsVerified"] == 24
    ):
        raise common.ProtocolError(422, "writer-isolation-order", "writer isolation requires authentication and stock guard proof")
    lease_status = result["leaseStatus"]
    lease_phase_fields = (
        "leaseWriteArmConfirmed", "leaseWriteRestoreConfirmed",
        "leaseExecuteArmConfirmed", "leaseExecuteRestoreConfirmed",
        "leaseBorrowedBitsCleared", "leaseTerminalMatchesOriginal",
    )
    lease_activity_phase_fields = lease_phase_fields[:4]
    lease_terminal_proof_fields = lease_phase_fields[4:]
    lease_resource_fields = (
        "jitDescriptorCreated", "jitDescriptorReleased",
        "jitWritableMappingCreated", "jitExecutableMappingCreated",
        "jitMappingsCapabilityBound", "jitMappingsReleased",
    )
    aggregate_cleanup_fields = (
        "stageCleanupVerified", "hostCleanupVerified", "cleanupVerified",
    )
    lease_tuple = (
        lease_status == "OK"
        and result["leaseWrites"] == 4
        and result["leaseCreateCalls"] == 1
        and result["leaseMapCalls"] == 1
        and result["oracleDiagnosticPhase"] == "oracle-complete"
        and all(result[name] for name in lease_phase_fields)
    )
    lease_zero = (
        result["leaseWrites"] == 0
        and result["leaseCreateCalls"] == 0
        and result["leaseMapCalls"] == 0
        and not any(result[name] for name in lease_activity_phase_fields)
        and not any(result[name] for name in lease_resource_fields)
    )
    write_phase_reached = (
        result["leaseWrites"] > 0
        or result["leaseCreateCalls"] > 0
        or result["leaseMapCalls"] > 0
        or any(result[name] for name in lease_activity_phase_fields[:2])
        or any(result[name] for name in lease_resource_fields)
    )
    execute_phase_reached = (
        result["leaseWrites"] > 2
        or result["leaseMapCalls"] > 0
        or any(result[name] for name in lease_activity_phase_fields[2:])
        or result["jitExecutableMappingCreated"]
    )
    exact_reached_phase_restore = (
        (not write_phase_reached or (
            result["leaseWriteArmConfirmed"]
            and result["leaseWriteRestoreConfirmed"]
            and result["leaseWrites"] >= 2
        ))
        and (not execute_phase_reached or (
            result["leaseExecuteArmConfirmed"]
            and result["leaseExecuteRestoreConfirmed"]
            and result["leaseWrites"] == 4
        ))
        and (
            not (write_phase_reached or execute_phase_reached)
            or (
                result["leaseBorrowedBitsCleared"]
                and result["leaseTerminalMatchesOriginal"]
            )
        )
    )
    created_jit_resources_released = (
        (not result["jitDescriptorCreated"] or result["jitDescriptorReleased"])
        and (
            not (
                result["jitWritableMappingCreated"]
                or result["jitExecutableMappingCreated"]
            )
            or result["jitMappingsReleased"]
        )
    )
    clean_error = (
        lease_status == "ERROR"
        and write_phase_reached
        and exact_reached_phase_restore
        and created_jit_resources_released
    )
    lease_activity = (
        result["leaseWrites"] > 0
        or result["leaseCreateCalls"] > 0
        or result["leaseMapCalls"] > 0
        or any(result[name] for name in lease_activity_phase_fields)
        or any(result[name] for name in lease_resource_fields)
    )
    if lease_status == "OK" and not lease_tuple:
        raise common.ProtocolError(
            422, "lease-success-incomplete",
            "successful lease requires the exact 4/1/1 tuple, both phase confirmations, and exact restoration",
        )
    if lease_status == "REFUSED" and not lease_zero:
        raise common.ProtocolError(
            422, "lease-refused-activity",
            "refused lease must have an all-zero activity and JIT-resource tuple",
        )
    if lease_status is None and (
        not lease_zero
        or any(result[name] for name in lease_terminal_proof_fields)
    ):
        raise common.ProtocolError(
            422, "lease-before-start", "unstarted lease must have an all-zero proof and JIT-resource tuple",
        )
    if result["leaseMapCalls"] > result["leaseCreateCalls"]:
        raise common.ProtocolError(
            422, "lease-map-before-create", "executable mapping cannot precede writable creation",
        )
    if (result["leaseCreateCalls"] == 1) != result["leaseWriteArmConfirmed"]:
        raise common.ProtocolError(
            422,
            "lease-create-phase-relation",
            "the writable-view callback must exactly follow a confirmed write arm",
        )
    if (result["leaseMapCalls"] == 1) != result["leaseExecuteArmConfirmed"]:
        raise common.ProtocolError(
            422,
            "lease-map-phase-relation",
            "the executable-view callback must exactly follow a confirmed execute arm",
        )
    if result["leaseWriteRestoreConfirmed"] and not result["leaseWriteArmConfirmed"]:
        raise common.ProtocolError(
            422, "lease-write-phase-order", "write restoration requires a confirmed write arm",
        )
    if result["leaseExecuteArmConfirmed"] and not result["leaseWriteRestoreConfirmed"]:
        raise common.ProtocolError(
            422, "lease-execute-phase-order", "execute arm requires completed write restoration",
        )
    if result["leaseExecuteRestoreConfirmed"] and not result["leaseExecuteArmConfirmed"]:
        raise common.ProtocolError(
            422, "lease-execute-restore-order", "execute restoration requires a confirmed execute arm",
        )
    if result["leaseBorrowedBitsCleared"] and not (
        result["leaseWriteRestoreConfirmed"]
        or result["leaseExecuteRestoreConfirmed"]
    ):
        raise common.ProtocolError(
            422, "lease-clear-order",
            "borrowed-bit clearance requires a restoration readback",
        )
    if (
        result["leaseTerminalMatchesOriginal"]
        and lease_status != "REFUSED"
        and not (
            result["leaseWriteRestoreConfirmed"]
            or result["leaseExecuteRestoreConfirmed"]
        )
    ):
        raise common.ProtocolError(
            422, "lease-terminal-order",
            "terminal restoration proof requires a restoration readback",
        )
    if lease_tuple and not (
        result["writerIsolationVerified"] and result["ownerRevalidated"]
    ):
        raise common.ProtocolError(
            422, "lease-order", "successful lease requires isolated, revalidated ownership",
        )
    if lease_status is not None and not (
        semantic_owner_proof
        and result["stockGuardsVerified"] == 24
        and result["writerIsolationVerified"]
    ):
        raise common.ProtocolError(
            422, "lease-attempt-order",
            "lease status requires the exact consumed semantic owner proof",
        )
    if lease_status == "QUARANTINED" and not (
        result["quarantined"]
        and not any(result[name] for name in aggregate_cleanup_fields)
    ):
        raise common.ProtocolError(
            422, "lease-quarantine-underclaim",
            "quarantined lease must quarantine the run and clear aggregate cleanup claims",
        )
    if lease_status == "ERROR" and not clean_error and not (
        result["quarantined"]
        and not any(result[name] for name in aggregate_cleanup_fields)
    ):
        raise common.ProtocolError(
            422, "lease-error-cleanup-underclaim",
            "an unproved lease error must quarantine the run and clear aggregate cleanup claims",
        )
    if lease_activity and not (lease_tuple or clean_error) and not (
        result["quarantined"]
        and not any(result[name] for name in aggregate_cleanup_fields)
    ):
        raise common.ProtocolError(
            422, "lease-partial-activity-underclaim",
            "partial writes or callbacks without complete proof require quarantine and unverified aggregate cleanup",
        )
    if (
        (
            result["jitDescriptorCreated"]
            or result["jitWritableMappingCreated"]
            or result["jitExecutableMappingCreated"]
        )
        and not created_jit_resources_released
        and not (
            result["quarantined"]
            and not any(result[name] for name in aggregate_cleanup_fields)
        )
    ):
        raise common.ProtocolError(
            422,
            "jit-resource-quarantine-underclaim",
            "unreleased created JIT resources require quarantine and unverified aggregate cleanup",
        )

    if result["jitDescriptorCreated"] and result["leaseCreateCalls"] != 1:
        raise common.ProtocolError(
            422, "descriptor-order", "JIT descriptor creation requires the writable-view callback",
        )
    if result["jitWritableMappingCreated"] and not result["jitDescriptorCreated"]:
        raise common.ProtocolError(
            422, "writable-map-order", "writable mapping requires its descriptor",
        )
    if result["jitExecutableMappingCreated"] and not (
        result["jitDescriptorCreated"]
        and result["jitWritableMappingCreated"]
        and result["leaseMapCalls"] == 1
    ):
        raise common.ProtocolError(
            422, "executable-map-order",
            "executable mapping requires the same descriptor and prior writable mapping",
        )
    expected_bound = (
        lease_tuple
        and result["jitWritableMappingCreated"]
        and result["jitExecutableMappingCreated"]
    )
    if result["jitMappingsCapabilityBound"] != expected_bound:
        raise common.ProtocolError(
            422, "mapping-capability-relation",
            "both JIT aliases are capability-bound only by the exact successful lease",
        )
    if result["jitDescriptorReleased"] and not result["jitDescriptorCreated"]:
        raise common.ProtocolError(
            422, "descriptor-release-order", "descriptor release requires creation",
        )
    if result["jitMappingsReleased"] and not (
        result["jitWritableMappingCreated"] or result["jitExecutableMappingCreated"]
    ):
        raise common.ProtocolError(
            422, "mapping-release-order", "mapping release requires at least one created JIT alias",
        )
    wx_alias_proof = (
        result["jitMappingsCapabilityBound"]
        and result["wxPatchMappingVerified"]
        and result["crossViewPatchVerified"]
        and result["patchCopyVerified"]
    )
    if any(result[name] for name in (
        "wxPatchMappingVerified", "crossViewPatchVerified", "patchCopyVerified",
    )) and not result["jitMappingsCapabilityBound"]:
        raise common.ProtocolError(
            422, "patch-alias-proof-order",
            "W^X and cross-view proof require both capability-bound aliases",
        )
    patch_prior = (
        lease_tuple
        and result["mmapCapabilityRecheckAttested"]
        and wx_alias_proof
        and result["stockGuardsVerified"] == 24
    )
    if result["patchExecutionAttempted"] and not patch_prior:
        raise common.ProtocolError(
            422, "patch-attempt-order",
            "RX patch execution requires exact lease, both W^X aliases, cross-view proof, and 24 stock guards",
        )
    if result["patchedGuardsVerified"] and not (
        result["patchExecutionAttempted"] and result["sysent11Restored"]
    ):
        raise common.ProtocolError(
            422, "patched-guard-order",
            "patched guards require RX patch dispatch and restored sysent",
        )
    if (result["bridgeCallbackRestored"] or result["sysent11Restored"]) and not result["patchExecutionAttempted"]:
        raise common.ProtocolError(
            422, "restore-order", "kernel restoration requires a patch attempt",
        )
    kernel_patch_complete = (
        result["patchExecutionAttempted"]
        and result["patchedGuardsVerified"] == 24
        and result["bridgeCallbackRestored"]
        and result["sysent11Restored"]
    )
    if (
        result["patchExecutionAttempted"]
        and (result["jitMappingsReleased"] or result["jitDescriptorReleased"])
        and not kernel_patch_complete
    ):
        raise common.ProtocolError(
            422, "jit-release-before-patch-proof",
            "post-dispatch patch resources cannot be released before all 24 patched guards",
        )
    postpatch_retirement_prior = (
        kernel_patch_complete
        and result["jitMappingsReleased"]
        and result["jitDescriptorReleased"]
        and result["aioCleanupVerified"]
    )
    if result["exploitRetired"] and result["patchExecutionAttempted"] and not postpatch_retirement_prior:
        raise common.ProtocolError(
            422, "retirement-order",
            "postpatch exploit retirement requires full patch proof and RX/RW/fd release",
        )
    if result["exploitRetired"] and not (
        result["patchExecutionAttempted"] or result["stageCleanupVerified"]
    ):
        raise common.ProtocolError(
            422, "prepatch-retirement-order",
            "prepatch exploit retirement requires verified stage cleanup",
        )
    hen_prior = postpatch_retirement_prior and result["exploitRetired"]
    if result["henRwxMapCreated"] and not hen_prior:
        raise common.ProtocolError(
            422, "hen-rwx-before-patch-proof",
            "anonymous RWX HEN mapping is forbidden before guard proof, sysent restoration, JIT release, and exploit retirement",
        )
    if (result["henCopyVerified"] or result["bssTailVerified"]) and not (
        result["henRwxMapCreated"] and hen_prior
    ):
        raise common.ProtocolError(
            422, "hen-copy-order", "HEN copy and zero-tail proof require the postpatch anonymous mapping",
        )
    launch_prior = (
        hen_prior
        and result["henRwxMapCreated"]
        and result["henCopyVerified"]
        and result["bssTailVerified"]
    )
    if result["goldhenLaunchAttempted"] and not launch_prior:
        raise common.ProtocolError(
            422, "launch-attempt-order", "launch requires complete postpatch HEN mapping proof",
        )
    if result["goldhenLaunchDispatched"] and not (
        result["goldhenLaunchAttempted"] and launch_prior
    ):
        raise common.ProtocolError(
            422, "dispatch-proof-incomplete", "launch dispatch requires complete proof",
        )
    if result["henMappingRetained"] != result["goldhenLaunchDispatched"]:
        raise common.ProtocolError(
            422, "hen-retention-relation",
            "the anonymous HEN mapping is retained only after successful pthread dispatch",
        )
    if result["henRwxMapCreated"] and not result["goldhenLaunchDispatched"] and not (
        result["quarantined"]
        and not any(result[name] for name in aggregate_cleanup_fields)
    ):
        raise common.ProtocolError(
            422, "hen-nondispatch-quarantine",
            "an anonymous HEN mapping without proven dispatch requires quarantine and unverified aggregate cleanup",
        )
    if result["goldhenLaunchDispatched"] and result["code"] not in {
        SUCCESS_CODE, "HOST_CLEANUP_UNVERIFIED",
    }:
        raise common.ProtocolError(
            422, "dispatch-code-mismatch", "dispatched launch has an invalid terminal code",
        )
    if result["code"] == "HOST_CLEANUP_UNVERIFIED" and not (
        result["goldhenLaunchDispatched"]
        and result["henMappingRetained"]
        and result["stageCleanupVerified"]
        and not result["hostCleanupVerified"]
        and not result["cleanupVerified"]
        and not result["quarantined"]
    ):
        raise common.ProtocolError(
            422, "host-cleanup-state-mismatch", "host cleanup failure requires a proven dispatch",
        )
    if result["patchExecutionAttempted"] and not result["exploitRetired"] and not result["quarantined"]:
        raise common.ProtocolError(
            422, "patch-quarantine-underclaim", "incomplete patch execution requires quarantine",
        )
    if result["goldhenLaunchAttempted"] and not result["goldhenLaunchDispatched"] and not result["quarantined"]:
        raise common.ProtocolError(
            422, "launch-quarantine-underclaim", "failed HEN launch requires quarantine",
        )
    if result["stageCleanupVerified"] and (
        (result["jitDescriptorCreated"] and not result["jitDescriptorReleased"])
        or (
            (
                result["jitWritableMappingCreated"]
                or result["jitExecutableMappingCreated"]
            )
            and not result["jitMappingsReleased"]
        )
        or (result["patchExecutionAttempted"] and not result["exploitRetired"])
        or result["quarantined"]
    ):
        raise common.ProtocolError(
            422, "stage-cleanup-order",
            "stage cleanup requires release of every created JIT descriptor/view and completed postpatch retirement",
        )
    if result["quarantined"] and result["stageCleanupVerified"]:
        raise common.ProtocolError(
            422, "quarantine-cleanup-conflict", "quarantine forbids verified stage cleanup",
        )
    if result["cleanupVerified"] != (
        result["stageCleanupVerified"] and result["hostCleanupVerified"]
    ):
        raise common.ProtocolError(
            422, "cleanup-relation", "cleanup verification relation mismatch",
        )
    if result["goldhenRuntimeObserved"]:
        raise common.ProtocolError(
            422, "runtime-overclaim", "this route has no runtime-readiness observer",
        )
    if not result["rebootRequired"]:
        raise common.ProtocolError(
            422, "reboot-underclaim", "every consumed result requires reboot",
        )
    success_proof = (
        result["goldhenLaunchDispatched"]
        and result["henMappingRetained"]
        and launch_prior
        and result["stageCleanupVerified"]
        and result["cleanupVerified"]
        and result["hostCleanupVerified"]
        and result["jitMappingsReleased"]
        and result["jitDescriptorReleased"]
        and not result["quarantined"]
    )
    if result["ok"] and not success_proof:
        raise common.ProtocolError(
            422, "success-proof-incomplete",
            "success requires released W^X aliases/fd and only the dispatched HEN mapping retained",
        )
    return result


class GoldhenDualmapRun:
    def __init__(self, *, state_path: Path, result_path: Path,
                 boot_tombstone: Path, event_log: common.DurableEventLog,
                 static_manifest: str, expected_client: str, expected_host: str,
                 hen_meta: dict[str, Any]) -> None:
        self.state_path = state_path
        self.result_path = result_path
        self.boot_tombstone = boot_tombstone
        self.event_log = event_log
        self.static_manifest = static_manifest
        self.expected_client = expected_client
        self.expected_host = expected_host
        self.hen_meta = dict(hen_meta)
        self.run_id = os.urandom(16).hex()
        self.challenge = os.urandom(32).hex()
        self.intent = os.urandom(32).hex()
        self.phase = "armed"
        self.pending_result_sha256: str | None = None
        self.telemetry_events = 0
        self.telemetry_bytes = 0
        self.lock = Lock()
        common.durable_create(self.state_path, common.json_bytes(self.document()))
        self.event("SERVER-ARMED")

    def document(self, *, phase: str | None = None, **extra: object) -> dict[str, Any]:
        return {
            "schema": STATE_SCHEMA,"phase": self.phase if phase is None else phase,
            "run_id": self.run_id,
            "static_manifest": self.static_manifest,
            "challenge_sha256": hashlib.sha256(bytes.fromhex(self.challenge)).hexdigest(),
            "intent_sha256": hashlib.sha256(bytes.fromhex(self.intent)).hexdigest(),
            "patch": {"sha256": PATCH_SHA256,"size": PATCH_SIZE,"offset": 0},
            "hen": self.hen_meta,**extra,
        }

    def event(self, tag: str, **detail: object) -> None:
        self.event_log.append({
            "schema": AUDIT_SCHEMA,
            "tag": tag,
            "run_id": self.run_id,
            "phase": self.phase,
            **detail,
        })

    def require_client(self, client: str) -> None:
        if client != self.expected_client:
            raise common.ProtocolError(403, "client-mismatch", "request did not come from the configured PS4 address")

    def require_host(self, host: str) -> None:
        if not hmac.compare_digest(host, self.expected_host):
            raise common.ProtocolError(403, "host-mismatch", "request Host did not match the pinned origin")

    def require_intent(self, intent: str) -> None:
        if not hmac.compare_digest(intent, self.intent):
            raise common.ProtocolError(403, "intent-mismatch", "one-shot intent mismatch")

    def _consume_boot_tombstone(self, client: str, claimed_at: str) -> None:
        with _boot_tombstone_lock(self.boot_tombstone):
            prior = load_boot_tombstone(self.boot_tombstone)
            if prior is not None and prior["blocked"]:
                raise common.ProtocolError(
                    410,
                    "cold-reboot-required",
                    f"boot tombstone remains blocked by run {prior['run_id']}",
                )
            blocked = {
                "schema": BOOT_TOMBSTONE_SCHEMA,
                "blocked": True,
                "run_id": self.run_id,
                "client": client,
                "claimed_at": claimed_at,
                "reset_at": None,
                "confirm_cold_reboot_after": None,
                "reboot_required": True,
                "runtime_observed": False,
                "launch_dispatched": None,
            }
            payload = common.json_bytes(blocked)
            if prior is None:
                common.durable_create(self.boot_tombstone, payload)
            else:
                common.durable_replace(self.boot_tombstone, payload)

    def claim(self, client: str) -> dict[str, Any]:
        self.require_client(client)
        with self.lock:
            if self.phase != "armed":
                raise common.ProtocolError(410, "claim-consumed", "the one-shot claim is already consumed")
            claimed_at = common.now()
            self._consume_boot_tombstone(client, claimed_at)
            common.durable_replace(
                self.state_path,
                common.json_bytes(self.document(
                    phase="claimed", claimed_at=claimed_at, client=client,
                    reboot_required=True, runtime_observed=False,
                    launch_dispatched=None,
                )),
            )
            self.phase = "claimed"
            self.event("CLAIM-CONSUMED", client=client)
            return {
                "schema": CLAIM_SCHEMA,"run_id": self.run_id,"challenge_hex": self.challenge,
                "max_arms": MAX_ARMS,"patch": {"sha256": PATCH_SHA256,"size": PATCH_SIZE,"offset": 0},
                "hen": self.hen_meta,
            }

    def _require_claimed_phase(self) -> None:
        if self.phase == "armed":
            raise common.ProtocolError(409, "claim-required", "claim must be consumed first")
        if self.phase != "claimed":
            raise common.ProtocolError(410, f"run-{self.phase}", f"{self.phase} run rejects mutation")

    def ensure_claimed(self, client: str) -> None:
        self.require_client(client)
        with self.lock:
            self._require_claimed_phase()

    def append_telemetry(self, tag: str, detail: str, encoded_bytes: int) -> None:
        if not isinstance(tag, str) or len(tag) > 64 or TELEMETRY_TAG.fullmatch(tag) is None:
            raise common.ProtocolError(422, "telemetry-fields", "telemetry tag is outside the bounded vocabulary")
        if detail != "":
            raise common.ProtocolError(422, "telemetry-fields", "GoldHEN telemetry detail must be empty")
        if type(encoded_bytes) is not int or not 0 <= encoded_bytes <= MAX_TELEMETRY:
            raise common.ProtocolError(422, "telemetry-size", "telemetry byte count is invalid")
        with self.lock:
            if self.phase not in {"armed", "claimed"}:
                raise common.ProtocolError(410, "telemetry-terminal", "terminal runs reject telemetry")
            if (
                self.telemetry_events >= MAX_TELEMETRY_EVENTS
                or self.telemetry_bytes + encoded_bytes > MAX_TELEMETRY_BYTES
            ):
                raise common.ProtocolError(429, "telemetry-budget-exhausted", "telemetry budget exhausted")
            self.telemetry_events += 1
            self.telemetry_bytes += encoded_bytes
            self.event("BROWSER-TELEMETRY", browser_tag=tag, detail="")

    def _record_commit_uncertain(self, step: str, error: OSError | None) -> None:
        self.phase = "commit-uncertain"
        common.durable_replace(
            self.state_path,
            common.json_bytes(self.document(
                phase="commit-uncertain",
                commit_uncertain_at=common.now(),
                commit_step=step,
                result_sha256=self.pending_result_sha256,
                detail="durable commit outcome is unknown" if error is None else str(error),
                reboot_required=True,
                runtime_observed=False,
                launch_dispatched=None,
            )),
        )
        self.event(
            "COMMIT-UNCERTAIN",
            commit_step=step,
            reboot_required=True,
            runtime_observed=False,
            launch_dispatched=None,
        )

    def complete(self, value: object, client: str) -> None:
        self.require_client(client)
        with self.lock:
            self._require_claimed_phase()
            result = validate_result(value, run_id=self.run_id)
            payload = common.json_bytes(result)
            digest = hashlib.sha256(payload).hexdigest()
            self.pending_result_sha256 = digest
            commit_step = "committing-state"
            try:
                common.durable_replace(
                    self.state_path,
                    common.json_bytes(self.document(
                        phase="committing", committing_at=common.now(),
                        result_sha256=digest, reboot_required=True,
                        runtime_observed=False, launch_dispatched=None,
                    )),
                )
                self.phase = "committing"
                commit_step = "result-publish"
                common.durable_publish(self.result_path, payload)
                commit_step = "final-state"
                common.durable_replace(
                    self.state_path,
                    common.json_bytes(self.document(
                        phase="completed", completed_at=common.now(),
                        result_sha256=digest, ok=result["ok"], code=result["code"],
                        reboot_required=True,
                        launch_dispatched=result["goldhenLaunchDispatched"],
                        runtime_observed=False,
                    )),
                )
            except OSError as error:
                try:
                    self._record_commit_uncertain(commit_step, error)
                except OSError:
                    self.phase = "commit-uncertain"
                raise
            self.phase = "completed"
            self.event(
                "RESULT-COMMITTED",
                ok=result["ok"],
                code=result["code"],
                reboot_required=True,
                launch_dispatched=result["goldhenLaunchDispatched"],
                runtime_observed=False,
            )

    def _abort(self, code: str, detail: str, client: str) -> None:
        with self.lock:
            self.require_client(client)
            if self.phase in {"completed", "aborted", "commit-uncertain"}:
                return
            if self.phase == "committing":
                self._record_commit_uncertain("terminal-abort", None)
                return
            common.durable_replace(
                self.state_path,
                common.json_bytes(self.document(
                    phase="aborted", aborted_at=common.now(), code=code,
                    detail=detail, reboot_required=True,
                    runtime_observed=False, launch_dispatched=None,
                )),
            )
            self.phase = "aborted"
            self.event(
                "RUN-ABORTED",
                code=code,
                detail=detail,
                reboot_required=True,
                runtime_observed=False,
                launch_dispatched=None,
            )

    def abort(self, code: str, detail: str, client: str) -> None:
        if code != "browser-stage-failed" or detail != "browser stage ended without a committed result":
            raise common.ProtocolError(422, "invalid-abort", "abort must use the fixed browser failure shape")
        self._abort(code, detail, client)

    def reject_terminal(self, client: str) -> None:
        self._abort(
            "server-terminal-rejection",
            "authorized terminal request rejected",
            client,
        )


class GoldhenHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    run: GoldhenDualmapRun
    static_root: Path
    static_payloads: Mapping[str, bytes]
    static_hashes: Mapping[str, str]
    hen_bytes: bytes

    def log_message(self, format: str, *args: object) -> None:
        return

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def send_json(self, status: int, value: object, *, close: bool = False) -> None:
        body = common.json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def fail(self, error: common.ProtocolError, *, terminal: bool) -> None:
        if terminal:
            try:
                self.run.reject_terminal(self.client_address[0])
            except common.ProtocolError:
                pass
        self.send_json(error.status, {"error": error.code,"detail": error.detail}, close=True)

    def one_header(self, name: str) -> str:
        values = self.headers.get_all(name, [])
        if len(values) != 1:
            raise common.ProtocolError(400, "invalid-header", f"exactly one {name} header is required")
        return values[0]

    def require_base(self) -> None:
        if self.headers.get_all("User-Agent", []) != [common.CANONICAL_FW14_UA]:
            raise common.ProtocolError(403, "user-agent-mismatch", "exact PS4 firmware 14.00 User-Agent required")
        self.run.require_client(self.client_address[0])
        self.run.require_host(self.one_header("Host"))

    def require_intent(self) -> None:
        self.run.require_intent(self.one_header(INTENT_HEADER))

    def require_empty(self) -> None:
        if self.headers.get("Transfer-Encoding") is not None or self.headers.get_all("Content-Length", []) not in ([], ["0"]):
            raise common.ProtocolError(400, "claim-body-forbidden", "claim body must be empty")

    def read_body(self, cap: int) -> bytes:
        if self.headers.get("Transfer-Encoding") is not None:
            raise common.ProtocolError(400, "transfer-encoding-forbidden", "Content-Length required")
        text = self.one_header("Content-Length")
        if re.fullmatch(r"0|[1-9][0-9]*", text) is None:
            raise common.ProtocolError(400, "invalid-content-length", "Content-Length must be canonical")
        length = int(text)
        if length <= 0 or length > cap:
            raise common.ProtocolError(413 if length > cap else 422, "invalid-body-length", "body length refused")
        body = self.rfile.read(length)
        if len(body) != length:
            raise common.ProtocolError(400, "short-body", "body ended early")
        return body

    def read_json(self) -> object:
        if self.one_header("Content-Type") != "application/json":
            raise common.ProtocolError(415, "content-type-mismatch", "application/json required")
        try:
            return json.loads(self.read_body(MAX_JSON).decode("utf-8"), object_pairs_hook=common.reject_duplicate_object)
        except (UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise common.ProtocolError(400, "invalid-json", str(error)) from error

    def verify_static(self, path: str) -> bytes:
        expected = self.static_hashes.get(path)
        if expected is None:
            raise common.ProtocolError(404, "static-path-refused", "only pinned assets are served")
        try:
            source = (self.static_root / path.removeprefix("/")).resolve(strict=True)
            source.relative_to(self.static_root)
            current = source.read_bytes()
        except (OSError, ValueError) as error:
            raise common.ProtocolError(409, "static-mutated", str(error)) from error
        if not hmac.compare_digest(hashlib.sha256(current).hexdigest(), expected):
            raise common.ProtocolError(409, "static-mutated", "pinned static file changed")
        return self.static_payloads[path]

    def do_GET(self) -> None:
        request = urlsplit(self.path)
        try:
            self.require_base()
            if request.path == "/hx1400-goldhen-dualmap/hen":
                self.require_intent()
                if request.query:
                    raise common.ProtocolError(404, "hen-query-refused", "HEN endpoint accepts no query")
                self.run.ensure_claimed(self.client_address[0])
                body = self.hen_bytes
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if request.path == STAGE_PAGE:
                expected = f"stage={STAGE_NAME}&retry=0&slots={STABLE_SLOTS}&g={STABLE_G}&intent={self.run.intent}"
                if request.query != expected:
                    raise common.ProtocolError(404, "stage-query-refused", "exact stage query required")
            payload = self.verify_static(request.path)
            content_type = mimetypes.guess_type(request.path)[0] or "application/octet-stream"
            if content_type.startswith("text/") or request.path.endswith(".js"):
                content_type += "; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except common.ProtocolError as error:
            self.fail(error, terminal=error.code == "static-mutated")
        except OSError:
            self.close_connection = True

    def do_POST(self) -> None:
        request = urlsplit(self.path)
        authorized = False
        try:
            self.require_base()
            self.require_intent()
            authorized = True
            if request.query:
                raise common.ProtocolError(404, "post-query-refused", "POST endpoints accept no query")
            if request.path == "/hx1400-goldhen-dualmap/claim":
                self.require_empty()
                self.send_json(200, self.run.claim(self.client_address[0]))
                return
            if request.path == "/hx1400-goldhen-dualmap/telemetry":
                if self.one_header("Content-Type") not in {"application/x-www-form-urlencoded","application/x-www-form-urlencoded;charset=UTF-8"}:
                    raise common.ProtocolError(415, "telemetry-content-type", "telemetry must be URL encoded")
                body = self.read_body(MAX_TELEMETRY)
                text = body.decode("utf-8")
                if not text.startswith("HX1400-GOLDHEN&"):
                    raise common.ProtocolError(422, "telemetry-sentinel", "telemetry sentinel mismatch")
                fields = parse_qs(text[len("HX1400-GOLDHEN&"):], keep_blank_values=True, strict_parsing=True)
                if set(fields) != {"tag","detail"} or any(len(values) != 1 for values in fields.values()):
                    raise common.ProtocolError(422, "telemetry-fields", "telemetry requires exactly tag and detail")
                self.run.append_telemetry(fields["tag"][0], fields["detail"][0], len(body))
                self.send_response(204); self.send_header("Content-Length", "0"); self.end_headers(); return
            if request.path == "/hx1400-goldhen-dualmap/result":
                self.run.complete(self.read_json(), self.client_address[0])
                self.send_response(204); self.send_header("Content-Length", "0"); self.end_headers(); return
            if request.path == "/hx1400-goldhen-dualmap/abort":
                value = common.exact_keys(self.read_json(), {"run_id","code","detail"}, "abort")
                if value["run_id"] != self.run.run_id:
                    raise common.ProtocolError(409, "abort-run-mismatch", "abort run ID mismatch")
                self.run.abort(value["code"], value["detail"], self.client_address[0])
                self.send_response(204); self.send_header("Content-Length", "0"); self.end_headers(); return
            raise common.ProtocolError(404, "post-path-refused", "unknown POST endpoint")
        except (UnicodeError, ValueError) as error:
            self.fail(common.ProtocolError(400, "invalid-request", str(error)), terminal=False)
        except common.ProtocolError as error:
            self.fail(error, terminal=authorized and request.path in {"/hx1400-goldhen-dualmap/result","/hx1400-goldhen-dualmap/abort"})
        except OSError as error:
            self.fail(common.ProtocolError(500, "durable-storage-failed", str(error)), terminal=authorized)

    def do_OPTIONS(self) -> None:
        self.fail(common.ProtocolError(405, "method-refused", "OPTIONS is not supported"), terminal=False)


class GoldhenServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def load_manifest(root: Path) -> tuple[Mapping[str, bytes], Mapping[str, str], str]:
    document = json.loads((root / STATIC_MANIFEST_NAME).read_text(encoding="utf-8"), object_pairs_hook=common.reject_duplicate_object)
    document = common.exact_keys(document, {"schema","files"}, "static-manifest")
    if document["schema"] != STATIC_SCHEMA:
        raise ValueError("unsupported GoldHEN static manifest schema")
    if not isinstance(document["files"], dict) or any(not isinstance(path, str) or not isinstance(digest, str) or HEX256.fullmatch(digest) is None for path, digest in document["files"].items()):
        raise ValueError("static manifest files must map paths to lowercase SHA-256")
    payloads, hashes, graph_digest = common.load_static_graph(
        root, document["files"], stage_page=STAGE_PAGE,
    )
    if not hmac.compare_digest(graph_digest, EXPECTED_STATIC_GRAPH_SHA256):
        raise ValueError(
            "reviewed static graph digest mismatch; update EXPECTED_STATIC_GRAPH_SHA256 only after manifest re-review"
        )
    return payloads, hashes, graph_digest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--public-host")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--expected-client")
    parser.add_argument("--state", type=Path)
    parser.add_argument("--events", type=Path)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--boot-tombstone", type=Path)
    parser.add_argument("--confirm-cold-reboot-after")
    parser.add_argument("--hen", type=Path, required=True)
    parser.add_argument("--hen-sha256", required=True)
    parser.add_argument("--trusted-isolated-network", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be in 1..65535")
    if HEX256.fullmatch(args.hen_sha256 or "") is None:
        parser.error("--hen-sha256 must be exact lowercase SHA-256")
    if not hmac.compare_digest(args.hen_sha256, HEN_SHA256):
        parser.error("--hen-sha256 does not match the pinned GoldHEN image")
    try:
        _exact_ipv4(args.host, "--host", allow_unspecified=True)
    except ValueError as error:
        parser.error(str(error))
    if args.public_host is None:
        args.public_host = args.host
    try:
        _exact_ipv4(args.public_host, "--public-host")
    except ValueError as error:
        parser.error(str(error))
    if (
        args.host not in LOOPBACKS or args.public_host not in LOOPBACKS
    ) and not args.trusted_isolated_network:
        parser.error("non-loopback IPv4 binding requires --trusted-isolated-network")
    if not args.check and (
        args.state is None
        or args.events is None
        or args.result is None
        or args.boot_tombstone is None
    ):
        parser.error(
            "live serving requires --state, --events, --result, and --boot-tombstone"
        )
    if args.check and args.confirm_cold_reboot_after is not None:
        parser.error("--confirm-cold-reboot-after is valid only for live serving")
    if args.expected_client is None:
        args.expected_client = "127.0.0.1" if args.host in LOOPBACKS else None
    if not args.check and args.expected_client is None:
        parser.error("non-loopback live serving requires --expected-client")
    if args.expected_client is not None:
        try:
            _exact_ipv4(args.expected_client, "--expected-client")
        except ValueError as error:
            parser.error(str(error))
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve(strict=True)
    static_payloads, static_hashes, static_manifest = load_manifest(root)
    hen_path = args.hen.resolve(strict=True)
    hen_bytes = hen_path.read_bytes()
    try:
        hen_meta = validate_hen(hen_bytes, args.hen_sha256)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print(f"CHECK PASS files={len(static_hashes)} manifest={static_manifest} hen={hen_meta['sha256']} serverConstructed=false bound=false")
    if args.check:
        return 0
    output_paths = [args.state.resolve(), args.events.resolve(), args.result.resolve()]
    tombstone_path = args.boot_tombstone.resolve()
    if len(set(output_paths + [tombstone_path])) != 4:
        raise SystemExit("state, event, result, and boot tombstone paths must differ")
    for path in output_paths:
        if path.exists() or not path.parent.is_dir():
            raise SystemExit(f"refusing output path: {path}")
    if not tombstone_path.parent.is_dir():
        raise SystemExit(f"refusing boot tombstone path: {tombstone_path}")
    for path in output_paths + [tombstone_path]:
        try:
            path.relative_to(root)
        except ValueError:
            pass
        else:
            raise SystemExit(f"durable path must be outside static root: {path}")
    try:
        prepare_boot_tombstone(
            tombstone_path,
            args.confirm_cold_reboot_after,
        )
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    common.durable_create(args.events.resolve(), b"")
    event_log = common.DurableEventLog(args.events.resolve())
    authority = args.public_host if args.port == 80 else f"{args.public_host}:{args.port}"
    run = GoldhenDualmapRun(
        state_path=args.state.resolve(),
        result_path=args.result.resolve(),
        boot_tombstone=tombstone_path,
        event_log=event_log,
        static_manifest=static_manifest,
        expected_client=args.expected_client,
        expected_host=authority,
        hen_meta=hen_meta,
    )
    GoldhenHandler.run = run
    GoldhenHandler.static_root = root
    GoldhenHandler.static_payloads = MappingProxyType(dict(static_payloads))
    GoldhenHandler.static_hashes = MappingProxyType(dict(static_hashes))
    GoldhenHandler.hen_bytes = hen_bytes
    server = GoldhenServer((args.host, args.port), GoldhenHandler)
    print(f"READY http://{authority}{STAGE_PAGE}?stage={STAGE_NAME}&retry=0&slots={STABLE_SLOTS}&g={STABLE_G}&intent={run.intent} run={run.run_id} client={args.expected_client} host={run.expected_host}")
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
