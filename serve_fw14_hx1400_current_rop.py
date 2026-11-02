#!/usr/bin/env python3
"""Strict offline-only host validator for the PS4 FW14 Hx1400 read-only ROP oracle."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Mapping

try:
    from .serve_fw14_kdump import (
        ProtocolError,
        exact_keys,
        exact_uint,
        load_static_graph,
        reject_duplicate_object,
    )
except ImportError:
    from serve_fw14_kdump import (
        ProtocolError,
        exact_keys,
        exact_uint,
        load_static_graph,
        reject_duplicate_object,
    )

STAGE_PAGE = "/fw14_hx1400_current_rop.html"
STAGE_NAME = "fw14-hx1400-current-rop"
STATIC_MANIFEST_NAME = "fw14_hx1400_current_rop_static.json"
RESULT_SCHEMA = "oms.fw14-hx1400-current-rop.result.v1"
STATIC_SCHEMA = "oms.fw14-hx1400-current-rop.static.v1"
MAX_ARMS = 32
LOWMAP_PAGE_BYTES = 0x4000
LOWMAP_MIN_ADDRESS = 0x100000
LOWMAP_ADDRESS_LIMIT = 0x100000000
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
CANDIDATES = (
    128, 96, 160, 64, 192, 32, 224, 120, 136, 88, 104, 152, 168, 56, 72,
    184, 200, 24, 40, 216, 232, 8, 16, 48, 80, 112, 144, 176, 208, 240,
)
SPRAY_MIN = 128
SPRAY_MAX = 144
ORACLE_DIAGNOSTIC_PHASES = frozenset({
    "not-started", "oracle-entered",
    "round-1-request-validated", "round-1-signature-before-ok",
    "round-1-chain-built", "round-1-bridge-returned",
    "round-1-signature-after-ok", "round-1-complete",
    "round-2-request-validated", "round-2-signature-before-ok",
    "round-2-chain-built", "round-2-bridge-returned",
    "round-2-signature-after-ok", "round-2-complete",
    "authority-consumed", "oracle-complete",
})
ORACLE_DIAGNOSTIC_PHASE_RANK = {
    phase: rank for rank, phase in enumerate((
        "not-started", "oracle-entered",
        "round-1-request-validated", "round-1-signature-before-ok",
        "round-1-chain-built", "round-1-bridge-returned",
        "round-1-signature-after-ok", "round-1-complete",
        "round-2-request-validated", "round-2-signature-before-ok",
        "round-2-chain-built", "round-2-bridge-returned",
        "round-2-signature-after-ok", "round-2-complete",
        "authority-consumed", "oracle-complete",
    ))
}
ORACLE_DIAGNOSTIC_REASONS = frozenset({
    "none", "request-validation", "signature-read", "signature-mismatch",
    "chain-build", "bridge-failed", "capture",
    "oracle-module-quarantine", "unknown",
})

RESULT_KEYS = {
    "schema", "ok", "code", "runId", "kbaseValidated", "maxArms", "armsAttempted",
    "possibleBlindWrites", "armRecords", "pairEstablished", "pairRound",
    "pairCandidateIndex", "pairCandidateFd", "pairTargetIndex", "pairTargetFd",
    "kvaSearchOutcome", "kvaSearchAttempts", "kvaSearchFd", "kvaSearchRc",
    "kvaSearchRef", "kvaSearchTreeAccepted", "rotationAttempted", "rotationError",
    "rotationRc", "rotationExpectedOpsMatch", "rotationPredicateMask",
    "kernelRwProved", "challengeWriteAttempted", "challengeWritten",
    "challengeRestored", "lowMapPolicyValidated", "lowMapMapped",
    "lowMapLeaseAcquired", "lowMapUnmapped", "lowMapLeaseRevoked",
    "aioCleanupVerified", "quarantined", "stageCleanupVerified",
    "hostCleanupVerified", "cleanupVerified", "rebootRequired",
    "oracleAttempted", "oracleCode", "oracleKernelMutated", "oracleCleanup",
    "oracleRebootRequired", "oracleExecutions", "oracleSignatureVerified",
    "oracleRopReadOnly", "oracleAuthorityConsumed",
    "oracleDiagnosticPhase", "oracleDiagnosticReason", "oracleSignatureChecks",
    "oracleRoundsStarted", "oracleRoundsCompleted",
    "currentObjectsAuthenticated",
}
BOOL_RESULT_KEYS = {
    "ok", "kbaseValidated", "pairEstablished", "kvaSearchTreeAccepted",
    "rotationAttempted", "rotationExpectedOpsMatch", "kernelRwProved",
    "challengeWriteAttempted", "challengeWritten", "challengeRestored",
    "lowMapPolicyValidated", "lowMapMapped", "lowMapLeaseAcquired",
    "lowMapUnmapped", "lowMapLeaseRevoked", "aioCleanupVerified",
    "quarantined", "stageCleanupVerified", "hostCleanupVerified",
    "cleanupVerified", "rebootRequired", "oracleAttempted",
    "oracleKernelMutated", "oracleCleanup", "oracleRebootRequired",
    "oracleSignatureVerified", "oracleRopReadOnly", "oracleAuthorityConsumed",
    "currentObjectsAuthenticated",
}
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
CONTINUABLE_ARM_OUTCOMES = frozenset({"evadd-failed", "no-match"})
QUARANTINE_ARM_OUTCOMES = frozenset({
    "event-delete-failed", "pair-delete-failed", "cleanup-failed",
})
KVA_SEARCH_OUTCOMES = frozenset({
    "accepted", "exhausted", "ref-mutated", "rejected-tree", "setsockopt-error",
})
NO_KVA_CODES = {
    "exhausted": "NO_KVA_EXHAUSTED",
    "ref-mutated": "NO_KVA_REF_MUTATED",
    "rejected-tree": "NO_KVA_REJECTED_TREE",
    "setsockopt-error": "NO_KVA_SETSOCKOPT",
}
ORACLE_SUCCESS_CODE = "OK_CURRENT_OBJECTS"
ORACLE_FAILURE_CODES = frozenset({
    "ERR_QUARANTINED", "ERR_REENTRANT", "ERR_GENERATION_CLOSED",
    "ERR_CONTEXT", "ERR_EXECUTOR", "ERR_EXECUTION",
    "ERR_ORACLE_DRIFT", "ERR_VALIDATION",
})
ORACLE_AMBIGUOUS_CODES = frozenset({
    "ERR_QUARANTINED", "ERR_REENTRANT",
})
ORACLE_EXECUTION_COUNTS = {
    "ERR_QUARANTINED": frozenset({0}),
    "ERR_REENTRANT": frozenset({0}),
    "ERR_GENERATION_CLOSED": frozenset({0}),
    "ERR_CONTEXT": frozenset({0}),
    "ERR_EXECUTOR": frozenset({0}),
    "ERR_EXECUTION": frozenset({0, 1, 2}),
    "ERR_ORACLE_DRIFT": frozenset({2}),
    "ERR_VALIDATION": frozenset({0}),
}

ORACLE_RESULT_CODES = ORACLE_FAILURE_CODES

POST_KVA_CODES = frozenset({
    "RB_GADGET", "ROTATION_GATE", "FAKE_OPS_READBACK", "BRIDGE_KQUEUE",
    "BRIDGE_EV_ADD", "BRIDGE_PROBE", "KRW_READ_BRIDGE", "KRW_WRITE_BRIDGE",
    "CHALLENGE_WRITE_READBACK",
    "CHALLENGE_RESTORE_READBACK", "ERR_GADGET_SIGNATURE", "STAGE_CLEANUP_UNVERIFIED",
    "OK_CURRENT_OBJECTS_REBOOT_REQUIRED",
}) | ORACLE_RESULT_CODES
ACCEPTED_KVA_CODES = POST_KVA_CODES | frozenset({
    "THREW", "HOST_CLEANUP_UNVERIFIED",
})
ROTATION_ERRORS = frozenset({
    "invocation", "snapshot", "invocation-and-snapshot",
})
PRE_CHALLENGE_CODES = frozenset({
    "RB_GADGET", "ROTATION_GATE", "FAKE_OPS_READBACK", "BRIDGE_KQUEUE",
    "BRIDGE_EV_ADD", "BRIDGE_PROBE",
})





def exact_signed(value: object, name: str) -> int:
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise ProtocolError(422, f"invalid-{name}", f"{name} must be a signed 32-bit integer")
    return value


def exact_nullable_uint(value: object, name: str, maximum: int) -> int | None:
    if value is None:
        return None
    return exact_uint(value, name, maximum)


def exact_nullable_signed(value: object, name: str) -> int | None:
    if value is None:
        return None
    return exact_signed(value, name)

def valid_lowmap_page(base: int) -> bool:
    return (
        LOWMAP_MIN_ADDRESS <= base
        and base % LOWMAP_PAGE_BYTES == 0
        and base + LOWMAP_PAGE_BYTES <= LOWMAP_ADDRESS_LIMIT
    )


def validate_arm_record(value: object, sequence: int) -> dict[str, Any]:
    record = exact_keys(value, ARM_KEYS, "arm-record")
    if exact_uint(record["sequence"], "arm-sequence", MAX_ARMS) != sequence:
        raise ProtocolError(422, "invalid-arm-sequence", "arm records must be contiguous and ordered")
    spray_count = exact_uint(record["sprayCount"], "spray-count", SPRAY_MAX)
    if spray_count < SPRAY_MIN:
        raise ProtocolError(422, "invalid-spray-count", "armed sweep requires 128..144 spray sockets")
    round_number = exact_uint(record["round"], "arm-round", 6)
    if round_number < 1:
        raise ProtocolError(422, "invalid-arm-round", "arm round must be in 1..6")
    candidate = exact_uint(record["candidateIndex"], "candidate-index", 0x10000)
    if candidate not in CANDIDATES:
        raise ProtocolError(422, "invalid-candidate-index", "candidate is not in the recovered BD-J order")
    if candidate >= spray_count:
        raise ProtocolError(422, "candidate-outside-spray", "candidate index must be inside the recorded spray")
    exact_uint(record["candidateFd"], "candidate-fd", 0x7FFFFFFF)
    exact_uint(record["dceFd"], "dce-fd", 0x7FFFFFFF)
    ev_add = exact_nullable_signed(record["evAddRc"], "ev-add-rc")
    scan_ok = exact_uint(record["scanOk"], "scan-ok", SPRAY_MAX)
    scan_errors = exact_uint(record["scanErrors"], "scan-errors", SPRAY_MAX)
    non_stock = exact_uint(record["nonStockOptions"], "non-stock-options", SPRAY_MAX)
    matches = exact_uint(record["matches"], "matches", SPRAY_MAX)
    repair_failures = exact_uint(record["repairFailures"], "repair-failures", SPRAY_MAX)
    if scan_ok + scan_errors > spray_count - 1:
        raise ProtocolError(422, "arm-scan-count-mismatch", "scan counters exceed all non-candidate sockets")
    if matches + non_stock > scan_ok:
        raise ProtocolError(422, "arm-scan-counter-mismatch", "match and non-stock counters exceed successful scans")
    target_index = exact_nullable_uint(record["targetIndex"], "target-index", SPRAY_MAX - 1)
    target_fd = exact_nullable_uint(record["targetFd"], "target-fd", 0x7FFFFFFF)
    if (target_index is None) != (target_fd is None):
        raise ProtocolError(422, "invalid-arm-target", "target index and descriptor must be jointly null or present")
    if target_index is not None and (target_index >= spray_count or target_index == candidate):
        raise ProtocolError(422, "invalid-arm-target", "target must be a distinct socket inside the recorded spray")
    ev_delete = exact_nullable_signed(record["evDeleteRc"], "ev-delete-rc")
    candidate_restore = exact_nullable_signed(record["candidateRestoreRc"], "candidate-restore-rc")
    dce_close = record["dceCloseOk"]
    if dce_close is not None and type(dce_close) is not bool:
        raise ProtocolError(422, "invalid-dce-close", "dceCloseOk must be null or boolean")
    outcome = record["outcome"]
    if not isinstance(outcome, str) or outcome not in ARM_OUTCOMES:
        raise ProtocolError(422, "invalid-arm-outcome", "unknown arm outcome")

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
        interrupted_ok = (
            progression_ok
            and candidate_restore is None
            and repair_failures == 0
            and dce_close is None
        )
        if not interrupted_ok:
            raise ProtocolError(422, "arm-outcome-mismatch", "interrupted arm fields violate producer progression")
        return record

    if ev_add is None:
        raise ProtocolError(422, "arm-outcome-mismatch", "completed arm requires an EV_ADD result")
    if ev_add != 0:
        if (
            scanned != 0 or non_stock != 0 or matches != 0 or target_recorded
            or ev_delete is not None or candidate_restore is not None
        ):
            raise ProtocolError(422, "arm-outcome-mismatch", "failed EV_ADD cannot report a victim scan")
    else:
        if scanned != spray_count - 1:
            raise ProtocolError(422, "arm-scan-count-mismatch", "completed EV_ADD requires a complete victim scan")
        if target_recorded != (matches == 1):
            raise ProtocolError(422, "arm-target-count-mismatch", "target metadata requires exactly one marker match")
        pair_scan = matches == 1 and scan_errors == 0
        if pair_scan:
            if ev_delete is None or candidate_restore is None:
                raise ProtocolError(422, "arm-outcome-mismatch", "unique complete scan requires delete and restore results")
        elif ev_delete is None or candidate_restore is not None:
            raise ProtocolError(422, "arm-outcome-mismatch", "non-pair scan requires only an event-delete result")

    cleanup_ok = repair_failures == 0 and dce_close is True
    cleanup_failed = dce_close is not None and (repair_failures != 0 or dce_close is False)
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
        raise ProtocolError(422, "arm-outcome-mismatch", "arm fields do not match the reported terminal state")
    return record


def validate_result(value: object, *, run_id: str) -> dict[str, Any]:
    result = exact_keys(value, RESULT_KEYS, "result")
    if result["schema"] != RESULT_SCHEMA:
        raise ProtocolError(422, "invalid-result-schema", "result schema mismatch")
    if result["runId"] != run_id:
        raise ProtocolError(409, "result-identity-mismatch", "result run ID does not match the claim")
    if not isinstance(result["code"], str) or not 1 <= len(result["code"]) <= 160:
        raise ProtocolError(422, "invalid-result-code", "result code must be bounded and nonempty")
    for key in BOOL_RESULT_KEYS:
        if type(result[key]) is not bool:
            raise ProtocolError(422, "invalid-result-boolean", f"{key} must be boolean")
    if result["ok"] != (result["code"] == "OK_CURRENT_OBJECTS_REBOOT_REQUIRED"):
        raise ProtocolError(422, "result-status-mismatch", "only OK_CURRENT_OBJECTS_REBOOT_REQUIRED may report ok=true")
    if exact_uint(result["maxArms"], "max-arms", MAX_ARMS) != MAX_ARMS:
        raise ProtocolError(422, "invalid-max-arms", "result must retain the fixed 32-arm claim")
    attempted = exact_uint(result["armsAttempted"], "arms-attempted", MAX_ARMS)
    possible_blind = exact_uint(result["possibleBlindWrites"], "possible-blind-writes", MAX_ARMS)
    records = result["armRecords"]
    if not isinstance(records, list) or len(records) != attempted:
        raise ProtocolError(422, "invalid-arm-record-count", "one arm record is required per attempted EV_ADD")
    validated = [validate_arm_record(record, index + 1) for index, record in enumerate(records)]

    spray_count = validated[0]["sprayCount"] if validated else None
    if spray_count is not None and any(record["sprayCount"] != spray_count for record in validated):
        raise ProtocolError(422, "spray-count-drift", "one run must retain a fixed spray cardinality")
    spray_by_index: dict[int, int] = {}
    spray_by_fd: dict[int, int] = {}
    dce_fds: set[int] = set()
    for record in validated:
        dce_fds.add(record["dceFd"])
        identities = [(record["candidateIndex"], record["candidateFd"])]
        if record["targetIndex"] is not None:
            identities.append((record["targetIndex"], record["targetFd"]))
        for index, fd in identities:
            previous_fd = spray_by_index.get(index)
            if previous_fd is not None and previous_fd != fd:
                raise ProtocolError(422, "spray-fd-drift", "one spray index changed descriptor identity")
            previous_index = spray_by_fd.get(fd)
            if previous_index is not None and previous_index != index:
                raise ProtocolError(422, "spray-fd-alias", "distinct spray indices cannot share one descriptor")
            spray_by_index[index] = fd
            spray_by_fd[fd] = index
    ordered_identities = sorted(spray_by_index.items())
    if any(
        left_fd >= right_fd
        for (_, left_fd), (_, right_fd) in zip(ordered_identities, ordered_identities[1:])
    ):
        raise ProtocolError(422, "spray-fd-order-mismatch", "spray descriptors must increase with socket index")
    if dce_fds.intersection(spray_by_fd):
        raise ProtocolError(422, "dce-spray-fd-alias", "DCE and spray descriptors must be disjoint")
    schedule = [
        (round_number, candidate)
        for round_number in range(1, 7)
        for candidate in CANDIDATES
        if spray_count is not None and candidate < spray_count
    ]
    cursor = 0
    for record in validated:
        needle = (record["round"], record["candidateIndex"])
        try:
            cursor = schedule.index(needle, cursor) + 1
        except ValueError as error:
            raise ProtocolError(422, "arm-order-mismatch", "arm records violate recovered round/candidate order") from error
    if any(record["outcome"] not in CONTINUABLE_ARM_OUTCOMES for record in validated[:-1]):
        raise ProtocolError(422, "terminal-arm-continued", "producer cannot arm again after a terminal arm outcome")

    paired = [record for record in validated if record["outcome"] == "paired"]
    if len(paired) != (1 if result["pairEstablished"] else 0):
        raise ProtocolError(422, "pair-count-mismatch", "result pair flag does not match arm records")
    expected_blind = attempted - (1 if result["pairEstablished"] else 0)
    if possible_blind != expected_blind:
        raise ProtocolError(422, "blind-write-accounting-mismatch", "every non-paired arm must remain a possible blind write")

    pair_fields = (
        "pairRound", "pairCandidateIndex", "pairCandidateFd", "pairTargetIndex", "pairTargetFd"
    )
    if result["pairEstablished"]:
        if attempted == 0 or paired[0] is not validated[-1]:
            raise ProtocolError(422, "pair-not-terminal", "the first unique pair must terminate the sweep")
        pair = paired[0]
        expected = (
            pair["round"], pair["candidateIndex"], pair["candidateFd"],
            pair["targetIndex"], pair["targetFd"],
        )
        if tuple(result[key] for key in pair_fields) != expected:
            raise ProtocolError(422, "pair-metadata-mismatch", "result pair metadata must match the paired arm")
    elif any(result[key] is not None for key in pair_fields):
        raise ProtocolError(422, "pair-metadata-overclaim", "unpaired result must use null pair metadata")
    lifecycle = (
        result["lowMapMapped"],
        result["lowMapLeaseAcquired"],
        result["lowMapUnmapped"],
        result["lowMapLeaseRevoked"],
    )
    if result["pairEstablished"]:
        pair = paired[0]
        requested = ((((pair["dceFd"] & 0xFFFF) << 16) | 0x9800) & 0xFFFFC000)
        expected_policy = valid_lowmap_page(requested)
        if result["lowMapPolicyValidated"] != expected_policy:
            raise ProtocolError(
                422,
                "lowmap-policy-mismatch",
                "lowMapPolicyValidated must derive from the paired DCE page",
            )
        if not expected_policy and (
            result["code"] != "LOWMAP_RANGE"
            or result["ok"]
            or any(lifecycle)
            or result["kernelRwProved"]
            or result["challengeWriteAttempted"]
            or result["challengeWritten"]
            or result["challengeRestored"]
        ):
            raise ProtocolError(
                422,
                "lowmap-address-out-of-policy",
                "an out-of-policy page may report only a pre-mmap LOWMAP_RANGE stop",
            )
    elif result["lowMapPolicyValidated"] or any(lifecycle):
        raise ProtocolError(
            422,
            "lowmap-unpaired-overclaim",
            "an unpaired result must use false low-map policy and lifecycle flags",
        )
    if result["lowMapLeaseAcquired"] and not result["lowMapMapped"]:
        raise ProtocolError(422, "lowmap-lease-without-map", "lease acquisition requires a mapped page")
    if result["lowMapUnmapped"] and not result["lowMapMapped"]:
        raise ProtocolError(422, "lowmap-unmap-without-map", "unmap requires a mapped page")
    if result["lowMapLeaseRevoked"] and not (
        result["lowMapLeaseAcquired"] and result["lowMapUnmapped"]
    ):
        raise ProtocolError(
            422,
            "lowmap-revoke-order",
            "lease revocation requires acquisition and successful unmap",
        )

    search_outcome = result["kvaSearchOutcome"]
    search_fields = (result["kvaSearchFd"], result["kvaSearchRc"])
    search_attempts = exact_uint(
        result["kvaSearchAttempts"], "kva-search-attempts", 96
    )
    search_ref = exact_uint(
        result["kvaSearchRef"], "kva-search-ref", 0xFFFFFFFF
    )
    if search_outcome is None:
        if (
            search_attempts != 0
            or search_ref != 0
            or any(field is not None for field in search_fields)
            or result["kvaSearchTreeAccepted"]
        ):
            raise ProtocolError(
                422, "kva-search-before-start",
                "unstarted KVA search requires null fields, false acceptance, and zero counters",
            )
        if (
            result["code"] in POST_KVA_CODES
            or result["code"] in NO_KVA_CODES.values()
            or result["kernelRwProved"]
            or result["challengeWriteAttempted"]
            or result["challengeWritten"]
            or result["challengeRestored"]
        ):
            raise ProtocolError(
                422, "kva-search-acceptance-required",
                "post-pair proof progress requires an accepted KVA search",
            )
    else:
        if search_outcome not in KVA_SEARCH_OUTCOMES:
            raise ProtocolError(
                422, "invalid-kva-search-outcome", "unknown KVA search outcome",
            )
        if not (
            result["pairEstablished"]
            and result["lowMapPolicyValidated"]
            and result["lowMapMapped"]
            and result["lowMapLeaseAcquired"]
        ):
            raise ProtocolError(
                422, "kva-search-lifecycle-mismatch",
                "KVA search requires the paired mapped-page lifecycle",
            )
        if not 1 <= search_attempts <= 96:
            raise ProtocolError(
                422, "invalid-kva-search-attempts", "KVA search attempts must be in 1..96",
            )
        exact_uint(result["kvaSearchFd"], "kva-search-fd", 0x7FFFFFFF)
        exact_signed(result["kvaSearchRc"], "kva-search-rc")
        if search_outcome == "accepted":
            if search_ref != 2 or not result["kvaSearchTreeAccepted"]:
                raise ProtocolError(
                    422, "kva-search-outcome-mismatch",
                    "accepted requires ref=2 and the private tree predicate",
                )
            if result["code"] not in ACCEPTED_KVA_CODES:
                raise ProtocolError(
                    422, "kva-search-code-mismatch",
                    "accepted KVA requires success or an enumerated post-KVA failure",
                )
        else:
            if result["kvaSearchTreeAccepted"]:
                raise ProtocolError(
                    422, "kva-search-acceptance-overclaim",
                    "a non-accepted KVA outcome cannot report an accepted private tree",
                )
            if result["code"] != NO_KVA_CODES[search_outcome]:
                raise ProtocolError(
                    422, "kva-search-code-mismatch",
                    "NO_KVA terminal code must exactly match the persisted outcome",
                )
            if (
                result["kernelRwProved"]
                or result["challengeWriteAttempted"]
                or result["challengeWritten"]
                or result["challengeRestored"]
            ):
                raise ProtocolError(
                    422, "kva-search-overclaim",
                    "non-accepted KVA search forbids KRW or challenge progress",
                )
            outcome_valid = {
                "exhausted": search_attempts == 96 and search_ref == 2 and result["kvaSearchRc"] == 0,
                "ref-mutated": search_ref != 2,
                "rejected-tree": search_ref == 2,
                "setsockopt-error": search_attempts == 96 and search_ref == 2 and result["kvaSearchRc"] != 0,
            }[search_outcome]
            if not outcome_valid:
                raise ProtocolError(
                    422, "kva-search-outcome-mismatch",
                    "persisted KVA predicates do not match the terminal outcome",
                )

    if attempted and not result["kbaseValidated"]:
        raise ProtocolError(
            422, "armed-without-kbase",
            "an armed run requires its private kernel base validation",
        )
    rotation_java_ok = False
    rotation_complete = False
    if not result["rotationAttempted"]:
        if (
            result["rotationError"] is not None
            or result["rotationRc"] is not None
            or result["rotationPredicateMask"] is not None
            or result["rotationExpectedOpsMatch"]
        ):
            raise ProtocolError(
                422,
                "rotation-before-start",
                "an unattempted rotation requires empty diagnostics",
            )
        if (
            result["challengeWriteAttempted"]
            or result["challengeWritten"]
            or result["challengeRestored"]
            or result["kernelRwProved"]
        ):
            raise ProtocolError(
                422,
                "proof-without-complete-rotation",
                "challenge or KRW progress requires a complete recovered-Java rotation",
            )
        if result["code"] == "ROTATION_GATE" or result["code"] in POST_ROTATION_CODES:
            raise ProtocolError(
                422,
                "rotation-attempt-underclaimed",
                "the terminal code requires an operation-3 rotation",
            )
    else:
        if search_outcome != "accepted" or not result["kbaseValidated"] or not paired:
            raise ProtocolError(
                422,
                "rotation-identity-missing",
                "rotation validation requires accepted KVA, pair, and private KBASE validation",
            )
        rotation_error = result["rotationError"]
        if rotation_error is not None:
            if not isinstance(rotation_error, str) or rotation_error not in ROTATION_ERRORS:
                raise ProtocolError(
                    422,
                    "invalid-rotation-error",
                    "rotationError must be an exact invocation/snapshot discriminator",
                )
            if result["code"] != "THREW":
                raise ProtocolError(
                    422, "rotation-error-code-mismatch",
                    "an operation-3 invocation/snapshot error requires THREW",
                )
            if rotation_error == "snapshot":
                exact_signed(result["rotationRc"], "rotation-rc")
            elif result["rotationRc"] is not None:
                raise ProtocolError(
                    422, "rotation-error-rc-mismatch",
                    "an invocation error cannot report a synthetic setsockopt rc",
                )
            if result["rotationPredicateMask"] is not None:
                raise ProtocolError(
                    422, "rotation-error-mask-overclaim",
                    "an invocation/snapshot error cannot report a predicate mask",
                )
            if not (
                result["quarantined"]
                and not result["stageCleanupVerified"]
                and not result["hostCleanupVerified"]
                and not result["cleanupVerified"]
                and result["lowMapMapped"]
                and result["lowMapLeaseAcquired"]
                and not result["lowMapUnmapped"]
                and not result["lowMapLeaseRevoked"]
                and not result["challengeWriteAttempted"]
                and not result["challengeWritten"]
                and not result["challengeRestored"]
                and not result["kernelRwProved"]
            ):
                raise ProtocolError(
                    422, "rotation-error-lifecycle-mismatch",
                    "operation-3 errors require quarantine with the low map retained",
                )
        else:
            rotation_rc = exact_signed(result["rotationRc"], "rotation-rc")
            rotation_mask = exact_uint(
                result["rotationPredicateMask"], "rotation-predicate-mask", 0x3FF
            )
            if result["rotationExpectedOpsMatch"] != bool(rotation_mask & (1 << 9)):
                raise ProtocolError(
                    422, "rotation-expected-ops-mismatch",
                    "expected-ops predicate must exactly match mask bit 9",
                )
            rotation_java_ok = (rotation_mask & 0x1FF) == 0x1FF
            rotation_complete = rotation_java_ok
            if result["code"] == "RB_GADGET":
                raise ProtocolError(
                    422, "rotation-after-rb-failure",
                    "RB_GADGET must stop before operation 3",
                )
            if result["code"] == "ROTATION_GATE" and rotation_java_ok:
                raise ProtocolError(
                    422, "rotation-gate-mismatch",
                    "ROTATION_GATE requires at least one recovered-Java predicate bit to be false",
                )
            if not rotation_java_ok and result["code"] != "ROTATION_GATE":
                raise ProtocolError(
                    422, "rotation-gate-code-mismatch",
                    "a failed rotation mask must terminate as ROTATION_GATE",
                )
            if result["code"] == "ROTATION_GATE" and not (
                result["quarantined"]
                and not result["stageCleanupVerified"]
                and not result["hostCleanupVerified"]
                and not result["cleanupVerified"]
                and not result["lowMapUnmapped"]
                and not result["lowMapLeaseRevoked"]
            ):
                raise ProtocolError(
                    422, "rotation-gate-lifecycle-mismatch",
                    "ROTATION_GATE requires quarantine with a retained low map",
                )
    proof_progress = (
        result["challengeWriteAttempted"]
        or result["challengeWritten"]
        or result["challengeRestored"]
        or result["kernelRwProved"]
    )
    if proof_progress and not rotation_complete:
        raise ProtocolError(
            422,
            "proof-without-complete-rotation",
            "challenge or KRW progress requires a complete recovered-Java rotation",
        )
    if result["code"] in PRE_CHALLENGE_CODES and proof_progress:
        raise ProtocolError(
            422,
            "producer-phase-progress-mismatch",
            "the terminal code occurs before any challenge or KRW progress",
        )
    if result["code"] in {"KRW_READ_BRIDGE", "KRW_WRITE_BRIDGE"} and (
        result["challengeWritten"] or result["kernelRwProved"]
    ):
        raise ProtocolError(
            422,
            "producer-phase-progress-mismatch",
            "a KRW bridge failure cannot claim a completed challenge write or proof",
        )
    if (
        result["code"] == "KRW_WRITE_BRIDGE"
        and not result["challengeWriteAttempted"]
    ):
        raise ProtocolError(
            422,
            "producer-phase-progress-mismatch",
            "KRW_WRITE_BRIDGE cannot occur before the challenge write attempt",
        )
    if result["code"] == "CHALLENGE_WRITE_READBACK" and not (
        result["challengeWriteAttempted"]
        and not result["challengeWritten"]
        and not result["kernelRwProved"]
    ):
        raise ProtocolError(
            422,
            "producer-phase-progress-mismatch",
            "CHALLENGE_WRITE_READBACK requires an attempted but unproved write",
        )
    if result["code"] == "CHALLENGE_RESTORE_READBACK" and not (
        result["challengeWriteAttempted"]
        and result["challengeWritten"]
        and not result["kernelRwProved"]
    ):
        raise ProtocolError(
            422,
            "producer-phase-progress-mismatch",
            "CHALLENGE_RESTORE_READBACK requires a written but unproved challenge",
        )
    written_unproved = (
        result["challengeWriteAttempted"]
        and result["challengeWritten"]
        and not result["kernelRwProved"]
    )
    if written_unproved and result["code"] != "CHALLENGE_RESTORE_READBACK":
        raise ProtocolError(
            422,
            "producer-phase-progress-mismatch",
            "a written but unproved challenge must terminate as CHALLENGE_RESTORE_READBACK",
        )
    reversible_proof = (
        result["challengeWriteAttempted"]
        and result["challengeWritten"]
        and result["challengeRestored"]
        and result["kernelRwProved"]
    )
    if result["code"] in ({
        "STAGE_CLEANUP_UNVERIFIED",
        "HOST_CLEANUP_UNVERIFIED",
        "OK_CURRENT_OBJECTS_REBOOT_REQUIRED",
    } | ORACLE_RESULT_CODES) and not reversible_proof:
        raise ProtocolError(
            422,
            "producer-phase-progress-mismatch",
            "cleanup completion and success codes require the reversible KRW proof",
        )
    if result["challengeWritten"] and not result["challengeWriteAttempted"]:
        raise ProtocolError(422, "challenge-attempt-underclaimed", "challenge write requires an attempt record")
    if result["challengeRestored"] and not result["challengeWriteAttempted"]:
        raise ProtocolError(422, "challenge-restore-underclaimed", "challenge restore requires an attempt record")
    if (
        result["challengeWriteAttempted"]
        and not result["challengeRestored"]
        and (result["stageCleanupVerified"] or result["cleanupVerified"])
    ):
        raise ProtocolError(
            422, "challenge-cleanup-overclaim",
            "an unrestored challenge forbids verified stage or overall cleanup",
        )
    if result["kernelRwProved"] and not (
        result["pairEstablished"]
        and result["challengeWriteAttempted"]
        and result["challengeWritten"]
        and result["challengeRestored"]
    ):
        raise ProtocolError(422, "kernel-proof-incomplete", "kernel R/W proof requires a unique pair and reversible challenge")
    oracle_code = result["oracleCode"]
    if oracle_code is not None and (
        not isinstance(oracle_code, str) or oracle_code not in (
            ORACLE_FAILURE_CODES | {ORACLE_SUCCESS_CODE}
        )
    ):
        raise ProtocolError(
            422,
            "invalid-oracle-code",
            "oracleCode must be null or an enumerated current-object oracle terminal code",
        )
    oracle_executions = exact_uint(
        result["oracleExecutions"], "oracle-executions", 2
    )
    diagnostic_phase = result["oracleDiagnosticPhase"]
    diagnostic_reason = result["oracleDiagnosticReason"]
    if type(diagnostic_phase) is not str or diagnostic_phase not in ORACLE_DIAGNOSTIC_PHASES:
        raise ProtocolError(422, "invalid-oracle-diagnostic-phase", "oracleDiagnosticPhase must be an enumerated phase")
    if type(diagnostic_reason) is not str or diagnostic_reason not in ORACLE_DIAGNOSTIC_REASONS:
        raise ProtocolError(422, "invalid-oracle-diagnostic-reason", "oracleDiagnosticReason must be an enumerated reason")
    signature_checks = exact_uint(
        result["oracleSignatureChecks"], "oracle-signature-checks", 4
    )
    rounds_started = exact_uint(
        result["oracleRoundsStarted"], "oracle-rounds-started", 2
    )
    rounds_completed = exact_uint(
        result["oracleRoundsCompleted"], "oracle-rounds-completed", 2
    )
    if rounds_completed > rounds_started or oracle_executions != rounds_completed:
        raise ProtocolError(422, "oracle-diagnostic-counter-order", "oracle diagnostic counters violate round order")
    expected_by_phase = {
        "not-started": (0, 0, 0), "oracle-entered": (0, 0, 0),
        "round-1-request-validated": (0, 0, 0),
        "round-1-signature-before-ok": (1, 0, 0),
        "round-1-chain-built": (1, 1, 0),
        "round-1-bridge-returned": (1, 1, 0),
        "round-1-signature-after-ok": (2, 1, 0),
        "round-1-complete": (2, 1, 1),
        "round-2-request-validated": (2, 1, 1),
        "round-2-signature-before-ok": (3, 1, 1),
        "round-2-chain-built": (3, 2, 1),
        "round-2-bridge-returned": (3, 2, 1),
        "round-2-signature-after-ok": (4, 2, 1),
        "round-2-complete": (4, 2, 2),
        "authority-consumed": (4, 2, 2),
        "oracle-complete": (4, 2, 2),
    }[diagnostic_phase]
    if (signature_checks, rounds_started, rounds_completed) != expected_by_phase:
        raise ProtocolError(422, "oracle-diagnostic-phase-counter-mismatch", "oracle counters must exactly match the reported phase")
    if result["oracleSignatureVerified"] != (signature_checks == 4 and rounds_completed == 2):
        raise ProtocolError(422, "oracle-signature-aggregate-mismatch", "signature aggregate must derive from four exact checks")
    if result["oracleRopReadOnly"] != (rounds_started > 0 and rounds_started == rounds_completed):
        raise ProtocolError(422, "oracle-round-aggregate-mismatch", "read-only aggregate must derive from completed rounds")
    expected_authority = diagnostic_phase in {"authority-consumed", "oracle-complete"}
    if result["oracleAuthorityConsumed"] != expected_authority:
        raise ProtocolError(422, "oracle-authority-phase-mismatch", "authority consumption must exactly match the diagnostic phase")
    if result["oracleKernelMutated"]:
        raise ProtocolError(
            422,
            "oracle-kernel-mutation",
            "the read-only current-object oracle must never report a kernel mutation",
        )
    if not result["oracleAttempted"]:
        if (
            oracle_code is not None
            or oracle_executions != 0
            or result["oracleCleanup"]
            or result["oracleRebootRequired"]
            or result["oracleSignatureVerified"]
            or result["oracleRopReadOnly"]
            or result["oracleAuthorityConsumed"]
            or result["currentObjectsAuthenticated"]
            or diagnostic_phase != "not-started"
            or diagnostic_reason != "none"
            or signature_checks != 0
            or rounds_started != 0
            or rounds_completed != 0
        ):
            raise ProtocolError(
                422,
                "pre-oracle-progress-overclaim",
                "an unattempted oracle requires null code, zero executions, and false oracle state",
            )
        if (
            result["code"] == "OK_CURRENT_OBJECTS_REBOOT_REQUIRED"
            or result["code"] in ORACLE_RESULT_CODES
        ):
            raise ProtocolError(
                422,
                "oracle-attempt-underclaimed",
                "an oracle terminal code requires an attempted oracle",
            )
    else:
        if diagnostic_phase == "not-started":
            raise ProtocolError(422, "oracle-diagnostic-attempt-underclaimed", "an attempted oracle requires diagnostic progress")
        if result["quarantined"] and not result["oracleCleanup"] and diagnostic_reason == "none":
            raise ProtocolError(422, "oracle-diagnostic-reason-missing", "quarantined oracle ambiguity requires a bounded failure reason")
        if not reversible_proof:
            raise ProtocolError(
                422,
                "oracle-before-reversible-proof",
                "the current-object oracle requires the corrected reversible KRW proof",
            )
        if oracle_code is None:
            raise ProtocolError(
                422, "oracle-code-missing", "an attempted oracle requires a terminal code"
            )
        if diagnostic_phase == "oracle-complete" and not (
            oracle_code == ORACLE_SUCCESS_CODE
            and oracle_executions == 2
            and result["oracleCleanup"]
            and not result["oracleRebootRequired"]
            and result["currentObjectsAuthenticated"]
        ):
            raise ProtocolError(
                422,
                "oracle-diagnostic-complete-mismatch",
                "oracle-complete requires the successful two-round oracle tuple",
            )
        expected_result_code = (
            "OK_CURRENT_OBJECTS_REBOOT_REQUIRED"
            if oracle_code == ORACLE_SUCCESS_CODE
            else "ERR_GADGET_SIGNATURE"
            if diagnostic_reason == "signature-mismatch"
            else oracle_code
        )
        if result["code"] not in {
            expected_result_code,
            "STAGE_CLEANUP_UNVERIFIED",
            "HOST_CLEANUP_UNVERIFIED",
        }:
            raise ProtocolError(
                422,
                "oracle-code-mismatch",
                "the stage result must preserve the oracle terminal code unless cleanup failed",
            )
        if (
            oracle_code in ORACLE_FAILURE_CODES
            and oracle_executions not in ORACLE_EXECUTION_COUNTS[oracle_code]
        ):
            raise ProtocolError(
                422,
                "oracle-execution-phase-mismatch",
                "oracle execution count is impossible for the reported terminal code",
            )
        if result["oracleCleanup"] == result["oracleRebootRequired"]:
            raise ProtocolError(
                422,
                "oracle-cleanup-reboot-mismatch",
                "oracle cleanup and oracle reboot requirement must be logical opposites",
            )
        authenticated_tuple = (
            oracle_executions == 2
            and result["oracleCleanup"]
            and not result["oracleRebootRequired"]
            and result["oracleSignatureVerified"]
            and result["oracleRopReadOnly"]
            and result["oracleAuthorityConsumed"]
        )
        if result["currentObjectsAuthenticated"] and not authenticated_tuple:
            raise ProtocolError(
                422,
                "oracle-authentication-overclaim",
                "authentication requires two executions and complete executor/output cleanup",
            )
        if oracle_code == ORACLE_SUCCESS_CODE:
            if not (
                diagnostic_phase == "oracle-complete"
                and diagnostic_reason == "none"
                and signature_checks == 4
                and rounds_started == 2
                and rounds_completed == 2
                and authenticated_tuple
                and result["currentObjectsAuthenticated"]
                and not result["oracleKernelMutated"]
            ):
                raise ProtocolError(
                    422,
                    "oracle-success-incomplete",
                    "oracle success requires two authenticated executions and complete cleanup",
                )
        elif oracle_code in ORACLE_AMBIGUOUS_CODES:
            if not (
                result["code"] == oracle_code
                and not result["oracleCleanup"]
                and result["oracleRebootRequired"]
                and not result["oracleAuthorityConsumed"]
                and not result["currentObjectsAuthenticated"]
                and result["quarantined"]
                and not result["stageCleanupVerified"]
                and not result["hostCleanupVerified"]
                and not result["cleanupVerified"]
            ):
                raise ProtocolError(
                    422,
                    "oracle-ambiguity-lifecycle-mismatch",
                    "executor ambiguity requires quarantine, retained output, and reboot",
                )
        else:
            if not (
                result["oracleCleanup"]
                and not result["oracleRebootRequired"]
                and not result["oracleAuthorityConsumed"]
                and not result["currentObjectsAuthenticated"]
            ):
                raise ProtocolError(
                    422,
                    "oracle-failure-cleanup-mismatch",
                    "a clean oracle rejection must preserve read-only lifecycle state",
                )
            if result["code"] == oracle_code and not (
                result["stageCleanupVerified"]
                and not result["quarantined"]
            ):
                raise ProtocolError(
                    422,
                    "oracle-failure-stage-cleanup-mismatch",
                    "an unmasked clean oracle failure requires verified stage cleanup",
                )
    quarantine_required = bool(
        validated and validated[-1]["outcome"] in QUARANTINE_ARM_OUTCOMES
    ) or any(
        record["evDeleteRc"] is not None and record["evDeleteRc"] != 0
        for record in validated
    )
    lowmap_cleanup_incomplete = (
        (result["lowMapMapped"] and not result["lowMapUnmapped"])
        or (result["lowMapLeaseAcquired"] and not result["lowMapLeaseRevoked"])
    )
    quarantine_required = quarantine_required or lowmap_cleanup_incomplete
    active_lowmap_lease = (
        result["lowMapLeaseAcquired"] and not result["lowMapLeaseRevoked"]
    )
    if active_lowmap_lease and result["hostCleanupVerified"]:
        raise ProtocolError(
            422,
            "lowmap-host-cleanup-overclaim",
            "an active lowmap lease forbids verified host cleanup",
        )
    if quarantine_required and not result["quarantined"]:
        raise ProtocolError(422, "terminal-quarantine-underclaimed", "event or lowmap cleanup hazard requires quarantine")
    if result["quarantined"] and result["stageCleanupVerified"]:
        raise ProtocolError(422, "quarantine-cleanup-conflict", "quarantine forbids verified stage cleanup")
    if lowmap_cleanup_incomplete and (
        result["stageCleanupVerified"] or result["cleanupVerified"]
    ):
        raise ProtocolError(
            422,
            "lowmap-cleanup-overclaim",
            "an unreleased low mapping or lease forbids verified cleanup",
        )
    if not result["aioCleanupVerified"] and (not result["quarantined"] or result["stageCleanupVerified"]):
        raise ProtocolError(422, "aio-cleanup-underclaimed", "unverified AIO cleanup requires quarantine")
    if result["cleanupVerified"] != (
        result["stageCleanupVerified"] and result["hostCleanupVerified"]
    ):
        raise ProtocolError(422, "cleanup-accounting-mismatch", "cleanup must equal stage and host cleanup")
    if not result["rebootRequired"]:
        raise ProtocolError(422, "reboot-underclaimed", "every consumed sweep result requires a cold reboot")
    if result["ok"]:
        required = (
            result["pairEstablished"]
            and result["kvaSearchOutcome"] == "accepted"
            and result["kernelRwProved"]
            and result["challengeWriteAttempted"]
            and result["challengeWritten"]
            and result["challengeRestored"]
            and result["lowMapMapped"]
            and result["lowMapLeaseAcquired"]
            and result["lowMapUnmapped"]
            and result["lowMapLeaseRevoked"]
            and result["aioCleanupVerified"]
            and result["stageCleanupVerified"]
            and result["hostCleanupVerified"]
            and result["cleanupVerified"]
            and not result["quarantined"]
            and result["kbaseValidated"]
        )
        if not required:
            raise ProtocolError(422, "success-proof-incomplete", "success requires reversible KRW and complete resource cleanup")
    return result


def load_manifest(root: Path) -> tuple[Mapping[str, bytes], Mapping[str, str], str]:
    document = json.loads(
        (root / STATIC_MANIFEST_NAME).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_object,
    )
    document = exact_keys(document, {"schema", "files"}, "static-manifest")
    if document["schema"] != STATIC_SCHEMA:
        raise ValueError("unsupported Hx current-object static manifest schema")
    if not isinstance(document["files"], dict) or any(
        not isinstance(path, str)
        or not isinstance(digest, str)
        or HEX256.fullmatch(digest) is None
        for path, digest in document["files"].items()
    ):
        raise ValueError("static manifest files must map paths to lowercase SHA-256")
    return load_static_graph(root, document["files"], stage_page=STAGE_PAGE)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if not args.check:
        parser.error("this program is a check-only validator; pass --check")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve(strict=True)
    _, static_hashes, static_manifest = load_manifest(root)
    print(
        "CHECK PASS "
        f"mode=proof maxArms={MAX_ARMS} files={len(static_hashes)} "
        f"manifest={static_manifest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
