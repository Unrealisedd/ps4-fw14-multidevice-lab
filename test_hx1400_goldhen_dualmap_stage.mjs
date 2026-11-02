import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  HX1400_GOLDHEN_DUALMAP_HEN_FLAGS,
  HX1400_GOLDHEN_DUALMAP_HEN_PROTECTION,
  HX1400_GOLDHEN_DUALMAP_JIT_BYTES,
  HX1400_GOLDHEN_DUALMAP_RW_MAP_ATTEMPTS,
  HX1400_GOLDHEN_DUALMAP_RX_MAP_ATTEMPTS,
  acquireHx1400GoldhenDualmapExecutableView,
  acquireHx1400GoldhenDualmapWritableView,
  cleanupHx1400GoldhenDualmapJitViews,
  deriveHx1400GoldhenDualmapExploitRetired,
  mapHx1400GoldhenDualmapPostpatchHen,
  validateHx1400GoldhenDualmapNonoverlap,
} from "./hx1400_goldhen_dualmap_stage.js";

const q = (lo, hi = 0) => Object.freeze({ lo: lo >>> 0, hi: hi >>> 0 });
const RW_ALIAS = q(0x50000000, 0x9);
const RX_ALIAS = q(0x51000000, 0x9);

function simplify(call) {
  return call.map((value) => value && typeof value === "object"
    ? { lo: value.lo >>> 0, hi: value.hi >>> 0 }
    : value);
}

test("writable and executable aliases each make one exact floating MAP_SHARED attempt", () => {
  assert.deepEqual(HX1400_GOLDHEN_DUALMAP_RW_MAP_ATTEMPTS, [
    { address: null, flags: 1 },
  ]);
  assert.deepEqual(HX1400_GOLDHEN_DUALMAP_RX_MAP_ATTEMPTS, [
    { address: null, flags: 1 },
  ]);

  const rwCalls = [];
  const rwRetained = [];
  const writable = acquireHx1400GoldhenDualmapWritableView(
    41,
    (...args) => {
      rwCalls.push(simplify(args));
      return RW_ALIAS;
    },
    (mapping) => rwRetained.push(mapping),
  );
  assert.deepEqual(rwCalls, [
    [null, 0x90000, 3, 1, 41, 0],
  ]);
  assert.deepEqual(writable, RW_ALIAS);
  assert.deepEqual(rwRetained, [writable]);

  const rxCalls = [];
  const executable = acquireHx1400GoldhenDualmapExecutableView(
    41,
    (...args) => {
      rxCalls.push(simplify(args));
      return RX_ALIAS;
    },
    () => {},
  );
  assert.deepEqual(rxCalls, [
    [null, 0x90000, 5, 1, 41, 0],
  ]);
  assert.deepEqual(executable, RX_ALIAS);
});

test("dual aliases must be distinct and nonoverlapping for the complete 0x90000 range", () => {
  assert.equal(validateHx1400GoldhenDualmapNonoverlap(RW_ALIAS, RX_ALIAS), true);
  assert.equal(validateHx1400GoldhenDualmapNonoverlap(RW_ALIAS, RW_ALIAS), false);
  assert.equal(
    validateHx1400GoldhenDualmapNonoverlap(RW_ALIAS, q(0x50080000, 0x9)),
    false,
  );
  assert.equal(
    validateHx1400GoldhenDualmapNonoverlap(RW_ALIAS, q(0x50090000, 0x9)),
    true,
  );
});

test("dual-resource cleanup is RX then RW then close and retains exactly the failed suffix", () => {
  const events = [];
  const success = cleanupHx1400GoldhenDualmapJitViews(
    RW_ALIAS,
    RX_ALIAS,
    41,
    (mapping, length) => { events.push(["unmap", mapping, length]); return true; },
    (fd) => { events.push(["close", fd]); return true; },
  );
  assert.deepEqual(events.map((entry) => entry[0] === "unmap" ? [entry[0], entry[1]] : entry), [
    ["unmap", RX_ALIAS], ["unmap", RW_ALIAS], ["close", 41],
  ]);
  assert.deepEqual(success, { ok: true, writable: null, executable: null, fd: -1, reason: "none" });

  const rxFailure = cleanupHx1400GoldhenDualmapJitViews(
    RW_ALIAS, RX_ALIAS, 41, () => false, () => { throw new Error("must not close"); },
  );
  assert.equal(rxFailure.ok, false);
  assert.deepEqual(rxFailure.writable, RW_ALIAS);
  assert.deepEqual(rxFailure.executable, RX_ALIAS);
  assert.equal(rxFailure.fd, 41);

  let unmaps = 0;
  const rwFailure = cleanupHx1400GoldhenDualmapJitViews(
    RW_ALIAS, RX_ALIAS, 41, () => (++unmaps === 1), () => { throw new Error("must not close"); },
  );
  assert.equal(rwFailure.ok, false);
  assert.deepEqual(rwFailure.writable, RW_ALIAS);
  assert.equal(rwFailure.executable, null);
  assert.equal(rwFailure.fd, 41);

  const closeFailure = cleanupHx1400GoldhenDualmapJitViews(
    RW_ALIAS, RX_ALIAS, 41, () => true, () => false,
  );
  assert.equal(closeFailure.ok, false);
  assert.equal(closeFailure.writable, null);
  assert.equal(closeFailure.executable, null);
  assert.equal(closeFailure.fd, 41);

  const rxThrow = cleanupHx1400GoldhenDualmapJitViews(
    RW_ALIAS, RX_ALIAS, 41, () => { throw new Error("rx"); }, () => true,
  );
  assert.deepEqual(rxThrow, {
    ok: false,
    writable: RW_ALIAS,
    executable: RX_ALIAS,
    fd: 41,
    reason: "executable JIT view cleanup failed",
  });

  let throwUnmaps = 0;
  const rwThrow = cleanupHx1400GoldhenDualmapJitViews(
    RW_ALIAS,
    RX_ALIAS,
    41,
    () => {
      throwUnmaps += 1;
      if (throwUnmaps === 2) throw new Error("rw");
      return true;
    },
    () => true,
  );
  assert.deepEqual(rwThrow, {
    ok: false,
    writable: RW_ALIAS,
    executable: null,
    fd: 41,
    reason: "writable JIT view cleanup failed",
  });

  const closeThrow = cleanupHx1400GoldhenDualmapJitViews(
    RW_ALIAS,
    RX_ALIAS,
    41,
    () => true,
    () => { throw new Error("close"); },
  );
  assert.deepEqual(closeThrow, {
    ok: false,
    writable: null,
    executable: null,
    fd: 41,
    reason: "JIT descriptor cleanup failed",
  });
});

test("verified cleanup retires established exploit authority only", () => {
  assert.equal(deriveHx1400GoldhenDualmapExploitRetired(true, true), true);
  assert.equal(deriveHx1400GoldhenDualmapExploitRetired(true, false), false);
  assert.equal(deriveHx1400GoldhenDualmapExploitRetired(false, true), false);
  assert.throws(() => deriveHx1400GoldhenDualmapExploitRetired(1, true), TypeError);
});

test("postpatch HEN mapping is anonymous RWX with prot7 flags0x1002 fd-1 offset0", () => {
  const calls = [];
  const retained = [];
  const mapped = q(0x34000000, 0x2);
  const result = mapHx1400GoldhenDualmapPostpatchHen(
    (...args) => { calls.push(simplify(args)); return mapped; },
    (mapping) => retained.push(mapping),
  );
  assert.deepEqual(calls, [[
    0,
    HX1400_GOLDHEN_DUALMAP_JIT_BYTES,
    HX1400_GOLDHEN_DUALMAP_HEN_PROTECTION,
    HX1400_GOLDHEN_DUALMAP_HEN_FLAGS,
    -1,
    0,
  ]]);
  assert.deepEqual(result, mapped);
  assert.deepEqual(retained, [mapped]);
});

test("security ordering writes patch through RW, verifies and dispatches RX, releases aliases, then fetches/maps HEN", async () => {
  const source = await readFile(new URL("./hx1400_goldhen_dualmap_stage.js", import.meta.url), "utf8");
  const ordered = [
    "copyTo(add64(state.jitRwMap, HX1400_GOLDHEN_DUALMAP_PATCH_OFFSET), patchBytes)",
    "verifyBytes(\n      add64(state.jitRxMap, HX1400_GOLDHEN_DUALMAP_PATCH_OFFSET)",
    "write8(add64(state.fakeOps, 32), state.jitRxMap)",
    "result.patchedGuardsVerified += 1",
    "const releasedJit = cleanupHx1400GoldhenDualmapJitViews(",
    "state.exploitRetired = deriveHx1400GoldhenDualmapExploitRetired(",
    "if (!result.exploitRetired) fail(\"EXPLOIT_NOT_RETIRED\")",
    "hen = await context.fetchHen()",
    "const henMapping = mapHx1400GoldhenDualmapPostpatchHen(",
    "q(add64(henMapping, HX1400_GOLDHEN_DUALMAP_HEN_OFFSET))",
  ].map((needle) => {
    const index = source.indexOf(needle);
    assert.notEqual(index, -1, `missing security-order marker: ${needle}`);
    return index;
  });
  for (let index = 1; index < ordered.length; index += 1)
    assert.ok(ordered[index - 1] < ordered[index], `marker ${index} is out of order`);
  assert.equal(source.indexOf("hen = await context.fetchHen()"), source.lastIndexOf("hen = await context.fetchHen()"));
  assert.doesNotMatch(source, /copyTo\(add64\(state\.jitRxMap/);
  assert.doesNotMatch(source, /write8\(add64\(state\.fakeOps, 32\), state\.jitRwMap\)/);
  const retirementAssignments = source.match(
    /state\.exploitRetired = deriveHx1400GoldhenDualmapExploitRetired\(/g,
  ) || [];
  assert.equal(retirementAssignments.length, 2);
  assert.ok(
    source.lastIndexOf("state.exploitRetired = deriveHx1400GoldhenDualmapExploitRetired(") >
      source.indexOf("  } catch (error) {\n    const code = error instanceof HxFailure"),
  );
});

test("stage registers a successful syscall533 descriptor before ownership or mmap", async () => {
  const source = await readFile(new URL("./hx1400_goldhen_dualmap_stage.js", import.meta.url), "utf8");
  const callback = source.slice(
    source.indexOf("createWritableView(registerDescriptor)"),
    source.indexOf("mapExecutableView(fd)"),
  );
  const registration = callback.indexOf("registerDescriptor(created)");
  const ownership = callback.indexOf("state.jitFd = ownFd(created)");
  const mapping = callback.indexOf("acquireHx1400GoldhenDualmapWritableView(");
  assert.ok(registration >= 0);
  assert.ok(registration < ownership);
  assert.ok(ownership < mapping);
  assert.doesNotMatch(callback, /flags:\s*17|,\s*7,\s*17,/);
});

test("dispose reports releases only for resource classes that existed", async () => {
  const source = await readFile(new URL("./hx1400_goldhen_dualmap_stage.js", import.meta.url), "utf8");
  const callback = source.slice(
    source.indexOf("disposeJit(fd)"),
    source.indexOf("      }));", source.indexOf("disposeJit(fd)")),
  );
  const ordered = [
    "const hadMappings =",
    "const hadDescriptor =",
    "cleanupHx1400GoldhenDualmapJitViews(",
    "result.jitMappingsReleased = hadMappings",
    "result.jitDescriptorReleased = hadDescriptor",
  ].map((needle) => callback.indexOf(needle));
  assert.ok(ordered.every((index) => index >= 0));
  for (let index = 1; index < ordered.length; index += 1)
    assert.ok(ordered[index - 1] < ordered[index]);
  assert.doesNotMatch(callback, /result\.jit(?:Mappings|Descriptor)Released = true/);
});
