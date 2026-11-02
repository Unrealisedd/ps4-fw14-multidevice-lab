import assert from "node:assert/strict";
import test from "node:test";

let moduleSerial = 0;
async function freshModule() {
  moduleSerial += 1;
  return import(`./hx1400_jit_dualmap_lease.js?dualmap-lease-test=${moduleSerial}`);
}

function context(mod, overrides = {}) {
  const base = {
    firmware: "14.00",
    source13Sha256: mod.HX1400_JIT_DUALMAP_LEASE_PROVENANCE.source13Sha256,
    generation: 3,
    target: Object.freeze({ opaque: true }),
    read32: () => 0,
    write32: () => 0,
    createWritableView: (registerDescriptor) => { registerDescriptor(17); return 17; },
    mapExecutableView: () => 0,
    disposeJit: () => 0,
    synchronous: true,
    exclusiveCredentialWriter: true,
    parkedWorkerIdentity: true,
    ucredIdentity: true,
    pidIdentity: true,
  };
  return Object.freeze(Object.assign(base, overrides));
}

const RECEIPT_KEYS = [
  "ok", "status", "error", "cleanupError", "cleanupWriteError",
  "cleanupReadbackError", "disposalError", "fd", "descriptorTransferred",
  "disposeAttempted", "descriptorDisposed", "quarantined", "rebootRequired",
  "generation", "reads", "writes", "createCalls", "mapCalls",
  "preReadsStable", "writeArmAttempted", "writeArmConfirmed",
  "writePostConfirmed", "writeRestoreAttempted", "writeRestoreConfirmed",
  "executeArmAttempted", "executeArmConfirmed", "executePostConfirmed",
  "executeRestoreAttempted", "executeRestoreConfirmed", "borrowedBitsCleared",
  "terminalMatchesOriginal",
];

function assertNotCanonicalKernelAddress(text) {
  const compact = text.replace(/[_:`\s-]/g, "");
  assert.doesNotMatch(compact, /(?:0x)?ffff[89a-f][0-9a-f]{11}/i);
  assert.doesNotMatch(text, /(?:184466[0-9]{14,}|-1(?:[0-9]{14,}))/);
}

function assertReceipt(value, forbidden = undefined) {
  assert.notEqual(value, forbidden);
  assert.equal(Object.getPrototypeOf(value), null);
  assert.equal(Object.isFrozen(value), true);
  assert.deepEqual(Reflect.ownKeys(value), RECEIPT_KEYS);
  for (const key of Reflect.ownKeys(value)) {
    assert.equal(typeof key, "string");
    assert.doesNotMatch(key, /address|pointer|target|ucred|kernel/i);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    assert.deepEqual(
      { enumerable: descriptor.enumerable, writable: descriptor.writable, configurable: descriptor.configurable },
      { enumerable: true, writable: false, configurable: false },
    );
    assert.ok("value" in descriptor);
    const item = descriptor.value;
    assert.ok(item === null || ["boolean", "number", "string"].includes(typeof item));
    assert.notEqual(typeof item, "bigint");
    if (typeof item === "string") assertNotCanonicalKernelAddress(item);
    if (typeof item === "number") {
      assert.equal(Number.isSafeInteger(item), true);
      assert.ok(item >= -0x80000000 && item <= 0xffffffff);
    }
  }
}

function assertNoDescriptor(value) {
  assert.equal(value.ok, false);
  assert.equal(value.fd, null);
  assert.equal(value.descriptorTransferred, false);
}

function assertNoSimultaneousBits(writes) {
  for (const value of writes) assert.notEqual(value & 0x60000000, 0x60000000);
}

function receiptFixture(overrides = {}, extraKey = undefined) {
  const value = Object.create(null);
  for (const key of RECEIPT_KEYS) {
    Object.defineProperty(value, key, {
      value: Object.hasOwn(overrides, key) ? overrides[key] : null,
      enumerable: true,
      writable: false,
      configurable: false,
    });
  }
  if (extraKey !== undefined) {
    Object.defineProperty(value, extraKey, {
      value: 1,
      enumerable: typeof extraKey === "symbol",
      writable: false,
      configurable: false,
    });
  }
  return Object.freeze(value);
}

async function runMachine(options = {}) {
  const mod = await freshModule();
  const target = Object.freeze({ opaque: Symbol("credential-word") });
  const original = options.original ?? 0x01234567;
  let word = original;
  let reads = 0;
  let writeCalls = 0;
  const writes = [];
  const disposals = [];
  const observations = [];
  const values = options.values ?? {};
  const read32 = values.read32 ?? (() => { reads += 1; return word; });
  const write32 = values.write32 ?? ((_target, value) => {
    writeCalls += 1;
    writes.push(value);
    word = value;
    return 0;
  });
  const createWritableView = values.createWritableView ?? ((registerDescriptor) => {
    observations.push(["create", word]);
    registerDescriptor(17);
    return 17;
  });
  const mapExecutableView = values.mapExecutableView ?? ((fd) => {
    observations.push(["map", word, fd]);
    return 0;
  });
  const disposeJit = values.disposeJit ?? ((fd) => {
    disposals.push([fd, word]);
    return 0;
  });
  const ctx = context(mod, {
    target,
    read32,
    write32,
    createWritableView,
    mapExecutableView,
    disposeJit,
    ...(options.contextOverrides ?? {}),
  });
  const result = mod.runHx1400JitDualmapLease(ctx);
  assertReceipt(result, target);
  assertNoSimultaneousBits(writes);
  return {
    mod, result, target, original, writes, disposals, observations,
    get word() { return word; },
    set word(value) { word = value; },
    get reads() { return reads; },
    get writeCalls() { return writeCalls; },
  };
}

test("exports frozen source13 provenance and generation-three W^X constants", async () => {
  const mod = await freshModule();
  assert.equal(Object.isFrozen(mod.HX1400_JIT_DUALMAP_LEASE_PROVENANCE), true);
  assert.equal(Object.isFrozen(mod.HX1400_JIT_DUALMAP_LEASE_CONSTANTS), true);
  assert.equal(mod.HX1400_JIT_DUALMAP_LEASE_PROVENANCE.firmware, "14.00");
  assert.equal(
    mod.HX1400_JIT_DUALMAP_LEASE_PROVENANCE.source13Sha256,
    "399367bed20e111200a0cd0ff13d3b6bfe3280cdd6105a675f149b4275515829",
  );
  assert.deepEqual(
    {
      generation: mod.HX1400_JIT_DUALMAP_LEASE_CONSTANTS.generation,
      writeMask: mod.HX1400_JIT_DUALMAP_LEASE_CONSTANTS.writeMask,
      executeMask: mod.HX1400_JIT_DUALMAP_LEASE_CONSTANTS.executeMask,
      combinedMask: mod.HX1400_JIT_DUALMAP_LEASE_CONSTANTS.combinedMask,
      scalarWidthBytes: mod.HX1400_JIT_DUALMAP_LEASE_CONSTANTS.scalarWidthBytes,
    },
    { generation: 3, writeMask: 0x40000000, executeMask: 0x20000000, combinedMask: 0x60000000, scalarWidthBytes: 4 },
  );
});

test("receipt validator rejects hidden, symbol, object, bigint, and pointer-like fixtures", () => {
  for (const fixture of [
    receiptFixture({}, "hidden"),
    receiptFixture({}, Symbol("hidden")),
    receiptFixture({ fd: {} }),
    receiptFixture({ fd: 1n }),
    receiptFixture({ error: "FFFF_FFFF_8123_4567" }),
    receiptFixture({ error: "18446603336221296231" }),
  ]) assert.throws(() => assertReceipt(fixture));
});

test("success performs exactly the four-write two-callback W^X sequence and transfers the fd", async () => {
  const events = [];
  let word = 0x01234567;
  const writes = [];
  let createCalls = 0;
  let mapCalls = 0;
  let disposeCalls = 0;
  const mod = await freshModule();
  const ctx = context(mod, {
    read32: () => { events.push(["read", word]); return word; },
    write32: (_target, value) => {
      events.push(["write", value]);
      writes.push(value);
      word = value;
      return 0;
    },
    createWritableView: (registerDescriptor) => {
      createCalls += 1;
      events.push(["create", word]);
      assert.equal(word, 0x41234567);
      registerDescriptor(19);
      return 19;
    },
    mapExecutableView: (fd) => {
      mapCalls += 1;
      events.push(["map", word, fd]);
      assert.equal(word, 0x21234567);
      assert.equal(fd, 19);
      return 0;
    },
    disposeJit: () => { disposeCalls += 1; return 0; },
  });
  const result = mod.runHx1400JitDualmapLease(ctx);
  assertReceipt(result, ctx.target);
  assert.deepEqual(writes, [0x41234567, 0x01234567, 0x21234567, 0x01234567]);
  assertNoSimultaneousBits(writes);
  assert.equal(createCalls, 1);
  assert.equal(mapCalls, 1);
  assert.equal(disposeCalls, 0);
  assert.equal(word, 0x01234567);
  assert.deepEqual(events.filter((event) => event[0] === "create" || event[0] === "map"), [
    ["create", 0x41234567],
    ["map", 0x21234567, 19],
  ]);
  assert.equal(result.ok, true);
  assert.equal(result.status, "OK");
  assert.equal(result.fd, 19);
  assert.equal(result.descriptorTransferred, true);
  assert.equal(result.writes, 4);
  assert.equal(result.reads, 10);
  assert.equal(result.createCalls, 1);
  assert.equal(result.mapCalls, 1);
  assert.equal(result.preReadsStable, true);
  assert.equal(result.writeArmConfirmed, true);
  assert.equal(result.writePostConfirmed, true);
  assert.equal(result.writeRestoreConfirmed, true);
  assert.equal(result.executeArmConfirmed, true);
  assert.equal(result.executePostConfirmed, true);
  assert.equal(result.executeRestoreConfirmed, true);
  assert.equal(result.borrowedBitsCleared, true);
  assert.equal(result.terminalMatchesOriginal, true);
  assert.equal(result.rebootRequired, true);
});

test("either preauthorized credential bit refuses without writes or callbacks", async () => {
  for (const original of [0x40000009, 0x20000009, 0x60000009]) {
    let calls = 0;
    const { result, writes } = await runMachine({
      original,
      values: {
        createWritableView: () => { calls += 1; return 1; },
        mapExecutableView: () => { calls += 1; return 0; },
        disposeJit: () => { calls += 1; return 0; },
      },
    });
    assert.equal(result.status, "REFUSED");
    assert.equal(result.error, "ERR_PREAUTHORIZED");
    assert.equal(result.preReadsStable, true);
    assert.deepEqual(writes, []);
    assert.equal(calls, 0);
  }
});

test("unstable and invalid pre-reads consume no capability and invoke no callback", async () => {
  {
    let read = 0;
    let calls = 0;
    const { result, writes } = await runMachine({
      values: {
        read32: () => (++read === 1 ? 1 : 2),
        createWritableView: () => { calls += 1; return 1; },
        mapExecutableView: () => { calls += 1; return 0; },
      },
    });
    assert.equal(result.error, "ERR_UNSTABLE_PRE_READ");
    assert.deepEqual(writes, []);
    assert.equal(calls, 0);
  }
  for (const invalid of [-1, 0x100000000, 1.5, undefined, 1n]) {
    let calls = 0;
    const { result, writes } = await runMachine({
      values: {
        read32: () => invalid,
        createWritableView: () => { calls += 1; return 1; },
        mapExecutableView: () => { calls += 1; return 0; },
      },
    });
    assert.equal(result.error, "ERR_PRE_READ");
    assert.deepEqual(writes, []);
    assert.equal(calls, 0);
  }
});

test("write arm failure restores exact original and never enters either capability callback", async () => {
  let word = 0x35;
  let writes = 0;
  let callbacks = 0;
  const values = [];
  const { result } = await runMachine({
    original: word,
    values: {
      read32: () => word,
      write32: (_target, value) => {
        writes += 1;
        values.push(value);
        word = value;
        return writes === 1 ? -1 : 0;
      },
      createWritableView: () => { callbacks += 1; return 7; },
      mapExecutableView: () => { callbacks += 1; return 0; },
    },
  });
  assert.deepEqual(values, [0x40000035, 0x35]);
  assert.equal(word, 0x35);
  assert.equal(callbacks, 0);
  assert.equal(result.error, "ERR_WRITE_ARM_WRITE");
  assert.equal(result.status, "QUARANTINED");
  assert.equal(result.writeRestoreConfirmed, true);
});

test("write arm readback mismatch restores exact original before any callback", async () => {
  let word = 0x41;
  let reads = 0;
  let callbacks = 0;
  const values = [];
  const { result } = await runMachine({
    original: word,
    values: {
      read32: () => {
        reads += 1;
        return reads === 3 ? 0x40000040 : word;
      },
      write32: (_target, value) => { values.push(value); word = value; return 0; },
      createWritableView: () => { callbacks += 1; return 8; },
      mapExecutableView: () => { callbacks += 1; return 0; },
    },
  });
  assert.deepEqual(values, [0x40000041, 0x41]);
  assert.equal(callbacks, 0);
  assert.equal(word, 0x41);
  assert.equal(result.error, "ERR_WRITE_ARM_READBACK");
  assert.equal(result.writeRestoreConfirmed, true);
});

test("negative create is a clean error only after exact write-phase restoration", async () => {
  let mapCalls = 0;
  let disposeCalls = 0;
  const { result, writes, word } = await runMachine({
    values: {
      createWritableView: () => -1,
      mapExecutableView: () => { mapCalls += 1; return 0; },
      disposeJit: () => { disposeCalls += 1; return 0; },
    },
  });
  assertNoDescriptor(result);
  assert.deepEqual(writes, [0x41234567, 0x01234567]);
  assert.equal(word, 0x01234567);
  assert.equal(result.status, "ERROR");
  assert.equal(result.error, "ERR_JIT_CREATE");
  assert.equal(result.quarantined, false);
  assert.equal(result.writePostConfirmed, true);
  assert.equal(result.writeRestoreConfirmed, true);
  assert.equal(mapCalls, 0);
  assert.equal(disposeCalls, 0);
  assert.equal(result.rebootRequired, true);
});

test("create throw and invalid returns quarantine after restoration and never map or dispose", async () => {
  const cases = [
    () => { throw new Error("0xffffffffdeadbeef"); },
    () => undefined,
    () => 1.5,
    () => 0x80000000,
    () => ({}),
  ];
  for (const createWritableView of cases) {
    let mapCalls = 0;
    let disposeCalls = 0;
    const { result, writes, word } = await runMachine({
      values: {
        createWritableView,
        mapExecutableView: () => { mapCalls += 1; return 0; },
        disposeJit: () => { disposeCalls += 1; return 0; },
      },
    });
    assertNoDescriptor(result);
    assert.deepEqual(writes, [0x41234567, 0x01234567]);
    assert.equal(word, 0x01234567);
    assert.equal(result.error, "ERR_JIT_CREATE_CALLBACK");
    assert.equal(result.quarantined, true);
    assert.equal(result.rebootRequired, true);
    assert.equal(mapCalls, 0);
    assert.equal(disposeCalls, 0);
    assert.doesNotMatch(JSON.stringify(result), /deadbeef/i);
  }
});

test("descriptor registration is one-shot, must match, and preserves ownership across callback failure", async () => {
  const cases = [
    {
      name: "throw-after-register",
      create(registerDescriptor) { registerDescriptor(71); throw new Error("after syscall"); },
      disposed: [71],
    },
    {
      name: "duplicate",
      create(registerDescriptor) {
        registerDescriptor(73);
        registerDescriptor(73);
        return 73;
      },
      disposed: [73],
    },
    {
      name: "mismatch",
      create(registerDescriptor) { registerDescriptor(75); return 76; },
      disposed: [75],
    },
    {
      name: "missing",
      create() { return 77; },
      disposed: [77],
    },
    {
      name: "registration-throw",
      create(registerDescriptor) { registerDescriptor(-1); return -1; },
      disposed: [],
    },
  ];
  for (const fixture of cases) {
    const disposed = [];
    const { result, writes, word } = await runMachine({
      values: {
        createWritableView: fixture.create,
        disposeJit(fd) { disposed.push(fd); return 0; },
      },
    });
    assert.equal(result.error, "ERR_JIT_CREATE_CALLBACK", fixture.name);
    assert.deepEqual(writes, [0x41234567, 0x01234567], fixture.name);
    assert.equal(word, 0x01234567, fixture.name);
    assert.deepEqual(disposed, fixture.disposed, fixture.name);
    assert.equal(result.disposeAttempted, fixture.disposed.length === 1, fixture.name);
    assert.equal(result.quarantined, true, fixture.name);
    assert.equal(result.rebootRequired, true, fixture.name);
  }
});

test("write-phase post-call unreadability and drift restore then dispose each known fd once", async () => {
  for (const mode of ["throw", "drift"]) {
    let word = 0x51;
    let reads = 0;
    const disposed = [];
    let mapCalls = 0;
    const values = [];
    const { result } = await runMachine({
      original: word,
      values: {
        read32: () => {
          reads += 1;
          if (reads === 4 && mode === "throw") throw new Error("unreadable");
          if (reads === 4 && mode === "drift") return 0x40000050;
          return word;
        },
        write32: (_target, value) => { values.push(value); word = value; return 0; },
        createWritableView: (registerDescriptor) => { registerDescriptor(29); return 29; },
        mapExecutableView: () => { mapCalls += 1; return 0; },
        disposeJit: (fd) => { disposed.push([fd, word]); return 0; },
      },
    });
    assert.deepEqual(values, [0x40000051, 0x51]);
    assert.deepEqual(disposed, [[29, 0x51]]);
    assert.equal(mapCalls, 0);
    assert.equal(result.error, mode === "throw" ? "ERR_WRITE_POST_READ" : "ERR_WRITE_POST_STATE");
    assert.equal(result.quarantined, true);
    assert.equal(result.descriptorDisposed, true);
    assert.equal(result.writeRestoreConfirmed, true);
  }
});

test("write-phase restore write failure is quarantined and disposes the descriptor once", async () => {
  let word = 0x61;
  let writes = 0;
  const values = [];
  const disposed = [];
  const { result } = await runMachine({
    original: word,
    values: {
      read32: () => word,
      write32: (_target, value) => {
        writes += 1;
        values.push(value);
        if (writes === 1) word = value;
        return writes === 1 ? 0 : -1;
      },
      createWritableView: (registerDescriptor) => { registerDescriptor(31); return 31; },
      disposeJit: (fd) => { disposed.push(fd); return 0; },
    },
  });
  assert.deepEqual(values, [0x40000061, 0x61]);
  assert.deepEqual(disposed, [31]);
  assert.equal(result.error, "ERR_WRITE_RESTORE_WRITE");
  assert.equal(result.cleanupWriteError, "ERR_WRITE_RESTORE_WRITE");
  assert.equal(result.cleanupReadbackError, "ERR_WRITE_RESTORE_STATE");
  assert.equal(result.writeRestoreConfirmed, false);
  assert.equal(result.quarantined, true);
});

test("write-phase restore unstable/readback state quarantines and does not enter execute phase", async () => {
  for (const mode of ["unstable", "state"]) {
    let word = 0x71;
    let reads = 0;
    let mapCalls = 0;
    const disposed = [];
    const { result } = await runMachine({
      original: word,
      values: {
        read32: () => {
          reads += 1;
          if (reads === 5) return mode === "unstable" ? 0x71 : 0x70;
          if (reads === 6) return mode === "unstable" ? 0x70 : 0x70;
          return word;
        },
        write32: (_target, value) => { word = value; return 0; },
        createWritableView: (registerDescriptor) => { registerDescriptor(37); return 37; },
        mapExecutableView: () => { mapCalls += 1; return 0; },
        disposeJit: (fd) => { disposed.push(fd); return 0; },
      },
    });
    assert.equal(
      result.error,
      mode === "unstable" ? "ERR_WRITE_RESTORE_UNSTABLE" : "ERR_WRITE_RESTORE_STATE",
    );
    assert.equal(result.cleanupReadbackError, result.error);
    assert.equal(mapCalls, 0);
    assert.deepEqual(disposed, [37]);
    assert.equal(result.quarantined, true);
  }
});

test("execute arm write failure restores exact original and disposes before returning", async () => {
  let word = 0x81;
  let writes = 0;
  let mapCalls = 0;
  const values = [];
  const disposed = [];
  const { result } = await runMachine({
    original: word,
    values: {
      read32: () => word,
      write32: (_target, value) => {
        writes += 1;
        values.push(value);
        word = value;
        return writes === 3 ? -1 : 0;
      },
      createWritableView: (registerDescriptor) => { registerDescriptor(41); return 41; },
      mapExecutableView: () => { mapCalls += 1; return 0; },
      disposeJit: (fd) => { disposed.push([fd, word]); return 0; },
    },
  });
  assert.deepEqual(values, [0x40000081, 0x81, 0x20000081, 0x81]);
  assert.equal(mapCalls, 0);
  assert.deepEqual(disposed, [[41, 0x81]]);
  assert.equal(result.error, "ERR_EXECUTE_ARM_WRITE");
  assert.equal(result.executeRestoreConfirmed, true);
  assert.equal(result.quarantined, true);
});

test("execute arm readback mismatch restores exact original without invoking map", async () => {
  let word = 0x91;
  let reads = 0;
  let mapCalls = 0;
  const values = [];
  const disposed = [];
  const { result } = await runMachine({
    original: word,
    values: {
      read32: () => {
        reads += 1;
        return reads === 7 ? 0x20000090 : word;
      },
      write32: (_target, value) => { values.push(value); word = value; return 0; },
      createWritableView: (registerDescriptor) => { registerDescriptor(43); return 43; },
      mapExecutableView: () => { mapCalls += 1; return 0; },
      disposeJit: (fd) => { disposed.push(fd); return 0; },
    },
  });
  assert.deepEqual(values, [0x40000091, 0x91, 0x20000091, 0x91]);
  assert.equal(mapCalls, 0);
  assert.deepEqual(disposed, [43]);
  assert.equal(result.error, "ERR_EXECUTE_ARM_READBACK");
  assert.equal(result.executeRestoreConfirmed, true);
});

test("clean nonzero execute-map result restores then disposes exactly once without quarantine", async () => {
  let disposeCalls = 0;
  const disposed = [];
  const { result, writes, word } = await runMachine({
    values: {
      mapExecutableView: () => -13,
      disposeJit: (fd) => { disposeCalls += 1; disposed.push([fd, 0x01234567]); return 0; },
    },
  });
  assertNoDescriptor(result);
  assert.deepEqual(writes, [0x41234567, 0x01234567, 0x21234567, 0x01234567]);
  assert.equal(word, 0x01234567);
  assert.equal(disposeCalls, 1);
  assert.deepEqual(disposed, [[17, 0x01234567]]);
  assert.equal(result.status, "ERROR");
  assert.equal(result.error, "ERR_JIT_MAP");
  assert.equal(result.quarantined, false);
  assert.equal(result.descriptorDisposed, true);
  assert.equal(result.executePostConfirmed, true);
  assert.equal(result.executeRestoreConfirmed, true);
});

test("execute-map throw and invalid returns quarantine, restore, and dispose exactly once", async () => {
  const cases = [
    () => { throw new Error("map failed"); },
    () => undefined,
    () => 0.5,
    () => 0x80000000,
    () => ({}),
  ];
  for (const mapExecutableView of cases) {
    let disposeCalls = 0;
    const { result, writes, word } = await runMachine({
      values: {
        mapExecutableView,
        disposeJit: () => { disposeCalls += 1; return 0; },
      },
    });
    assertNoDescriptor(result);
    assert.deepEqual(writes, [0x41234567, 0x01234567, 0x21234567, 0x01234567]);
    assert.equal(word, 0x01234567);
    assert.equal(result.error, "ERR_JIT_MAP_CALLBACK");
    assert.equal(result.quarantined, true);
    assert.equal(result.rebootRequired, true);
    assert.equal(disposeCalls, 1);
    assert.equal(result.descriptorDisposed, true);
  }
});

test("execute post-call unreadability and credential drift restore and dispose once", async () => {
  for (const mode of ["throw", "drift"]) {
    let word = 0xa1;
    let reads = 0;
    const disposed = [];
    const values = [];
    const { result } = await runMachine({
      original: word,
      values: {
        read32: () => {
          reads += 1;
          if (reads === 8 && mode === "throw") throw new Error("unreadable");
          if (reads === 8 && mode === "drift") return 0x200000a0;
          return word;
        },
        write32: (_target, value) => { values.push(value); word = value; return 0; },
        createWritableView: (registerDescriptor) => { registerDescriptor(47); return 47; },
        mapExecutableView: () => 0,
        disposeJit: (fd) => { disposed.push([fd, word]); return 0; },
      },
    });
    assert.deepEqual(values, [0x400000a1, 0xa1, 0x200000a1, 0xa1]);
    assert.deepEqual(disposed, [[47, 0xa1]]);
    assert.equal(result.error, mode === "throw" ? "ERR_EXECUTE_POST_READ" : "ERR_EXECUTE_POST_STATE");
    assert.equal(result.executeRestoreConfirmed, true);
    assert.equal(result.quarantined, true);
  }
});

test("execute restore write failure quarantines and still disposes exactly once", async () => {
  let word = 0xb1;
  let writes = 0;
  const values = [];
  const disposed = [];
  const { result } = await runMachine({
    original: word,
    values: {
      read32: () => word,
      write32: (_target, value) => {
        writes += 1;
        values.push(value);
        if (writes !== 4) word = value;
        return writes === 4 ? -1 : 0;
      },
      createWritableView: (registerDescriptor) => { registerDescriptor(53); return 53; },
      mapExecutableView: () => 0,
      disposeJit: (fd) => { disposed.push(fd); return 0; },
    },
  });
  assert.deepEqual(values, [0x400000b1, 0xb1, 0x200000b1, 0xb1]);
  assert.deepEqual(disposed, [53]);
  assert.equal(result.error, "ERR_EXECUTE_RESTORE_WRITE");
  assert.equal(result.cleanupWriteError, "ERR_EXECUTE_RESTORE_WRITE");
  assert.equal(result.cleanupReadbackError, "ERR_EXECUTE_RESTORE_STATE");
  assert.equal(result.executeRestoreConfirmed, false);
  assert.equal(result.quarantined, true);
});

test("execute restore unstable and wrong-state readback are quarantined and dispose once", async () => {
  for (const mode of ["unstable", "state"]) {
    let word = 0xc1;
    let reads = 0;
    const disposed = [];
    const { result } = await runMachine({
      original: word,
      values: {
        read32: () => {
          reads += 1;
          if (reads === 9) return mode === "unstable" ? 0xc1 : 0xc0;
          if (reads === 10) return 0xc0;
          return word;
        },
        write32: (_target, value) => { word = value; return 0; },
        createWritableView: (registerDescriptor) => { registerDescriptor(59); return 59; },
        mapExecutableView: () => 0,
        disposeJit: (fd) => { disposed.push(fd); return 0; },
      },
    });
    assert.equal(
      result.error,
      mode === "unstable" ? "ERR_EXECUTE_RESTORE_UNSTABLE" : "ERR_EXECUTE_RESTORE_STATE",
    );
    assert.deepEqual(disposed, [59]);
    assert.equal(result.descriptorDisposed, true);
    assert.equal(result.quarantined, true);
  }
});

test("unreadable restoration verification quarantines both phases and disposes known descriptors", async () => {
  for (const phase of ["write", "execute"]) {
    let word = 0xc5;
    let reads = 0;
    let mapCalls = 0;
    const disposed = [];
    const { result } = await runMachine({
      original: word,
      values: {
        read32: () => {
          reads += 1;
          if (reads === (phase === "write" ? 5 : 9)) throw new Error("restore unreadable");
          return word;
        },
        write32: (_target, value) => { word = value; return 0; },
        createWritableView: (registerDescriptor) => { registerDescriptor(60); return 60; },
        mapExecutableView: () => { mapCalls += 1; return 0; },
        disposeJit: (fd) => { disposed.push([fd, word]); return 0; },
      },
    });
    const expected = phase === "write"
      ? "ERR_WRITE_RESTORE_READ"
      : "ERR_EXECUTE_RESTORE_READ";
    assert.equal(result.error, expected);
    assert.equal(result.cleanupReadbackError, expected);
    assert.equal(result.quarantined, true);
    assert.equal(result.rebootRequired, true);
    assert.equal(result.terminalMatchesOriginal, false);
    assert.deepEqual(disposed, [[60, 0xc5]]);
    assert.equal(mapCalls, phase === "write" ? 0 : 1);
  }
});

test("unreadable arm confirmation restores before callbacks in both phases", async () => {
  for (const phase of ["write", "execute"]) {
    let word = 0xc7;
    let reads = 0;
    let createCalls = 0;
    let mapCalls = 0;
    const disposed = [];
    const { result } = await runMachine({
      original: word,
      values: {
        read32: () => {
          reads += 1;
          if (reads === (phase === "write" ? 3 : 7)) throw new Error("arm unreadable");
          return word;
        },
        write32: (_target, value) => { word = value; return 0; },
        createWritableView: (registerDescriptor) => { createCalls += 1; registerDescriptor(62); return 62; },
        mapExecutableView: () => { mapCalls += 1; return 0; },
        disposeJit: (fd) => { disposed.push([fd, word]); return 0; },
      },
    });
    assert.equal(
      result.error,
      phase === "write" ? "ERR_WRITE_ARM_READBACK" : "ERR_EXECUTE_ARM_READBACK",
    );
    assert.equal(result.quarantined, true);
    assert.equal(result.terminalMatchesOriginal, true);
    if (phase === "write") {
      assert.equal(createCalls, 0);
      assert.equal(mapCalls, 0);
      assert.deepEqual(disposed, []);
    } else {
      assert.equal(createCalls, 1);
      assert.equal(mapCalls, 0);
      assert.deepEqual(disposed, [[62, 0xc7]]);
    }
  }
});

test("disposal nonzero and throw quarantine without replacing the clean map error", async () => {
  for (const disposeJit of [() => -1, () => { throw new Error("close failed"); }]) {
    let disposeCalls = 0;
    const { result } = await runMachine({
      values: {
        mapExecutableView: () => 13,
        disposeJit: (fd) => { disposeCalls += 1; return disposeJit(fd); },
      },
    });
    assertNoDescriptor(result);
    assert.equal(disposeCalls, 1);
    assert.equal(result.error, "ERR_JIT_MAP");
    assert.equal(result.disposalError, "ERR_DISPOSE");
    assert.equal(result.disposeAttempted, true);
    assert.equal(result.descriptorDisposed, false);
    assert.equal(result.quarantined, true);
    assert.equal(result.rebootRequired, true);
  }
});

test("callback credential drift is never accepted and exact-original cleanup precedes disposal", async () => {
  for (const phase of ["write", "execute"]) {
    let word = 0xd1;
    const values = [];
    const disposed = [];
    let mapCalls = 0;
    const { result } = await runMachine({
      original: word,
      values: {
        read32: () => word,
        write32: (_target, value) => { values.push(value); word = value; return 0; },
        createWritableView: (registerDescriptor) => {
          registerDescriptor(61);
          if (phase === "write") word = 0x400000d0;
          return 61;
        },
        mapExecutableView: () => {
          mapCalls += 1;
          if (phase === "execute") word = 0x200000d0;
          return 0;
        },
        disposeJit: (fd) => { disposed.push([fd, word]); return 0; },
      },
    });
    assert.equal(result.quarantined, true);
    assert.equal(result.terminalMatchesOriginal, true);
    assert.equal(result.borrowedBitsCleared, true);
    assert.deepEqual(disposed, [[61, 0xd1]]);
    if (phase === "write") {
      assert.equal(result.error, "ERR_WRITE_POST_STATE");
      assert.equal(mapCalls, 0);
      assert.deepEqual(values, [0x400000d1, 0xd1]);
    } else {
      assert.equal(result.error, "ERR_EXECUTE_POST_STATE");
      assert.equal(mapCalls, 1);
      assert.deepEqual(values, [0x400000d1, 0xd1, 0x200000d1, 0xd1]);
    }
  }
});

test("reentry from both capability callbacks is refused while the outer lease completes", async () => {
  const mod = await freshModule();
  let word = 0xe1;
  let ctx;
  const inner = [];
  ctx = context(mod, {
    read32: () => word,
    write32: (_target, value) => { word = value; return 0; },
    createWritableView: (registerDescriptor) => {
      registerDescriptor(67);
      inner.push(mod.runHx1400JitDualmapLease(ctx));
      return 67;
    },
    mapExecutableView: () => { inner.push(mod.runHx1400JitDualmapLease(ctx)); return 0; },
  });
  const outer = mod.runHx1400JitDualmapLease(ctx);
  assert.equal(outer.ok, true);
  assert.equal(outer.fd, 67);
  assert.equal(inner.length, 2);
  for (const value of inner) {
    assertReceipt(value, ctx.target);
    assertNoDescriptor(value);
    assert.equal(value.error, "ERR_REENTRY");
    assert.equal(value.reads, 0);
    assert.equal(value.writes, 0);
    assert.equal(value.rebootRequired, true);
  }
});

test("invalid context does not consume generation; reaching pre-read does", async () => {
  const mod = await freshModule();
  const invalid = mod.runHx1400JitDualmapLease(Object.freeze({}));
  assert.equal(invalid.error, "ERR_CONTEXT");
  assert.equal(invalid.rebootRequired, false);
  let reads = 0;
  const valid = mod.runHx1400JitDualmapLease(context(mod, {
    read32: () => { reads += 1; throw new Error("read failed"); },
  }));
  assert.equal(valid.error, "ERR_PRE_READ");
  assert.equal(valid.rebootRequired, true);
  assert.equal(reads, 1);
  const closed = mod.runHx1400JitDualmapLease(context(mod));
  assert.equal(closed.error, "ERR_GENERATION_CLOSED");
  assert.equal(closed.reads, 0);
  assert.equal(closed.rebootRequired, true);
  assert.equal(closed.quarantined, false);
});

test("quarantine persists into every later generation-closed receipt", async () => {
  const mod = await freshModule();
  let word = 0xf1;
  const disposed = [];
  const first = mod.runHx1400JitDualmapLease(context(mod, {
    read32: () => word,
    write32: (_target, value) => { word = value; return 0; },
    createWritableView(registerDescriptor) {
      registerDescriptor(79);
      throw new Error("mapping callback failed after syscall533");
    },
    disposeJit(fd) { disposed.push([fd, word]); return 0; },
  }));
  assert.equal(first.status, "QUARANTINED");
  assert.equal(first.rebootRequired, true);
  assert.deepEqual(disposed, [[79, 0xf1]]);
  const closed = mod.runHx1400JitDualmapLease(Object.freeze({}));
  assert.equal(closed.error, "ERR_GENERATION_CLOSED");
  assert.equal(closed.status, "QUARANTINED");
  assert.equal(closed.quarantined, true);
  assert.equal(closed.rebootRequired, true);
});

test("identity, provenance, synchronous, and writer-exclusion gates fail before execution", async () => {
  for (const override of [
    { firmware: "13.52" },
    { source13Sha256: "0".repeat(64) },
    { generation: 2 },
    { synchronous: false },
    { exclusiveCredentialWriter: false },
    { parkedWorkerIdentity: false },
    { ucredIdentity: false },
    { pidIdentity: false },
  ]) {
    const mod = await freshModule();
    let calls = 0;
    const result = mod.runHx1400JitDualmapLease(context(mod, {
      ...override,
      read32: () => { calls += 1; return 0; },
      write32: () => { calls += 1; return 0; },
      createWritableView: () => { calls += 1; return 1; },
      mapExecutableView: () => { calls += 1; return 0; },
      disposeJit: () => { calls += 1; return 0; },
    }));
    assert.equal(result.error, "ERR_CONTEXT");
    assert.equal(calls, 0);
  }
});

test("hostile getters and non-plain prototypes are rejected without getter or callback execution", async () => {
  const mod = await freshModule();
  let getterCalls = 0;
  const hostile = {};
  for (const name of [
    "firmware", "source13Sha256", "generation", "target", "read32", "write32",
    "createWritableView", "mapExecutableView", "disposeJit", "synchronous",
    "exclusiveCredentialWriter", "parkedWorkerIdentity", "ucredIdentity", "pidIdentity",
  ]) Object.defineProperty(hostile, name, {
    enumerable: true,
    get() { getterCalls += 1; throw new Error("getter"); },
  });
  Object.freeze(hostile);
  const getterResult = mod.runHx1400JitDualmapLease(hostile);
  assert.equal(getterResult.error, "ERR_CONTEXT");
  assert.equal(getterCalls, 0);
  assert.equal(getterResult.reads, 0);
  assert.equal(getterResult.writes, 0);

  const other = await freshModule();
  let callbacks = 0;
  const base = { ...context(other, {
    read32: () => { callbacks += 1; return 0; },
    write32: () => { callbacks += 1; return 0; },
    createWritableView: () => { callbacks += 1; return 1; },
    mapExecutableView: () => { callbacks += 1; return 0; },
  }) };
  const badPrototype = Object.freeze(Object.assign(Object.create({ poisoned: true }), base));
  const prototypeResult = other.runHx1400JitDualmapLease(badPrototype);
  assert.equal(prototypeResult.error, "ERR_CONTEXT");
  assert.equal(callbacks, 0);
});

test("hostile Proxy introspection can only reenter a refused lease and cannot reach callbacks", async () => {
  const mod = await freshModule();
  let inner = null;
  let callbacks = 0;
  const target = context(mod, {
    read32: () => { callbacks += 1; return 0; },
    write32: () => { callbacks += 1; return 0; },
    createWritableView: () => { callbacks += 1; return 1; },
    mapExecutableView: () => { callbacks += 1; return 0; },
    disposeJit: () => { callbacks += 1; return 0; },
  });
  let proxy;
  proxy = new Proxy(target, {
    getPrototypeOf() {
      if (inner === null) inner = mod.runHx1400JitDualmapLease(proxy);
      throw new Error("hostile proxy");
    },
  });
  const outer = mod.runHx1400JitDualmapLease(proxy);
  assert.equal(outer.error, "ERR_CONTEXT");
  assert.equal(inner.error, "ERR_REENTRY");
  assert.equal(callbacks, 0);
  assert.equal(outer.reads, 0);
  assert.equal(outer.writes, 0);
});
