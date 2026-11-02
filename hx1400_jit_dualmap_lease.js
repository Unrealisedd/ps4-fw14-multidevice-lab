const objectCreate = Object.create;
const objectDefineProperty = Object.defineProperty;
const objectFreeze = Object.freeze;
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectIsFrozen = Object.isFrozen;
const plainObjectPrototype = Object.prototype;
const reflectApply = Reflect.apply;
const reflectOwnKeys = Reflect.ownKeys;
const numberIsInteger = Number.isInteger;

export const HX1400_JIT_DUALMAP_LEASE_PROVENANCE = objectFreeze({
  firmware: "14.00",
  source13Sha256: "399367bed20e111200a0cd0ff13d3b6bfe3280cdd6105a675f149b4275515829",
  source13Only: true,
  jitCreateHandlerRva: 0x106f00,
  mmapHandlerRva: 0x1fa460,
  writeHelperRva: 0x3b31c0,
  executeHelperRva: 0x3b3220,
  jitResolverRva: 0x1075c0,
});

export const HX1400_JIT_DUALMAP_LEASE_CONSTANTS = objectFreeze({
  generation: 3,
  writeMask: 0x40000000,
  executeMask: 0x20000000,
  combinedMask: 0x60000000,
  scalarWidthBytes: 4,
});

const CONTEXT_FIELDS = objectFreeze([
  "firmware",
  "source13Sha256",
  "generation",
  "target",
  "read32",
  "write32",
  "createWritableView",
  "mapExecutableView",
  "disposeJit",
  "synchronous",
  "exclusiveCredentialWriter",
  "parkedWorkerIdentity",
  "ucredIdentity",
  "pidIdentity",
]);

const RECEIPT_FIELDS = objectFreeze([
  "ok", "status", "error", "cleanupError", "cleanupWriteError",
  "cleanupReadbackError", "disposalError", "fd", "descriptorTransferred",
  "disposeAttempted", "descriptorDisposed", "quarantined", "rebootRequired",
  "generation", "reads", "writes", "createCalls", "mapCalls",
  "preReadsStable", "writeArmAttempted", "writeArmConfirmed",
  "writePostConfirmed", "writeRestoreAttempted", "writeRestoreConfirmed",
  "executeArmAttempted", "executeArmConfirmed", "executePostConfirmed",
  "executeRestoreAttempted", "executeRestoreConfirmed", "borrowedBitsCleared",
  "terminalMatchesOriginal",
]);

let active = false;
let generationConsumed = false;
let generationQuarantined = false;

function receipt(values) {
  if (generationConsumed) values.rebootRequired = true;
  if (generationQuarantined) {
    values.quarantined = true;
    if (!values.ok) values.status = "QUARANTINED";
  }
  const result = objectCreate(null);
  for (let index = 0; index < RECEIPT_FIELDS.length; index += 1) {
    const name = RECEIPT_FIELDS[index];
    objectDefineProperty(result, name, {
      value: values[name], enumerable: true, writable: false, configurable: false,
    });
  }
  return objectFreeze(result);
}

function initial(status, error) {
  return {
    ok: false,
    status,
    error,
    cleanupError: null,
    cleanupWriteError: null,
    cleanupReadbackError: null,
    disposalError: null,
    fd: null,
    descriptorTransferred: false,
    disposeAttempted: false,
    descriptorDisposed: false,
    quarantined: false,
    rebootRequired: false,
    generation: HX1400_JIT_DUALMAP_LEASE_CONSTANTS.generation,
    reads: 0,
    writes: 0,
    createCalls: 0,
    mapCalls: 0,
    preReadsStable: false,
    writeArmAttempted: false,
    writeArmConfirmed: false,
    writePostConfirmed: false,
    writeRestoreAttempted: false,
    writeRestoreConfirmed: false,
    executeArmAttempted: false,
    executeArmConfirmed: false,
    executePostConfirmed: false,
    executeRestoreAttempted: false,
    executeRestoreConfirmed: false,
    borrowedBitsCleared: false,
    terminalMatchesOriginal: false,
  };
}

function dataValue(context, name) {
  const descriptor = objectGetOwnPropertyDescriptor(context, name);
  if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
    throw new TypeError("context field contract");
  }
  return descriptor.value;
}

function validateContext(context) {
  try {
    if (
      context === null || typeof context !== "object" ||
      objectGetPrototypeOf(context) !== plainObjectPrototype || !objectIsFrozen(context)
    ) return null;
    const keys = reflectOwnKeys(context);
    if (keys.length !== CONTEXT_FIELDS.length) return null;
    for (let fieldIndex = 0; fieldIndex < CONTEXT_FIELDS.length; fieldIndex += 1) {
      let found = false;
      for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
        if (keys[keyIndex] === CONTEXT_FIELDS[fieldIndex]) found = true;
      }
      if (!found) return null;
    }
    const values = objectCreate(null);
    for (let index = 0; index < CONTEXT_FIELDS.length; index += 1) {
      const name = CONTEXT_FIELDS[index];
      values[name] = dataValue(context, name);
    }
    if (
      values.firmware !== HX1400_JIT_DUALMAP_LEASE_PROVENANCE.firmware ||
      values.source13Sha256 !== HX1400_JIT_DUALMAP_LEASE_PROVENANCE.source13Sha256 ||
      values.generation !== HX1400_JIT_DUALMAP_LEASE_CONSTANTS.generation ||
      typeof values.read32 !== "function" || typeof values.write32 !== "function" ||
      typeof values.createWritableView !== "function" ||
      typeof values.mapExecutableView !== "function" || typeof values.disposeJit !== "function" ||
      values.synchronous !== true || values.exclusiveCredentialWriter !== true ||
      values.parkedWorkerIdentity !== true || values.ucredIdentity !== true ||
      values.pidIdentity !== true
    ) return null;
    return values;
  } catch (_) {
    return null;
  }
}

function readExact(values, state) {
  state.reads += 1;
  const value = reflectApply(values.read32, undefined, [values.target]);
  if (!numberIsInteger(value) || value < 0 || value > 0xffffffff) {
    throw new TypeError("read32 contract");
  }
  return value >>> 0;
}

function writeExact(values, state, value) {
  state.writes += 1;
  const result = reflectApply(values.write32, undefined, [values.target, value >>> 0]);
  if (result !== 0) throw new TypeError("write32 contract");
}

function rememberCleanupError(state, field, error) {
  if (state[field] === null) state[field] = error;
  if (state.cleanupError === null) state.cleanupError = error;
}

function restoreOriginal(values, state, original, phase) {
  const isWritePhase = phase === "write";
  const prefix = isWritePhase ? "WRITE" : "EXECUTE";
  const attemptedField = isWritePhase ? "writeRestoreAttempted" : "executeRestoreAttempted";
  const confirmedField = isWritePhase ? "writeRestoreConfirmed" : "executeRestoreConfirmed";
  let firstError = null;

  state[attemptedField] = true;
  try {
    writeExact(values, state, original);
  } catch (_) {
    firstError = `ERR_${prefix}_RESTORE_WRITE`;
    rememberCleanupError(state, "cleanupWriteError", firstError);
  }

  let first;
  let second;
  try {
    first = readExact(values, state);
    second = readExact(values, state);
  } catch (_) {
    const error = `ERR_${prefix}_RESTORE_READ`;
    if (firstError === null) firstError = error;
    rememberCleanupError(state, "cleanupReadbackError", error);
    state[confirmedField] = false;
    state.terminalMatchesOriginal = false;
    state.borrowedBitsCleared = false;
    return firstError;
  }

  if (first !== second) {
    const error = `ERR_${prefix}_RESTORE_UNSTABLE`;
    if (firstError === null) firstError = error;
    rememberCleanupError(state, "cleanupReadbackError", error);
    state[confirmedField] = false;
    state.terminalMatchesOriginal = false;
    state.borrowedBitsCleared = false;
    return firstError;
  }

  state.borrowedBitsCleared =
    (second & HX1400_JIT_DUALMAP_LEASE_CONSTANTS.writeMask) === 0 &&
    (second & HX1400_JIT_DUALMAP_LEASE_CONSTANTS.executeMask) === 0;
  state.terminalMatchesOriginal = second === original;
  state[confirmedField] = state.terminalMatchesOriginal;
  if (!state.terminalMatchesOriginal) {
    const error = `ERR_${prefix}_RESTORE_STATE`;
    if (firstError === null) firstError = error;
    rememberCleanupError(state, "cleanupReadbackError", error);
  }
  return firstError;
}

function disposeDescriptor(values, state, fd) {
  state.disposeAttempted = true;
  try {
    state.descriptorDisposed = reflectApply(values.disposeJit, undefined, [fd]) === 0;
  } catch (_) {
    state.descriptorDisposed = false;
  }
  if (!state.descriptorDisposed) state.disposalError = "ERR_DISPOSE";
}

function finishFailure(values, state, error, cleanFailure, fdKnown, fd) {
  state.error = error;
  if (fdKnown) disposeDescriptor(values, state, fd);
  const quarantine = !cleanFailure || state.cleanupError !== null || state.disposalError !== null;
  if (quarantine) generationQuarantined = true;
  state.status = quarantine ? "QUARANTINED" : "ERROR";
  state.quarantined = quarantine;
  return receipt(state);
}

function signedInt32(value) {
  return numberIsInteger(value) && value >= -0x80000000 && value <= 0x7fffffff;
}

export function runHx1400JitDualmapLease(context) {
  if (active) return receipt(initial("REFUSED", "ERR_REENTRY"));
  if (generationConsumed) return receipt(initial("REFUSED", "ERR_GENERATION_CLOSED"));

  // Reserve before inspecting context so Proxy traps cannot enter a peer generation.
  active = true;
  const state = initial("ERROR", "ERR_INTERNAL");
  let values = null;
  let original = 0;
  let mutationStarted = false;
  let phase = "write";
  let fdKnown = false;
  let fd = null;

  try {
    values = validateContext(context);
    if (values === null) {
      state.status = "REFUSED";
      state.error = "ERR_CONTEXT";
      return receipt(state);
    }

    // A structurally valid generation is consumed when it reaches its pre-read.
    generationConsumed = true;
    let first;
    let second;
    try {
      first = readExact(values, state);
      second = readExact(values, state);
    } catch (_) {
      state.status = "REFUSED";
      state.error = "ERR_PRE_READ";
      return receipt(state);
    }
    if (first !== second) {
      state.status = "REFUSED";
      state.error = "ERR_UNSTABLE_PRE_READ";
      return receipt(state);
    }

    original = first;
    state.preReadsStable = true;
    if (
      (original & HX1400_JIT_DUALMAP_LEASE_CONSTANTS.combinedMask) !== 0
    ) {
      state.status = "REFUSED";
      state.error = "ERR_PREAUTHORIZED";
      state.terminalMatchesOriginal = true;
      return receipt(state);
    }

    const writeArmed = (original | HX1400_JIT_DUALMAP_LEASE_CONSTANTS.writeMask) >>> 0;
    state.writeArmAttempted = true;
    mutationStarted = true;
    let writeArmError = null;
    try {
      writeExact(values, state, writeArmed);
    } catch (_) {
      writeArmError = "ERR_WRITE_ARM_WRITE";
    }
    if (writeArmError === null) {
      try {
        state.writeArmConfirmed = readExact(values, state) === writeArmed;
      } catch (_) {
        writeArmError = "ERR_WRITE_ARM_READBACK";
      }
      if (writeArmError === null && !state.writeArmConfirmed)
        writeArmError = "ERR_WRITE_ARM_READBACK";
    }
    if (writeArmError !== null) {
      const restoreError = restoreOriginal(values, state, original, "write");
      return finishFailure(values, state, writeArmError || restoreError, false, false, null);
    }

    state.createCalls = 1;
    let createResult = null;
    let createError = null;
    let descriptorRegistrations = 0;
    let descriptorRegistrationOpen = true;
    const registerDescriptor = (registeredFd) => {
      if (!descriptorRegistrationOpen || descriptorRegistrations !== 0)
        throw new TypeError("descriptor registration contract");
      descriptorRegistrations = 1;
      if (!signedInt32(registeredFd) || registeredFd < 0)
        throw new TypeError("descriptor registration contract");
      fdKnown = true;
      fd = registeredFd;
    };
    try {
      createResult = reflectApply(values.createWritableView, undefined, [registerDescriptor]);
      descriptorRegistrationOpen = false;
      if (!signedInt32(createResult)) {
        createError = "ERR_JIT_CREATE_CALLBACK";
      } else if (createResult >= 0) {
        if (!fdKnown) {
          fdKnown = true;
          fd = createResult;
          createError = "ERR_JIT_CREATE_CALLBACK";
        } else if (descriptorRegistrations !== 1 || createResult !== fd) {
          createError = "ERR_JIT_CREATE_CALLBACK";
        }
      } else if (descriptorRegistrations !== 0) {
        createError = "ERR_JIT_CREATE_CALLBACK";
      }
    } catch (_) {
      descriptorRegistrationOpen = false;
      createError = "ERR_JIT_CREATE_CALLBACK";
    }

    let writePostError = null;
    try {
      state.writePostConfirmed = readExact(values, state) === writeArmed;
    } catch (_) {
      writePostError = "ERR_WRITE_POST_READ";
    }
    if (writePostError === null && !state.writePostConfirmed)
      writePostError = "ERR_WRITE_POST_STATE";

    const writeRestoreError = restoreOriginal(values, state, original, "write");
    if (createError !== null || writePostError !== null || writeRestoreError !== null) {
      const error = createError || writePostError || writeRestoreError;
      return finishFailure(values, state, error, false, fdKnown, fd);
    }
    if (createResult < 0) {
      return finishFailure(values, state, "ERR_JIT_CREATE", true, false, null);
    }

    phase = "execute";
    const executeArmed = (original | HX1400_JIT_DUALMAP_LEASE_CONSTANTS.executeMask) >>> 0;
    state.executeArmAttempted = true;
    let executeArmError = null;
    try {
      writeExact(values, state, executeArmed);
    } catch (_) {
      executeArmError = "ERR_EXECUTE_ARM_WRITE";
    }
    if (executeArmError === null) {
      try {
        state.executeArmConfirmed = readExact(values, state) === executeArmed;
      } catch (_) {
        executeArmError = "ERR_EXECUTE_ARM_READBACK";
      }
      if (executeArmError === null && !state.executeArmConfirmed)
        executeArmError = "ERR_EXECUTE_ARM_READBACK";
    }
    if (executeArmError !== null) {
      restoreOriginal(values, state, original, "execute");
      return finishFailure(values, state, executeArmError, false, true, fd);
    }

    state.mapCalls = 1;
    let mapResult = null;
    let mapError = null;
    let mapCleanFailure = false;
    try {
      mapResult = reflectApply(values.mapExecutableView, undefined, [fd]);
      if (!signedInt32(mapResult)) mapError = "ERR_JIT_MAP_CALLBACK";
      else if (mapResult !== 0) {
        mapError = "ERR_JIT_MAP";
        mapCleanFailure = true;
      }
    } catch (_) {
      mapError = "ERR_JIT_MAP_CALLBACK";
    }

    let executePostError = null;
    try {
      state.executePostConfirmed = readExact(values, state) === executeArmed;
    } catch (_) {
      executePostError = "ERR_EXECUTE_POST_READ";
    }
    if (executePostError === null && !state.executePostConfirmed)
      executePostError = "ERR_EXECUTE_POST_STATE";

    const executeRestoreError = restoreOriginal(values, state, original, "execute");
    if (mapError !== null || executePostError !== null || executeRestoreError !== null) {
      const error = mapError || executePostError || executeRestoreError;
      const cleanFailure = mapCleanFailure && executePostError === null && executeRestoreError === null;
      return finishFailure(values, state, error, cleanFailure, true, fd);
    }

    state.ok = true;
    state.status = "OK";
    state.error = null;
    state.fd = fd;
    state.descriptorTransferred = true;
    return receipt(state);
  } catch (_) {
    if (values !== null && mutationStarted) {
      restoreOriginal(values, state, original, phase);
      if (fdKnown && !state.disposeAttempted) disposeDescriptor(values, state, fd);
    }
    state.ok = false;
    state.status = mutationStarted ? "QUARANTINED" : "REFUSED";
    state.error = "ERR_INTERNAL";
    if (mutationStarted) generationQuarantined = true;
    state.quarantined = mutationStarted;
    return receipt(state);
  } finally {
    active = false;
  }
}
