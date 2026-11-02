function errorText(error) {
  return error && error.message ? error.message : String(error);
}

export function createFw14CommonCleanup(options) {
  const {
    workers,
    restoreWorker,
    liveFds,
    closeFd,
    restoreAffinity,
    restoreMainPivot,
    clearBuffers,
    emit = () => {},
  } = options;
  if (!Array.isArray(workers) || !Array.isArray(liveFds))
    throw new TypeError("cleanup resource collections must be arrays");
  for (const operation of [
    restoreWorker,
    closeFd,
    restoreAffinity,
    restoreMainPivot,
    clearBuffers,
  ])
    if (typeof operation !== "function")
      throw new TypeError("cleanup operations must be functions");

  let running = false;
  const report = (tag, detail) => {
    try {
      emit(tag, detail);
    } catch (_) {}
  };

  return async function cleanupFw14Common() {
    if (running) throw new Error("FW14 common cleanup is already running");
    running = true;
    let stage = "workers";
    try {
      const workerFailures = [];
      let workerRestored = 0,
        workerAlreadyClean = 0;
      for (const worker of workers) {
        if (worker.terminated) {
          workerAlreadyClean++;
          continue;
        }
        try {
          await restoreWorker(worker);
          if (!worker.terminated)
            throw new Error(worker.name + " did not terminate");
          workerRestored++;
        } catch (error) {
          workerFailures.push(worker.name + ": " + errorText(error));
        }
      }
      report(
        "FW14-WORKER-RESTORE",
        "restored=" +
          workerRestored +
          " already_clean=" +
          workerAlreadyClean +
          " failed=" +
          workerFailures.length,
      );
      if (workerFailures.length)
        throw new Error("worker cleanup failed: " + workerFailures.join("; "));

      stage = "descriptors";
      const uniqueFds = Array.from(new Set(liveFds));
      liveFds.length = 0;
      const fdFailures = [];
      let closed = 0;
      for (const fd of uniqueFds) {
        let result = -1;
        try {
          result = closeFd(fd);
        } catch (error) {
          fdFailures.push(fd + ": " + errorText(error));
          liveFds.push(fd);
          continue;
        }
        if (result === 0) closed++;
        else {
          fdFailures.push(fd + ": close returned " + result);
          liveFds.push(fd);
        }
      }
      report(
        "FW14-FD-RESTORE",
        "closed=" +
          closed +
          "/" +
          uniqueFds.length +
          " remaining=" +
          liveFds.length,
      );
      if (fdFailures.length)
        throw new Error("descriptor cleanup failed: " + fdFailures.join("; "));

      stage = "affinity";
      if ((await restoreAffinity()) !== true)
        throw new Error("affinity restoration did not verify");

      stage = "main-pivot";
      if ((await restoreMainPivot()) !== true)
        throw new Error("main pivot restoration did not verify");

      stage = "buffers";
      const cleared = (await clearBuffers()) || {};
      report(
        "FW14-USER-BUFFERS-CLEARED",
        "buffers=" +
          (cleared.buffers || 0) +
          " bytes=" +
          (cleared.bytes || 0),
      );
      report("FW14-COMMON-CLEANUP", "verified=1");
      return true;
    } catch (error) {
      report(
        "FW14-COMMON-CLEANUP",
        "verified=0 stage=" + stage + " error=" + errorText(error),
      );
      throw error;
    } finally {
      running = false;
    }
  };
}

export function shouldRunLegacyWorkerCleanup(options) {
  const {
    fw14Leak2,
    fw14Kdump,
    mainArmed,
    commonCleanup,
    aioCleanup,
  } = options;
  return (
    (fw14Leak2 || (fw14Kdump && mainArmed && !commonCleanup)) &&
    !(fw14Kdump && aioCleanup)
  );
}

export async function finishFw14AttemptCleanup(options) {
  const {
    mainArmed,
    cleanupAlreadyAttempted = false,
    aioCleanup,
    commonCleanup,
    emit = () => {},
    setState = () => {},
  } = options;
  if (!mainArmed) return { attempted: false, aioSafe: true, incomplete: false };
  if (cleanupAlreadyAttempted) {
    emit(
      "FW14-CLEANUP-RETAINED",
      "prior cleanup attempt failed; dependencies retained for reboot safety",
    );
    setState(
      "Cleanup could not be fully verified; reboot before another attempt",
      "bad",
    );
    return { attempted: false, aioSafe: false, incomplete: true };
  }

  let aioSafe = typeof aioCleanup !== "function";
  let incomplete = false;
  if (typeof aioCleanup === "function") {
    try {
      await aioCleanup();
      aioSafe = true;
    } catch (error) {
      incomplete = true;
      emit("FW14-CLEANUP-FAIL", errorText(error));
    }
  }
  if (aioSafe) {
    try {
      if (typeof commonCleanup !== "function")
        throw new Error("FW14 common cleanup helper unavailable");
      await commonCleanup();
    } catch (error) {
      incomplete = true;
      emit("FW14-CLEANUP-FAIL", errorText(error));
    }
  }
  if (incomplete)
    setState(
      "Cleanup could not be fully verified; reboot before another attempt",
      "bad",
    );
  return { attempted: true, aioSafe, incomplete };
}
