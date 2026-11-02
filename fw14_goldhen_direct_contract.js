export const CANONICAL_FW14_UA = "Mozilla/5.0 (PlayStation; PlayStation 4/14.00) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";

export const FW14_GOLDHEN_DIRECT_PROFILE = Object.freeze({
  slots: 9100000,
  drain: 12,
});

export const FW14_GOLDHEN_PATCH = Object.freeze({
  sha256: "165d2ad966b3829d1fbcb53d5e7ecbc20563de4a6a49ee70d8126d0256a49c02",
  size: 632,
  offset: 0,
});

export const FW14_GOLDHEN_HEN = Object.freeze({
  sha256: "29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06",
  size: 0x89440,
  offset: 0x4000,
  head: "e9a64a0000",
  entry: 0x4aab,
});

export function isFw14GoldhenDirectRoute(locationLike, contractModuleUrl = import.meta.url) {
  if (
    !locationLike ||
    typeof locationLike !== "object" ||
    typeof locationLike.href !== "string"
  ) return false;
  let expected;
  try {
    expected = new URL("./", contractModuleUrl);
  } catch (_) {
    return false;
  }
  return (
    locationLike.href === expected.href &&
    locationLike.pathname === expected.pathname &&
    locationLike.search === "" &&
    locationLike.hash === ""
  );
}

function randomHex(byteLength, randomSource) {
  if (!randomSource || typeof randomSource.getRandomValues !== "function") {
    throw new Error("Cryptographic randomness is unavailable.");
  }
  const bytes = new Uint8Array(byteLength);
  randomSource.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

export function buildFw14GoldhenLocalClaim(randomSource = globalThis.crypto) {
  const runId = randomHex(16, randomSource);
  const challenge = randomHex(32, randomSource);
  return Object.freeze({
    schema: "oms.fw14-hx1400-goldhen-dualmap.claim.v1",
    run_id: runId,
    challenge_hex: challenge,
    max_arms: 32,
    patch: FW14_GOLDHEN_PATCH,
    hen: FW14_GOLDHEN_HEN,
  });
}
