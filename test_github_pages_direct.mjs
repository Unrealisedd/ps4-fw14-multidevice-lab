import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  CANONICAL_FW14_UA,
  FW14_GOLDHEN_DIRECT_PROFILE,
  FW14_GOLDHEN_HEN,
  FW14_GOLDHEN_PATCH,
  buildFw14GoldhenLocalClaim,
  isFw14GoldhenDirectRoute,
} from "./fw14_goldhen_direct_contract.js";

const html = readFileSync(
  new URL("./index.html", import.meta.url),
  "utf8",
);
const entry = readFileSync(
  new URL("./fw14_hx1400_goldhen_dualmap_entry.js", import.meta.url),
  "utf8",
);
const client = readFileSync(
  new URL("./jb_hx1400_goldhen_dualmap.js", import.meta.url),
  "utf8",
);

test("direct route is the canonical project root with no URL delimiters", () => {
  const moduleUrl = "https://example.github.io/project/fw14_goldhen_direct_contract.js";
  assert.equal(
    isFw14GoldhenDirectRoute(new URL("https://example.github.io/project/"), moduleUrl),
    true,
  );
  for (const href of [
    "https://example.github.io/",
    "https://other.example/project/",
    "https://example.github.io/project",
    "https://example.github.io/project/index.html",
    "https://example.github.io/project/fw14_hx1400_goldhen_dualmap.html",
    "https://example.github.io/project/sub/",
    "https://example.github.io/project/?retry=0",
    "https://example.github.io/project/#start",
    "https://example.github.io/project/?",
    "https://example.github.io/project/#",
    "https://example.github.io/project/?#",
  ]) {
    assert.equal(isFw14GoldhenDirectRoute(new URL(href), moduleUrl), false, href);
  }
});

test("contract pins the FW14 identity, direct profile, and frozen local claim", () => {
  assert.equal(
    CANONICAL_FW14_UA,
    "Mozilla/5.0 (PlayStation; PlayStation 4/14.00) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  );
  assert.deepEqual(FW14_GOLDHEN_DIRECT_PROFILE, { slots: 9100000, drain: 12 });

  let next = 0;
  const claim = buildFw14GoldhenLocalClaim({
    getRandomValues(bytes) {
      for (let index = 0; index < bytes.length; index += 1) bytes[index] = next++;
      return bytes;
    },
  });
  assert.deepEqual(Object.keys(claim), [
    "schema", "run_id", "challenge_hex", "max_arms", "patch", "hen",
  ]);
  assert.equal(claim.run_id, "000102030405060708090a0b0c0d0e0f");
  assert.equal(
    claim.challenge_hex,
    "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
  );
  assert.equal(claim.run_id.length, 32);
  assert.equal(claim.challenge_hex.length, 64);
  assert.equal(claim.schema, "oms.fw14-hx1400-goldhen-dualmap.claim.v1");
  assert.equal(claim.max_arms, 32);
  assert.deepEqual(claim.patch, {
    sha256: "165d2ad966b3829d1fbcb53d5e7ecbc20563de4a6a49ee70d8126d0256a49c02",
    size: 632,
    offset: 0,
  });
  assert.deepEqual(claim.hen, {
    sha256: "39452f5e1c305ac9efcb4745eef7958b4db8c6d85299529f08700970b009ea4d",
    size: 0x48a18,
    offset: 0x4000,
    head: "e9a6160000",
    entry: 0x16ab,
  });
  assert.equal(claim.patch, FW14_GOLDHEN_PATCH);
  assert.equal(claim.hen, FW14_GOLDHEN_HEN);
  assert.ok(Object.isFrozen(claim));
  assert.ok(Object.isFrozen(claim.patch));
  assert.ok(Object.isFrozen(claim.hen));
  assert.throws(() => buildFw14GoldhenLocalClaim(null), /randomness is unavailable/i);
  assert.throws(() => buildFw14GoldhenLocalClaim({}), /randomness is unavailable/i);
});

test("HTML exposes a deliberate direct launcher under the Pages CSP", () => {
  assert.match(html, /Content-Security-Policy[^>]+default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'/i);
  assert.match(html, /GoldHEN[\s\S]*SiSTR0/i);
  assert.match(html, /href=\"https:\/\/github\.com\/GoldHEN\/GoldHEN\"/i);
  assert.match(html, /GoldHEN v2\.4b18\.13/i);
  assert.match(html, /href="\.\/GOLDHEN_LICENSES\.txt"/i);
  assert.match(html, /<input[^>]+id=\"accept\"[^>]+type=\"checkbox\"/i);
  assert.match(html, /<button[^>]+id=\"start\"[^>]+disabled/i);
  assert.match(html, /id=\"state\"/i);
  assert.match(html, /id=\"out\"/i);
  assert.match(html, /<script[^>]+type="module"[^>]+src="\.\/fw14_hx1400_goldhen_dualmap_entry\.js\?v=fw14-pages-direct-2"/i);
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/i);
});

test("entry binds the click before importing and starting the client", () => {
  const clickBinding = entry.indexOf('start.addEventListener(\"click\"');
  const clientImport = entry.indexOf('import("./jb_hx1400_goldhen_dualmap.js?v=fw14-pages-direct-2")');
  const clientStart = entry.indexOf("await clientModule.startHx1400GoldhenDualmapClient()");
  assert.ok(clickBinding >= 0);
  assert.ok(clientImport > clickBinding);
  assert.ok(clientStart > clientImport);
  assert.equal(entry.indexOf('import(\"./jb_hx1400_goldhen_dualmap.js'), clientImport);
  assert.equal(entry.indexOf("startHx1400GoldhenDualmapClient()"), clientStart + "await clientModule.".length);
  assert.match(entry, /if\s*\(!ready\s*\|\|\s*!accept\.checked\)/);
});

test("direct sources contain no gateway APIs and make only the relative HEN GET", () => {
  const directSources = `${entry}\n${client}`;
  for (const forbidden of [
    /one[-_ ]time password|\botp\b/i,
    /localhost|127\.0\.0\.1|192\.168\./i,
    /\bintent\b/i,
    /telemetry/i,
    /XMLHttpRequest/i,
    /\/hx1400-goldhen-dualmap\/(?:claim|result|abort|hen)\b/i,
    /\/kdump\/(?:challenge|result|abort)\b/i,
  ]) {
    assert.doesNotMatch(directSources, forbidden);
  }
  assert.doesNotMatch(directSources, /refresh the page|run again/i);
  assert.match(directSources, /cold reboot before another attempt/i);
  assert.match(client, /new URL\("\.\/hen\.bin", import\.meta\.url\)/);
  assert.match(client, /method:\s*"GET"/);
  assert.match(client, /cache:\s*"no-store"/);
  assert.match(client, /credentials:\s*"omit"/);
  assert.match(client, /redirect:\s*"error"/);
  assert.match(client, /FW14_GOLDHEN_DIRECT_PROFILE/);
  assert.match(client, /buildFw14GoldhenLocalClaim/);
  const core = readFileSync(new URL("./core_hx1400_lowmap.js", import.meta.url), "utf8");
  assert.match(core, /const CARRIER_SLOTS = FW14_GOLDHEN_DIRECT_PROFILE\.slots/);
  assert.match(core, /const DRAIN_COUNT = FW14_GOLDHEN_DIRECT_PROFILE\.drain/);
  assert.doesNotMatch(core, /URLSearchParams|location\.search/);
  assert.doesNotMatch(client, /fetch\(\s*["'`]\//);
  assert.equal((client.match(/\bfetch\s*\(/g) || []).length, 1);
});
