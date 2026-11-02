import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("./github-pages/portal.js", import.meta.url), "utf8");
const indexSource = readFileSync(new URL("./github-pages/index.html", import.meta.url), "utf8");

test("Pages cache-busts the portal script with its content digest", () => {
  const digest = createHash("sha256").update(source).digest("hex").slice(0, 8);
  assert.ok(indexSource.includes(`<script src="portal.js?v=${digest}" defer></script>`));
});


function clickWith(host) {
  let click;
  let focused = 0;
  const navigations = [];
  const gateway = {
    value: host,
    focus() {
      focused += 1;
    },
  };
  const open = {
    disabled: false,
    addEventListener(type, handler) {
      assert.equal(type, "click");
      click = handler;
    },
  };
  const status = { textContent: "" };
  const elements = { gateway, open, status };

  vm.runInNewContext(source, {
    document: {
      getElementById(id) {
        return elements[id];
      },
    },
    fetch() {
      return new Promise(() => {});
    },
    window: {
      location: {
        assign(url) {
          navigations.push(url);
        },
      },
    },
  });
  assert.equal(typeof click, "function");
  click();
  return { focused, navigations, open, status };
}

test("Pages transfers only to canonical RFC 1918 gateway addresses", () => {
  for (const host of ["10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.83"]) {
    const result = clickWith(host);
    assert.deepEqual(result.navigations, [`http://${host}/`]);
    assert.equal(result.open.disabled, true);
    assert.equal(result.focused, 0);
  }
});

test("Pages refuses public, loopback, link-local, noncanonical, and malformed addresses", () => {
  for (const host of [
    "8.8.8.8",
    "127.0.0.1",
    "169.254.1.1",
    "172.15.255.255",
    "172.32.0.1",
    "192.0.2.1",
    "192.168.001.83",
    "0.0.0.0",
    "256.1.1.1",
    "localhost",
    "192.168.1.83:80",
    " 192.168.1.83",
    "192.168.1.83 ",
    "192.168.1.83\n",
  ]) {
    const result = clickWith(host);
    assert.deepEqual(result.navigations, [], host);
    assert.equal(result.open.disabled, false, host);
    assert.equal(result.focused, 1, host);
    assert.equal(
      result.status.textContent,
      "Enter the exact private IPv4 shown by the local gateway operator.",
      host,
    );
  }
});
