import {
  CANONICAL_FW14_UA,
  isFw14GoldhenDirectRoute,
} from "./fw14_goldhen_direct_contract.js?v=fw14-pages-direct-1";

const PAGE_ATTEMPT_KEY = "jb-fw14-hx1400-goldhen-dualmap-page-attempted";
const KERNEL_ATTEMPT_KEY = "jb-fw14-hx1400-goldhen-dualmap-arm-attempted";
const CLICK_KEY = "jb-fw14-hx1400-goldhen-dualmap-click-token";
const start = document.getElementById("start");
const accept = document.getElementById("accept");
const message = document.getElementById("msg");
let ready = false;

function refuse(text) {
  ready = false;
  start.disabled = true;
  accept.disabled = true;
  message.textContent = text;
  document.body.className = "fail";
}

if (!isFw14GoldhenDirectRoute(location, import.meta.url)) {
  refuse("Refused: open the exact project-root launcher with no query or fragment.");
} else if (navigator.userAgent !== CANONICAL_FW14_UA) {
  refuse("Refused: exact PlayStation 4 firmware 14.00 identity required.");
} else {
  try {
    if (sessionStorage.getItem(PAGE_ATTEMPT_KEY) === "1") {
      throw new Error("This page attempt is already consumed.");
    }
    if (sessionStorage.getItem(KERNEL_ATTEMPT_KEY) === "1") {
      throw new Error("A kernel attempt is already consumed; cold reboot required.");
    }
    ready = true;
    message.textContent = "Read the risk statement, acknowledge it, then click exactly once.";
  } catch (error) {
    refuse(String((error && error.message) || error));
  }
}

accept.addEventListener("change", () => {
  start.disabled = !(ready && accept.checked);
});

start.addEventListener("click", async () => {
  start.disabled = true;
  accept.disabled = true;
  message.textContent = "Attempt consumed. Do not reload. Cold reboot afterward.";
  try {
    if (!ready || !accept.checked) throw new Error("Risk acknowledgment missing.");
    if (sessionStorage.getItem(PAGE_ATTEMPT_KEY) !== null) {
      throw new Error("This page attempt is already consumed.");
    }
    if (sessionStorage.getItem(KERNEL_ATTEMPT_KEY) !== null) {
      throw new Error("A kernel attempt is already consumed; cold reboot required.");
    }
    sessionStorage.setItem(PAGE_ATTEMPT_KEY, "1");
    if (sessionStorage.getItem(PAGE_ATTEMPT_KEY) !== "1") {
      throw new Error("Could not persist the page latch.");
    }
    sessionStorage.setItem(CLICK_KEY, "1");
    if (sessionStorage.getItem(CLICK_KEY) !== "1") {
      throw new Error("Could not store the click token.");
    }

    const int64Descriptor = Object.getOwnPropertyDescriptor(globalThis, "int64");
    let clientModule;
    try {
      clientModule = await import("./jb_hx1400_goldhen_dualmap.js?v=fw14-pages-direct-1");
    } finally {
      if (int64Descriptor === undefined) {
        if (!delete globalThis.int64 || Object.prototype.hasOwnProperty.call(globalThis, "int64")) {
          throw new Error("Could not withdraw imported global int64.");
        }
      } else {
        Object.defineProperty(globalThis, "int64", int64Descriptor);
      }
    }
    if (!clientModule || typeof clientModule.startHx1400GoldhenDualmapClient !== "function") {
      throw new Error("Client start export is unavailable.");
    }
    await clientModule.startHx1400GoldhenDualmapClient();
  } catch (error) {
    sessionStorage.removeItem(CLICK_KEY);
    refuse(String((error && error.message) || error));
  }
});
