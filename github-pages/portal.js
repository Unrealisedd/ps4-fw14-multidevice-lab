"use strict";

const gatewayInput = document.getElementById("gateway");
const openButton = document.getElementById("open");
const status = document.getElementById("status");

function canonicalIPv4(value) {
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return false;
    const octet = Number(part);
    return octet >= 0 && octet <= 255;
  });
}

openButton.addEventListener("click", () => {
  const host = gatewayInput.value.trim();
  if (!canonicalIPv4(host) || host === "0.0.0.0") {
    status.textContent = "Enter the exact IPv4 shown by the local gateway operator.";
    gatewayInput.focus();
    return;
  }
  openButton.disabled = true;
  status.textContent = "Opening the isolated local gateway. One-time codes are entered there, never on GitHub.";
  window.location.assign(`http://${host}/`);
});

fetch("release-manifest.json", { cache: "no-store", credentials: "omit", redirect: "error" })
  .then((response) => {
    if (!response.ok || response.headers.get("content-type")?.split(";", 1)[0] !== "application/json") {
      throw new Error("release metadata unavailable");
    }
    return response.json();
  })
  .then((manifest) => {
    if (
      manifest?.schema !== "oms.fw14-hx1400-access.release.v1" ||
      typeof manifest.version !== "string" ||
      !/^[0-9a-f]{64}$/.test(manifest.staticGraphSha256 || "")
    ) {
      throw new Error("release metadata invalid");
    }
    status.textContent = `Reviewed release ${manifest.version}; static graph ${manifest.staticGraphSha256.slice(0, 12)}…`;
  })
  .catch(() => {
    status.textContent = "Release metadata could not be verified here. Ask the operator to run the local offline check.";
  });
