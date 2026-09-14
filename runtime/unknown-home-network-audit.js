"use strict";

const fs = require("fs");
const path = require("path");
const ROOTS = [
  "/media/cryptofs/apps/usr/palm/services", "/media/developer/apps/usr/palm/services",
  "/media/cryptofs/apps/usr/palm/applications", "/media/developer/apps/usr/palm/applications"
];
const LIMITS = { entries: 16000, packageEntries: 1200, bytes: 48 * 1024 * 1024, fileBytes: 2 * 1024 * 1024, milliseconds: 8000, findings: 64, depth: 12 };
// Indicators are review leads, never proof of an active proxy or permission to delete an app.
const MARKERS = [
  { provider: "Bright Data", pattern: /\bbrd_api\.js\b|\bbrd_sdk\b|\bbrightdata\b/i },
  { provider: "Massive", pattern: /\.massivesdk\b|\bmassive-sdk\b/i },
  { provider: "Honeygain / Oxylabs", pattern: /\bhoneygain\b|\boxylabs\b/i }
];
const SKIP = /^(?:\.git|cache|logs?|history|userdata|profile|profiles|databases?|cookies|private-ca)$/i;
const SELF = /^(?:org\.unknown\.home(?:\.service)?)$/;

function scanPackages(options) {
  options = options || {};
  const io = options.fs || fs;
  const now = options.now || Date.now;
  const limits = Object.assign({}, LIMITS, options.limits);
  const roots = options.roots || ROOTS;
  const start = now();
  const report = { scope: "bounded-installed-code-indicators", entries: 0, filesRead: 0, bytesRead: 0,
    packages: 0, findings: [], incomplete: false, skippedLarge: 0, skippedLinks: 0,
    skippedDirectories: 0, excludedOwnPackages: 0, errors: 0, missingRoots: 0 };
  let packageEntries = 0;
  const seen = new Set();
  const stop = () => report.entries >= limits.entries || report.bytesRead >= limits.bytes ||
    now() - start >= limits.milliseconds || report.findings.length >= limits.findings;
  function note(packageId, relative, text, kind) {
    MARKERS.forEach((marker) => {
      const key = packageId + ":" + relative + ":" + marker.provider;
      if (report.findings.length < limits.findings && marker.pattern.test(text) && !seen.has(key)) {
        seen.add(key);
        report.findings.push({ packageId: packageId, file: relative, provider: marker.provider,
          evidence: kind, classification: "indicator-only" });
      }
    });
  }
  function visit(root, relative, packageId, depth) {
    if (stop() || packageEntries >= limits.packageEntries) { report.incomplete = true; return; }
    packageEntries++;
    report.entries++;
    const full = path.join(root, relative);
    try {
      const stat = io.lstatSync(full);
      if (stat.isSymbolicLink()) { report.skippedLinks++; report.incomplete = true; return; }
      note(packageId, relative, relative, "package-path");
      if (stat.isDirectory()) {
        if (depth >= limits.depth || SKIP.test(path.basename(relative))) { report.skippedDirectories++; report.incomplete = true; return; }
        for (const entry of io.readdirSync(full)) {
          if (stop() || packageEntries >= limits.packageEntries) { report.incomplete = true; break; }
          visit(root, path.join(relative, entry), packageId, depth + 1);
        }
        return;
      }
      if (!stat.isFile() || !/\.(?:js|mjs|cjs|html|json)$/i.test(relative)) return;
      if (stat.size > limits.fileBytes) { report.skippedLarge++; report.incomplete = true; return; }
      if (report.bytesRead + stat.size > limits.bytes) { report.incomplete = true; return; }
      // A fixed-size read plus O_NOFOLLOW avoids following a replaced file or allocating a grown file.
      const flags = io.constants.O_RDONLY | (io.constants.O_NOFOLLOW || 0) | (io.constants.O_NONBLOCK || 0);
      const fd = io.openSync(full, flags);
      try {
        const fresh = io.fstatSync(fd);
        // Some Windows hosts report lstat.dev=0 but a volume ID through fstat.
        const deviceChanged = fresh.dev !== stat.dev && !(process.platform === "win32" && stat.dev === 0);
        if (!fresh.isFile() || deviceChanged || fresh.ino !== stat.ino || fresh.size !== stat.size) {
          report.incomplete = true; return;
        }
        const bytes = Buffer.alloc(stat.size);
        let used = 0;
        while (used < bytes.length) {
          const count = io.readSync(fd, bytes, used, bytes.length - used, used);
          if (!count) break;
          used += count;
        }
        report.filesRead++;
        report.bytesRead += used;
        if (used !== stat.size) report.incomplete = true;
        note(packageId, relative, bytes.toString("utf8", 0, used), "code-token");
      } finally { io.closeSync(fd); }
    } catch (_) { report.errors++; report.incomplete = true; }
  }
  for (const root of roots) {
    if (stop()) { report.incomplete = true; break; }
    try {
      for (const packageId of io.readdirSync(root)) {
        if (stop()) { report.incomplete = true; break; }
        if (SELF.test(packageId)) { report.excludedOwnPackages++; continue; }
        report.packages++;
        packageEntries = 0;
        visit(root, packageId, packageId, 0);
      }
    } catch (error) {
      if (error.code === "ENOENT") report.missingRoots++;
      else report.errors++;
      report.incomplete = true;
    }
  }
  report.elapsedMs = now() - start;
  report.outcome = report.findings.length ? "review-indicators" : "no-known-indicators-in-scanned-files";
  report.limit = "Not a clean bill of health. Native binaries, downloaded code, renamed SDKs and excluded files are not examined. No app was disabled.";
  return report;
}

function capabilities(options) {
  options = options || {};
  const io = options.fs || fs;
  const resolve = options.resolve || ((name) => name);
  const read = (name) => { try { return io.readFileSync(resolve(name), "utf8"); } catch (_) { return null; } };
  const matches = read("/proc/net/ip_tables_matches");
  const tables4 = read("/proc/net/ip_tables_names");
  const tables6 = read("/proc/net/ip6_tables_names");
  const ipv6 = read("/proc/net/if_inet6");
  const hasLine = (text, word) => text === null ? null : text.split(/\s+/).includes(word);
  let sharedNetworkProcess = null;
  try {
    sharedNetworkProcess = false;
    const pids = io.readdirSync(resolve("/proc")).filter((name) => /^\d+$/.test(name));
    if (pids.length > 2048) sharedNetworkProcess = null;
    else pids.forEach((pid) => {
      const command = read("/proc/" + pid + "/cmdline");
      if (command && command.includes("WebAppMgr") && command.includes("network.mojom.NetworkService")) sharedNetworkProcess = true;
    });
  } catch (_) { sharedNetworkProcess = null; }
  return {
    ipv4FilterLoaded: hasLine(tables4, "filter"), ipv6FilterLoaded: hasLine(tables6, "filter"),
    ipv6AddressesPresent: ipv6 === null ? null : Boolean(ipv6.trim()),
    ownerMatchLoaded: hasLine(matches, "owner"), cgroupMatchLoaded: hasLine(matches, "cgroup"),
    sharedWebAppNetworkProcess: sharedNetworkProcess,
    meaning: "Read-only observations, not a kernel support test or proof of router isolation. Unloaded matches may exist on other firmware."
  };
}

function audit(options) {
  return { checkedAt: new Date().toISOString(), changesMade: false,
    lanUpnp: { state: "not-enforced", verified: false, detail: "App SSDP discovery and direct UPnP control are not blocked by the LG service switches." },
    residentialProxy: { state: "not-enforced", verified: false, detail: "Outbound app relays remain possible. DNS, UPnP and inbound-port blocks do not prevent them." },
    capabilities: capabilities(options), packages: scanPackages(options) };
}

if (require.main === module) {
  try {
    if (process.platform !== "linux" || process.getuid() !== 0) throw new Error("Rooted Linux TV required");
    process.stdout.write(JSON.stringify(audit()) + "\n");
  } catch (error) { process.stderr.write(error.message + "\n"); process.exitCode = 1; }
}
module.exports = { scanPackages: scanPackages, capabilities: capabilities, audit: audit, LIMITS: LIMITS };
