"use strict";

const fs = require("fs");
const path = require("path");
const privacy = require("./unknown-home-privacy.js");
const EXTRA_DISCOVERY = ["avahi-daemon", "avahi-adaptor", "ssc"];
const DIRECTORIES = ["/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/"];
const PORTS = { 5353: "mDNS", 1900: "SSDP/UPnP", 5355: "LLMNR", 137: "NetBIOS names" };
const LIMITS = { processes: 4096, descriptors: 32768, fileBytes: 524288, sockets: 256 };
const BASE = "/var/lib/unknown-home/privacy";
const STUB_PATH = "/run/unknown-home-privacy/disabled";

// This probe only reads local state. It never starts a service, sends a packet,
// repairs a blocker, or writes a log, even when the screen polls repeatedly.
function inspect(options) {
  options = options || {};
  const io = options.fs || fs;
  const resolve = options.resolve || ((name) => name);
  const started = Date.now();
  const errors = [];
  let processComplete = true;
  let socketsComplete = true;
  const note = (text) => { if (!errors.includes(text) && errors.length < 24) errors.push(text); };
  function read(name, optional) {
    let fd;
    try {
      fd = io.openSync(resolve(name), "r");
      const data = Buffer.alloc(LIMITS.fileBytes + 1);
      let size = 0;
      while (size < data.length) {
        const n = io.readSync(fd, data, size, data.length - size, null);
        if (!n) break;
        size += n;
      }
      if (size > LIMITS.fileBytes) throw new Error("size limit");
      return data.slice(0, size).toString("utf8");
    } catch (error) {
      if (!(optional && error.code === "ENOENT")) note("Unreadable: " + name);
      return null;
    } finally { if (fd !== undefined) io.closeSync(fd); }
  }
  function stat(name) {
    try { return io.statSync(resolve(name)); }
    catch (error) { if (!["ENOENT", "ENOTDIR"].includes(error.code)) note("Cannot inspect: " + name); return null; }
  }
  function link(name) { return io.readlinkSync(resolve(name)); }
  function json(name, fallback) {
    const text = read(name, true);
    if (text === null) return fallback;
    try { return JSON.parse(text); }
    catch (_) { note("Invalid state: " + name); return null; }
  }
  let globalNamespace = false;
  try { globalNamespace = link("/proc/self/ns/mnt") === link("/proc/1/ns/mnt"); }
  catch (_) { note("Global mount namespace could not be checked"); }
  const root = options.testing ? options.root !== false : process.platform === "linux" && process.getuid() === 0;
  if (!root) note("Root access required for complete evidence");
  if (!globalNamespace) note("Jailed or unknown mount namespace");
  const config = json(BASE + "/config.json", {});
  const runtime = json(BASE + "/runtime.json", {});
  const boot = read("/proc/sys/kernel/random/boot_id");
  const mountText = read("/proc/self/mountinfo");
  const mounts = privacy.parseMounts(mountText || "");
  const registryValid = Boolean(runtime && boot && runtime.boot === boot.trim() && runtime.targets && typeof runtime.targets === "object");
  const stub = stat(STUB_PATH);
  let stubValid = false;
  try {
    const info = io.lstatSync(resolve(STUB_PATH));
    stubValid = info.isFile() && !info.isSymbolicLink() && info.uid === 0 && !(info.mode & 0o022) &&
      read(STUB_PATH) === privacy.STUB;
  } catch (error) { if (error.code !== "ENOENT") note("Blocker integrity could not be checked"); }
  const sockets = [];
  const connections = [];
  const microphones = { devices: [], complete: true, hardwareCutoffVerified: false };
  const pcm = read("/proc/asound/pcm", true);
  if (pcm === null) microphones.complete = false;
  (pcm || "").split("\n").slice(0, 128).forEach((line) => {
    const match = /^(\d+)-(\d+): (.*?) :.*capture (\d+)/.exec(line);
    if (!match) return;
    const card = Number(match[1]), device = Number(match[2]);
    const target = "/dev/snd/pcmC" + card + "D" + device + "c";
    const states = [];
    for (let sub = 0; sub < Math.min(Number(match[4]), 32); sub++) {
      const raw = read("/proc/asound/card" + card + "/pcm" + device + "c/sub" + sub + "/status", true);
      states.push(raw === null ? "UNKNOWN" : raw.trim() === "closed" ? "CLOSED" : ((raw.match(/^state:\s*(\S+)/m) || [])[1] || "UNKNOWN"));
    }
    if (states.includes("UNKNOWN") || Number(match[4]) > 32) microphones.complete = false;
    microphones.devices.push({ path: target, name: match[3], states: states, owners: [],
      identifiedMicrophone: /^WoV PDM Mic(?: |$)/.test(match[3]) });
  });
  function endpoint(value, family) {
    const parts = value.split(":"), hex = parts[0];
    if (!/^[A-Fa-f0-9]+$/.test(hex)) return "Unknown";
    let address;
    if (!family.endsWith("6")) address = hex.match(/../g).reverse().map((pair) => parseInt(pair, 16)).join(".");
    else address = "[" + (hex.match(/.{8}/g) || []).map((word) => word.match(/../g).reverse().join("")).join("").match(/.{4}/g).join(":") + "]";
    return address + ":" + parseInt(parts[1], 16);
  }
  ["udp", "udp6", "tcp", "tcp6"].forEach((family) => {
    const raw = read("/proc/net/" + family, true);
    if (raw === null) {
      // Missing IPv6 tables are common on older kernels, not evidence of a block.
      if (!family.endsWith("6")) { socketsComplete = false; note("Socket inventory unavailable: " + family); }
      return;
    }
    raw.trim().split("\n").slice(1).forEach((line) => {
      const fields = line.trim().split(/\s+/);
      if (fields.length < 10) { socketsComplete = false; return; }
      const port = parseInt(fields[1].split(":")[1], 16);
      if (!/^0+:0000$/.test(fields[2])) {
        if (connections.length < LIMITS.sockets) connections.push({ protocol: family, remote: endpoint(fields[2], family), state: fields[3], inode: fields[9], owners: [] });
        else { socketsComplete = false; note("Connection inventory limit reached"); }
      }
      if (!PORTS[port] || (family.startsWith("tcp") && fields[3] !== "0A")) return;
      if (sockets.length >= LIMITS.sockets) { socketsComplete = false; note("Socket inventory limit reached"); return; }
      sockets.push({ protocol: family, port: port, service: PORTS[port], inode: fields[9], owners: [] });
    });
  });
  const processes = [];
  let pids = [];
  try { pids = io.readdirSync(resolve("/proc")).filter((pid) => /^[1-9][0-9]*$/.test(pid)); }
  catch (_) { processComplete = false; note("Process inventory unavailable"); }
  if (pids.length > LIMITS.processes) { processComplete = false; note("Process inventory limit reached"); }
  let descriptors = 0;
  pids.slice(0, LIMITS.processes).forEach((pid) => {
    let executable;
    try { executable = link("/proc/" + pid + "/exe").replace(/ \(deleted\)$/, ""); }
    catch (error) {
      if (!["ENOENT", "ESRCH", "EINVAL"].includes(error.code)) { processComplete = false; note("Some process identities are unreadable"); }
      return;
    }
    processes.push({ pid: Number(pid), executable: executable, name: path.posix.basename(executable) });
    if (!sockets.length && !connections.length && !microphones.devices.length) return;
    let fds;
    try { fds = io.readdirSync(resolve("/proc/" + pid + "/fd")); }
    catch (error) { if (!["ENOENT", "ESRCH"].includes(error.code)) { socketsComplete = false; note("Some socket owners are unreadable"); } return; }
    for (const fd of fds) {
      if (++descriptors > LIMITS.descriptors) { socketsComplete = false; note("Socket ownership limit reached"); break; }
      try {
        const target = link("/proc/" + pid + "/fd/" + fd);
        const match = /^socket:\[(\d+)\]$/.exec(target);
        if (match) sockets.concat(connections).forEach((socket) => {
          if (socket.inode === match[1] && !socket.owners.some((owner) => owner.pid === Number(pid))) socket.owners.push({ pid: Number(pid), executable: executable });
        });
        microphones.devices.forEach((device) => {
          if (target === device.path && !device.owners.some((owner) => owner.pid === Number(pid))) device.owners.push({ pid: Number(pid), executable: executable });
        });
      } catch (error) { if (!["ENOENT", "ESRCH", "EINVAL"].includes(error.code)) { socketsComplete = false; note("Some socket owners are unreadable"); } }
    }
  });
  if (sockets.some((socket) => !socket.owners.length)) { socketsComplete = false; note("Some discovery sockets have no identified owner"); }
  if (!socketsComplete || !processComplete) microphones.complete = false;
  const contextValid = root && globalNamespace && mountText !== null && boot !== null;
  function serviceRow(name, required, managed) {
    const canonical = "/usr/sbin/" + name;
    const found = DIRECTORIES.map((dir) => dir + name).filter((file) => stat(file));
    const live = processes.filter((item) => item.name === name);
    live.forEach((item) => { if (!found.includes(item.executable)) found.push(item.executable); });
    const info = stat(canonical);
    const entry = registryValid && runtime.targets[name];
    const owned = Boolean(managed && stubValid && stub && info && entry && !entry.pending &&
      mounts.some((mount) => mount.id === entry.mountId && mount.target === canonical) &&
      info.dev === stub.dev && info.ino === stub.ino);
    const variant = found.some((file) => file !== canonical);
    const checked = contextValid && processComplete;
    const blocked = checked && owned && !variant;
    return { name: name, required: required, managed: managed, paths: found, present: found.length > 0,
      pids: live.map((item) => item.pid).slice(0, 32), running: live.length ? true : processComplete ? false : null,
      blocker: !managed ? "outside-profile" : !found.length ? "not-detected" : !checked ? "unverified" :
        blocked ? "verified" : owned && variant ? "partial" : "missing",
      variant: variant };
  }
  const controls = {};
  Object.keys(privacy.PROFILES).forEach((key) => {
    const profile = privacy.PROFILES[key];
    const configured = Boolean(config && config.version === 1 && typeof config[key] === "boolean");
    const enabled = configured ? config[key] : null;
    const rows = profile.required.concat(profile.optional).map((name) => serviceRow(name, profile.required.includes(name), true));
    const present = rows.filter((row) => row.present);
    const missing = rows.filter((row) => row.required && !row.present).map((row) => row.name);
    const allBlocked = !missing.length && present.length > 0 && present.every((row) => row.blocker === "verified" && row.running === false);
    const extras = key === "discovery" ? EXTRA_DISCOVERY.map((name) => serviceRow(name, false, false)).filter((row) => row.present) : [];
    const exposed = key === "discovery" && (sockets.length > 0 || extras.length > 0);
    controls[key] = { enabled: enabled, verified: enabled === true && allBlocked && !exposed,
      state: !contextValid || !processComplete || !configured ? "unverified" : missing.length ? "unsupported" :
        exposed ? "attention" : !enabled ? "off" : allBlocked ? "verified" : "attention",
      rows: rows.concat(extras), missing: missing, detail: profile.limit };
  });
  // An unreadable path/config cannot be turned into a green check.
  if (errors.some((item) => /^(Unreadable|Cannot inspect|Invalid state|Blocker integrity)/.test(item))) {
    Object.keys(controls).forEach((key) => { if (controls[key].verified) { controls[key].verified = false; controls[key].state = "unverified"; } });
  }
  const release = read("/etc/webos-release", true);
  const versionLines = (release || "").split("\n").filter((line) => /^(WEBOS_RELEASE|WEBOS_DISTRO_VERSION|WEBOS_BUILD_ID|WEBOS_DISTRO_NAME)=/.test(line)).slice(0, 4);
  // Read capability declarations, never request a scan, location or HDMI data.
  const acrPermissions = json("/usr/share/luna-service2/client-permissions.d/com.webos.service.acr.perm.json", {});
  const wifiPermissions = json("/usr/share/luna-service2/api-permissions.d/webos-connman-adapter.api.json", {});
  const acrGrants = acrPermissions && acrPermissions["com.webos.service.acr"];
  const wifiScanDeclared = Boolean(wifiPermissions && Object.keys(wifiPermissions).some((key) =>
    Array.isArray(wifiPermissions[key]) && wifiPermissions[key].includes("com.webos.service.wifi/scan")));
  const location = {
    acrPathState: controls.acr.state,
    acrBlockVerified: controls.acr.verified,
    acrBroadPermissionDeclared: Array.isArray(acrGrants) ? acrGrants.includes("all") : null,
    wifiScanApiDeclared: wifiScanDeclared,
    wifiServices: processes.filter((item) => ["wpa_supplicant", "connmand", "webos-connman-adapter"].includes(item.name)),
    scanActivity: "not-measured",
    allLocationCollectionBlocked: false,
    hdmiMetadataBlocked: false,
    alphonsoEgressBlocked: false,
    detail: "Known ACR block covers that executable, including its HDMI recognition and location reporting. Wi-Fi scan activity, other collectors, IP geolocation and HDMI CEC/SPD metadata are not blocked or certified absent."
  };
  return { version: 1, checkedAt: new Date().toISOString(), durationMs: Date.now() - started, readOnly: true,
    device: { architecture: options.architecture || process.arch, kernel: (read("/proc/sys/kernel/osrelease", true) || "Unknown").trim(), release: versionLines },
    context: { root: root, globalNamespace: globalNamespace, processInventoryComplete: processComplete, socketInventoryComplete: socketsComplete },
    controls: controls, location: location, processes: processes, microphones: microphones, network: { state: sockets.length ? "exposed" : socketsComplete ? "not-enforced" : "unverified",
      connections: connections.map((connection) => ({ protocol: connection.protocol, remote: connection.remote, state: connection.state, owners: connection.owners })),
      isolationVerified: false, sockets: sockets.map((socket) => ({ protocol: socket.protocol, port: socket.port, service: socket.service, owners: socket.owners })),
      detail: "Listeners show discovery capability, not proof of scanning or uploads. No LAN isolation is verified; peer names can arrive in broadcasts." },
    errors: errors, coverage: "Known executable identities and discovery ports only. Missing or renamed components are not certified safe.",
    bootProtection: "Snapshot only. Root startup protection has an early-boot gap." };
}
if (require.main === module) {
  try { process.stdout.write(JSON.stringify(inspect()) + "\n"); }
  catch (error) { process.stderr.write("Diagnostics unavailable: " + error.message + "\n"); process.exitCode = 1; }
}
module.exports = { inspect: inspect, LIMITS: LIMITS };
