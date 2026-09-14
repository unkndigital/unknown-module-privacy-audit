"use strict";

const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const crypto = require("crypto");

const VERSION = 1;
const BASE = "/var/lib/unknown-home/privacy";
const VOLATILE = "/run/unknown-home-privacy";
const STUB = "#!/bin/sh\n# Unknown Home privacy: intentionally disabled optional LG service.\nexit 0\n";
// Exact, optional service executables only. Never match process-name substrings.
const PROFILES = {
  acr: { required: ["acr2"], optional: [], limit: "Known LG ACR executable blocked; not a hardware capture interlock." },
  voice: {
    required: ["voiceinput", "voiceconductor"],
    optional: ["voiceinput_sound", "voiceinput_preprocessor", "voiceinput_hidraw", "voiceinput_network",
      "voiceclick", "com.webos.service.microphone", "trigger_thinq", "trigger_alexa"],
    limit: "LG voice services blocked. Voice search and assistants unavailable; not a physical microphone disconnect."
  },
  telemetry: {
    required: ["uploadd", "rdxd"], optional: ["rdx_reporter", "admanager", "adoverlay-service"],
    limit: "Known LG diagnostic upload and ad services blocked. Shared LG services and embedded SDKs are not covered."
  },
  discovery: {
    required: ["ssdp-discovery-lgtv"], optional: ["upnpd", "mdnsd"],
    limit: "Known system discovery services blocked. Apps can still discover/control UPnP devices directly; this is not LAN isolation."
  }
};
const KEYS = Object.keys(PROFILES);
const ALLOWED = new Set(KEYS.reduce((all, key) => all.concat(PROFILES[key].required, PROFILES[key].optional), []));

function parseMounts(text) {
  return String(text).trim().split("\n").filter(Boolean).map((line) => {
    const fields = line.split(" ");
    return { id: fields[0], target: (fields[4] || "").replace(/\\([0-7]{3})/g, (_, octal) => String.fromCharCode(parseInt(octal, 8))) };
  });
}

function validateChange(payload) {
  if (!payload || !KEYS.concat(["logging"]).includes(payload.control) || typeof payload.enabled !== "boolean" ||
      Object.keys(payload).some((key) => !["control", "enabled"].includes(key))) {
    throw new Error("Expected a known privacy control and a boolean enabled value");
  }
  return { control: payload.control, enabled: payload.enabled };
}

function createEngine(options) {
  options = options || {};
  const io = options.fs || fs;
  const resolve = options.resolve || ((name) => name);
  const run = options.run || ((file, args) => {
    const result = cp.spawnSync(file, args, { encoding: "utf8", timeout: 5000, maxBuffer: 65536 });
    if (result.error || result.status !== 0) throw new Error(path.basename(file) + " failed (" + (result.status == null ? "timeout/unavailable" : result.status) + ")");
    return String(result.stdout || "");
  });
  const signal = options.signal || ((pid) => process.kill(pid, "SIGTERM"));
  const wait = options.wait || (() => cp.spawnSync("/bin/sleep", ["1"], { timeout: 2000 }));
  const read = (name) => io.readFileSync(resolve(name), "utf8");
  const exists = (name) => io.existsSync(resolve(name));
  const stat = (name) => io.statSync(resolve(name));
  const json = (name, fallback) => { try { return JSON.parse(read(name)); } catch (error) { if (error.code === "ENOENT") return fallback; throw new Error("Invalid privacy state: " + path.basename(name)); } };
  const sameFile = (a, b) => { try { const x = stat(a); const y = stat(b); return x.dev === y.dev && x.ino === y.ino; } catch (_) { return false; } };
  const mounts = () => parseMounts(read("/proc/self/mountinfo"));
  const boot = () => read("/proc/sys/kernel/random/boot_id").trim();
  const defaults = () => ({ version: VERSION, logging: false, acr: false, voice: false, telemetry: false, discovery: false });
  const config = () => {
    const value = json(BASE + "/config.json", defaults());
    if (value.version !== VERSION || KEYS.concat(["logging"]).some((key) => typeof value[key] !== "boolean")) throw new Error("Unsupported privacy configuration");
    return value;
  };
  const runtime = () => {
    const value = json(BASE + "/runtime.json", { boot: boot(), targets: {} });
    if (value.boot !== boot()) return { boot: boot(), targets: {} };
    if (!value.targets || Object.keys(value.targets).some((name) => !ALLOWED.has(name))) throw new Error("Invalid privacy target registry");
    return value;
  };
  function privateDir(name) {
    if (exists(name)) {
      const info = io.lstatSync(resolve(name));
      if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022)) throw new Error("Unsafe privacy directory");
    } else {
      io.mkdirSync(resolve(name), { recursive: true, mode: 0o700 });
    }
  }
  function write(name, value) {
    const content = JSON.stringify(value, null, 2) + "\n";
    if (exists(name) && read(name) === content) return;
    const temp = resolve(name + ".tmp-" + process.pid);
    io.writeFileSync(temp, content, { mode: 0o600, flag: "wx" });
    io.renameSync(temp, resolve(name));
  }
  function prepare() {
    if (!options.testing && (process.platform !== "linux" || process.getuid() !== 0)) throw new Error("Rooted Linux TV required");
    if (!options.testing && io.readlinkSync("/proc/self/ns/mnt") !== io.readlinkSync("/proc/1/ns/mnt")) throw new Error("Shared TV mount namespace required; jailed services are unsupported");
    privateDir(BASE);
    privateDir(VOLATILE);
    if (!exists(VOLATILE + "/disabled")) io.writeFileSync(resolve(VOLATILE + "/disabled"), STUB, { mode: 0o755, flag: "wx" });
    const info = io.lstatSync(resolve(VOLATILE + "/disabled"));
    if (!info.isFile() || info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022) || read(VOLATILE + "/disabled") !== STUB) throw new Error("Privacy blocker integrity failed");
  }
  function lock(action) {
    prepare();
    const lockDir = resolve(VOLATILE + "/lock");
    try { io.mkdirSync(lockDir, { mode: 0o700 }); }
    catch (error) {
      if (error.code !== "EEXIST") throw error;
      const owner = json(VOLATILE + "/lock/owner.json", null);
      if (!owner || exists("/proc/" + owner.pid)) throw new Error("Another privacy operation is running");
      io.unlinkSync(path.join(lockDir, "owner.json"));
      io.rmdirSync(lockDir);
      io.mkdirSync(lockDir, { mode: 0o700 });
    }
    write(VOLATILE + "/lock/owner.json", { pid: process.pid });
    try { return action(); }
    finally { io.unlinkSync(path.join(lockDir, "owner.json")); io.rmdirSync(lockDir); }
  }
  function processes() {
    const result = [];
    io.readdirSync(resolve("/proc")).filter((entry) => /^[1-9][0-9]*$/.test(entry)).forEach((pid) => {
      try {
        const executable = io.readlinkSync(resolve("/proc/" + pid + "/exe")).replace(/ \(deleted\)$/, "");
        if (executable.startsWith("/usr/sbin/") && ALLOWED.has(path.basename(executable))) {
          const info = stat("/proc/" + pid + "/exe");
          result.push({ pid: Number(pid), name: path.basename(executable), dev: info.dev, ino: info.ino });
        }
      } catch (error) {
        // A disappearing process is normal; a denied inventory cannot establish protection.
        if (!["ENOENT", "ESRCH", "EINVAL"].includes(error.code)) throw new Error("Process inventory could not be verified");
      }
    });
    return result;
  }
  function owned(name, entry, table) {
    return Boolean(entry && table.some((item) => item.id === entry.mountId && item.target === "/usr/sbin/" + name) &&
      sameFile("/usr/sbin/" + name, VOLATILE + "/disabled"));
  }
  function preflight(key, state) {
    const profile = PROFILES[key];
    profile.required.forEach((name) => { if (!exists("/usr/sbin/" + name)) throw new Error("Unsupported firmware: missing " + name); });
    const names = profile.required.concat(profile.optional).filter((name) => exists("/usr/sbin/" + name));
    const table = mounts();
    names.forEach((name) => {
      const target = "/usr/sbin/" + name;
      if (owned(name, state.targets[name], table)) return;
      if (table.some((item) => item.target === target)) throw new Error("Refusing foreign mount: " + name);
      const info = io.lstatSync(resolve(target));
      if (!info.isFile() || info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022)) throw new Error("Unsupported executable: " + name);
      const fd = io.openSync(resolve(target), "r");
      const magic = Buffer.alloc(4);
      try { io.readSync(fd, magic, 0, 4, 0); } finally { io.closeSync(fd); }
      if (!magic.equals(Buffer.from([127, 69, 76, 70]))) throw new Error("Non-ELF service rejected: " + name);
    });
    return names;
  }
  function stop(name, entry) {
    // Unit names are derived only from the fixed profile. LS2 dynamic children are handled by inode below.
    try {
      const exec = run("/bin/systemctl", ["show", name + ".service", "--property=ExecStart", "--value"]);
      if (exec.includes("path=/usr/sbin/" + name + " ") || exec.includes("path=/usr/sbin/" + name + ";")) {
        run("/bin/systemctl", ["stop", name + ".service"]);
      }
    } catch (_) { /* Not every firmware uses systemd for these optional services. */ }
    processes().filter((item) => item.name === name && item.dev === entry.dev && item.ino === entry.ino).forEach((item) => {
      try {
        const fresh = stat("/proc/" + item.pid + "/exe");
        if (fresh.dev === entry.dev && fresh.ino === entry.ino) signal(item.pid);
      } catch (error) { if (!["ESRCH", "ENOENT"].includes(error.code)) throw error; }
    });
  }
  function remove(name, state) {
    const entry = state.targets[name];
    if (!entry) return;
    const table = mounts();
    const target = "/usr/sbin/" + name;
    if (table.some((item) => item.target === target)) {
      if (!owned(name, entry, table)) throw new Error("Refusing to unmount a changed/foreign overlay: " + name);
      run("/bin/umount", [target]);
      if (mounts().some((item) => item.target === target)) throw new Error("Overlay removal failed: " + name);
    }
    delete state.targets[name];
    write(BASE + "/runtime.json", state);
  }
  function enable(key, state) {
    const names = preflight(key, state);
    const added = [];
    try {
      names.forEach((name) => {
        if (!owned(name, state.targets[name], mounts())) {
          const target = "/usr/sbin/" + name;
          const info = stat(target);
          // Journal intent before mutation so a killed helper can recover its own overlay.
          state.targets[name] = { dev: info.dev, ino: info.ino, mountId: null, pending: true };
          write(BASE + "/runtime.json", state);
          run("/bin/mount", ["--bind", VOLATILE + "/disabled", target]);
          added.push(name);
          const mount = mounts().filter((item) => item.target === target).pop();
          if (!mount || !sameFile(target, VOLATILE + "/disabled")) throw new Error("Overlay verification failed: " + name);
          state.targets[name].mountId = mount.id;
          state.targets[name].pending = false;
          write(BASE + "/runtime.json", state);
        }
      });
      names.forEach((name) => stop(name, state.targets[name]));
      if (processes().some((item) => names.includes(item.name))) wait();
      if (processes().some((item) => names.includes(item.name))) throw new Error("A protected service did not stop; change rolled back");
    } catch (error) {
      const errors = [];
      added.reverse().forEach((name) => { try { remove(name, state); } catch (rollback) { errors.push(rollback.message); } });
      if (errors.length) throw new Error(error.message + "; rollback incomplete: " + errors.join(", "));
      throw error;
    }
  }
  function recover(state) {
    Object.keys(state.targets).forEach((name) => {
      const entry = state.targets[name];
      if (!entry.pending) return;
      const table = mounts().filter((item) => item.target === "/usr/sbin/" + name);
      if (table.length === 1 && sameFile("/usr/sbin/" + name, VOLATILE + "/disabled")) {
        entry.mountId = table[0].id;
        entry.pending = false;
      } else if (!table.length) {
        delete state.targets[name];
      } else throw new Error("Interrupted operation conflicts with an existing mount: " + name);
    });
    write(BASE + "/runtime.json", state);
  }
  function status() {
    const desired = config();
    const state = runtime();
    const table = mounts();
    const live = processes();
    const controls = {};
    KEYS.forEach((key) => {
      const profile = PROFILES[key];
      const names = profile.required.concat(profile.optional).filter((name) => exists("/usr/sbin/" + name));
      const missing = profile.required.filter((name) => !names.includes(name));
      const blocked = names.filter((name) => owned(name, state.targets[name], table));
      const running = live.filter((item) => names.includes(item.name)).map((item) => item.name);
      const verified = !missing.length && names.length > 0 && blocked.length === names.length && !running.length;
      controls[key] = {
        enabled: desired[key], supported: !missing.length, verified: desired[key] && verified,
        state: missing.length ? "unsupported" : desired[key] ? (verified ? "verified" : "not-protected") : blocked.length ? "restore-needed" : "off",
        blocked: blocked, detected: names, running: Array.from(new Set(running)), missing: missing,
        coverage: "known-services-only", detail: profile.limit
      };
    });
    return { version: VERSION, available: true, checkedAt: new Date().toISOString(), logging: desired.logging,
      controls: controls, bootProtection: "Applied by the root startup hook; an early-boot gap remains.",
      networkIsolation: false, hardwareMicrophoneCutoff: false };
  }
  function record(kind, result, explicit) {
    const signature = JSON.stringify(Object.keys(result.controls).map((key) => result.controls[key]));
    const digest = crypto.createHash("sha256").update(signature).digest("hex");
    const prior = json(VOLATILE + "/last-check.json", {});
    write(VOLATILE + "/last-check.json", { digest: digest, status: result });
    if (!config().logging || (!explicit && prior.digest === digest)) return;
    const entries = json(BASE + "/events.json", []);
    if (!Array.isArray(entries)) throw new Error("Invalid local privacy log");
    entries.push({ time: result.checkedAt, kind: kind, controls: KEYS.map((key) => key + ": " + result.controls[key].state) });
    write(BASE + "/events.json", entries.slice(-128));
  }
  function reconcile() {
    return lock(() => {
      const desired = config();
      const state = runtime();
      recover(state);
      const errors = [];
      KEYS.forEach((key) => {
        try {
          if (desired[key]) enable(key, state);
          else PROFILES[key].required.concat(PROFILES[key].optional).forEach((name) => remove(name, state));
        } catch (error) { errors.push({ control: key, error: error.message }); }
      });
      const result = status();
      result.errors = errors;
      record("reconcile", result, false);
      return result;
    });
  }
  function change(payload) {
    const request = validateChange(payload);
    return lock(() => {
      const desired = config();
      const state = runtime();
      recover(state);
      if (request.control !== "logging") {
        if (request.enabled) enable(request.control, state);
        else PROFILES[request.control].required.concat(PROFILES[request.control].optional).forEach((name) => remove(name, state));
      }
      desired[request.control] = request.enabled;
      write(BASE + "/config.json", desired);
      const result = status();
      record(request.control + (request.enabled ? " enabled" : " disabled"), result, true);
      return result;
    });
  }
  function inspect() { return lock(() => { const result = status(); record("manual check", result, true); return result; }); }
  function networkAudit() { return lock(() => {
    const result = require("./unknown-home-network-audit.js").audit();
    record("network audit: app LAN/UPnP and proxy blocks not enforced; " + result.packages.findings.length + " indicators", status(), true);
    return result;
  }); }
  function logs(clear) { return lock(() => { if (clear) write(BASE + "/events.json", []); return { events: json(BASE + "/events.json", []).slice(-128).reverse() }; }); }
  return { change: change, reconcile: reconcile, status: status, inspect: inspect, logs: logs, preflight: preflight, networkAudit: networkAudit };
}

if (require.main === module) {
  try {
    const engine = createEngine();
    const command = process.argv[2] || "status";
    let result;
    if (command === "set") result = engine.change({ control: process.argv[3], enabled: process.argv[4] === "on" ? true : process.argv[4] === "off" ? false : null });
    else if (command === "reconcile") result = engine.reconcile();
    else if (command === "status") result = engine.status();
    else if (command === "check") result = engine.inspect();
    else if (command === "network-audit") result = engine.networkAudit();
    else if (command === "log" || command === "clear-log") result = engine.logs(command === "clear-log");
    else if (command === "disable-all") { KEYS.forEach((key) => engine.change({ control: key, enabled: false })); result = engine.status(); }
    else throw new Error("Unknown privacy command");
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch (error) { process.stderr.write(error.message + "\n"); process.exitCode = 1; }
}

module.exports = { createEngine: createEngine, validateChange: validateChange, parseMounts: parseMounts, PROFILES: PROFILES, STUB: STUB };
