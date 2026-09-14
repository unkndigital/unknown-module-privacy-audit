"use strict";
const fs = require("fs");
const cp = require("child_process");
const privacy = require("./unknown-home-privacy.js");
const BASE = "/var/lib/unknown-home/privacy";
const RUN = "/run/unknown-home-privacy";
const TARGET = /^\/dev\/snd\/pcmC\d+D\d+c$/;

function create(options) {
  options = options || {};
  const io = options.fs || fs;
  const resolve = options.resolve || ((p) => p);
  const inspect = options.inspect || (() => require("./unknown-home-privacy-diagnostics.js").inspect());
  const read = (p) => io.readFileSync(resolve(p), "utf8");
  const exists = (p) => io.existsSync(resolve(p));
  const json = (p, fallback) => { if (!exists(p)) return fallback; const t = read(p); if (t.length > 131072) throw Error("Oversized microphone state"); return JSON.parse(t); };
  const run = options.run || ((file, args) => {
    const r = cp.spawnSync(file, args, { timeout: 5000, encoding: "utf8", maxBuffer: 8192 });
    if (r.error || r.status !== 0) throw Error("Microphone overlay operation failed");
  });
  const boot = () => read("/proc/sys/kernel/random/boot_id").trim();
  function config() {
    const c = json(BASE + "/microphone.json", { version: 1, enabled: false });
    if (c.version !== 1 || typeof c.enabled !== "boolean") throw Error("Invalid microphone configuration");
    return c;
  }
  function runtime() {
    const r = json(RUN + "/microphone-state.json", { boot: boot(), targets: {} });
    if (r.boot !== boot()) return { boot: boot(), targets: {} };
    if (!r.targets || Object.keys(r.targets).some((p) => !TARGET.test(p))) throw Error("Invalid capture target registry");
    return r;
  }
  function table() { return privacy.parseMounts(read("/proc/self/mountinfo")); }
  function same(p) {
    try {
      const a = io.statSync(resolve(p)), b = io.lstatSync(resolve(RUN + "/microphone-disabled"));
      return b.isFile() && !b.isSymbolicLink() && b.uid === 0 && !(b.mode & 0o777) && b.size === 0 && a.dev === b.dev && a.ino === b.ino;
    } catch (_) { return false; }
  }
  function owned(p, r, mounts) {
    return Boolean(r.targets[p] && mounts.some((m) => m.target === p && m.id === r.targets[p].mountId) && same(p));
  }
  function status(snapshot) {
    snapshot = snapshot || inspect();
    const c = config(), r = runtime(), mounts = table();
    const devices = snapshot.microphones && snapshot.microphones.devices || [];
    const blocked = devices.filter((d) => owned(d.path, r, mounts)).map((d) => d.path);
    const held = devices.filter((d) => d.owners.length || d.states.some((s) => s !== "CLOSED"));
    const context = snapshot.context || {};
    const verified = c.enabled && context.root && context.globalNamespace && snapshot.microphones.complete &&
      snapshot.controls.voice.verified && devices.length > 0 && blocked.length === devices.length && !held.length;
    return { enabled: c.enabled, verified: Boolean(verified), state: !c.enabled ? Object.keys(r.targets).length ? "restore-needed" : "off" : verified ? "verified" : "unverified",
      detected: devices.length, blocked: blocked, activeOrUnknown: held.map((d) => d.path),
      detail: "LG voice services plus currently detected ALSA capture nodes. Covers normal built-in, USB/camera and Bluetooth capture paths; remote audio relies on the LG voice-input block. Not a hardware cutoff or a guarantee against proprietary/direct-driver paths. Boot/hotplug gaps remain." };
  }
  function privateDir(p) {
    if (!exists(p)) io.mkdirSync(resolve(p), { recursive: true, mode: 0o700 });
    const s = io.lstatSync(resolve(p));
    if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== 0 || (s.mode & 0o022)) throw Error("Unsafe microphone state directory");
  }
  function write(p, value) {
    const text = JSON.stringify(value) + "\n";
    if (exists(p) && read(p) === text) return;
    const temp = resolve(p + ".tmp-" + process.pid);
    io.writeFileSync(temp, text, { mode: 0o600, flag: "wx" });
    io.renameSync(temp, resolve(p));
  }
  function restore(p, r) {
    const mounts = table();
    if (mounts.some((m) => m.target === p)) {
      if (!owned(p, r, mounts)) throw Error("Refusing foreign capture mount: " + p);
      run("/bin/umount", [p]);
      if (table().some((m) => m.target === p)) throw Error("Capture restoration failed");
    }
    delete r.targets[p];
    write(RUN + "/microphone-state.json", r);
  }
  function change(enabled) {
    if (typeof enabled !== "boolean") throw Error("Expected a boolean microphone block setting");
    let snapshot = inspect();
    if (!snapshot.context.root || !snapshot.context.globalNamespace) throw Error("Unjailed root context required");
    privateDir(BASE); privateDir(RUN);
    const lock = resolve(RUN + "/microphone-lock");
    try { io.mkdirSync(lock, {mode:0o700}); } catch (_) { throw Error("Microphone operation already running; stale locks clear at reboot"); }
    try {
      const r = runtime();
      Object.keys(r.targets).forEach((p) => {
        if (!r.targets[p].pending) return;
        const m = table().filter((item) => item.target === p);
        if (m.length === 1 && same(p)) { r.targets[p].mountId = m[0].id; r.targets[p].pending = false; }
        else if (!m.length) delete r.targets[p];
        else throw Error("Interrupted capture operation conflicts with an existing mount");
      });
      write(RUN + "/microphone-state.json", r);
      if (!enabled) {
        Object.keys(r.targets).forEach((p) => restore(p, r));
        write(BASE + "/microphone.json", { version: 1, enabled: false });
        return status(inspect());
      }
      if (!snapshot.controls.voice.verified) throw Error("Verified LG voice-service blocking is required for remote audio protection");
      if (!snapshot.microphones.complete || !snapshot.microphones.devices.length) throw Error("Capture inventory incomplete; no devices changed");
      const devices = snapshot.microphones.devices;
      if (devices.some((d) => d.owners.length || d.states.some((s) => s !== "CLOSED"))) throw Error("Capture device open, active, or unknown; no devices changed");
      devices.forEach((d) => {
        if (!TARGET.test(d.path)) throw Error("Unsupported capture device path");
        if (owned(d.path, r, table())) return;
        if (table().some((m) => m.target === d.path)) throw Error("Foreign capture overlay detected");
        const s = io.lstatSync(resolve(d.path));
        if (!s.isCharacterDevice() || s.isSymbolicLink() || s.uid !== 0) throw Error("Unsupported capture node");
      });
      const stub = RUN + "/microphone-disabled";
      if (!exists(stub)) io.writeFileSync(resolve(stub), "", {mode:0o000,flag:"wx"});
      const s = io.lstatSync(resolve(stub));
      if (!s.isFile() || s.isSymbolicLink() || s.uid !== 0 || (s.mode & 0o777) || s.size) throw Error("Capture blocker integrity failure");
      const added = [];
      try {
        devices.forEach((d) => {
          if (owned(d.path, r, table())) return;
          r.targets[d.path] = { pending: true, mountId: null };
          write(RUN + "/microphone-state.json", r);
          added.push(d.path);
          run("/bin/mount", ["--bind", stub, d.path]);
          const m = table().filter((item) => item.target === d.path);
          if (m.length !== 1 || !same(d.path)) throw Error("Capture mount verification failed");
          r.targets[d.path] = {pending:false,mountId:m[0].id};
          write(RUN + "/microphone-state.json", r);
        });
        snapshot = inspect();
        if (!snapshot.context.root || !snapshot.context.globalNamespace || !snapshot.controls.voice.verified ||
          !snapshot.microphones.complete || !snapshot.microphones.devices.length ||
          snapshot.microphones.devices.some((d) => d.owners.length || d.states.some((s) => s !== "CLOSED") || !owned(d.path, r, table()))) throw Error("Capture state changed during operation");
        write(BASE + "/microphone.json", {version:1,enabled:true});
        return status(snapshot);
      } catch (error) {
        const failures = [];
        added.reverse().forEach((p) => {
          try {
            // A timed-out mount may have succeeded; recover only our exact inode.
            if (r.targets[p] && r.targets[p].pending) {
              const mounts = table().filter((item) => item.target === p);
              if (mounts.length === 1 && same(p)) r.targets[p] = {pending:false,mountId:mounts[0].id};
            }
            restore(p, r);
          } catch (e) { failures.push(e.message); }
        });
        if (failures.length) throw Error(error.message + "; restoration needs attention: " + failures.join(", "));
        throw error;
      }
    } finally { io.rmdirSync(lock); }
  }
  return { status: status, change: change, reconcile: () => config().enabled ? change(true) : status() };
}
if (require.main === module) {
  try {
    const engine = create(), command = process.argv[2] || "status";
    const result = command === "on" ? engine.change(true) : command === "off" ? engine.change(false) : command === "reconcile" ? engine.reconcile() : command === "status" ? engine.status() : null;
    if (!result) throw Error("Unknown microphone command");
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch (error) { process.stderr.write(error.message + "\n"); process.exitCode = 1; }
}
module.exports = { create: create };
