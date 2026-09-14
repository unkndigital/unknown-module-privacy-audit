"use strict";
const fs = require("fs");
const crypto = require("crypto");
const BASE = "/var/lib/unknown-home/privacy";
const RUN = "/run/unknown-home-privacy";
function readJson(p, fallback) {
  try { const s=fs.statSync(p); if(s.size>2097152) throw Error("Audit state limit exceeded"); return JSON.parse(fs.readFileSync(p,"utf8")); }
  catch(e) { if(e.code==="ENOENT") return fallback; throw e; }
}
function directory(p) {
  if(!fs.existsSync(p)) fs.mkdirSync(p,{recursive:true,mode:0o700});
  const s=fs.lstatSync(p);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==0||(s.mode&0o022)) throw Error("Unsafe audit directory");
}
function write(p,v) {
  const data=JSON.stringify(v)+"\n";
  if(Buffer.byteLength(data)>2097152) throw Error("Audit state limit exceeded");
  const temp=p+".tmp-"+process.pid;
  fs.writeFileSync(temp,data,{mode:0o600,flag:"wx"});
  fs.renameSync(temp,p);
}
function settings() {
  const value=readJson(BASE+"/audit-settings.json",{version:1,enabled:false});
  if(value.version!==1||typeof value.enabled!=="boolean") throw Error("Invalid audit configuration");
  return value;
}
function entries() { const value=readJson(RUN+"/audit-events.json",[]); if(!Array.isArray(value)) throw Error("Invalid audit events"); return value.slice(-128).reverse(); }
function stateMap(snapshot) {
  const map={};
  map["Capture block"] = snapshot.microphoneBlock ? snapshot.microphoneBlock.state : "Not verified";
  map["Location coverage"] = snapshot.location ? snapshot.location.acrPathState + " | Other location and egress paths not blocked" : "Not verified";
  Object.keys(snapshot.controls).forEach((key)=>{ const c=snapshot.controls[key]; map["Protection: "+key]=c.state+" | "+c.rows.filter((r)=>r.running).map((r)=>r.name+" PID "+r.pids.join(",")).join("; "); });
  (snapshot.microphones.devices||[]).forEach((d)=>{map["Capture: "+d.path]=d.name+" | "+d.states.join(",")+" | "+d.owners.map((o)=>o.executable+" PID "+o.pid).join(",");});
  (snapshot.network.connections||[]).forEach((c)=>{map["Connection: "+c.protocol+" "+c.remote]=c.state+" | "+c.owners.map((o)=>o.executable+" PID "+o.pid).join(",");});
  (snapshot.network.sockets||[]).forEach((s)=>{map["Listener: "+s.protocol+" "+s.port]=s.service+" | "+s.owners.map((o)=>o.executable+" PID "+o.pid).join(",");});
  (snapshot.processes||[]).filter((p)=>p.pid!==process.pid).forEach((p)=>{map["Process: "+p.pid]=p.executable;});
  return map;
}
function diff(prior,current,time) {
  const events=[];
  Object.keys(current).forEach((key)=>{
    if(prior[key]!==current[key]) events.push({time:time,kind:key.slice(0,240),controls:[(Object.prototype.hasOwnProperty.call(prior,key)?"Changed: ":"Observed: ")+String(current[key]).slice(0,600)]});
  });
  Object.keys(prior).forEach((key)=>{if(!Object.prototype.hasOwnProperty.call(current,key)) events.push({time:time,kind:key.slice(0,240),controls:["No longer observed in this sample"]});});
  return events;
}
function record(snapshot) {
  if(!settings().enabled) return;
  if(!snapshot.context.root||!snapshot.context.globalNamespace) throw Error("Unjailed root required for audit recording");
  directory(RUN);
  const lock=RUN+"/audit-lock";
  try{fs.mkdirSync(lock,{mode:0o700});}catch(e){
    if(e.code==="EEXIST")throw Error("Audit writer locked; no sample recorded. A stale RAM lock clears on reboot.");
    throw e;
  }
  try{
    const state=stateMap(snapshot);
    const digest=crypto.createHash("sha256").update(JSON.stringify(state)).digest("hex");
    const prior=readJson(RUN+"/audit-last.json",null);
    if(prior&&prior.digest===digest)return;
    const old=prior?prior.state:{};
    let changes=diff(old,state,snapshot.checkedAt);
    if(!prior){
      changes=changes.filter((e)=>!e.kind.startsWith("Process: "));
      changes.unshift({time:snapshot.checkedAt,kind:"Audit baseline",controls:[(snapshot.processes||[]).length+" process identities sampled; subsequent changes are recorded."]});
    }
    if(!snapshot.context.processInventoryComplete||!snapshot.context.socketInventoryComplete||!snapshot.microphones.complete) changes.push({time:snapshot.checkedAt,kind:"Audit coverage incomplete",controls:["Unreadable or capped inventory; this is not proof of inactivity."]});
    const existing=readJson(RUN+"/audit-events.json",[]);
    if(!Array.isArray(existing)) throw Error("Invalid audit events");
    write(RUN+"/audit-events.json",existing.concat(changes).slice(-128));
    write(RUN+"/audit-last.json",{digest:digest,state:state});
  }finally{fs.rmdirSync(lock);}
}
function snapshot(recordEnabled) {
  const result=require("./unknown-home-privacy-diagnostics.js").inspect();
  result.microphoneBlock=require("./unknown-home-microphone.js").create().status(result);
  result.audit={enabled:settings().enabled,retention:"Last 128 events in RAM; cleared on reboot",sampling:"10 seconds while live diagnostics is visible; about 60 seconds through the root guardian otherwise"};
  if(recordEnabled && result.audit.enabled) {
    try { record(result); result.audit.recordingState="sampled"; }
    catch(error) { result.audit.recordingState="error"; result.audit.error=error.message; }
  }
  return result;
}
function setEnabled(enabled) {
  if(typeof enabled!=="boolean")throw Error("Expected a boolean audit setting");
  if(process.platform!=="linux"||process.getuid()!==0)throw Error("Root required");
  directory(BASE);
  write(BASE+"/audit-settings.json",{version:1,enabled:enabled});
  return settings();
}
function clear() {
  directory(RUN);
  const lock=RUN+"/audit-lock";
  fs.mkdirSync(lock,{mode:0o700});
  try { write(RUN+"/audit-events.json",[]); write(RUN+"/audit-last.json",null); }
  finally { fs.rmdirSync(lock); }
}
if(require.main===module) {
  try{
    const cmd=process.argv[2]||"inspect";
    let result;
    if(cmd==="inspect")result=snapshot(true);
    else if(cmd==="sample")result=settings().enabled?snapshot(true):{enabled:false};
    else if(cmd==="on"||cmd==="off")result=setEnabled(cmd==="on");
    else if(cmd==="log")result={events:entries()};
    else throw Error("Unknown audit command");
    process.stdout.write(JSON.stringify(result)+"\n");
    if(cmd==="sample" && result.audit && result.audit.recordingState==="error") process.exitCode=1;
  }catch(e){process.stderr.write(e.message+"\n");process.exitCode=1;}
}
module.exports={snapshot:snapshot,entries:entries,clear:clear,diff:diff,stateMap:stateMap,setEnabled:setEnabled};
