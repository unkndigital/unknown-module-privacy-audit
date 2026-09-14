"use strict";
const support=require("./module-support");
function create(options){
  options=options||{};const s=options.support||support.create("privacy-audit"),audit=options.audit||require("./runtime/unknown-home-privacy-audit"),network=options.network||require("./runtime/unknown-home-network-audit");
  function enabled(){return s.read(s.base+"/privacy/audit-settings.json",{enabled:false}).enabled===true;}
  async function run(action,args){
    args=args||{};
    if(action==="enable"){s.claim();const saved=s.state();if(saved)audit.setEnabled(saved.desired===true);s.save({desired:enabled(),suspended:false});}
    else if(action==="disable"){s.claim();s.suspend(enabled());audit.setEnabled(false);}
    else if(action==="reconcile"||action==="maintenance"){s.claim();if(enabled()){const result=audit.snapshot(true);if(result.audit.recordingState==="error")throw Error(result.audit.error);}}
    else if(action==="setRecording"){if(typeof args.enabled!=="boolean")throw Error("Expected enabled boolean");audit.setEnabled(args.enabled);s.save({desired:args.enabled});}
    else if(action==="inspect")return audit.snapshot(false);
    else if(action==="networkAudit")return network.audit();
    else if(action==="viewLog")return {events:audit.entries()};
    else if(action==="clearLog"){audit.clear();return {events:[]};}
    else if(!["status","health"].includes(action))throw Error("Unknown audit action");
    return {healthy:true,recording:enabled(),retention:"Last 128 events in RAM; reboot clears events",sampling:"About 60 seconds through Core; no packet contents or microphone audio recorded",coverage:"Sampled process, capture-device and network metadata; not a complete activity recorder"};
  }
  return {run};
}
if(require.main===module)support.main(create);module.exports={create};
