import {
  HX1400_JIT_DUALMAP_LEASE_CONSTANTS,
  HX1400_JIT_DUALMAP_LEASE_PROVENANCE,
  runHx1400JitDualmapLease,
} from "./hx1400_jit_dualmap_lease.js?v=hx1400-goldhen-dualmap-1";

const freeze = Object.freeze;
const create = Object.create;
const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const getPrototypeOf = Object.getPrototypeOf;
const isFrozen = Object.isFrozen;
const ownKeys = Reflect.ownKeys;
const apply = Reflect.apply;
const weakMapDelete = WeakMap.prototype.delete;
const weakMapGet = WeakMap.prototype.get;
const weakMapSet = WeakMap.prototype.set;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;

export const HX1400_GOLDHEN_DUALMAP_OWNER_PROTOCOL = "hx1400-goldhen-dualmap-gs-relocation-set/v1";
export const HX1400_GOLDHEN_DUALMAP_SOURCE13_SHA256 = "399367bed20e111200a0cd0ff13d3b6bfe3280cdd6105a675f149b4275515829";
export const HX1400_GOLDHEN_DUALMAP_GS_SOURCE13_RVA = 0x74d6e3;
export const HX1400_GOLDHEN_DUALMAP_EXECUTABLE_RELOCATION_DELTAS = freeze([0,0x2a0,0x2b0,0x2c0]);
export const HX1400_GOLDHEN_DUALMAP_GS_CANDIDATE_RVAS = freeze([0x74d6e3,0x74d983,0x74d993,0x74d9a3]);
export const HX1400_GOLDHEN_DUALMAP_GS_GADGET_BYTES = freeze([0x65,0x48,0x8b,0x04,0x25,0,0,0,0,0x5d,0xc3]);
export const HX1400_GOLDHEN_DUALMAP_DWORD_GADGET_RVA = 0x2f1cc;
export const HX1400_GOLDHEN_DUALMAP_DWORD_GADGET_BYTES = freeze([0x89,0x07,0x5d,0xc3]);
export const HX1400_GOLDHEN_DUALMAP_SYSENT477_RVA = 0x11084e0;
export const HX1400_GOLDHEN_DUALMAP_SYSENT533_RVA = 0x1108f60;
export const HX1400_GOLDHEN_DUALMAP_MMAP_JITSHM_OFFSET = 0x573;
export const HX1400_GOLDHEN_DUALMAP_HANDLER_MASK = freeze([20,21,22,23,45,46,47,48,62,63,64,65]);
export const HX1400_GOLDHEN_DUALMAP_HELPER_MASK = freeze([0x23,0x24,0x25,0x26,0x32,0x33,0x34,0x35]);
export const HX1400_GOLDHEN_DUALMAP_MMAP_JITSHM_MASK = freeze([0x1c,0x1d,0x1e,0x1f,0x2b,0x2c,0x2d,0x2e]);
const HX1400_GOLDHEN_DUALMAP_TEXT_LIMIT_RVA = 0xd00000;
const HX1400_GOLDHEN_DUALMAP_HANDLER_RIP_RVA = 0x275cea0;


const HANDLER = hex("554889e54157415641554154534883ec484c8d3d885f65024989fc4889f3498b07488945d0488bbf30010000e88fc22a0085c07515498bbc2430010000e8dec22a0085c00f84ad010000");
const HELPER62 = hex("554889e5415653488b476841be01000000480fbae03e72254889fb480fbae0387309e859ca060085c07512807b5f317509e84ad8060085c075034531f64489f05b415e5dc3");
const HELPER61 = hex("554889e5415653488b476841be01000000480fbae03d72254889fb480fbae0387309e8f9c9060085c07512807b5f317509e8ead7060085c075034531f64489f05b415e5dc3");
const MMAP_JITSHM = hex("488b004c8b7580488945888b4010498bbe30010000898570ffffffe8cd871b00498bbe300100004189c4e81e881b008b9570ffffff89d180e1fb85c00fb6c90f45ca4585e40f44ca755f85c0745b4c8b75880fb6d180e1dd4c8b5d900fb6c941807e14000f44caeb484c8b308b4824be1100000041b00a83e1010f44f18b48244c8b5d908d5622440fb6d2f6c102440f44d6e9dcfdffff4c8b304c8b5d9041b23341b00be9cafdffff4c8b5d904c8b758831d24409e0488b45a8440fb6d141b007440f44d2");
const SECOND_XOR = freeze({lo:0xa5c31f7d,hi:0x6e91d24b});
const privateOwners = new WeakMap();
const authenticated = new WeakSet();
const consumed = new WeakSet();
let oracleActive = false;
let oracleClosed = false;
let ownerActive = false;
let ownerGeneration = 0;
let ownerRebootRequired = false;
let ownerQuarantined = false;

function hex(text) {
  const bytes = new Uint8Array(text.length >>> 1);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return freeze(Array.from(bytes));
}
function exact(value, names, frozen) {
  if (!value || typeof value !== "object" || getPrototypeOf(value) !== Object.prototype || (frozen && !isFrozen(value))) return null;
  const keys = ownKeys(value);
  if (keys.length !== names.length) return null;
  for (const name of names) {
    const descriptor = getOwnPropertyDescriptor(value, name);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true || !keys.includes(name)) return null;
  }
  return value;
}
function qword(value, name) {
  if (!value || typeof value !== "object" || !Number.isInteger(value.lo) || !Number.isInteger(value.hi) || value.lo < 0 || value.lo > 0xffffffff || value.hi < 0 || value.hi > 0xffffffff) throw new TypeError(name);
  return freeze({lo:value.lo>>>0,hi:value.hi>>>0});
}
function add(value, offset) {
  const lo = ((value.lo>>>0)+(offset>>>0))>>>0;
  return freeze({lo,hi:((value.hi>>>0)+(lo<(value.lo>>>0)?1:0))>>>0});
}
function same(a,b) { return (a.lo>>>0)===(b.lo>>>0)&&(a.hi>>>0)===(b.hi>>>0); }
function kernelPointer(value) { return value && (value.hi>>>16)===0xffff && (value.hi&0x8000)!==0 && (value.lo&7)===0; }
function less(a,b) { return (a.hi>>>0)===(b.hi>>>0)?(a.lo>>>0)<(b.lo>>>0):(a.hi>>>0)<(b.hi>>>0); }
function kernelTextPointer(value,kbase) {
  return kernelPointer(value)&&!less(value,kbase)&&less(value,add(kbase,HX1400_GOLDHEN_DUALMAP_TEXT_LIMIT_RVA));
}
function uint32(value,name) { if (!Number.isInteger(value)||value<0||value>0xffffffff) throw new TypeError(name); return value>>>0; }
function bytes(value, length, name) {
  if (!(value instanceof Uint8Array) || value.length !== length) throw new TypeError(name);
  return new Uint8Array(value);
}
function equalBytes(a,b,mask) {
  if (a.length!==b.length) return false;
  for (let i=0;i<a.length;i+=1)
    if (mask.indexOf(i)===-1&&a[i]!==b[i]) return false;
  return true;
}
function readU32(blob, offset) { return (blob[offset]|(blob[offset+1]<<8)|(blob[offset+2]<<16)|(blob[offset+3]<<24))>>>0; }
function readQword(blob, offset) { return freeze({lo:readU32(blob,offset),hi:readU32(blob,offset+4)}); }
function addSigned32(value, displacement) {
  const signed=displacement|0;
  const lo=((value.lo>>>0)+(signed>>>0))>>>0;
  const carry=lo<(value.lo>>>0)?1:0;
  const sign=signed<0?0xffffffff:0;
  return freeze({lo,hi:((value.hi>>>0)+sign+carry)>>>0});
}
function rel32Target(base, blob, instruction) {
  if (blob[instruction]!==0xe8) throw new Error("rel32 opcode");
  return addSigned32(add(base,instruction+5),readU32(blob,instruction+1)|0);
}
function handlerRipTarget(base, blob) {
  if (blob[0x11]!==0x4c||blob[0x12]!==0x8d||blob[0x13]!==0x3d)
    throw new Error("handler RIP opcode");
  return addSigned32(add(base,0x18),readU32(blob,0x14)|0);
}
function stableBytes(readBytes,address,length,name) {
  const first=bytes(apply(readBytes,undefined,[address,length]),length,name);
  const second=bytes(apply(readBytes,undefined,[address,length]),length,name);
  if (!equalBytes(first,second,[])) throw new Error(name+" unstable");
  return first;
}

export function attestHx1400GoldhenDualmapLiveSemantics(context) {
  const fields=["kernelBase","readBytes"];
  if (!exact(context,fields,true)||typeof context.readBytes!=="function") return freeze({ok:false,code:"ERR_ATTEST_CONTEXT",pointerFree:true});
  try {
    const kbase=qword(context.kernelBase,"kernelBase");
    if (!kernelPointer(kbase)||(kbase.lo&0x3fff)!==0) throw new Error("kernel base");
    const record=stableBytes(context.readBytes,add(kbase,HX1400_GOLDHEN_DUALMAP_SYSENT533_RVA),0x30,"sysent533");
    const handler=readQword(record,8);
    let createReserved=true;
    for (let i=4;i<8;i+=1) createReserved=createReserved&&record[i]===0;
    for (let i=16;i<44;i+=1) createReserved=createReserved&&record[i]===0;
    if (readU32(record,0)!==3||!createReserved||readU32(record,44)!==1||!kernelTextPointer(handler,kbase)||(handler.lo&0xf)!==0) throw new Error("sysent533 record");
    const handlerBytes=stableBytes(context.readBytes,handler,HANDLER.length,"handler");
    if (!equalBytes(handlerBytes,HANDLER,HX1400_GOLDHEN_DUALMAP_HANDLER_MASK)) throw new Error("handler skeleton");
    if (!same(handlerRipTarget(handler,handlerBytes),add(kbase,HX1400_GOLDHEN_DUALMAP_HANDLER_RIP_RVA))) throw new Error("handler RIP target");
    const helper62=rel32Target(handler,handlerBytes,0x2c);
    const helper61=rel32Target(handler,handlerBytes,0x3d);
    if (!kernelTextPointer(helper62,kbase)||!kernelTextPointer(helper61,kbase)||(helper62.lo&0xf)!==0||(helper61.lo&0xf)!==0||same(helper62,helper61)) throw new Error("helper target");
    const helper62Bytes=stableBytes(context.readBytes,helper62,HELPER62.length,"helper62");
    const helper61Bytes=stableBytes(context.readBytes,helper61,HELPER61.length,"helper61");
    if (!equalBytes(helper62Bytes,HELPER62,HX1400_GOLDHEN_DUALMAP_HELPER_MASK)||!equalBytes(helper61Bytes,HELPER61,HX1400_GOLDHEN_DUALMAP_HELPER_MASK)) throw new Error("helper skeleton");
    const alternate62=[
      rel32Target(helper62,helper62Bytes,0x22),
      rel32Target(helper62,helper62Bytes,0x31),
    ];
    const alternate61=[
      rel32Target(helper61,helper61Bytes,0x22),
      rel32Target(helper61,helper61Bytes,0x31),
    ];
    for (let index=0;index<alternate62.length;index+=1) {
      if (!kernelTextPointer(alternate62[index],kbase)||!kernelTextPointer(alternate61[index],kbase)||
          (alternate62[index].lo&0xf)!==0||(alternate61[index].lo&0xf)!==0||
          !same(alternate62[index],alternate61[index]))
        throw new Error("alternate helper target");
    }
    if (same(alternate62[0],alternate62[1])) throw new Error("alternate helper alias");
    const mmapRecord=stableBytes(context.readBytes,add(kbase,HX1400_GOLDHEN_DUALMAP_SYSENT477_RVA),0x30,"sysent477");
    const mmapHandler=readQword(mmapRecord,8);
    let mmapReserved=true;
    for (let i=4;i<8;i+=1) mmapReserved=mmapReserved&&mmapRecord[i]===0;
    for (let i=20;i<40;i+=1) mmapReserved=mmapReserved&&mmapRecord[i]===0;
    if (readU32(mmapRecord,0)!==6||readU32(mmapRecord,16)!==0xd2||readU32(mmapRecord,40)!==1||!mmapReserved||readU32(mmapRecord,44)!==1||!kernelTextPointer(mmapHandler,kbase)||(mmapHandler.lo&0xf)!==0||same(mmapHandler,handler)) throw new Error("sysent477 record");
    const mmapJitshm=add(mmapHandler,HX1400_GOLDHEN_DUALMAP_MMAP_JITSHM_OFFSET);
    const mmapJitshmBytes=stableBytes(context.readBytes,mmapJitshm,MMAP_JITSHM.length,"mmap jitshm");
    if (!equalBytes(mmapJitshmBytes,MMAP_JITSHM,HX1400_GOLDHEN_DUALMAP_MMAP_JITSHM_MASK)) throw new Error("mmap jitshm skeleton");
    if (!same(rel32Target(mmapJitshm,mmapJitshmBytes,0x1b),helper62)||!same(rel32Target(mmapJitshm,mmapJitshmBytes,0x2a),helper61)) throw new Error("mmap capability targets");
    const dword=stableBytes(context.readBytes,add(kbase,HX1400_GOLDHEN_DUALMAP_DWORD_GADGET_RVA),4,"dword gadget");
    if (!equalBytes(dword,HX1400_GOLDHEN_DUALMAP_DWORD_GADGET_BYTES,[])) throw new Error("dword gadget");
    return freeze({ok:true,code:"OK",pointerFree:true,sysent477Stable:true,sysent533Stable:true,handlerSemanticMatch:true,helper62SemanticMatch:true,helper61SemanticMatch:true,mmapHandlerSemanticMatch:true,mmapJitshmCapabilityMatch:true,dwordGadgetMatch:true,relocationAwareCallGraph:true,source13Derived:true});
  } catch (_) {
    return freeze({ok:false,code:"ERR_LIVE_SEMANTICS",pointerFree:true});
  }
}

function readIdentity(context, thread) {
  const read64=(address,label)=>qword(apply(context.read64,context,[address]),label);
  const read32=(address,label)=>uint32(apply(context.read32,context,[address]),label);
  if (!kernelPointer(thread)) throw new Error("thread");
  const proc=read64(add(thread,0x08),"proc");
  const tdUcred=read64(add(thread,0x130),"td_ucred");
  const ucred=read64(add(proc,0x40),"p_ucred");
  const filedesc=read64(add(proc,0x48),"p_fd");
  const pid=read32(add(proc,0xb0),"p_pid");
  const syscallPid=uint32(apply(context.getpid,context,[]),"getpid");
  const groups=read64(add(ucred,0x118),"groups");
  if (!kernelPointer(proc)||!kernelPointer(tdUcred)||!kernelPointer(ucred)||!kernelPointer(filedesc)||!kernelPointer(groups)||!same(tdUcred,ucred)||pid!==syscallPid) throw new Error("identity");
  return freeze({thread,proc,ucred,filedesc,pid,groups});
}
function sameIdentity(a,b) { return same(a.thread,b.thread)&&same(a.proc,b.proc)&&same(a.ucred,b.ucred)&&same(a.filedesc,b.filedesc)&&a.pid===b.pid&&same(a.groups,b.groups); }
function ownerResult(code, owner) {
  const ok=code==="OK_CURRENT_OWNER";
  const attestation=ok&&owner&&owner.attestation;
  const mmapCapabilityRecheckAttested=!!(
    attestation&&attestation.helper62SemanticMatch===true&&
    attestation.helper61SemanticMatch===true&&
    attestation.mmapJitshmCapabilityMatch===true
  );
  const result=freeze({schema:"oms.fw14-hx1400-goldhen-dualmap.owner.v1",ok,code,kernelMutated:false,stableRounds:ok?2:0,pointerFree:true,cleanup:true,rebootRequired:false,mmapCapabilityRecheckAttested});
  if (ok&&mmapCapabilityRecheckAttested) { apply(weakSetAdd,authenticated,[result]); apply(weakMapSet,privateOwners,[result,owner]); }
  return result;
}

export function runHx1400GoldhenDualmapOwnerOracle(context) {
  if (oracleActive) return ownerResult("ERR_REENTRY",null);
  if (oracleClosed) return ownerResult("ERR_GENERATION_CLOSED",null);
  oracleActive=true; oracleClosed=true;
  try {
    const names=["firmware","mode","challenge","kernelExecutor","kernelBase","read64","read32","readBytes","getpid"];
    if (!exact(context,names,true)||context.firmware!=="14.00"||context.mode!=="read-only") return ownerResult("ERR_CONTEXT",null);
    const challenge=qword(context.challenge,"challenge");
    const executor=context.kernelExecutor;
    const execNames=["protocol","synchronous","currentThreadGs","readOnly","source13Sha256","source13GadgetRva","candidateRvas","gadgetBytes","uniqueExactRuntimeResolution","signatureCheckedBeforeAndAfter","executeCurrentThread"];
    if (!exact(executor,execNames,true)||executor.protocol!==HX1400_GOLDHEN_DUALMAP_OWNER_PROTOCOL||executor.synchronous!==true||executor.currentThreadGs!==true||executor.readOnly!==true||executor.source13Sha256!==HX1400_GOLDHEN_DUALMAP_SOURCE13_SHA256||executor.source13GadgetRva!==HX1400_GOLDHEN_DUALMAP_GS_SOURCE13_RVA||!isFrozen(executor.candidateRvas)||!equalBytes(executor.candidateRvas,HX1400_GOLDHEN_DUALMAP_GS_CANDIDATE_RVAS,[])||!isFrozen(executor.gadgetBytes)||!equalBytes(executor.gadgetBytes,HX1400_GOLDHEN_DUALMAP_GS_GADGET_BYTES,[])||executor.uniqueExactRuntimeResolution!==true||executor.signatureCheckedBeforeAndAfter!==true||typeof executor.executeCurrentThread!=="function"||typeof context.read64!=="function"||typeof context.read32!=="function"||typeof context.readBytes!=="function"||typeof context.getpid!=="function") return ownerResult("ERR_EXECUTOR",null);
    const attestation=attestHx1400GoldhenDualmapLiveSemantics(freeze({kernelBase:context.kernelBase,readBytes:context.readBytes}));
    if (!attestation.ok) return ownerResult(attestation.code,null);
    const execute=(round,roundChallenge)=>{
      let captured=null,count=0;
      const acknowledgement=freeze(create(null));
      const request=freeze({protocol:HX1400_GOLDHEN_DUALMAP_OWNER_PROTOCOL,round,challenge:roundChallenge,acknowledgement,capture(value){if(count!==0)throw new Error("capture");count+=1;captured=qword(value,"thread");}});
      const reply=apply(executor.executeCurrentThread,executor,[request]);
      if(reply!==acknowledgement||count!==1||captured===null) throw new Error("executor reply");
      return readIdentity(context,captured);
    };
    const first=execute(1,challenge);
    const second=execute(2,freeze({lo:(challenge.lo^SECOND_XOR.lo)>>>0,hi:(challenge.hi^SECOND_XOR.hi)>>>0}));
    if (!sameIdentity(first,second)) return ownerResult("ERR_OWNER_DRIFT",null);
    return ownerResult("OK_CURRENT_OWNER",freeze({identity:first,context,attestation}));
  } catch (_) { return ownerResult("ERR_VALIDATION",null); }
  finally { oracleActive=false; }
}

function publicLease(receipt, generation, revalidated) {
  ownerRebootRequired = ownerRebootRequired || receipt.rebootRequired === true;
  ownerQuarantined = ownerQuarantined || receipt.quarantined === true;
  return freeze({
    schema:"oms.fw14-hx1400-goldhen-dualmap.lease.v1",
    ok:receipt.ok===true,status:receipt.status,error:receipt.error,
    cleanupError:receipt.cleanupError,cleanupWriteError:receipt.cleanupWriteError,
    cleanupReadbackError:receipt.cleanupReadbackError,disposalError:receipt.disposalError,
    fd:receipt.fd,descriptorTransferred:receipt.descriptorTransferred,
    disposeAttempted:receipt.disposeAttempted,descriptorDisposed:receipt.descriptorDisposed,
    quarantined:ownerQuarantined,rebootRequired:ownerRebootRequired,
    generation:receipt.generation,reads:receipt.reads,writes:receipt.writes,
    createCalls:receipt.createCalls,mapCalls:receipt.mapCalls,
    preReadsStable:receipt.preReadsStable,
    writeArmAttempted:receipt.writeArmAttempted,writeArmConfirmed:receipt.writeArmConfirmed,
    writePostConfirmed:receipt.writePostConfirmed,
    writeRestoreAttempted:receipt.writeRestoreAttempted,
    writeRestoreConfirmed:receipt.writeRestoreConfirmed,
    executeArmAttempted:receipt.executeArmAttempted,
    executeArmConfirmed:receipt.executeArmConfirmed,
    executePostConfirmed:receipt.executePostConfirmed,
    executeRestoreAttempted:receipt.executeRestoreAttempted,
    executeRestoreConfirmed:receipt.executeRestoreConfirmed,
    borrowedBitsCleared:receipt.borrowedBitsCleared,
    terminalMatchesOriginal:receipt.terminalMatchesOriginal,
    ownerRevalidated:revalidated===true,pointerFree:true,
  });
}
function refusedLease(error, generation, revalidated, quarantined) {
  ownerQuarantined = ownerQuarantined || quarantined === true;
  const effectiveQuarantine = ownerQuarantined;
  return freeze({
    schema:"oms.fw14-hx1400-goldhen-dualmap.lease.v1",
    ok:false,status:effectiveQuarantine?"QUARANTINED":"REFUSED",error,
    cleanupError:null,cleanupWriteError:null,cleanupReadbackError:null,disposalError:null,
    fd:null,descriptorTransferred:false,disposeAttempted:false,descriptorDisposed:false,
    quarantined:effectiveQuarantine,rebootRequired:ownerRebootRequired,
    generation:HX1400_JIT_DUALMAP_LEASE_CONSTANTS.generation,
    reads:0,writes:0,createCalls:0,mapCalls:0,preReadsStable:false,
    writeArmAttempted:false,writeArmConfirmed:false,writePostConfirmed:false,
    writeRestoreAttempted:false,writeRestoreConfirmed:false,
    executeArmAttempted:false,executeArmConfirmed:false,executePostConfirmed:false,
    executeRestoreAttempted:false,executeRestoreConfirmed:false,
    borrowedBitsCleared:false,terminalMatchesOriginal:false,
    ownerRevalidated:revalidated===true,pointerFree:true,
  });
}


export function consumeHx1400GoldhenDualmapOwnerLease(ownerResultValue, operation) {
  if (ownerActive) return refusedLease("ERR_OWNER_REENTRY",ownerGeneration,false,false);
  let valid=false,used=false;
  try {
    valid=apply(weakSetHas,authenticated,[ownerResultValue]);
    used=apply(weakSetHas,consumed,[ownerResultValue]);
  } catch (_) {
    return refusedLease("ERR_OWNER_TOKEN",ownerGeneration,false,false);
  }
  if (!valid||used) return refusedLease("ERR_OWNER_TOKEN",ownerGeneration,false,false);
  const owner=apply(weakMapGet,privateOwners,[ownerResultValue]);
  apply(weakSetAdd,consumed,[ownerResultValue]);
  apply(weakMapDelete,privateOwners,[ownerResultValue]);
  ownerActive=true;
  ownerRebootRequired=true;
  ownerGeneration+=1;
  try {
    const fields=["aioCleanupVerified","bridgeCallActive","exclusiveGeneration","otherCredentialWriter","read32","write32","createWritableView","mapExecutableView","disposeJit"];
    if (!owner||!exact(operation,fields,true)||operation.aioCleanupVerified!==true||operation.bridgeCallActive!==false||operation.exclusiveGeneration!==true||operation.otherCredentialWriter!==false||typeof operation.read32!=="function"||typeof operation.write32!=="function"||typeof operation.createWritableView!=="function"||typeof operation.mapExecutableView!=="function"||typeof operation.disposeJit!=="function")
      return refusedLease("ERR_WRITER_ISOLATION",ownerGeneration,false,false);
    let fresh;
    try {
      fresh=readIdentity(owner.context,owner.identity.thread);
    } catch (_) {
      return refusedLease("ERR_OWNER_DRIFT",ownerGeneration,false,false);
    }
    if (!sameIdentity(fresh,owner.identity))
      return refusedLease("ERR_OWNER_DRIFT",ownerGeneration,false,false);
    const attestation=attestHx1400GoldhenDualmapLiveSemantics(freeze({kernelBase:owner.context.kernelBase,readBytes:owner.context.readBytes}));
    if (!attestation.ok||attestation.helper62SemanticMatch!==true||attestation.helper61SemanticMatch!==true||attestation.mmapJitshmCapabilityMatch!==true)
      return refusedLease(attestation.ok?"ERR_LIVE_SEMANTICS":attestation.code,ownerGeneration,true,false);
    const target=add(owner.identity.ucred,0x6c);
    const receipt=runHx1400JitDualmapLease(freeze({firmware:"14.00",source13Sha256:HX1400_JIT_DUALMAP_LEASE_PROVENANCE.source13Sha256,generation:HX1400_JIT_DUALMAP_LEASE_CONSTANTS.generation,target,read32:operation.read32,write32:operation.write32,createWritableView:operation.createWritableView,mapExecutableView:operation.mapExecutableView,disposeJit:operation.disposeJit,synchronous:true,exclusiveCredentialWriter:true,parkedWorkerIdentity:true,ucredIdentity:true,pidIdentity:true}));
    return publicLease(receipt,ownerGeneration,true);
  } catch (_) {
    return refusedLease("ERR_OWNER_OPERATION",ownerGeneration,false,true);
  } finally {
    ownerActive=false;
  }
}
