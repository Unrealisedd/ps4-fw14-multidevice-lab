import assert from "node:assert/strict";
import test from "node:test";

const HANDLER = "554889e54157415641554154534883ec484c8d3d885f65024989fc4889f3498b07488945d0488bbf30010000e88fc22a0085c07515498bbc2430010000e8dec22a0085c00f84ad010000";
const HELPER62 = "554889e5415653488b476841be01000000480fbae03e72254889fb480fbae0387309e859ca060085c07512807b5f317509e84ad8060085c075034531f64489f05b415e5dc3";
const HELPER61 = "554889e5415653488b476841be01000000480fbae03d72254889fb480fbae0387309e8f9c9060085c07512807b5f317509e8ead7060085c075034531f64489f05b415e5dc3";
const MMAP_JITSHM = "488b004c8b7580488945888b4010498bbe30010000898570ffffffe8cd871b00498bbe300100004189c4e81e881b008b9570ffffff89d180e1fb85c00fb6c90f45ca4585e40f44ca755f85c0745b4c8b75880fb6d180e1dd4c8b5d900fb6c941807e14000f44caeb484c8b308b4824be1100000041b00a83e1010f44f18b48244c8b5d908d5622440fb6d2f6c102440f44d6e9dcfdffff4c8b304c8b5d9041b23341b00be9cafdffff4c8b5d904c8b758831d24409e0488b45a8440fb6d141b007440f44d2";
const hex = (value) => Uint8Array.from(value.match(/../g).map((part) => parseInt(part, 16)));
const add = (value, offset) => {
  const lo = ((value.lo >>> 0) + (offset >>> 0)) >>> 0;
  return Object.freeze({lo, hi: ((value.hi >>> 0) + (lo < (value.lo >>> 0) ? 1 : 0)) >>> 0});
};
const key = (value) => `${value.hi >>> 0}:${value.lo >>> 0}`;
const put32 = (view, offset, value) => view.setUint32(offset, value >>> 0, true);
const put64 = (view, offset, value) => { put32(view, offset, value.lo); put32(view, offset + 4, value.hi); };

let moduleGeneration=0;
async function moduleFor(name) {
  moduleGeneration+=1;
  return import(`./hx1400_goldhen_dualmap_owner.js?fixture=${name}-${moduleGeneration}`);
}

function fixture(api, {gadgetMismatch = false, handlerMismatch = false, mmapMismatch = false, helper62Mismatch = false, helper61Mismatch = false, relocated = false} = {}) {
  const kbase = Object.freeze({lo:0x10000000,hi:0xffffffff});
  const thread = add(kbase, 0x1800000);
  const proc = add(kbase, 0x1810000);
  const ucred = add(kbase, 0x1820000);
  const filedesc = add(kbase, 0x1830000);
  const groups = add(kbase, 0x1840000);
  const qwords = new Map([
    [key(add(thread,0x08)),proc],[key(add(thread,0x130)),ucred],
    [key(add(proc,0x40)),ucred],[key(add(proc,0x48)),filedesc],
    [key(add(ucred,0x118)),groups],
  ]);
  const handlerRva = 0x106f00 + (relocated ? 0x2a0 : 0);
  const helperDelta = relocated ? 0x2b0 : 0;
  const helper62Rva = 0x3b31c0 + helperDelta;
  const helper61Rva = 0x3b3220 + helperDelta;
  const mmapHandlerRva = 0x1fa460 + (relocated ? 0x2c0 : 0);
  const mmapJitshmRva = mmapHandlerRva + api.HX1400_GOLDHEN_DUALMAP_MMAP_JITSHM_OFFSET;
  const alternateRvas = [0x41fc40 + helperDelta, 0x420a40 + helperDelta];
  const handler = add(kbase,handlerRva);
  const mmapHandler = add(kbase,mmapHandlerRva);
  const record = new Uint8Array(0x30);
  const recordView = new DataView(record.buffer);
  put32(recordView,0,3); put64(recordView,8,handler); put32(recordView,0x2c,1);
  const mmapRecord = new Uint8Array(0x30);
  const mmapRecordView = new DataView(mmapRecord.buffer);
  put32(mmapRecordView,0,6); put64(mmapRecordView,8,mmapHandler); put32(mmapRecordView,16,0xd2); put32(mmapRecordView,40,1); put32(mmapRecordView,0x2c,1);
  const handlerBytes=hex(HANDLER);
  const handlerView=new DataView(handlerBytes.buffer,handlerBytes.byteOffset,handlerBytes.byteLength);
  put32(handlerView,0x14,0x275cea0-(handlerRva+0x18));
  put32(handlerView,0x2d,helper62Rva-(handlerRva+0x31));
  put32(handlerView,0x3e,helper61Rva-(handlerRva+0x42));
  if(handlerMismatch) handlerBytes[0]^=0xff;
  const helper62Bytes=hex(HELPER62);
  const helper61Bytes=hex(HELPER61);
  for (const [blob,baseRva] of [[helper62Bytes,helper62Rva],[helper61Bytes,helper61Rva]]) {
    const view=new DataView(blob.buffer,blob.byteOffset,blob.byteLength);
    put32(view,0x23,alternateRvas[0]-(baseRva+0x27));
    put32(view,0x32,alternateRvas[1]-(baseRva+0x36));
  }
  if(helper62Mismatch) helper62Bytes[0x23]^=0x01;
  if(helper61Mismatch) helper61Bytes[0x23]^=0x01;
  const mmapJitshmBytes=hex(MMAP_JITSHM);
  const mmapJitshmView=new DataView(mmapJitshmBytes.buffer,mmapJitshmBytes.byteOffset,mmapJitshmBytes.byteLength);
  put32(mmapJitshmView,0x1c,helper62Rva-(mmapJitshmRva+0x20));
  put32(mmapJitshmView,0x2b,helper61Rva-(mmapJitshmRva+0x2f));
  if(mmapMismatch) mmapJitshmBytes[0]^=0xff;
  const blobs = new Map([
    [key(add(kbase,api.HX1400_GOLDHEN_DUALMAP_SYSENT477_RVA)),mmapRecord],
    [key(add(kbase,api.HX1400_GOLDHEN_DUALMAP_SYSENT533_RVA)),record],
    [key(handler),handlerBytes],
    [key(add(kbase,helper62Rva)),helper62Bytes],
    [key(add(kbase,helper61Rva)),helper61Bytes],
    [key(add(kbase,mmapJitshmRva)),mmapJitshmBytes],
    [key(add(kbase,api.HX1400_GOLDHEN_DUALMAP_DWORD_GADGET_RVA)),Uint8Array.from(gadgetMismatch?[0x90,0x07,0x5d,0xc3]:[0x89,0x07,0x5d,0xc3])],
  ]);
  const context = Object.freeze({
    firmware:"14.00", mode:"read-only", challenge:Object.freeze({lo:0x11223344,hi:0x55667788}),
    kernelExecutor:Object.freeze({
      protocol:api.HX1400_GOLDHEN_DUALMAP_OWNER_PROTOCOL,synchronous:true,currentThreadGs:true,readOnly:true,
      source13Sha256:api.HX1400_GOLDHEN_DUALMAP_SOURCE13_SHA256,source13GadgetRva:api.HX1400_GOLDHEN_DUALMAP_GS_SOURCE13_RVA,
      candidateRvas:api.HX1400_GOLDHEN_DUALMAP_GS_CANDIDATE_RVAS,gadgetBytes:api.HX1400_GOLDHEN_DUALMAP_GS_GADGET_BYTES,
      uniqueExactRuntimeResolution:true,signatureCheckedBeforeAndAfter:true,
      executeCurrentThread(request){request.capture(thread);return request.acknowledgement;},
    }),
    kernelBase:kbase,
    read64(address){const value=qwords.get(key(address));if(!value)throw new Error(`read64 ${key(address)}`);return value;},
    read32(address){if(key(address)===key(add(proc,0xb0)))return 31337;throw new Error("read32");},
    readBytes(address,length){const value=blobs.get(key(address));if(!value||value.length!==length)throw new Error(`readBytes ${key(address)} ${length}`);return new Uint8Array(value);},
    getpid(){return 31337;},
  });
  return {context,qwords,ucred};
}

function operation({value = 0x00123456, onWritable = null, onExecutable = null} = {}) {
  const writes=[]; let scalar=value>>>0; let creates=0; let maps=0; let disposes=0;
  const context=Object.freeze({
    aioCleanupVerified:true,bridgeCallActive:false,exclusiveGeneration:true,otherCredentialWriter:false,
    read32(){return scalar;},
    write32(_address,next){writes.push(next>>>0);scalar=next>>>0;return 0;},
    createWritableView(registerDescriptor){creates+=1;if(onWritable)onWritable(scalar);registerDescriptor(41);return 41;},
    mapExecutableView(fd){maps+=1;if(onExecutable)onExecutable(fd,scalar);return 0;},
    disposeJit(){disposes+=1;return 0;},
  });
  return {context,writes,get scalar(){return scalar;},get creates(){return creates;},get maps(){return maps;},get disposes(){return disposes;}};
}

test("owner pins a bounded unique runtime resolver to published executable deltas", async () => {
  const api=await moduleFor("relocation-contract");
  assert.equal(api.HX1400_GOLDHEN_DUALMAP_OWNER_PROTOCOL,"hx1400-goldhen-dualmap-gs-relocation-set/v1");
  assert.equal(api.HX1400_GOLDHEN_DUALMAP_GS_SOURCE13_RVA,0x74d6e3);
  assert.deepEqual(api.HX1400_GOLDHEN_DUALMAP_EXECUTABLE_RELOCATION_DELTAS,[0,0x2a0,0x2b0,0x2c0]);
  assert.deepEqual(api.HX1400_GOLDHEN_DUALMAP_GS_CANDIDATE_RVAS,[0x74d6e3,0x74d983,0x74d993,0x74d9a3]);
  const fx=fixture(api);
  const invalidExecutor=Object.freeze({
    ...fx.context.kernelExecutor,
    candidateRvas:Object.freeze([0x74d6e3]),
  });
  const result=api.runHx1400GoldhenDualmapOwnerOracle(Object.freeze({
    ...fx.context,
    kernelExecutor:invalidExecutor,
  }));
  assert.equal(result.ok,false);
  assert.equal(result.code,"ERR_EXECUTOR");
});

test("source13 live attestation refuses either helper, mmap, handler, or dword mismatch before credential mutation", async () => {
  for (const kind of ["handler","mmap","helper62","helper61","gadget"]) {
    const api=await moduleFor(`mismatch-${kind}`);
    const fx=fixture(api,{
      gadgetMismatch:kind==="gadget",
      handlerMismatch:kind==="handler",
      mmapMismatch:kind==="mmap",
      helper62Mismatch:kind==="helper62",
      helper61Mismatch:kind==="helper61",
    });
    const result=api.runHx1400GoldhenDualmapOwnerOracle(fx.context);
    assert.equal(result.ok,false);
    const op=operation();
    const lease=api.consumeHx1400GoldhenDualmapOwnerLease(result,op.context);
    assert.equal(lease.ok,false);
    assert.equal(op.writes.length,0);
    assert.equal(op.creates,0);
    assert.equal(op.maps,0);
  }
});

test("relocation-aware semantic call graph accepts the observed FW14 code-region deltas", async () => {
  const api=await moduleFor("relocated-fw14");
  const fx=fixture(api,{relocated:true});
  const owner=api.runHx1400GoldhenDualmapOwnerOracle(fx.context);
  assert.equal(owner.ok,true);
  assert.equal(owner.code,"OK_CURRENT_OWNER");
  assert.doesNotMatch(JSON.stringify(owner),/0x[0-9a-f]{8,16}/i);
});

test("owner drift and writer-isolation refusal happen before the first credential write", async () => {
  const driftApi=await moduleFor("drift");
  const driftFx=fixture(driftApi);
  const driftOwner=driftApi.runHx1400GoldhenDualmapOwnerOracle(driftFx.context);
  driftFx.qwords.set(key(add(add(driftFx.context.kernelBase,0x1800000),0x130)), add(driftFx.context.kernelBase,0x1850000));
  const driftOp=operation();
  const drift=driftApi.consumeHx1400GoldhenDualmapOwnerLease(driftOwner,driftOp.context);
  assert.equal(drift.error,"ERR_OWNER_DRIFT");
  assert.equal(driftOp.writes.length,0); assert.equal(driftOp.creates,0);

  const isolationApi=await moduleFor("isolation");
  const isolationFx=fixture(isolationApi);
  const owner=isolationApi.runHx1400GoldhenDualmapOwnerOracle(isolationFx.context);
  const op=operation();
  const refused=isolationApi.consumeHx1400GoldhenDualmapOwnerLease(owner,Object.freeze({...op.context,otherCredentialWriter:true}));
  assert.equal(refused.error,"ERR_WRITER_ISOLATION");
  assert.equal(refused.rebootRequired,true);
  assert.equal(op.writes.length,0); assert.equal(op.creates,0);
  const retry=isolationApi.consumeHx1400GoldhenDualmapOwnerLease(owner,op.context);
  assert.equal(retry.error,"ERR_OWNER_TOKEN");
  assert.equal(retry.rebootRequired,true);
  assert.equal(op.writes.length,0); assert.equal(op.creates,0);
});

test("owner rejects the obsolete generation-2 mapped-JIT callback boundary", async () => {
  const api=await moduleFor("obsolete-callback");
  const fx=fixture(api);
  const owner=api.runHx1400GoldhenDualmapOwnerOracle(fx.context);
  const op=operation();
  const refused=api.consumeHx1400GoldhenDualmapOwnerLease(owner,Object.freeze({
    ...op.context,
    createMappedJit(){return 41;},
  }));
  assert.equal(refused.error,"ERR_WRITER_ISOLATION");
  assert.deepEqual(op.writes,[]);
  assert.equal(op.creates,0);
  assert.equal(op.maps,0);
});

test("private owner lease exposes the exact generation-3 W^X callback and receipt contract", async () => {
  const api=await moduleFor("success");
  const fx=fixture(api);
  const owner=api.runHx1400GoldhenDualmapOwnerOracle(fx.context);
  assert.equal(owner.ok,true);
  assert.equal(owner.mmapCapabilityRecheckAttested,true);
  assert.doesNotMatch(JSON.stringify(owner),/0x[0-9a-f]{8,16}/i);
  const observed=[];
  const op=operation({
    onWritable:(scalar)=>observed.push(["writable",scalar]),
    onExecutable:(fd,scalar)=>observed.push(["executable",fd,scalar]),
  });
  const receipt=api.consumeHx1400GoldhenDualmapOwnerLease(owner,op.context);
  assert.equal(receipt.ok,true);
  assert.equal(receipt.pointerFree,true);
  assert.deepEqual(op.writes,[0x40123456,0x00123456,0x20123456,0x00123456]);
  assert.deepEqual(observed,[["writable",0x40123456],["executable",41,0x20123456]]);
  assert.equal(op.creates,1);
  assert.equal(op.maps,1);
  assert.equal(op.disposes,0);
  assert.equal(receipt.writes,4);
  assert.equal(receipt.createCalls,1);
  assert.equal(receipt.mapCalls,1);
  assert.equal(receipt.writeArmConfirmed,true);
  assert.equal(receipt.writeRestoreConfirmed,true);
  assert.equal(receipt.executeArmConfirmed,true);
  assert.equal(receipt.executeRestoreConfirmed,true);
  assert.equal(receipt.borrowedBitsCleared,true);
  assert.equal(receipt.terminalMatchesOriginal,true);
  assert.equal(receipt.descriptorTransferred,true);
  assert.equal(receipt.rebootRequired,true);
  assert.equal(op.scalar,0x00123456);
  const second=api.consumeHx1400GoldhenDualmapOwnerLease(owner,op.context);
  assert.equal(second.ok,false);
  assert.equal(op.creates,1);
  assert.equal(op.maps,1);
  assert.equal(second.rebootRequired,true);
});
