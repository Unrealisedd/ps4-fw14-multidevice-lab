const freeze = (values) => Object.freeze(values.slice());

export const HX1400_P = freeze([
  0x1102d88, 0x250be, 0x48a18, 0x16ab, 0xb811, 0xb8ea, 0xb9f8, 0xbda0,
  0xbe54, 0xccfa, 0xce6d, 0xd03e, 0x798754, 0x1a312b0, 0x152a108, 0x349ee,
  0x73e886, 0x1c9dc, 0x2be040, 0x2be070, 0xe4f40, 0x1ca05, 0x184ab2,
  0x3b0a2a, 0x31b494, 0x58136, 0x6aaf3, 0x3fc327, 0x2e3d59, 0x2f1cb,
  0x42f9f3,
]);

export const HX1400_GUARD_RVAS = freeze([
  0x4c2, 0xacd, 0x2bd79d, 0x2bd7e1, 0x2bd85d, 0x2bd8a1, 0x2bda4d,
  0x2bdefd, 0x2bdfcd, 0x391fc6, 0x4b5, 0x4b9, 0x1b7504, 0x1b7a43,
  0x1b7a53, 0x1b7a73, 0x1b7ab8, 0x2fcb5c, 0x628684, 0x628f6f,
  0x1faada, 0x1faadd, 0x490, 0x3be3c0,
]);
export const HX1400_GUARD_WIDTHS = freeze([
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 4, 4,
]);
export const HX1400_GUARD_STOCK = freeze([
  0x72, 0x76, 0x76, 0x76, 0x76, 0x76, 0x76, 0x76, 0x76, 0x74,
  0x1372, 0xf75, 0x840f, 0x850f, 0x840f, 0x840f, 0x820f, 0x850f,
  0x774, 0x4175, 0x33, 0x33, 0xffffffff, 0xe5894855,
]);
export const HX1400_GUARD_PATCHED = freeze([
  0xeb, 0xeb, 0xeb, 0xeb, 0xeb, 0xeb, 0xeb, 0xeb, 0xeb, 0xeb, 0xeb,
  0xeb, 0xe990, 0x4eb, 0x4eb, 0xe990, 0xe990, 0x4eb, 0xeb, 0xeb, 0x37,
  0x37, 0, 0xc3c03148,
]);

export const HX1400_CANDIDATES = freeze([
  128, 96, 160, 64, 192, 32, 224, 120, 136, 88, 104, 152, 168, 56, 72,
  184, 200, 24, 40, 216, 232, 8, 16, 48, 80, 112, 144, 176, 208, 240,
]);

export const HX1400_PATCH_HEX =
  "b9820000c00f3248c1e22089c04809c2488d8a40feffff0f20c04825fffffeff0f22c0b8eb040000beeb040000bf90e9ffff41b8eb000000668981437a1b00b8" +
  "eb04000041b9eb00000041baeb0000006689815ccb2f0041bbeb000000b890e9ffff4881c2fe4e02006689b1537a1b006689b9737a1b006644898184866200c6" +
  "81cd0a0000ebc6819dd72b00ebc681e1d72b00ebc6815dd82b00ebc681a1d82b00ebc6814dda2b00ebc681fdde2b00ebc681cddf2b00eb664489896f8f6200c7" +
  "819004000000000000c681c2040000eb66448991b904000066448999b5040000c681c61f3900eb66898104751b00c781b87a1b0090e93c01c781c0e33b004831" +
  "c0c3c681daaa1f0037c681ddaa1f0037c781802d100102000000488991882d1001c781ac2d1001010000000f20c0480d000001000f22c00f20c04825fffffeff" +
  "0f22c0b8eb480000ba040000004531c04531c9be0500000066898191571200b8eb060000bf05000000668981d357120041ba0100000048b84183bfa004000000" +
  "41bb01000000488981db571200b804000000668981ed571200b8498bffffc781e9571200498b87d0c681ef57120000c781f6571200498bb7b0668991fa571200" +
  "c681fc57120000c7810e581200498b87406689b112581200c6811458120000c7811b581200498bb7206689b91f581200c6812158120000c78133581200498dbf" +
  "c06644898137581200c6813958120000c7813f581200498dbfe06644898943581200c6814558120000c78152581200498dbf006644899156581200c681585812" +
  "0000c7815e581200498dbf206644899962581200c68164581200006689816f581200c68171581200ff0f20c0480d000001000f22c031c0c3";

export const HX1400_SOURCE_PINS = Object.freeze({
  firmware: "14.00",
  patchBytes: 632,
  patchSha256: "165d2ad966b3829d1fbcb53d5e7ecbc20563de4a6a49ee70d8126d0256a49c02",
  henBytes: 0x48a18,
  henEntry: 0x16ab,
  mark: Object.freeze({ lo: 0x4f544a31, hi: 0x4d4d524f }),
  ident: Object.freeze({ lo: 0x52544f4f, hi: 0x31344b50 }),
  uidMagic: Object.freeze({ lo: 0x13, hi: 0x48010000 }),
  anchorRva: 0x798754,
  challengeRva: 27557776,
  allprocRva: 28476728,
  rootvnodeRva: 34827920,
  sysentNargRva: 17837440,
});

export const HX1400_SYSCALLS = Object.freeze({
  read: 3, write: 4, open: 5, close: 6, getpid: 20, getuid: 24, munmap: 73, socket: 97,
  setsockopt: 105, getsockopt: 118, fstat: 189, sysctl: 202, kqueue: 362,
  kevent: 363, mmap: 477, cpusetGetaffinity: 487, cpusetSetaffinity: 488,
  jitshmCreate: 533, aioMultiDelete: 662, aioMultiPoll: 664,
  aioMultiCancel: 666, aioSubmitCmd: 669,
});
