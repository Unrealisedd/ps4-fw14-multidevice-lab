const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotateRight(value, count) {
  return (value >>> count) | (value << (32 - count));
}

export class Sha256 {
  constructor() {
    this.state = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    this.block = new Uint8Array(64);
    this.schedule = new Uint32Array(64);
    this.blockLength = 0;
    this.totalLength = 0;
    this.finished = false;
  }

  update(input) {
    if (this.finished) throw new Error("SHA-256 instance already finalized");
    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    this.totalLength += bytes.byteLength;
    if (this.totalLength > Number.MAX_SAFE_INTEGER)
      throw new Error("SHA-256 input is too large");

    let offset = 0;
    if (this.blockLength !== 0) {
      const take = Math.min(64 - this.blockLength, bytes.byteLength);
      this.block.set(bytes.subarray(0, take), this.blockLength);
      this.blockLength += take;
      offset = take;
      if (this.blockLength === 64) {
        this.compress(this.block, 0);
        this.blockLength = 0;
      }
    }
    while (offset + 64 <= bytes.byteLength) {
      this.compress(bytes, offset);
      offset += 64;
    }
    if (offset < bytes.byteLength) {
      this.block.set(bytes.subarray(offset), 0);
      this.blockLength = bytes.byteLength - offset;
    }
    return this;
  }

  compress(bytes, offset) {
    const w = this.schedule;
    for (let i = 0; i < 16; i++) {
      const at = offset + i * 4;
      w[i] =
        ((bytes[at] << 24) |
          (bytes[at + 1] << 16) |
          (bytes[at + 2] << 8) |
          bytes[at + 3]) >>>
        0;
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15];
      const y = w[i - 2];
      const s0 = rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >>> 3);
      const s1 = rotateRight(y, 17) ^ rotateRight(y, 19) ^ (y >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = this.state[0];
    let b = this.state[1];
    let c = this.state[2];
    let d = this.state[3];
    let e = this.state[4];
    let f = this.state[5];
    let g = this.state[6];
    let h = this.state[7];
    for (let i = 0; i < 64; i++) {
      const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const choose = (e & f) ^ (~e & g);
      const t1 = (h + sum1 + choose + K[i] + w[i]) >>> 0;
      const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (sum0 + majority) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    this.state[0] = (this.state[0] + a) >>> 0;
    this.state[1] = (this.state[1] + b) >>> 0;
    this.state[2] = (this.state[2] + c) >>> 0;
    this.state[3] = (this.state[3] + d) >>> 0;
    this.state[4] = (this.state[4] + e) >>> 0;
    this.state[5] = (this.state[5] + f) >>> 0;
    this.state[6] = (this.state[6] + g) >>> 0;
    this.state[7] = (this.state[7] + h) >>> 0;
  }

  digest() {
    if (this.finished) throw new Error("SHA-256 instance already finalized");
    this.finished = true;
    const finalLength = this.blockLength < 56 ? 64 : 128;
    const finalBlocks = new Uint8Array(finalLength);
    finalBlocks.set(this.block.subarray(0, this.blockLength), 0);
    finalBlocks[this.blockLength] = 0x80;
    const bitHigh = Math.floor(this.totalLength / 0x20000000) >>> 0;
    const bitLow = (this.totalLength * 8) >>> 0;
    const end = finalLength - 8;
    finalBlocks[end] = bitHigh >>> 24;
    finalBlocks[end + 1] = bitHigh >>> 16;
    finalBlocks[end + 2] = bitHigh >>> 8;
    finalBlocks[end + 3] = bitHigh;
    finalBlocks[end + 4] = bitLow >>> 24;
    finalBlocks[end + 5] = bitLow >>> 16;
    finalBlocks[end + 6] = bitLow >>> 8;
    finalBlocks[end + 7] = bitLow;
    this.compress(finalBlocks, 0);
    if (finalLength === 128) this.compress(finalBlocks, 64);

    const output = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      const value = this.state[i];
      output[i * 4] = value >>> 24;
      output[i * 4 + 1] = value >>> 16;
      output[i * 4 + 2] = value >>> 8;
      output[i * 4 + 3] = value;
    }
    return output;
  }
}

export function sha256(bytes) {
  return new Sha256().update(bytes).digest();
}
