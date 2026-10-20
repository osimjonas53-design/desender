/*
 * Incremental SHA-256 for browsers. SubtleCrypto.digest needs the whole
 * input in memory at once, so large files are hashed here in slices.
 *
 * The round constants and initial values are derived from primes at load
 * time (fractional parts of cube and square roots), not typed in by hand.
 * tests/test_sha256_js.py checks the output against Node's crypto module.
 */
(function (root) {
  "use strict";

  function fracBits32(x) {
    return Math.floor((x - Math.floor(x)) * 4294967296) >>> 0;
  }

  function firstPrimes(n) {
    const out = [];
    for (let c = 2; out.length < n; c++) {
      let prime = true;
      for (let d = 2; d * d <= c; d++) if (c % d === 0) { prime = false; break; }
      if (prime) out.push(c);
    }
    return out;
  }

  const PRIMES = firstPrimes(64);
  const K = new Uint32Array(PRIMES.map((p) => fracBits32(Math.cbrt(p))));
  const H0 = new Uint32Array(PRIMES.slice(0, 8).map((p) => fracBits32(Math.sqrt(p))));

  function rotr(x, n) {
    return (x >>> n) | (x << (32 - n));
  }

  class Sha256 {
    constructor() {
      this.h = new Uint32Array(H0);
      this.block = new Uint8Array(64);
      this.blockLen = 0;
      this.totalBytes = 0;
      this.w = new Uint32Array(64);
    }

    _compress(data, offset) {
      const w = this.w;
      for (let i = 0; i < 16; i++) {
        const j = offset + i * 4;
        w[i] = ((data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3]) >>> 0;
      }
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = this.h;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e;
        e = (d + t1) >>> 0;
        d = c; c = b; b = a;
        a = (t1 + t2) >>> 0;
      }
      this.h[0] = (this.h[0] + a) >>> 0;
      this.h[1] = (this.h[1] + b) >>> 0;
      this.h[2] = (this.h[2] + c) >>> 0;
      this.h[3] = (this.h[3] + d) >>> 0;
      this.h[4] = (this.h[4] + e) >>> 0;
      this.h[5] = (this.h[5] + f) >>> 0;
      this.h[6] = (this.h[6] + g) >>> 0;
      this.h[7] = (this.h[7] + h) >>> 0;
    }

    /** Feed a Uint8Array. May be called any number of times. */
    update(bytes) {
      let pos = 0;
      this.totalBytes += bytes.length;
      if (this.blockLen > 0) {
        const take = Math.min(64 - this.blockLen, bytes.length);
        this.block.set(bytes.subarray(0, take), this.blockLen);
        this.blockLen += take;
        pos = take;
        if (this.blockLen === 64) {
          this._compress(this.block, 0);
          this.blockLen = 0;
        }
      }
      while (bytes.length - pos >= 64) {
        this._compress(bytes, pos);
        pos += 64;
      }
      if (pos < bytes.length) {
        this.block.set(bytes.subarray(pos), 0);
        this.blockLen = bytes.length - pos;
      }
      return this;
    }

    /** Finish and return the digest as lowercase hex. The object cannot be reused. */
    hex() {
      const bitLenHi = Math.floor((this.totalBytes * 8) / 4294967296);
      const bitLenLo = (this.totalBytes * 8) >>> 0;
      const pad = new Uint8Array(((this.blockLen < 56) ? 56 : 120) - this.blockLen + 8);
      pad[0] = 0x80;
      const tail = pad.length - 8;
      pad[tail] = (bitLenHi >>> 24) & 0xff;
      pad[tail + 1] = (bitLenHi >>> 16) & 0xff;
      pad[tail + 2] = (bitLenHi >>> 8) & 0xff;
      pad[tail + 3] = bitLenHi & 0xff;
      pad[tail + 4] = (bitLenLo >>> 24) & 0xff;
      pad[tail + 5] = (bitLenLo >>> 16) & 0xff;
      pad[tail + 6] = (bitLenLo >>> 8) & 0xff;
      pad[tail + 7] = bitLenLo & 0xff;
      const savedTotal = this.totalBytes;
      this.update(pad);
      this.totalBytes = savedTotal;
      let out = "";
      for (let i = 0; i < 8; i++) out += this.h[i].toString(16).padStart(8, "0");
      return out;
    }
  }

  /** Hash a Blob or File in slices without loading it whole. */
  async function hashBlob(blob, sliceSize, onProgress) {
    const size = sliceSize || 4 * 1024 * 1024;
    const hasher = new Sha256();
    for (let off = 0; off < blob.size; off += size) {
      const part = new Uint8Array(await blob.slice(off, off + size).arrayBuffer());
      hasher.update(part);
      if (onProgress) onProgress(Math.min(off + part.length, blob.size), blob.size);
    }
    return hasher.hex();
  }

  const api = { Sha256, hashBlob };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.AirBridgeSha256 = api;
})(typeof self !== "undefined" ? self : globalThis);
