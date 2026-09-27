// Byte helpers + ByteQueue buffer for TCP stream reassembly. Pure JS, no deps.
export const concat = (...a) => {
  const n = a.reduce((s, x) => s + x.length, 0);
  const r = new Uint8Array(n);
  let o = 0; for (const x of a) { r.set(x, o); o += x.length; }
  return r;
};
export const u16 = (b, o) => b[o] << 8 | b[o + 1];
export const u32 = (b, o) => (b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]) >>> 0;
export const u24 = (b, o) => (b[o] << 16 | b[o + 1] << 8 | b[o + 2]) >>> 0;
export const w16 = (b, o, v) => { b[o] = v >> 8 & 0xFF; b[o + 1] = v & 0xFF; };
export const w24 = (b, o, v) => { b[o] = v >> 16 & 0xFF; b[o + 1] = v >> 8 & 0xFF; b[o + 2] = v & 0xFF; };
export const w32 = (b, o, v) => { b[o] = v >>> 24 & 0xFF; b[o + 1] = v >>> 16 & 0xFF; b[o + 2] = v >>> 8 & 0xFF; b[o + 3] = v & 0xFF; };
export const hex = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
export const utf8 = (b) => new TextDecoder().decode(b);
// bytes(s): if a string, UTF-8 encode; if an array of numbers / Uint8Array, copy as bytes; if a number, one byte.
export const bytes = (s) => {
  if (typeof s === 'string') return new TextEncoder().encode(s);
  if (typeof s === 'number') return new Uint8Array([s]);
  if (s instanceof Uint8Array) return s;
  if (Array.isArray(s)) return Uint8Array.from(s);
  return new Uint8Array(s);
};
export const rng = (n) => crypto.getRandomValues(new Uint8Array(n));
export const rng16 = () => u16(rng(2), 0);
export const rng32 = () => u32(rng(4), 0);

// Small growable byte queue: append(raw) then read(n) returns a Uint8Array.
export class ByteQueue {
  constructor() { this.buf = new Uint8Array(0); }
  append(bytes) { this.buf = this.buf.length ? concat(this.buf, bytes) : bytes; }
  peek() { return this.buf; }
  get length() { return this.buf.length; }
  skip(n) { this.buf = this.buf.subarray(n); }
  read(n) { const r = this.buf.subarray(0, n); this.buf = this.buf.subarray(n); return r; }
}

// Stream buffer that reassembles the 2-byte-length-prefixed OpenVPN-TCP packets.
// Each call to push(chunk) returns an array of complete packet Uint8Arrays.
export class TcpPacketStream {
  constructor(maxLen = 65535) { this.q = new ByteQueue(); this.maxLen = maxLen; }
  push(chunk) {
    this.q.append(chunk);
    const out = [];
    while (this.q.length >= 2) {
      const plen = u16(this.q.buf, 0); // 2-byte big-endian length prefix
      if (plen < 1 || plen > this.maxLen) { this.q.buf = new Uint8Array(0); break; } // protocol error
      if (this.q.length >= 2 + plen) {
        this.q.skip(2);
        out.push(this.q.read(plen));
      } else break;
    }
    return out;
  }
}

// Minimal DER (ASN.1) parser. Returns a tree of {tag, value(Uint8Array), children?}.
export function derParse(input) {
  let off = 0;
  function readLen() {
    let l = input[off]; off++;
    if (l & 0x80) {
      const n = l & 0x7F; let v = 0;
      for (let i = 0; i < n; i++) { v = v * 256 + input[off]; off++; }
      return v;
    }
    return l;
  }
  function readElem() {
    const elemStart = off;
    const tag = input[off]; off++;
    const len = readLen();
    const start = off;
    const value = input.subarray(start, start + len);
    off += len;
    let children = null;
    if ((tag & 0x20) && len > 0) {
      children = [];
      let c = start; const end = start + len;
      while (c < end) { off = c; children.push(readElem()); c = off; }
    }
    return { tag, start, value, children, len, total: off - elemStart };
  }
  return readElem();
}
