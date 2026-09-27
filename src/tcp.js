// User-space IPv4/TCP stack that rides on top of an OpenVPN tunnel.
// A single TcpFlow is a TCP connection in the user-space stack: it exchanges
// IPv4/TCP segments with the peer through the tunnel's raw IPv4 channel and
// exposes { readable, writable, close } to the application (VLESS). It is
// structured as its own object so the whole flow can later be multiplexed.
//
// Scope: TCP over IPv4, one flow per connection (v1 of the proxy). Includes a
// bounded state machine, a cumulative-acknowledgement send queue with RTO /
// exponential-backoff retransmission, a receive-side out-of-order buffer,
// FIN/RST handling, an MSS option, checksum validation and IPv4-fragment
// rejection. It is deliberately not a full RFC 793 implementation.
import { concat, u16, u32, w16, w32, rng16, rng32, bytes } from './openvpn/bytes.js';

export const MSS = 1200;           // conservative segment size (user-tunable)
const MAX_RETRIES = 5;
const RTO_INIT = 1000;             // ms, initial retransmission timeout
const RTO_MAX = 32000;
const WINDOW = 65535;

function ipB(ip) {
  if (typeof ip !== 'string' || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) { const e = new Error('INVALID_IP ' + String(ip)); e.code = 'INVALID_IP'; throw e; }
  return new Uint8Array(ip.split('.').map(Number));
}
function foldSum(d, o, n) { let s = 0; for (let i = o; i < o + n - 1; i += 2) s += u16(d, i); if (n & 1) s += d[o + n - 1] << 8; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); return s & 0xFFFF; }
const cksum = (d, o, n) => (~foldSum(d, o, n)) & 0xFFFF;
const cksumOk = (d, o, n) => foldSum(d, o, n) === 0xFFFF; // sum incl stored cksum == 0xFFFF

// ---- segment parsing (receive side) ----
// Parse an IPv4 packet as TCP. Returns null if not a well-formed, non-fragmented
// TCP segment (fragmented IPv4 packets are deliberately not reassembled).
function parseSegment(ip) {
  if (ip.length < 40 || ip[9] !== 6) return null;
  const ihl = (ip[0] & 0x0F) * 4;
  if (ihl < 20 || ihl > 60 || ip.length < ihl + 20) return null;
  // IPv4 fragmentation: MF flag or non-zero fragment offset -> reject (drop)
  if ((ip[6] & 0x20) || ((ip[6] & 0x1F) << 8 | ip[7]) !== 0) return null;
  const totalLen = u16(ip, 2);
  if (totalLen < ihl + 20 || totalLen > ip.length) return null;
  // validate IPv4 header checksum
  if (!cksumOk(ip, 0, ihl)) return null;
  const tcp = ihl;
  const off = (ip[tcp + 12] >> 4) * 4;
  if (off < 20 || off > 60 || tcp + off > totalLen) return null;
  const doff = off;
  const payload = ip.subarray(tcp + doff, totalLen);
  // validate TCP checksum (pseudo-header); the 2-byte length field is the TCP
  // segment length (totalLen - tcp), not the pseudo-header length
  const tl = totalLen - tcp;
  const pseudo = new Uint8Array(12 + tl);
  pseudo.set(ip.subarray(12, 16), 0); pseudo.set(ip.subarray(16, 20), 4); pseudo[9] = 6;
  pseudo[10] = (tl >> 8) & 0xFF; pseudo[11] = tl & 0xFF;
  pseudo.set(ip.subarray(tcp, totalLen), 12);
  if (!cksumOk(pseudo, 0, 12 + tl)) return null;
  // parse options (ignore unknown kinds; never crash)
  let mss = null, optOff = tcp + 20;
  while (optOff < tcp + doff) {
    const kind = ip[optOff];
    if (kind === 0) break;                     // EOL
    if (kind === 1) { optOff += 1; continue; } // NOP
    if (optOff + 2 > tcp + doff) break;
    const len = ip[optOff + 1];
    if (len < 2 || optOff + len > tcp + doff) break;
    if (kind === 2 && len === 4) mss = u16(ip, optOff + 2);
    optOff += len;
  }
  return {
    srcPort: u16(ip, tcp), dstPort: u16(ip, tcp + 2),
    seq: u32(ip, tcp + 4), ack: u32(ip, tcp + 8),
    flags: ip[tcp + 13], window: u16(ip, tcp + 14), mss, payload,
  };
}

const FLAG_FIN = 0x01, FLAG_SYN = 0x02, FLAG_RST = 0x04, FLAG_PSH = 0x08, FLAG_ACK = 0x10;

export class TcpFlow {
  constructor(tunnel, srcIp, dstIp, dstPort) {
    this.tunnel = tunnel;
    this.tunnelW = tunnel.writable.getWriter();
    this.srcIp = srcIp; this.dstIp = dstIp;
    this.srcPort = 10000 + (rng16() % 50000);
    this.dstPort = dstPort;
    this.srcB = ipB(srcIp); this.dstB = ipB(dstIp);
    this.mss = MSS;
    // send side
    this.iss = rng32(); this.sndUna = this.iss; this.sndNxt = this.iss;
    this.unacked = [];            // { seq, endSeq, payload, flags, sentAt, retries }
    // receive side
    this.rcvNxt = 0; this.rcvWnd = WINDOW;
    this.outOfOrder = [];         // { seq, endSeq, payload, flags }
    this.pendingFin = -1;
    // state / lifecycle
    this.state = 'CLOSED';
    this.rto = RTO_INIT;
    this.reader = null;
    this.timer = null;
    this.ctrl = null;             // readable controller
    this.appClosed = false;
    this.deliver = () => {};      // app data callback
    this.onShutdown = () => {};   // app EOF / close callback
    this.establishedResolve = null;
    this._est = new Promise((r) => { this.establishedResolve = r; });
    this.peerClosed = false;
    this._closed = false;
  }
  established() { return this._est; }

  _emit(flags, payload, seq, ack) {
    const opts = (flags & FLAG_SYN) ? bytes([2, 4, this.mss >> 8, this.mss & 0xFF]) : null; // MSS option on SYN
    const tcpHdrLen = 20 + (opts ? opts.length : 0);
    const tl = tcpHdrLen + payload.length;
    const il = 20 + tl;
    const f = new Uint8Array(il);
    const v = new DataView(f.buffer);
    // IPv4
    f[0] = 0x45;
    v.setUint16(2, il);
    v.setUint16(4, rng16());
    v.setUint16(6, 0);
    f[8] = 64; f[9] = 6;
    f.set(this.srcB, 12); f.set(this.dstB, 16);
    v.setUint16(10, cksum(f, 0, 20));
    // TCP
    v.setUint16(20, this.srcPort); v.setUint16(22, this.dstPort);
    v.setUint32(24, seq >>> 0); v.setUint32(28, ack >>> 0);
    f[32] = ((tcpHdrLen >> 2) << 4); // TCP data offset in the high nibble
    f[33] = flags;
    v.setUint16(34, this.rcvWnd);
    if (opts) f.set(opts, 40);
    if (payload.length) f.set(payload, 20 + tcpHdrLen);
    // pseudo header
    const pseudo = new Uint8Array(12 + tl);
    pseudo.set(this.srcB, 0); pseudo.set(this.dstB, 4); pseudo[9] = 6;
    pseudo[10] = (tl >> 8) & 0xFF; pseudo[11] = tl & 0xFF;
    pseudo.set(f.subarray(20, 20 + tl), 12);
    v.setUint16(36, cksum(pseudo, 0, 12 + tl));
    this.tunnelW.write(f).catch(() => {});
    return f;
  }

  _track(seq, endSeq, payload, flags) {
    this.unacked.push({ seq: seq >>> 0, endSeq: endSeq >>> 0, payload, flags, sentAt: Date.now(), retries: 0 });
  }
  _deliver(seg, partialOff) {
    // segment bytes from partialOff..(len) are newly contiguous
    const d = seg.payload.subarray(partialOff);
    if (d.length) this.deliver(d);
    this.rcvNxt = (this.rcvNxt + (seg.payload.length - partialOff)) >>> 0;
  }

  // Feed a parsed inbound segment (returns nothing). Updates state + ACKs.
  onSegment(pkt) {
    const s = parseSegment(pkt);
    if (!s) return;
    // cumulative ACK: release every segment fully covered by the ACK
    if (s.flags & FLAG_ACK) {
      const ack = s.ack;
      if (seqLt(this.sndUna, ack)) {
        this.sndUna = ack;
        this.unacked = this.unacked.filter((seg) => !seqLe(seg.endSeq, ack));
        if (!this.unacked.length) this.rto = RTO_INIT;
      }
      if (this.state === 'SYN_SENT' && ack === (this.iss + 1) >>> 0) {
        this.state = 'ESTABLISHED';
        this.rcvNxt = (s.seq + 1) >>> 0; // the peer's SYN consumes one seq slot
        this.establishedResolve();
        this._sendAck();
      }
    }
    // RST terminates the flow immediately
    if (s.flags & FLAG_RST) { this._shutdown(true); return; }
    // receive-side data (+ SYN / FIN slots)
    const len = s.payload.length;
    if (len || (s.flags & FLAG_SYN) || (s.flags & FLAG_FIN)) {
      this._receive({ seq: s.seq, endSeq: (s.seq + len) >>> 0, payload: s.payload, flags: s.flags });
      if (s.flags & FLAG_FIN) {
        const finPos = (s.seq + len) >>> 0;
        if (seqLe(finPos, this.rcvNxt)) { this.rcvNxt = (finPos + 1) >>> 0; this._peerFin(); }
      }
    }
    this._sendAck();
  }

  _receive(seg) {
    const segEnd = seg.endSeq;
    if (process.env.TCPDBG) console.log('[recv] seq=' + seg.seq + ' end=' + segEnd + ' rcvNxt=' + this.rcvNxt + ' len=' + seg.payload.length + ' dup=' + seqLe(segEnd, this.rcvNxt));
    // fully duplicate (already fully delivered)
    if (seqLe(segEnd, this.rcvNxt)) return;
    // exactly contiguous at rcvNxt
    if (seg.seq === this.rcvNxt) {
      this._deliver(seg, 0);
      this._drain();
      return;
    }
    // overlaps rcvNxt from the left (rcvNxt inside this segment)
    if (seqLt(seg.seq, this.rcvNxt) && seqLt(this.rcvNxt, segEnd)) {
      this._deliver(seg, (this.rcvNxt - seg.seq) >>> 0);
      this._drain();
      return;
    }
    // ahead of rcvNxt -> buffer
    if (seqLt(this.rcvNxt, seg.seq)) {
      if (process.env.TCPDBG) console.log('[recv] buffering seq=' + seg.seq + ' (lt=' + seqLt(this.rcvNxt, seg.seq) + ')');
      this.outOfOrder.push(seg);
      this.outOfOrder.sort((a, b) => a.seq - b.seq);
    }
  }
  _drain() {
    for (;;) {
      const i = this.outOfOrder.findIndex((x) => x.seq === this.rcvNxt);
      if (i < 0) break;
      const seg = this.outOfOrder[i];
      this.outOfOrder.splice(i, 1);
      if (process.env.TCPDBG) console.log('[drain] delivering buffered seq=' + seg.seq + ' len=' + seg.payload.length);
      this._deliver(seg, 0);
    }
  }
  _peerFin() {
    this.peerClosed = true;
    if (this.state === 'ESTABLISHED' || this.state === 'SYN_SENT') this.state = 'CLOSE_WAIT';
    else if (this.state === 'FIN_WAIT_1') { this.state = 'CLOSE_WAIT'; }
    this._sendAck();
    this.onShutdown(); // EOF to the app read side
  }

  _sendAck() {
    if (this.state === 'CLOSED') return;
    this._emit(FLAG_ACK, new Uint8Array(0), this.sndNxt, this.rcvNxt);
  }

  // ---- application sending ----
  write(data) {
    const d = data instanceof Uint8Array ? data : new Uint8Array(data);
    if (this._closed) return Promise.resolve();
    for (let o = 0; o < d.length; o += this.mss) {
      const seg = d.subarray(o, Math.min(o + this.mss, d.length));
      const seq = this.sndNxt;
      this._emit(FLAG_PSH | FLAG_ACK, seg, seq, this.rcvNxt);
      this._track(seq, (seq + seg.length) >>> 0, seg, FLAG_PSH | FLAG_ACK);
      this.sndNxt = (this.sndNxt + seg.length) >>> 0;
    }
    return Promise.resolve();
  }
  fin() {
    if (this._closed || (this.state !== 'ESTABLISHED' && this.state !== 'CLOSE_WAIT' && this.state !== 'FIN_WAIT_2')) return;
    const seq = this.sndNxt;
    this._emit(FLAG_FIN | FLAG_ACK, new Uint8Array(0), seq, this.rcvNxt);
    this._track(seq, (seq + 1) >>> 0, new Uint8Array(0), FLAG_FIN | FLAG_ACK);
    this.sndNxt = (this.sndNxt + 1) >>> 0;
    if (this.state === 'ESTABLISHED') this.state = 'FIN_WAIT_1';
    else if (this.state === 'CLOSE_WAIT') this.state = 'LAST_ACK';
  }

  // Periodic retransmission / RTO:: called by a timer.
  tick() {
    if (this._closed) return;
    const now = Date.now();
    const overdue = this.unacked.filter((seg) => now - seg.sentAt >= this.rto);
    if (!overdue.length) return;
    for (const seg of overdue) {
      seg.retries++;
      if (seg.retries > MAX_RETRIES) { this._shutdown(true); return; }
      seg.sentAt = now;
      this._emit(seg.flags, seg.payload, seg.seq, this.rcvNxt);
    }
    this.rto = Math.min(RTO_MAX, this.rto * 2);
    if (this.state === 'SYN_SENT' && this.unacked.length) { /* keep waiting */ }
  }
  get hasUnacked() { return this.unacked.length > 0; }

  _shutdown(reset) {
    if (this._closed) return;
    this._closed = true;
    try { clearInterval(this.timer); } catch { }
    try { this.reader && this.reader.cancel(); } catch { }
    try { this.tunnel.close && this.tunnel.close(); } catch { }
    this.ctrl && (this.ctrl.close(), (this.ctrl = null));
  }
}

// 32-bit sequence comparison helpers (RFC 793 style): a is "before" b when the
// signed 32-bit difference (a - b) is negative.
function seqLt(a, b) { return ((a - b) | 0) < 0; }
function seqLe(a, b) { return ((a - b) | 0) <= 0; }

export async function createTcp(tunnel, srcIp, dstIp, dstPort) {
  const flow = new TcpFlow(tunnel, srcIp, dstIp, dstPort);
  const ready = flow.established();
  // --- application readable stream ---
  let ctrl = null;
  const readable = new ReadableStream({
    start: (c) => { ctrl = c; flow.ctrl = c; flow.deliver = (d) => { try { c.enqueue(d); } catch { } }; flow.onShutdown = () => { try { c.close(); } catch { } }; },
    cancel: () => { flow.fin(); },
  });
  // --- wire tunnel reader ---
  const rd = tunnel.readable.getReader();
  flow.reader = rd;
  const pump = (async () => {
    try {
      for (;;) { const { value, done } = await rd.read(); if (done) break; flow.onSegment(value); }
    } catch { }
    finally { }
  })();
  // --- handshake: SYN ---
  flow.state = 'SYN_SENT';
  flow._emit(FLAG_SYN, new Uint8Array(0), flow.iss, 0);
  flow._track(flow.iss, (flow.iss + 1) >>> 0, new Uint8Array(0), FLAG_SYN);
  flow.sndNxt = (flow.iss + 1) >>> 0;
  // --- retransmission timer ---
  const timer = setInterval(() => flow.tick(), 250);
  flow.timer = timer;
  const handshake = await Promise.race([
    ready,
    new Promise((_, rej) => { flow.timer.handshakeLimit = setTimeout(() => { const e = new Error('TCP_HANDSHAKE_TIMEOUT'); e.code = 'TCP_HANDSHAKE_TIMEOUT'; rej(e); }, 15000); }),
  ]).catch((e) => { flow._shutdown(true); throw e; });
  clearTimeout(flow.timer.handshakeLimit);

  // --- application writable stream ---
  const writable = new WritableStream({
    write: (chunk) => flow.write(chunk),
    close: () => { flow.fin(); },
    abort: () => flow._shutdown(true),
  });
  return { readable, writable, close: () => flow._shutdown(true) };
}
