// User-space IPv4/TCP stack that rides on top of an OpenVPN tunnel.
// The tunnel exposes { readable (raw IPv4 packets), writable (raw IPv4 packets),
// virtualIp, close }. createTcp() does the TCP handshake and bidirectional relay,
// returning { readable, writable, close } for the application (VLESS) side.
import { concat, u16, u32, rng16, rng32 } from './openvpn/bytes.js';

const MSS = 1400;

function ipB(ip) {
  if (typeof ip !== 'string' || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) { const e = new Error('INVALID_IP ' + String(ip)); e.code = 'INVALID_IP'; throw e; }
  return new Uint8Array(ip.split('.').map(Number));
}
function cksum(d, o, n) { let s = 0; for (let i = o; i < o + n - 1; i += 2) s += u16(d, i); if (n & 1) s += d[o + n - 1] << 8; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); return (~s) & 0xFFFF; }

export async function createTcp(tunnel, srcIp, dstIp, dstPort) {
  const tunnelW = tunnel.writable.getWriter();
  const srcPort = 10000 + (rng16() % 50000);
  const srcB = ipB(srcIp), dstB = ipB(dstIp);
  let seq = rng32(), ack = 0;
  const ipTpl = new Uint8Array(20);
  ipTpl.set([0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6]);
  ipTpl.set(srcB, 12); ipTpl.set(dstB, 16);
  const pseudo = new Uint8Array(1432);
  pseudo.set(srcB); pseudo.set(dstB, 4); pseudo[9] = 6;

  const frame = (flags, data = new Uint8Array(0)) => {
    const pl = data.length, tl = 20 + pl, il = 20 + tl, f = new Uint8Array(il), v = new DataView(f.buffer);
    f.set(ipTpl, 0);
    v.setUint16(2, il); v.setUint16(4, rng16()); v.setUint16(10, cksum(f, 0, 20));
    v.setUint16(20, srcPort); v.setUint16(22, dstPort); v.setUint32(24, seq); v.setUint32(28, ack);
    f[32] = 0x50; f[33] = flags; v.setUint16(34, 65535);
    if (pl) f.set(data, 40);
    pseudo[10] = tl >> 8; pseudo[11] = tl & 0xFF; pseudo.set(f.subarray(20, 20 + tl), 12);
    v.setUint16(36, cksum(pseudo, 0, 12 + tl));
    return f;
  };

  const match = (ip) => {
    if (ip.length < 40 || ip[9] !== 6) return null;
    const ihl = (ip[0] & 0xF) * 4;
    if (u16(ip, ihl) !== dstPort || u16(ip, ihl + 2) !== srcPort) return null;
    return { flags: ip[ihl + 13], seq: u32(ip, ihl + 4), off: ihl + ((ip[ihl + 12] >> 4) & 0xF) * 4, tcp: ihl };
  };

  let reader = null;
  const close = () => { try { reader?.cancel(); } catch { } try { tunnel.close?.(); } catch { } };

  const handshake = async () => {
    await tunnelW.write(frame(0x02)); seq++;
    const r = tunnel.readable.getReader(); reader = r;
    for (let i = 0; i < 40; i++) {
      const { value, done } = await r.read();
      if (done) throw new Error('TARGET_TCP_FAILED');
      const m = match(value);
      if (!m) continue;
      if ((m.flags & 0x12) === 0x12) { ack = (m.seq + 1) >>> 0; await tunnelW.write(frame(0x10)); return; }
    }
    throw new Error('TARGET_TCP_FAILED');
  };

  const acceptData = async (ctrl) => {
    try {
      let pend = [], pLen = 0;
      const flush = () => { if (!pLen) return; ctrl.enqueue(pend.length === 1 ? pend[0] : concat(...pend)); pend = []; pLen = 0; tunnelW.write(frame(0x10)).catch(() => { }); };
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        const m = match(value);
        if (!m) continue;
        if (m.off < value.length) {
          const d = value.subarray(m.off);
          if (d.length) { ack = (m.seq + d.length) >>> 0; pend.push(new Uint8Array(d)); pLen += d.length; }
        }
        if (m.flags & 0x01) { flush(); ack = (ack + 1) >>> 0; tunnelW.write(frame(0x11)).catch(() => { }); ctrl.close(); return; }
        if (pLen >= 32768) flush();
      }
      ctrl.close();
    } catch { try { ctrl.close(); } catch { } }
  };

  const run = async () => {
    await handshake();
    let ctrl = null;
    const readable = new ReadableStream({ start: c => { ctrl = c; }, cancel: () => tunnelW.write(frame(0x11)).catch(() => { }) });
    acceptData(ctrl);
    const writable = new WritableStream({
      async write(chunk) {
        const d = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
        if (d.length <= MSS) { await tunnelW.write(frame(0x18, d)); seq = (seq + d.length) >>> 0; return; }
        for (let o = 0; o < d.length; o += MSS) { const seg = d.subarray(o, Math.min(o + MSS, d.length)); await tunnelW.write(frame(0x18, seg)); seq = (seq + seg.length) >>> 0; }
      },
      close: () => tunnelW.write(frame(0x11)).catch(() => { }),
      abort: close,
    });
    return { readable, writable, close };
  };
  return run();
}
