// Unit tests for the user-space TcpFlow stack: byte-stream reassembly, out-of-order
// reordering, duplicate suppression, retransmission, FIN and RST, and checksum
// rejection. Builds synthetic IPv4/TCP segments and feeds them to TcpFlow.onSegment.
import { TcpFlow, MSS, getMux, createTcp } from '../src/tcp.js';

let fail = 0;
const ok = (name, cond) => { if (!cond) { fail++; console.log('FAIL', name); } else console.log('ok', name); };

// ---- segment builder (peer -> client) ----
let nextId = 0x1111;
function foldSum(d, o, n) { let s = 0; for (let i = o; i < o + n - 1; i += 2) s += (d[i] << 8 | d[i + 1]); if (n & 1) s += d[o + n - 1] << 8; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); return s & 0xFFFF; }
const cksum = (d, o, n) => (~foldSum(d, o, n)) & 0xFFFF;
function w16(b, o, v) { b[o] = v >> 8 & 0xFF; b[o + 1] = v & 0xFF; }
function w32(b, o, v) { b[o] = v >>> 24 & 0xFF; b[o + 1] = v >>> 16 & 0xFF; b[o + 2] = v >>> 8 & 0xFF; b[o + 3] = v & 0xFF; }
function ipB(ip) { return Uint8Array.from(ip.split('.').map(Number)); }
function makeSeg({ srcIp = '10.8.0.1', dstIp = '10.8.0.2', sport = 80, dport, seq, ack = 0, flags = 0x18, payload = new Uint8Array(0), mss = false, badCksum = false }) {
  const opts = mss ? Uint8Array.from([2, 4, MSS >> 8, MSS & 0xFF]) : null;
  const tcpHdr = 20 + (opts ? opts.length : 0);
  const tl = tcpHdr + payload.length, il = 20 + tl;
  const f = new Uint8Array(il);
  f[0] = 0x45; w16(f, 2, il); w16(f, 4, nextId++); f[8] = 64; f[9] = 6;
  f.set(ipB(srcIp), 12); f.set(ipB(dstIp), 16);
  w16(f, 10, cksum(f, 0, 20));
  w16(f, 20, sport); w16(f, 22, dport); w32(f, 24, seq >>> 0); w32(f, 28, ack >>> 0);
  f[32] = (tcpHdr >> 2) << 4; f[33] = flags; w16(f, 34, 65535);
  if (opts) f.set(opts, 40);
  if (payload.length) f.set(payload, 20 + tcpHdr);
  const pseudo = new Uint8Array(12 + tl);
  pseudo.set(ipB(srcIp), 0); pseudo.set(ipB(dstIp), 4); pseudo[9] = 6; w16(pseudo, 10, tl);
  pseudo.set(f.subarray(20, 20 + tl), 12);
  w16(f, 36, cksum(pseudo, 0, 12 + tl));
  if (badCksum) f[36] ^= 0xFF;
  return f;
}

function mkFlow() {
  const out = [];
  // A flow no longer owns the tunnel: it talks to a multiplexer that owns the
  // single tunnel reader/writer and routes inbound packets by local port.
  const tunnel = { writable: null, readable: null, close: () => {} };
  const mux = {
    tunnel,
    allocPort: () => 10000 + Math.floor(Math.random() * 50000),
    send: (pkt) => { out.push(pkt); },
    addFlow: () => {},
    removeFlow: () => {},
  };
  const flow = new TcpFlow(mux, '10.8.0.2', '10.8.0.1', 80);
  return { flow, out };
}

const delivered = (flow, arr) => { flow.deliver = (d) => arr.push(Buffer.from(d)); flow.onShutdown = () => { }; };

(async () => {
  // (1) handshake + in-order data + FIN
  {
    const { flow, out } = mkFlow();
    const app = []; delivered(flow, app);
    flow.state = 'SYN_SENT';
    const iss = flow.iss, cport = flow.srcPort;
    flow._emit(0x02, new Uint8Array(0), iss, 0); // SYN
    flow._track(iss, (iss + 1) >>> 0, new Uint8Array(0), 0x02);
    flow.sndNxt = (iss + 1) >>> 0;
    const peer = { s: 0xAABBCC00 >>> 0 };
    // SYN-ACK
    flow.onSegment(makeSeg({ dport: cport, seq: peer.s, ack: (iss + 1) >>> 0, flags: 0x12 }));
    await flow.established();
    ok('handshake ESTABLISHED', flow.state === 'ESTABLISHED');
    // data: 'ABC' at seq rcvNxt
    const data = Uint8Array.from([0x41, 0x42, 0x43]);
    flow.onSegment(makeSeg({ dport: cport, seq: (peer.s + 1) >>> 0, ack: (iss + 1) >>> 0, flags: 0x18, payload: data }));
    ok('in-order data delivered', Buffer.concat(app).toString() === 'ABC');
    // FIN
    flow.onSegment(makeSeg({ dport: cport, seq: (peer.s + 1 + 3) >>> 0, ack: (iss + 1) >>> 0, flags: 0x11 }));
    ok('FIN => CLOSE_WAIT', flow.state === 'CLOSE_WAIT');
  }

  // (2) out-of-order reordering: feed #3, #1, #2 -> delivered 1,2,3
  {
    const { flow } = mkFlow();
    const app = []; delivered(flow, app);
    flow.state = 'ESTABLISHED';
    const base = 0x11000000 >>> 0; const cport = flow.srcPort;
    flow.rcvNxt = base;
    const mkData = (n, b) => makeSeg({ dport: cport, seq: (base + n * 4) >>> 0, ack: 0, flags: 0x18, payload: Uint8Array.from([b, b + 1, b + 2, b + 3]) });
    flow.onSegment(mkData(2, 0x30)); // #3, missing 1&2
    ok('out-of-order: nothing before gap filled', app.length === 0);
    flow.onSegment(mkData(0, 0x10)); // #1
    ok('out-of-order: only #1 so far', Buffer.concat(app).toString() === '\x10\x11\x12\x13');
    flow.onSegment(mkData(1, 0x20)); // #2 -> drains #1,#2,#3
    ok('out-of-order reassembled in order', Buffer.concat(app).toString() === '\x10\x11\x12\x13\x20\x21\x22\x23\x30\x31\x32\x33');
  }

  // (3) duplicate suppression
  {
    const { flow } = mkFlow();
    const app = []; delivered(flow, app);
    flow.state = 'ESTABLISHED';
    const base = 0x22000000 >>> 0, cport = flow.srcPort;
    flow.rcvNxt = base;
    const d = makeSeg({ dport: cport, seq: base, ack: 0, flags: 0x18, payload: Uint8Array.from([7, 8]) });
    flow.onSegment(d);
    flow.onSegment(d); // duplicate
    const got = Buffer.concat(app);
    ok('duplicate suppressed', got.length === 2 && got[0] === 7 && got[1] === 8);
  }

  // (4) retransmission on timeout
  {
    const { flow, out } = mkFlow();
    const app = []; delivered(flow, app);
    flow.state = 'ESTABLISHED';
    const base = 0x33000000 >>> 0, cport = flow.srcPort;
    // establish some state
    const d = makeSeg({ dport: cport, seq: base, ack: 0, flags: 0x18, payload: Uint8Array.from([1, 2, 3]) });
    flow.onSegment(d);
    // app writes data -> queued unacked
    await flow.write(Uint8Array.from([9, 9, 9]));
    const before = out.length;
    // force overdue
    const seg = flow.unacked[0];
    seg.sentAt = seg.sentAt - 2000;
    flow.tick();
    ok('retransmitted (more packets emitted)', out.length > before);
    ok('retries incremented', flow.unacked[0].retries === 1);
  }

  // (5) RST terminates flow
  {
    const { flow } = mkFlow();
    const app = []; delivered(flow, app);
    flow.state = 'ESTABLISHED';
    const cport = flow.srcPort;
    let closed = false; flow.onShutdown = () => { closed = true; };
    flow.onSegment(makeSeg({ dport: cport, seq: 0x44000000 >>> 0, ack: 0, flags: 0x04 }));
    ok('RST closed the flow', flow._closed === true);
  }

  // (6) invalid checksum segment dropped
  {
    const { flow } = mkFlow();
    const app = []; delivered(flow, app);
    flow.state = 'ESTABLISHED';
    const cport = flow.srcPort;
    flow.onSegment(makeSeg({ dport: cport, seq: 0x55000000 >>> 0, flags: 0x18, payload: Uint8Array.from([1, 2]), badCksum: true }));
    ok('bad-checksum segment ignored', Buffer.concat(app).length === 0);
  }

  // (7) overlap: rcvNxt=1500, segment 1400-1800 -> only 1500-1800 delivered
  {
    const { flow } = mkFlow();
    const app = []; delivered(flow, app);
    flow.state = 'ESTABLISHED';
    const cport = flow.srcPort;
    const rcvNxt = 1500;
    flow.rcvNxt = rcvNxt;
    const payload = new Uint8Array(400).map((_, i) => i & 0xFF);
    flow.onSegment(makeSeg({ dport: cport, seq: 1400, ack: 0, flags: 0x18, payload }));
    const got = Buffer.concat(app);
    ok('overlap delivers only [1500..1800]', got.length === 300 && got[0] === payload[100]);
    ok('rcvNxt advanced to 1800', flow.rcvNxt === 1800);
  }

  // (8) multiplexer: TWO TCP flows share ONE tunnel, routed by local port.
  // This is what removes the per-connection OpenVPN handshake (the "-1" cause).
  {
    const sent = [];
    let feedCtrl = null, tunnelClosed = false;
    const readable = new ReadableStream({ start: (c) => { feedCtrl = c; } });
    const writable = new WritableStream({ write: (c) => { sent.push(c); } });
    const tunnel = { readable, writable, close: () => { tunnelClosed = true; } };
    const mux = getMux(tunnel);
    const feed = (pkt) => feedCtrl.enqueue(pkt);
    const tick = () => new Promise((r) => setTimeout(r, 5));
    const rd32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;

    const p1 = createTcp(mux, '10.8.0.2', '10.8.0.1', 80);
    await tick();                       // WritableStream.write is dispatched async
    const syn1 = sent[0];
    const port1 = (syn1[20] << 8) | syn1[21], iss1 = rd32(syn1, 24);
    const p2 = createTcp(mux, '10.8.0.2', '10.8.0.1', 443);
    await tick();
    const syn2 = sent[1];
    const port2 = (syn2[20] << 8) | syn2[21], iss2 = rd32(syn2, 24);
    ok('two flows over one tunnel get distinct local ports', port1 !== port2 && sent.length === 2);

    const peer1 = 0xAABB0000 >>> 0, peer2 = 0xCCDD0000 >>> 0;
    feed(makeSeg({ dport: port1, seq: peer1, ack: (iss1 + 1) >>> 0, flags: 0x12 }));
    feed(makeSeg({ dport: port2, seq: peer2, ack: (iss2 + 1) >>> 0, flags: 0x12 }));
    await tick();
    await p1; await p2;
    ok('both flows established through the single tunnel', mux.flows.size === 2);

    const fo1 = mux.flows.get(port1), fo2 = mux.flows.get(port2);
    const before1 = fo1.rcvNxt, before2 = fo2.rcvNxt;
    feed(makeSeg({ dport: port2, seq: (peer2 + 1) >>> 0, ack: (iss2 + 1) >>> 0, flags: 0x18, payload: Uint8Array.from([0x41, 0x42]) }));
    await tick();
    ok('segment routed to the owning flow only', fo2.rcvNxt === ((before2 + 2) >>> 0) && fo1.rcvNxt === before1);

    fo1._shutdown(true);
    ok('closing one flow leaves the shared tunnel up', mux.alive && !tunnelClosed && mux.flows.size === 1);

    mux.close();
    let code = '';
    try { await createTcp(mux, '10.8.0.2', '10.8.0.1', 80); } catch (e) { code = e.code; }
    ok('a closed tunnel rejects new flows (TUNNEL_CLOSED)', code === 'TUNNEL_CLOSED');
  }

  console.log(fail ? ('\n' + fail + ' failures') : '\nALL TCP PASS');
  process.exit(fail ? 1 : 0);
})();
