// local/vlesstls.mjs — REAL TLS handshake over VLESS+WS+OpenVPN, the exact path
// a real client (v2rayN/Xray latency test) uses: target port 443 + TLS.
//
//   node local/vlesstls.mjs [workerHost] [sni] [targetPort]
//
// It wraps the WebSocket in a Duplex and hands that to node:tls, so the
// ClientHello/ServerHello are genuine — if this succeeds, HTTPS through the
// tunnel works and any remaining "-1" is client-side config.
import tls from 'node:tls';
import net from 'node:net';
import crypto from 'node:crypto';
import { Duplex } from 'node:stream';

const host = process.argv[2] || 'test33333.wang.dpdns.org';
const sni = process.argv[3] || 'www.gstatic.com';
const dport = +(process.argv[4] || 443);
const UUID = '2523c510-9ff0-415b-9582-93949bfae7e3';
const t0 = Date.now();
const el = () => `+${Date.now() - t0}ms`;
const HARD = +(process.env.PROBE_MS || 40000);

function vlessHeader(hostname, port) {
  const h = UUID.replace(/-/g, '');
  const name = Buffer.from(hostname, 'utf8');
  const p = Buffer.alloc(23 + name.length);
  p[0] = 0;                                   // version
  for (let i = 0; i < 16; i++) p[1 + i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  p[17] = 0;                                  // optLen
  p[18] = 1;                                  // cmd = tcp
  p.writeUInt16BE(port, 19);
  p[21] = 2;                                  // addrType = domain
  p[22] = name.length;
  name.copy(p, 23);
  return p;
}

function frame(opcode, payload) {
  const p = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const mask = crypto.randomBytes(4);
  let head;
  if (p.length < 126) head = Buffer.from([0x80 | opcode, 0x80 | p.length]);
  else if (p.length < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | opcode; head[1] = 0x80 | 126; head.writeUInt16BE(p.length, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x80 | opcode; head[1] = 0x80 | 127; head.writeBigUInt64BE(BigInt(p.length), 2); }
  const masked = Buffer.alloc(p.length);
  for (let i = 0; i < p.length; i++) masked[i] = p[i] ^ mask[i % 4];
  return Buffer.concat([head, mask, masked]);
}

const sock = tls.connect({ host, port: 443, servername: host }, () => {
  const key = crypto.randomBytes(16).toString('base64');
  sock.write([
    'GET / HTTP/1.1', `Host: ${host}`, 'Upgrade: websocket', 'Connection: Upgrade',
    `Sec-WebSocket-Key: ${key}`, 'Sec-WebSocket-Version: 13', '', '',
  ].join('\r\n'));
});
sock.setNoDelay(true);

const hdr = vlessHeader(sni, dport);
let sentHeader = false, handshakeDone = false, incomplete = Buffer.alloc(0), wsBuf = Buffer.alloc(0);
let remoteBytes = 0, streamHead = Buffer.alloc(0), dumped = false, vlessHdrSeen = false;

const up = new Duplex({
  read() { },
  write(chunk, enc, cb) {
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, enc);
    if (!sentHeader) { sentHeader = true; console.log(`=== ${el()} first write ${b.length}B -> prepend VLESS header (${hdr.length}B) for ${sni}:${dport} [domain type=2]`); sock.write(frame(2, Buffer.concat([hdr, b]))); }
    else { console.log(`=== ${el()} write ${b.length}B -> VLESS frame`); sock.write(frame(2, b)); }
    cb();
  },
  final(cb) { try { sock.write(frame(8, Buffer.alloc(0))); } catch { } cb(); },
});

sock.on('data', (chunk) => {
  wsBuf = Buffer.concat([wsBuf, chunk]);
  if (!handshakeDone) {
    const i = wsBuf.indexOf('\r\n\r\n');
    if (i < 0) return;
    const head = wsBuf.subarray(0, i).toString('latin1');
    wsBuf = wsBuf.subarray(i + 4);
    handshakeDone = true;
    console.log(`=== ${el()} WS 101 ok, extensions accepted: ${(head.match(/sec-websocket-extensions:.*/i) || ['none'])[0]}`);
    startTls();
  }
  for (;;) {
    if (wsBuf.length < 2) return;
    const b0 = wsBuf[0], b1 = wsBuf[1];
    const op = b0 & 0x0f;
    let len = b1 & 0x7f, off = 2;
    if (len === 126) { if (wsBuf.length < 4) return; len = wsBuf.readUInt16BE(2); off = 4; }
    else if (len === 127) { if (wsBuf.length < 10) return; len = Number(wsBuf.readBigUInt64BE(2)); off = 10; }
    if (b1 & 0x80) off += 4;
    if (wsBuf.length < off + len) return;
    const payload = wsBuf.subarray(off, off + len);
    wsBuf = wsBuf.subarray(off + len);
    if (op === 8) { console.log(`=== ${el()} WS close frame`); up.push(null); return; }
    if (op !== 2 && op !== 1 && op !== 0) continue;
    let body = payload;
    if (!vlessHdrSeen) {
      // The Worker prepends the VLESS response header [version][addonsLen] to the
      // FIRST remote frame (possibly inside a later frame if earlier ones were
      // control frames) — strip it before handing bytes to TLS.
      vlessHdrSeen = true;
      if (body.length < 2) continue;
      console.log(`=== ${el()} VLESS response header = ${body.subarray(0, 2).toString('hex')} (expect 0000)`);
      body = body.subarray(2);
      if (!body.length) continue;
    }
    remoteBytes += body.length;
    if (streamHead.length < 400) streamHead = Buffer.concat([streamHead, body.subarray(0, 400 - streamHead.length)]);
    console.log(`=== ${el()} remote ${body.length}B (total ${remoteBytes}) first8=${body.subarray(0, 8).toString('hex')}`);
    if (remoteBytes >= 200 && !dumped) {
      dumped = true;
      const printable = streamHead.toString('latin1').replace(/[^\x20-\x7e]/g, '.');
      console.log(`\n--- STREAM HEAD (${streamHead.length}B) bytes[0]=0x${streamHead[0].toString(16)} firstRecordByte=${streamHead[0] === 0x16 ? 'TLS_HANDSHAKE' : 'NOT_TLS'}`);
      console.log(`--- hex  : ${streamHead.subarray(0, 96).toString('hex')}`);
      console.log(`--- latin: ${printable.slice(0, 96)}\n`);
    }
    up.push(body);
  }
});
sock.on('error', (e) => { console.log(`!! ${el()} WS ERROR ${e.code || ''} ${e.message}`); process.exit(2); });

let tlsSock = null;
function startTls() {
  tlsSock = tls.connect({ socket: up, servername: sni, rejectUnauthorized: false }, () => {
    const c = tlsSock.getPeerCertificate() || {};
    console.log(`\n*** ${el()} TLS HANDSHAKE OK  proto=${tlsSock.getProtocol()} authorized=${tlsSock.authorized}`);
    console.log(`*** cert subject=${JSON.stringify(c.subject)} issuer=${JSON.stringify(c.issuer)} valid_to=${c.valid_to}`);
    tlsSock.write(`GET /generate_204 HTTP/1.1\r\nHost: ${sni}\r\nUser-Agent: probe\r\nConnection: close\r\n\r\n`);
  });
  tlsSock.on('data', (d) => {
    const s = d.toString('latin1');
    console.log(`*** ${el()} HTTPS RESPONSE (${d.length}B):\n${s.slice(0, 300).replace(/\r\n/g, ' | ')}`);
    if (/HTTP\/1\.[01] (200|204)/.test(s)) { console.log(`\n=== HTTPS THROUGH TUNNEL OK (${el()}) ===`); process.exit(0); }
  });
  tlsSock.on('error', (e) => { console.log(`!! ${el()} TLS ERROR ${e.code || ''} ${e.message}`); process.exit(3); });
  tlsSock.on('close', () => { console.log(`--- ${el()} TLS closed, remoteBytes=${remoteBytes}`); process.exit(remoteBytes > 0 ? 0 : 3); });
}

setTimeout(() => { console.log(`TIMEOUT after ${HARD}ms (handshakeDone=${handshakeDone} remoteBytes=${remoteBytes})`); process.exit(4); }, HARD);
