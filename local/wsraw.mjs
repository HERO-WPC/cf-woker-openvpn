// local/wsraw.mjs — raw WebSocket client over node:tls. No dependencies, and
// crucially NO Sec-WebSocket-Extensions, so permessage-deflate is never
// negotiated and every frame arrives byte-for-byte as the Worker sent it.
//
//   node local/wsraw.mjs <host> [path] [text|vless] [earlyDataB64]
//
// text  : send "ping", print every frame (tests both directions, keeps RSV1 visible)
// vless : send a real VLESS header+payload for 1.1.1.1:80 and print the tunnel reply
import tls from 'node:tls';
import net from 'node:net';
import crypto from 'node:crypto';

// Accepts either a full URL (ws://127.0.0.1:8788/ or wss://host/path) or a bare host.
const target = process.argv[2] || '';
const a3 = process.argv[3] || '';
const a4 = process.argv[4] || '';
const isMode = (s) => ['text', 'vless', 'hs', 'early'].includes(String(s).toLowerCase());
const mode = (isMode(a3) ? a3 : a4 || 'text').toLowerCase();
const pathArg = isMode(a3) ? a4 : a3;
const earlyB64 = process.argv[5] || '';
let host, port, wpath, useTls;
if (target.includes('://')) {
  const u = new URL(target);
  useTls = u.protocol === 'wss:';
  host = u.hostname;
  port = +(u.port || (useTls ? 443 : 80));
  wpath = pathArg && pathArg.startsWith('/') ? pathArg : (u.pathname || '/');
} else {
  host = target; port = 443; useTls = true; wpath = pathArg || '/dbg-ws';
}
if (!host) { console.log('usage: node local/wsraw.mjs <ws-url|host> [path] [text|vless|hs] [earlyDataB64]'); process.exit(1); }
const hostHeader = (port === 443 || port === 80) ? host : `${host}:${port}`;

const UUID = '2523c510-9ff0-415b-9582-93949bfae7e3';
const t0 = Date.now();
const el = () => `+${Date.now() - t0}ms`;

function vlessPacket() {
  const h = UUID.replace(/-/g, '');
  const pay = Buffer.from('GET / HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n');
  const p = Buffer.alloc(26 + pay.length);
  p[0] = 0;
  for (let i = 0; i < 16; i++) p[1 + i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  p[17] = 0; p[18] = 1; p[19] = 0; p[20] = 80; p[21] = 1;
  p[22] = 1; p[23] = 1; p[24] = 1; p[25] = 1;
  pay.copy(p, 26);
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

const onConnect = () => {
  const key = crypto.randomBytes(16).toString('base64');
  const lines = [
    `GET ${wpath} HTTP/1.1`,
    `Host: ${hostHeader}`,
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Key: ${key}`,
    'Sec-WebSocket-Version: 13',
  ];
  if (earlyB64) lines.push(`Sec-WebSocket-Protocol: ${earlyB64}`);
  lines.push('', '');
  const req = lines.join('\r\n');
  console.log(`=== REQUEST (${el()}) -> ${useTls ? 'wss' : 'ws'}://${hostHeader}${wpath} ===\n${req}`);
  sock.write(req);
};
// No Sec-WebSocket-Extensions on purpose: nothing may negotiate
// permessage-deflate, so frames stay byte-for-byte.
const sock = useTls ? tls.connect({ host, port, servername: host }, onConnect) : net.connect({ host, port }, onConnect);
sock.setNoDelay(true);

let handshakeDone = false;
let buf = Buffer.alloc(0);
let dataFrames = 0;
let sawNonEmpty = false;

const finish = (code) => { const c = code; try { sock.destroy(); } catch { } console.log(`--- ${el()} exit=${c} dataFrames=${dataFrames} sawNonEmpty=${sawNonEmpty}`); process.exit(c); };
const hardTimer = setTimeout(() => { console.log('TIMEOUT: no data'); finish(3); }, +(process.env.PROBE_MS || 22000));

sock.on('data', (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  if (!handshakeDone) {
    const i = buf.indexOf('\r\n\r\n');
    if (i < 0) return;
    const head = buf.subarray(0, i).toString('latin1');
    buf = buf.subarray(i + 4);
    handshakeDone = true;
    console.log(`\n=== RESPONSE HEADERS (${el()}) ===\n${head}`);
    const status = head.split('\r\n')[0];
    if (!/101/.test(status)) { console.log('not a 101 -> abort'); clearTimeout(hardTimer); finish(2); return; }
    // second, optional: check the accepted subprotocol / extensions the edge added
    setTimeout(() => {
      if (mode === 'vless') { console.log(`\n=== SEND vless frame (${el()}) 67B -> 1.1.1.1:80`); sock.write(frame(2, vlessPacket())); }
      else if (mode === 'text') { console.log(`\n=== SEND text ping (${el()})`); sock.write(frame(1, 'ping')); }
      else console.log(`\n(${mode} mode: sending nothing, waiting for the backend)`);
    }, 250);
  }
  // parse frames
  for (;;) {
    if (buf.length < 2) return;
    const b0 = buf[0], b1 = buf[1];
    const fin = (b0 & 0x80) >> 7, rsv1 = (b0 & 0x40) >> 6, op = b0 & 0x0f;
    const masked = (b1 & 0x80) >> 7;
    let len = b1 & 0x7f, off = 2;
    if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
    else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
    let maskKey = null;
    if (masked) { if (buf.length < off + 4) return; maskKey = buf.subarray(off, off + 4); off += 4; }
    if (buf.length < off + len) return;
    let payload = Buffer.from(buf.subarray(off, off + len));
    if (maskKey) for (let i = 0; i < payload.length; i++) payload[i] ^= maskKey[i % 4];
    buf = buf.subarray(off + len);
    dataFrames++;
    if (payload.length) sawNonEmpty = true;
    const printable = payload.toString('latin1').replace(/[^\x20-\x7e]/g, '.');
    console.log(`FRAME ${el()} fin=${fin} rsv1=${rsv1} op=${op} len=${payload.length} hex=${payload.subarray(0, 24).toString('hex')}`);
    console.log(`      latin1="${printable.slice(0, 200)}"`);
    if (op === 8) { console.log('  -> close frame'); clearTimeout(hardTimer); finish(sawNonEmpty ? 0 : 3); return; }
    if (mode === 'vless' && payload.length > 2) { clearTimeout(hardTimer); setTimeout(() => finish(0), 300); return; }
    if (mode === 'early' && payload.length > 2) { clearTimeout(hardTimer); setTimeout(() => finish(0), 300); return; }
  }
});

sock.on('error', (e) => { console.log(`SOCKET ERROR ${el()} ${e.code || ''} ${e.message}`); clearTimeout(hardTimer); finish(2); });
sock.on('close', () => { if (!handshakeDone) { console.log(`SOCKET CLOSED before handshake ${el()}`); clearTimeout(hardTimer); finish(2); } });
