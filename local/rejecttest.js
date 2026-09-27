// Local reject test: send a VLESS request with a WRONG uuid to the local server's
// "/" and confirm the handler replies with a VLESS_REJECT text frame + close.
// Proves the handleWs reject path works; if CF stays silent, it is a deploy /
// message-delivery problem, not this code.
import net from 'node:net';
import crypto from 'node:crypto';
import { uuidToBytes } from '../src/vless.js';

const PORT = +(process.argv[2] || 8080);
const UUID = process.argv[3] || '00000000-0000-0000-0000-000000000000';
const id = uuidToBytes(UUID);
function buildVless(ip, port, payload) {
  const parts = [0]; for (const x of id) parts.push(x);
  parts.push(0, 1, port >> 8, port & 0xff, 1);
  for (const x of ip.split('.').map(Number)) parts.push(x);
  for (const x of payload) parts.push(x);
  return Uint8Array.from(parts);
}
function wsFrame(payload) {
  const mask = crypto.randomBytes(4); const len = payload.length;
  let hdr; if (len < 126) hdr = [0x82, 0x80 | len];
  else hdr = [0x82, 0x80 | 126, len >> 8, len & 0xFF];
  const out = Buffer.alloc(hdr.length + 4 + len);
  out.set(hdr, 0); out.set(mask, hdr.length);
  for (let i = 0; i < len; i++) out[hdr.length + 4 + i] = payload[i] ^ mask[i & 3];
  return out;
}
const socket = net.connect(PORT, '127.0.0.1');
socket.once('connect', () => {
  const key = crypto.randomBytes(16).toString('base64');
  socket.write('GET / HTTP/1.1\r\nHost: 127.0.0.1:' + PORT + '\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ' + key + '\r\nSec-WebSocket-Version: 13\r\n\r\n');
});
let buf = Buffer.alloc(0), handshook = false;
const payload = new TextEncoder().encode('GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n');
const vless = buildVless('1.1.1.1', 80, payload);
socket.on('data', (d) => {
  buf = Buffer.concat([buf, d]);
  if (!handshook) {
    const i = buf.indexOf('\r\n\r\n'); if (i < 0) return;
    const head = buf.slice(0, i).toString('latin1');
    console.log('WS: ' + head.split('\r\n')[0]);
    if (!/ 101 /.test(head)) { console.log('HANDSHAKE FAILED'); process.exit(1); }
    handshook = true; buf = buf.slice(i + 4);
    console.log('send VLESS with uuid=' + UUID);
    socket.write(wsFrame(vless));
  }
  while (handshook && buf.length >= 2) {
    const b0 = buf[0], b1 = buf[1];
    let len = b1 & 0x7F, off = 2;
    if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
    if (buf.length < off + len) return;
    const p = buf.subarray(off, off + len); buf = buf.subarray(off + len);
    const op = b0 & 0x0F;
    if (op === 8) { console.log('=== WS CLOSE (as expected) ==='); process.exit(0); }
    if (op === 9) continue;
    console.log('frame op=' + op + ' text=' + (op === 1 ? p.toString() : p.toString('hex').slice(0, 40)));
    if (op === 1 && p.toString() === 'VLESS_REJECT') console.log('=== VLESS_REJECT RECEIVED (expected) ===');
  }
});
socket.on('error', (e) => { console.log('ERR ' + e.message); process.exit(1); });
setTimeout(() => { console.log('TIMEOUT (handler never replied)'); process.exit(1); }, 15000);
