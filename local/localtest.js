// Connect to the LOCAL VLESS->OpenVPN server over ws://127.0.0.1:PORT and send a
// VLESS request (IPv4 target) to prove the full path (UUID+parser+WS+OpenVPN+TCP).
import net from 'node:net';
import crypto from 'node:crypto';
import { uuidToBytes } from '../src/vless.js';

const PORT = +(process.argv[2] || 8080);
const UUID = '2523c510-9ff0-415b-9582-93949bfae7e3';
const id = uuidToBytes(UUID);

function buildVless(ip, port, payload) {
  const parts = [0]; for (const x of id) parts.push(x);
  parts.push(0, 1, port >> 8, port & 0xff, 1); // addon0,cmd1,port,type1=IPv4
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
let buf = Buffer.alloc(0), handshook = false, sent = false;
const payload = new TextEncoder().encode('GET / HTTP/1.0\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n');
const vless = buildVless('1.1.1.1', 80, payload);
socket.on('data', (d) => {
  buf = Buffer.concat([buf, d]);
  if (!handshook) {
    const i = buf.indexOf('\r\n\r\n');
    if (i < 0) return;
    const head = buf.slice(0, i).toString('latin1');
    console.log('=== WS handshake ===\n' + head.split('\r\n').slice(0, 5).join('\n'));
    if (!/ 101 /.test(head)) { console.log('HANDSHAKE FAILED'); process.exit(1); }
    handshook = true; buf = buf.slice(i + 4);
    console.log('=== sending VLESS (IPv4 1.1.1.1:80) len ' + vless.length + ' ===');
    socket.write(wsFrame(vless));
    sent = true;
  }
  // parse server frames
  while (handshook && buf.length >= 2) {
    const b0 = buf[0], b1 = buf[1];
    let len = b1 & 0x7F, off = 2;
    if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
    if (buf.length < off + len) return;
    const p = buf.subarray(off, off + len); buf = buf.subarray(off + len);
    const op = b0 & 0x0F;
    if (op === 8) { console.log('WS CLOSE'); process.exit(1); }
    if (op === 9) continue;
    console.log('WS frame op=' + op + ' len=' + len + ' text=' + (op === 1 ? p.toString() : p.toString('hex').slice(0, 60)));
    if (op === 1 || op === 2) {
      const t = p.toString(op === 1 ? 'utf8' : 'latin1');
      if (t.includes('HTTP/1.1') || t.includes('301') || t.length > 20) { console.log('=== VLESS WORKED ==='); console.log(t.slice(0, 300)); process.exit(0); }
    }
  }
});
socket.on('error', (e) => { console.log('ERR', e.message); process.exit(1); });
setTimeout(() => { console.log('TIMEOUT'); process.exit(1); }, 90000);