// Local echo test against the LOCAL server's /dbg-ws (no TLS/proxy). Confirms the
// probe logic + the echo endpoint work before we rely on them against Cloudflare.
import net from 'node:net';
import crypto from 'node:crypto';

const PORT = +(process.argv[2] || 8080);
const PATH = process.argv[3] || '/dbg-ws';
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
  socket.write('GET ' + PATH + ' HTTP/1.1\r\nHost: 127.0.0.1:' + PORT + '\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ' + key + '\r\nSec-WebSocket-Version: 13\r\n\r\n');
});
let buf = Buffer.alloc(0), handshook = false;
const payload = new TextEncoder().encode('ECHO-TEST-PAYLOAD-1234');
socket.on('data', (d) => {
  buf = Buffer.concat([buf, d]);
  if (!handshook) {
    const i = buf.indexOf('\r\n\r\n'); if (i < 0) return;
    const head = buf.slice(0, i).toString('latin1');
    console.log('=== WS handshake ===\n' + head.split('\r\n').slice(0, 4).join('\n'));
    if (!/ 101 /.test(head)) { console.log('HANDSHAKE FAILED'); process.exit(1); }
    handshook = true; buf = buf.slice(i + 4);
    console.log('=== send ' + payload.length + ' bytes to ' + PATH + ' ===');
    socket.write(wsFrame(payload));
  }
  while (handshook && buf.length >= 2) {
    const b0 = buf[0], b1 = buf[1];
    let len = b1 & 0x7F, off = 2;
    if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
    if (buf.length < off + len) return;
    const p = buf.subarray(off, off + len); buf = buf.subarray(off + len);
    const op = b0 & 0x0F;
    const txt = p.toString('utf8');
    console.log('frame op=' + op + ' len=' + len + ' text=' + txt);
    if (txt.startsWith('DBG_HELLO')) console.log('=== GREETING OK (outbound pipe) ===');
    if (txt.startsWith('DBG_ECHO:22:')) { console.log('=== ECHO OK (inbound+outbound) ==='); process.exit(0); }
    const p2 = p; void p2;
  }
});
socket.on('error', (e) => { console.log('ERR ' + e.message); process.exit(1); });
setTimeout(() => { console.log('TIMEOUT'); process.exit(1); }, 15000);
