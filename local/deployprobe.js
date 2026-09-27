// Probe the DEPLOYED worker over wss://test33333.wang.dpdns.org/ through the
// local CONNECT proxy, sending a real VLESS handshake (IPv4 1.1.1.1:80).
// Mirrors what a v2rayN VLESS+WS client does, so we see the server's response.
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { uuidToBytes } from '../src/vless.js';

const HOST = 'test33333.wang.dpdns.org';
const PORT = 443;
const UUID = '00000000-0000-0000-0000-000000000000'; // WRONG UUID on purpose
const PROXY = { host: '127.0.0.1', port: 10808 };
const id = uuidToBytes(UUID);

function buildVless(ip, port, payload) {
  const parts = [0]; for (const x of id) parts.push(x);
  parts.push(0, 1, port >> 8, port & 0xff, 1); // addon0,cmd1 TCP,port,type1=IPv4
  for (const x of ip.split('.').map(Number)) parts.push(x);
  for (const x of payload) parts.push(x);
  return Uint8Array.from(parts);
}
function wsFrame(payload) {
  const mask = crypto.randomBytes(4); const len = payload.length;
  let hdr; if (len < 126) hdr = [0x82, 0x80 | len];
  else if (len < 65536) hdr = [0x82, 0x80 | 126, len >> 8, len & 0xFF];
  else hdr = [0x82, 0x80 | 127, 0, 0, 0, 0, len >> 24 & 0xff, len >> 16 & 0xff, len >> 8 & 0xff, len & 0xff];
  const out = Buffer.alloc(hdr.length + 4 + len);
  out.set(hdr, 0); out.set(mask, hdr.length);
  for (let i = 0; i < len; i++) out[hdr.length + 4 + i] = payload[i] ^ mask[i & 3];
  return out;
}

console.log('CONNECT proxy ' + PROXY.host + ':' + PROXY.port + ' -> ' + HOST + ':' + PORT);
const tunnel = net.connect(PROXY.port, PROXY.host);
let excess = Buffer.alloc(0);

tunnel.once('connect', () => {
  tunnel.write('CONNECT ' + HOST + ':' + PORT + ' HTTP/1.1\r\nHost: ' + HOST + ':' + PORT + '\r\n\r\n');
});
// readable-mode pump (paused socket, same proven pattern as local/server.js):
// consume the proxy CONNECT response, then hand the socket to TLS.
let proxyBuf = Buffer.alloc(0);
const pump = () => {
  for (;;) {
    const c = tunnel.read(); if (c === null) return;
    proxyBuf = Buffer.concat([proxyBuf, c]);
    const i = proxyBuf.indexOf('\r\n\r\n');
    if (i >= 0) {
      const head = proxyBuf.slice(0, i).toString('latin1');
      console.log('PROXY: ' + head.split('\r\n')[0]);
      if (!/ 200 /.test(head)) { console.log('PROXY CONNECT FAILED'); process.exit(1); }
      excess = proxyBuf.slice(i + 4);
      tunnel.removeListener('readable', pump);
      startTls();
      return;
    }
  }
};
tunnel.on('readable', pump);
tunnel.on('error', (e) => { console.log('PROXY ERR ' + e.message); process.exit(1); });

function startTls() {
  const tlsSocket = tls.connect({ socket: tunnel, servername: HOST, ALPNProtocols: ['http/1.1'] });
  tlsSocket.on('secureConnect', () => {
    console.log('TLS secured, protocol=' + tlsSocket.getProtocol());
    if (excess.length) tlsSocket.write(excess);
    const key = crypto.randomBytes(16).toString('base64');
    tlsSocket.write('GET / HTTP/1.1\r\nHost: ' + HOST + '\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ' + key + '\r\nSec-WebSocket-Version: 13\r\n\r\n');
  });
  let buf = Buffer.alloc(0), handshook = false;
  tlsSocket.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    if (!handshook) {
      const i = buf.indexOf('\r\n\r\n');
      if (i < 0) return;
      const head = buf.slice(0, i).toString('latin1');
      console.log('=== WS handshake ===\n' + head.split('\r\n').slice(0, 6).join('\n'));
      if (!/ 101 /.test(head)) { console.log('HANDSHAKE FAILED'); process.exit(1); }
      handshook = true; buf = buf.slice(i + 4);
      const payload = new TextEncoder().encode('GET / HTTP/1.0\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n');
      const vless = buildVless('1.1.1.1', 80, payload);
      console.log('=== sending VLESS (IPv4 1.1.1.1:80) len ' + vless.length + ' ===');
      tlsSocket.write(wsFrame(vless));
    }
    while (handshook && buf.length >= 2) {
      const b0 = buf[0], b1 = buf[1];
      let len = b1 & 0x7F, off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      if (buf.length < off + len) return;
      const p = buf.subarray(off, off + len); buf = buf.subarray(off + len);
      const op = b0 & 0x0F;
      if (op === 8) { console.log('WS CLOSE (len=' + p.length + ' reason=' + p.toString('utf8').slice(0, 80) + ')'); process.exit(1); }
      if (op === 9) continue;
      console.log('WS frame op=' + op + ' len=' + len + ' text=' + (op === 1 ? p.toString() : p.toString('hex').slice(0, 60)));
      if (op === 1 || op === 2) {
        const t = p.toString(op === 1 ? 'utf8' : 'latin1');
        if (/HTTP\/1\.[01]/.test(t) || t.includes('301') || t.length > 20) { console.log('=== VLESS WORKED on DEPLOYED worker ==='); console.log(t.slice(0, 300)); process.exit(0); }
      }
    }
  });
  tlsSocket.on('error', (e) => { console.log('TLS ERR ' + e.message); process.exit(1); });
  tlsSocket.on('close', () => { console.log('(server closed TLS)'); process.exit(1); });
}

setTimeout(() => { console.log('TIMEOUT'); process.exit(1); }, 60000);
