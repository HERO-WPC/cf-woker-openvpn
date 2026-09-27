// Local runner for the VLESS->OpenVPN worker, so you can connect with a VLESS
// client on 127.0.0.1 without Cloudflare. Pure Node: an HTTP server for
// /ovpn-test + /sock-test and a minimal RFC6455 WebSocket server for the VLESS
// entry. `connect` uses node:net directly (or the local proxy when OVPN_PROXY=1).
// Usage: node local/server.js [port]   (default 8080)
import http from 'node:http';
import net from 'node:net';
import { Readable, Writable, PassThrough } from 'node:stream';
import crypto from 'node:crypto';
import { route } from '../src/handler.js';

const PORT = +(process.argv[2] || 8080);
const USE_PROXY = !!process.env.OVPN_PROXY;

// ---- cloudflare:sockets connect() shim ----
function connect({ hostname, port }) {
  if (USE_PROXY) {
    // tunnel through the local HTTP CONNECT proxy (accelerated access)
    const socket = net.connect(10808, '127.0.0.1');
    const pass = new PassThrough();
    socket.pause();
    let bridging = false;
    const opened = new Promise((res, rej) => {
      socket.once('connect', () => socket.write(`CONNECT ${hostname}:${port} HTTP/1.1\r\nHost: ${hostname}:${port}\r\n\r\n`));
      let buf = Buffer.alloc(0);
      const pump = () => {
        for (;;) {
          const c = socket.read(); if (c === null) return;
          buf = Buffer.concat([buf, c]);
          const i = buf.indexOf('\r\n\r\n');
          if (i >= 0) {
            const head = buf.slice(0, i).toString('latin1');
            const excess = buf.slice(i + 4);
            if (!/ 200 /.test(head)) { socket.destroy(); rej(new Error('proxy CONNECT failed')); return; }
            if (excess.length) pass.write(excess);
            bridging = true; socket.removeAllListeners('readable'); socket.pipe(pass); res(); return;
          }
        }
      };
      socket.on('readable', pump); socket.on('error', rej);
    });
    return { opened, readable: Readable.toWeb(pass, { encoding: null }), writable: new WritableStream({ write(c) { return new Promise((r, j) => socket.write(c, (e) => e ? j(e) : r())); }, close() { socket.end(); }, abort() { socket.destroy(); } }), close: () => { try { socket.destroy(); } catch { } } };
  }
  const socket = net.connect(port, hostname);
  return {
    opened: new Promise((res, rej) => { socket.once('connect', res); socket.once('error', (e) => rej(e)); }),
    readable: Readable.toWeb(socket, { encoding: null }),
    writable: Writable.toWeb(socket, { decodeStrings: false }),
    close: () => { try { socket.destroy(); } catch { } },
  };
}

// ---- minimal RFC6455 WebSocket server adapter (server half of WebSocketPair) ----
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function wsframe(payload, opcode = 0x02) {
  let hdr; const len = payload.length;
  if (len < 126) hdr = [0x80 | opcode, len];
  else if (len < 65536) hdr = [0x80 | opcode, 126, len >> 8, len & 0xFF];
  else hdr = [0x80 | opcode, 127, 0, 0, 0, 0, len >> 24 & 0xff, len >> 16 & 0xff, len >> 8 & 0xff, len & 0xff];
  return Buffer.from([...hdr, ...payload]);
}
function makePair(socket) {
  const server = {
    listeners: {},
    binaryType: 'arraybuffer',
    accept() { },
    on(t, f) { (this.listeners[t] ||= []).push(f); },
    addEventListener(t, f) { this.on(t, f); },
    removeEventListener(t, f) { this.listeners[t] = (this.listeners[t] || []).filter((x) => x !== f); },
    _emit(t, ev) { (this.listeners[t] || []).forEach((f) => { try { f(ev); } catch { } }); },
    send(data) { try { const b = typeof data === 'string' ? Buffer.from(data) : Buffer.from(data.buffer || data); socket.write(wsframe(b)); } catch { } },
    close() { try { socket.write(Buffer.from([0x88, 0x00])); } catch { } try { socket.end(); } catch { } },
  };
  const client = {};
  let buf = Buffer.alloc(0);
  const feed = () => {
    while (buf.length >= 2) {
      const b0 = buf[0], b1 = buf[1];
      let len = b1 & 0x7F, off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      const masked = !!(b1 & 0x80);
      const mask = masked ? buf.subarray(off, off + 4) : null; off += masked ? 4 : 0;
      if (buf.length < off + len) return;
      let p = buf.subarray(off, off + len);
      if (mask) { const u = Buffer.alloc(len); for (let k = 0; k < len; k++) u[k] = p[k] ^ mask[k & 3]; p = u; }
      buf = buf.subarray(off + len);
      const op = b0 & 0x0F;
      if (op === 8) { server._emit('close', { code: 1000, reason: '' }); return; }
      if (op === 9) { try { socket.write(wsframe(p, 0x0A)); } catch { } continue; }
      server._emit('message', { data: p.buffer.slice(p.byteOffset, p.byteOffset + p.length) });
    }
  };
  socket.on('data', (d) => { buf = Buffer.concat([buf, d]); feed(); });
  socket.on('close', () => server._emit('close', { code: 1006, reason: '' }));
  socket.on('error', () => server._emit('error', new Error('socket error')));
  return { client, server };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const r = new Request('http://localhost' + url.pathname + url.search, { method: req.method, headers: req.headers });
  const resp = await route(r, { connect, createPair: null });
  res.statusCode = resp.status;
  for (const [k, v] of resp.headers) res.setHeader(k, v);
  const body = new Uint8Array(await resp.arrayBuffer());
  res.end(Buffer.from(body));
});

server.on('upgrade', async (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\nSec-WebSocket-Extensions: \r\n\r\n');
  const { client, server: wsServer } = makePair(socket);
  const url = new URL(req.url, 'http://localhost');
  const r = new Request('http://localhost' + url.pathname + url.search, { method: 'GET', headers: req.headers });
  try { await route(r, { connect, createPair: () => [client, wsServer] }); }
  catch (err) {
    // Node cannot construct a 101 Response (the `webSocket` option is Workers-only),
    // but handleWs already registered its listeners before that, and the WS
    // handshake above was sent manually. Keep the socket alive for non-101 errors.
    if (!/status.*range|101|webSocket/i.test(String((err && err.message) || err))) { try { socket.destroy(); } catch { } }
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('Local VLESS->OpenVPN server on ws://127.0.0.1:' + PORT + '/  (uuid 2523c510-9ff0-415b-9582-93949bfae7e3)');
  console.log('  /ovpn-test  /sock-test   connectMode=' + (USE_PROXY ? 'proxy' : 'direct'));
});