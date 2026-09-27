// Node test harness: polyfills cloudflare:sockets (connect) with node:net and
// runs the OpenVPN client against a real server. Usage:
//   node test/vpngate.js [ovpnFile] [--debug]
import net from 'net';
import { Readable, Writable } from 'stream';
import { readFileSync, writeFileSync } from 'fs';
import { parseOvpn } from '../src/openvpn/config.js';
import { openVpnConn } from '../src/openvpn/client.js';
import { createTcp } from '../src/tcp.js';
import { root } from './root.js';

// --- cloudflare:sockets polyfill ---
import { PassThrough } from 'stream';
const USE_PROXY = process.env.OVPN_PROXY !== '0'; // sandbox egress is proxied
export function cfConnect({ hostname, port }) {
  if (!USE_PROXY) return cfConnectDirect({ hostname, port });
  const socket = net.connect(10808, '127.0.0.1');
  const pass = new PassThrough();
  socket.pause();
  let bridging = false;
  const opened = new Promise((res, rej) => {
    socket.once('connect', () => { socket.write(`CONNECT ${hostname}:${port} HTTP/1.1\r\nHost: ${hostname}:${port}\r\n\r\n`); });
    let buf = Buffer.alloc(0);
    const pump = () => {
      for (;;) {
        const c = socket.read();
        if (c === null) return;
        buf = Buffer.concat([buf, c]);
        const i = buf.indexOf('\r\n\r\n');
        if (i >= 0) {
          const head = buf.slice(0, i).toString('latin1');
          const excess = buf.slice(i + 4);
          if (!/ 200 /.test(head)) { socket.destroy(); rej(new Error('proxy CONNECT failed')); return; }
          if (excess.length) pass.write(excess);
          bridging = true; socket.removeAllListeners('readable'); socket.pipe(pass);
          res();
          return;
        }
      }
    };
    socket.on('readable', pump);
    socket.on('error', rej);
  });
  return {
    opened,
    readable: Readable.toWeb(pass, { encoding: null }),
    writable: new WritableStream({
      write(c) { return new Promise((r, j) => socket.write(c, (e) => e ? j(e) : r())); },
      close() { socket.end(); },
      abort() { socket.destroy(); },
    }),
    close: () => { try { socket.destroy(); } catch { } },
  };
}
export function cfConnectDirect({ hostname, port }) {
  const socket = net.connect(port, hostname);
  const opened = new Promise((res, rej) => {
    socket.once('connect', () => res());
    socket.once('error', (e) => rej(e));
  });
  const readable = Readable.toWeb(socket, { encoding: null });
  const writable = Writable.toWeb(socket, { decodeStrings: false });
  return {
    opened, readable, writable,
    close: () => { try { socket.destroy(); } catch { } },
  };
}

const ovpnFile = process.argv[2] || root('test/configs/sample0.ovpn');
const debug = process.argv.includes('--debug');

(async () => {
  const conf = readFileSync(ovpnFile, 'utf8');
  let cfg;
  try { cfg = parseOvpn(conf); } catch (e) { console.error('CONFIG ERR', e.message); process.exit(1); }
  if (process.env.DUMP_KM2) globalThis.__DUMP_KM2 = (b) => { writeFileSync(root('test/km2.bin'), Buffer.from(b)); };
  console.log('config: remote=' + JSON.stringify(cfg.remotes), 'cipher=' + cfg.cipher, 'auth=' + cfg.auth, 'tlsAuth=' + !!cfg.tlsAuth);
  const log = debug ? (m) => console.log('[ovpn]', m) : () => {};
  const t0 = Date.now();
  const tunnel = await openVpnConn(cfg, { connect: cfConnect }, { log });
  console.log('OPENVPN CONNECTED in', Date.now() - t0, 'ms virtualIp=', tunnel.virtualIp);

  // quick TCP test through the tunnel: connect to a target and read
  const TARGET_IP = process.argv[3] || '1.1.1.1';
  const TARGET_PORT = +(process.argv[4] || 80);
  console.log('TCP to', TARGET_IP + ':' + TARGET_PORT);
  const tcp = await createTcp(tunnel, tunnel.virtualIp, TARGET_IP, TARGET_PORT);
  console.log('TCP established');
  const wr = tcp.writable.getWriter();
  const rd = tcp.readable.getReader();
  const http = `GET / HTTP/1.0\r\nHost: ${TARGET_IP}\r\nUser-Agent: cf-worker-openvpn\r\n\r\n`;
  await wr.write(new TextEncoder().encode(http));
  const chunks = [];
  try {
    for (let i = 0; i < 20; i++) {
      const { value, done } = await Promise.race([rd.read(), timeout(8000)]);
      if (done) break;
      if (value) { chunks.push(value); if (chunks.join('').length > 4000) break; }
    }
  } catch (e) { console.log('read timeout'); }
  const body = chunks.map(c => new TextDecoder().decode(c)).join('');
  console.log('=== HTTP RESPONSE (first 700 chars) ===');
  console.log(body.slice(0, 700));
  process.exit(0);
})().catch(e => { console.error('FAILED:', e.message, e.stack && e.stack.split('\n').slice(0, 6).join('\n')); process.exit(1); });

function timeout(ms) { return new Promise((_, rej) => setTimeout(() => rej(new Error('T')), ms)); }