// nodecheck.js <host> <port> [<ovpn-template>]
// Connects to a VPN Gate OpenVPN TCP node, then fetches api.ipify.org over the
// tunnel to confirm the egress IP. Reuses the CA/config from a template ovpn.
import { readFileSync } from 'fs';
import net from 'net';
import tls from 'tls';
import { Readable, PassThrough } from 'stream';
import { parseOvpn } from '../src/openvpn/config.js';
import { openVpnConn } from '../src/openvpn/client.js';
import { createTcp } from '../src/tcp.js';
import { root } from './root.js';

const host = process.argv[2];
const port = +(process.argv[3]);
const debug = process.argv.includes('--debug');
const tpl = process.argv.slice(4).find((a) => !a.startsWith('--')) || root('test/configs/sample0.ovpn');
if (!host) { console.error('usage: node test/nodecheck.js <host> <port> [--debug] [<ovpn-template>]'); process.exit(1); }

function cfConnect({ hostname, port }) {
  const socket = net.connect(10808, '127.0.0.1');
  const pass = new PassThrough(); socket.pause(); let bridging = false;
  const opened = new Promise((res, rej) => {
    socket.once('connect', () => { socket.write(`CONNECT ${hostname}:${port} HTTP/1.1\r\nHost: ${hostname}:${port}\r\n\r\n`); });
    let buf = Buffer.alloc(0);
    const pump = () => { for (;;) { const c = socket.read(); if (c === null) return; buf = Buffer.concat([buf, c]); const i = buf.indexOf('\r\n\r\n'); if (i >= 0) { const head = buf.slice(0, i).toString('latin1'); const excess = buf.slice(i + 4); if (!/ 200 /.test(head)) { socket.destroy(); rej(new Error('proxy CONNECT failed')); return; } if (excess.length) pass.write(excess); bridging = true; socket.removeAllListeners('readable'); socket.pipe(pass); res(); return; } } };
    socket.on('readable', pump); socket.on('error', rej);
  });
  return { opened, readable: Readable.toWeb(pass, { encoding: null }), writable: new WritableStream({ write(c) { return new Promise((r, j) => socket.write(c, (e) => e ? j(e) : r())); }, close() { socket.end(); }, abort() { socket.destroy(); } }), close: () => { try { socket.destroy(); } catch { } } };
}

function proxyTls(hostname, port) {
  return new Promise((res, rej) => {
    const socket = net.connect(10808, '127.0.0.1');
    socket.once('connect', () => socket.write(`CONNECT ${hostname}:${port} HTTP/1.1\r\nHost: ${hostname}:${port}\r\n\r\n`));
    let buf = Buffer.alloc(0);
    const pump = () => { for (;;) { const c = socket.read(); if (c === null) return; buf = Buffer.concat([buf, c]); const i = buf.indexOf('\r\n\r\n'); if (i >= 0) { const head = buf.slice(0, i).toString('latin1'); const excess = buf.slice(i + 4); if (!/ 200 /.test(head)) { socket.destroy(); rej(new Error('proxy ' + head.slice(0, 60))); return; } socket.removeAllListeners('readable'); const t = tls.connect({ socket, servername: hostname }, () => res(t)); t.on('error', rej); if (excess.length) t.write(excess); return; } } };
    socket.on('readable', pump); socket.on('error', rej);
  });
}

async function dohResolve(hn) {
  try {
    const sock = await proxyTls('cloudflare-dns.com', 443);
    sock.write(`GET /dns-query?name=${encodeURIComponent(hn)}&type=A HTTP/1.1\r\nHost: cloudflare-dns.com\r\nAccept: application/dns-json\r\nUser-Agent: node\r\nConnection: close\r\n\r\n`);
    let resp = Buffer.alloc(0);
    await new Promise((resolve, reject) => { sock.on('data', (d) => resp = Buffer.concat([resp, d])); sock.on('end', resolve); sock.on('error', reject); sock.on('close', resolve); });
    const i = resp.indexOf('\r\n\r\n'); const body = resp.slice(i + 4).toString('utf8');
    try { return JSON.parse(body).Answer?.find((a) => a.type === 1)?.data ?? null; } catch { return null; }
  } catch { return null; }
}

// build config from template, overriding remote
const raw = readFileSync(tpl, 'utf8');
let cfgText = raw.replace(/^remote\s+\S+\s+\d+$/m, `remote ${host} ${port}`);
let cfg = parseOvpn(cfgText);
cfg.username = 'vpn'; cfg.password = 'vpn';

console.log(`== ${host}:${port} ==`);
const log = debug ? (m) => console.log('  [ovpn]', m) : () => {};
let tunnel = null;
for (let a = 0; a < 3 && !tunnel; a++) {
  try {
    const t = await openVpnConn(cfg, { connect: cfConnect }, { log });
    if (t.virtualIp) tunnel = t; else { try { t.close(); } catch { } console.log('  attempt', a, 'no virtualIp'); }
  } catch (e) { console.log('  attempt', a, 'ERR', e.message); }
}
if (!tunnel) { console.log('  RESULT: FAIL (could not connect)'); process.exit(1); }
console.log('  connected, virtualIp=', tunnel.virtualIp);
const ip = await dohResolve('api.ipify.org');
if (!ip) { console.log('  RESULT: CONNECTED (no egress check)'); process.exit(0); }
try {
  const tcp = await createTcp(tunnel, tunnel.virtualIp, ip, 80);
  const wr = tcp.writable.getWriter(); const rd = tcp.readable.getReader();
  await wr.write(new TextEncoder().encode(`GET / HTTP/1.0\r\nHost: api.ipify.org\r\nUser-Agent: cf-worker-openvpn\r\n\r\n`));
  let buf = '';
  for (let i = 0; i < 20; i++) {
    const { value, done } = await Promise.race([rd.read(), new Promise((r) => setTimeout(() => r({ done: true, value: null }), 6000))]);
    if (done || !value) break;
    buf += new TextDecoder().decode(value);
    if (buf.length > 1200) break;
  }
  const m = buf.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
  console.log('  RESULT: ' + (m ? ('OK egress=' + m[1]) : ('HTTP but no IP: ' + buf.slice(0, 80).replace(/\r\n/g, ' '))));
} catch (e) { console.log('  RESULT: CONNECTED but TCP ERR', e.message); }
process.exit(0);
