// Verify egress IP through the VPN Gate tunnel (DoH over the local proxy).
import { readFileSync } from 'fs';
import net from 'net';
import tls from 'tls';
import { Readable, PassThrough } from 'stream';
import { parseOvpn } from '../src/openvpn/config.js';
import { openVpnConn } from '../src/openvpn/client.js';
import { createTcp } from '../src/tcp.js';
import { root } from './root.js';

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
    let buf = Buffer.alloc(0); let excess = Buffer.alloc(0);
    const pump = () => { for (;;) { const c = socket.read(); if (c === null) return; buf = Buffer.concat([buf, c]); const i = buf.indexOf('\r\n\r\n'); if (i >= 0) { const head = buf.slice(0, i).toString('latin1'); excess = buf.slice(i + 4); if (!/ 200 /.test(head)) { socket.destroy(); rej(new Error('proxy ' + head.slice(0, 60))); return; } socket.removeAllListeners('readable'); const t = tls.connect({ socket, servername: hostname }, () => res(t)); t.on('error', rej); if (excess.length) t.write(excess); return; } } };
    socket.on('readable', pump); socket.on('error', rej);
  });
}

async function dohResolve(host) {
  const sock = await proxyTls('cloudflare-dns.com', 443);
  const url = `/dns-query?name=${encodeURIComponent(host)}&type=A`;
  sock.write(`GET ${url} HTTP/1.1\r\nHost: cloudflare-dns.com\r\nAccept: application/dns-json\r\nUser-Agent: node\r\nConnection: close\r\n\r\n`);
  let resp = Buffer.alloc(0);
  await new Promise((resolve, reject) => {
    sock.on('data', (d) => { resp = Buffer.concat([resp, d]); });
    sock.on('end', resolve); sock.on('error', reject); sock.on('close', resolve);
  });
  const i = resp.indexOf('\r\n\r\n');
  const body = resp.slice(i + 4).toString('utf8');
  try { const j = JSON.parse(body); return j.Answer?.find((a) => a.type === 1)?.data ?? null; } catch { console.log('doh body', body.slice(0, 200)); return null; }
}

const cfg = parseOvpn(readFileSync(root('test/configs/sample0.ovpn'), 'utf8'));
let tunnel = null;
for (let attempt = 0; attempt < 4 && !tunnel; attempt++) {
  try {
    const t = await openVpnConn(cfg, { connect: cfConnect }, { log: () => {} });
    if (t.virtualIp) tunnel = t;
    else { try { t.close(); } catch { } console.log('attempt', attempt, 'got no virtualIp, retrying...'); }
  } catch (e) { console.log('attempt', attempt, 'failed:', e.message); }
}
if (!tunnel) { console.log('COULD NOT CONNECT to VPN Gate node'); process.exit(1); }
console.log('VPN connected virtualIp=', tunnel.virtualIp);

const host = 'api.ipify.org';
const ip = await dohResolve(host);
console.log('resolve', host, '->', ip);
if (!ip) { process.exit(1); }
const tcp = await createTcp(tunnel, tunnel.virtualIp, ip, 80);
const wr = tcp.writable.getWriter(); const rd = tcp.readable.getReader();
await wr.write(new TextEncoder().encode(`GET / HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: cf-worker-openvpn\r\n\r\n`));
let buf = '';
for (let i = 0; i < 20; i++) {
  const { value, done } = await Promise.race([rd.read(), new Promise((r) => setTimeout(() => r({ done: true, value: null }), 5000))]);
  if (done || !value) break;
  buf += new TextDecoder().decode(value);
  if (buf.length > 1500) break;
}
console.log('=== egress IP response ===');
console.log(buf.replace(/\r\n/g, '\n').split('\n').filter(l => l.length).slice(0, 15).join('\n'));
process.exit(0);
