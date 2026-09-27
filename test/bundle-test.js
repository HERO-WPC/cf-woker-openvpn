// Executes the BUNDLED _worker.js in Node (with a proxy-based stand-in for
// cloudflare:sockets) and runs a real /ovpn-test request through it. This
// catches runtime errors in the bundle (e.g. strict-mode issues) that plain
// syntax checks miss. Requires the local proxy at 127.0.0.1:10808.
import { readFileSync, writeFileSync, rmSync } from 'fs';
import { pathToFileURL } from 'node:url';

const bundle = readFileSync('D:/桌面/worker-openvpn-tcp/_worker.js', 'utf8');
if (!/^import \{ connect \} from 'cloudflare:sockets';/m.test(bundle)) {
  console.error('unexpected bundle header'); process.exit(1);
}
const shim = `
import net from 'node:net';
import { Readable, PassThrough } from 'node:stream';
const connect = ({ hostname, port }) => {
  const socket = net.connect(10808, '127.0.0.1');
  const pass = new PassThrough(); socket.pause(); let bridging = false;
  const opened = new Promise((res, rej) => {
    socket.once('connect', () => { socket.write(\`CONNECT \${hostname}:\${port} HTTP/1.1\\r\\nHost: \${hostname}:\${port}\\r\\n\\r\\n\`); });
    let buf = Buffer.alloc(0);
    const pump = () => { for (;;) { const c = socket.read(); if (c === null) return; buf = Buffer.concat([buf, c]); const i = buf.indexOf('\\r\\n\\r\\n'); if (i >= 0) { const head = buf.slice(0, i).toString('latin1'); const excess = buf.slice(i + 4); if (!/ 200 /.test(head)) { socket.destroy(); rej(new Error('proxy CONNECT failed')); return; } if (excess.length) pass.write(excess); bridging = true; socket.removeAllListeners('readable'); socket.pipe(pass); res(); return; } } };
    socket.on('readable', pump); socket.on('error', rej);
  });
  return { opened, readable: Readable.toWeb(pass, { encoding: null }), writable: new WritableStream({ write(c) { return new Promise((r, j) => socket.write(c, (e) => e ? j(e) : r())); }, close() { socket.end(); }, abort() { socket.destroy(); } }), close: () => { try { socket.destroy(); } catch { } } };
};
`;

const local = bundle.replace(/^import \{ connect \} from 'cloudflare:sockets';/m, '').replace(/^\/\/ AUTO-GENERATED/, '// (test shim applied for cloudflare:sockets)\n// AUTO-GENERATED');
const outPath = 'D:/桌面/worker-openvpn-tcp/_worker.local.mjs';
writeFileSync(outPath, shim + local);

try {
  const mod = await import(pathToFileURL(outPath).href + '?t=' + Date.now());
  // GET /ovpn-test with no config: uses the embedded VPN Gate node.
  const req = new Request('http://localhost/ovpn-test', { method: 'GET' });
  const res = await mod.default.fetch(req);
  const j = await res.json();
  console.log('status', res.status);
  console.log('ok=', j.ok, 'virtualIp=', j.virtualIp, 'stage=', j.stage || '-', 'err=', j.error || '-');
  console.log('response head:', String(j.response || '').replace(/\r\n/g, ' ').slice(0, 120));
  const pass = j.ok === true && !!j.virtualIp && (j.response || '').length > 0;
  console.log(pass ? 'BUNDLE TEST PASSED' : 'BUNDLE TEST FAILED');
  process.exit(pass ? 0 : 1);
} catch (e) {
  console.error('BUNDLE TEST CRASHED:', e.message);
  console.error((e.stack || '').split('\n').slice(0, 6).join('\n'));
  process.exit(1);
} finally {
  try { rmSync(outPath); } catch { }
}