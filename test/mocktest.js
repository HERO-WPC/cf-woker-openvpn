// Validates the OpenVPN client end-to-end against a local mock server.
// Node's real TLS stack is the independent TLS peer. Runs the IPv4/TCP stack
// and an HTTP request through the tunnel.
import { startMockServer } from './mockserver.js';
import { openVpnConn } from '../src/openvpn/client.js';
import { createTcp } from '../src/tcp.js';
import { Readable, Writable } from 'stream';
import net from 'net';

function directConnect({ hostname, port }) {
  const socket = net.connect(port, hostname);
  const opened = new Promise((res, rej) => { socket.once('connect', () => res()); socket.once('error', (e) => rej(e)); });
  const readable = Readable.toWeb(socket, { encoding: null });
  const writable = Writable.toWeb(socket, { decodeStrings: false });
  return { opened, readable, writable, close: () => { try { socket.destroy(); } catch { } } };
}

const cipher = process.argv[2] || 'AES-128-GCM';
const debug = process.argv.includes('--debug');
const noEms = process.argv.includes('--no-ems');

(async () => {
  const mock = await startMockServer({ cipher, auth: 'SHA1', useV2: true, disableEms: noEms, recordTls: debug, log: debug ? (m) => console.log('[mock]', m) : () => {} });
  console.log('mock server on 127.0.0.1:' + mock.port, 'cipher=' + cipher, noEms ? '(no EMS)' : '');

  const cfg = {
    client: true, dev: 'tun', proto: 'tcp', remotes: [{ host: '127.0.0.1', port: mock.port }],
    ca: mock.certPem, tlsAuth: '', keyDirection: 0, cipher, dataCiphers: cipher, auth: 'SHA1',
    username: 'vpn', password: 'vpn', userPassInline: false, remoteCertTls: true, hasCert: false, hasKey: false,
  };

  const log = debug ? (m) => console.log('[ovpn]', m) : () => {};
  const t0 = Date.now();
  const tunnel = await openVpnConn(cfg, { connect: directConnect }, { log });
  console.log('OPENVPN CONNECTED in', Date.now() - t0, 'ms virtualIp=', tunnel.virtualIp);

  const tcp = await createTcp(tunnel, tunnel.virtualIp, '10.8.0.1', 80);
  console.log('TCP established');
  const wr = tcp.writable.getWriter();
  const rd = tcp.readable.getReader();
  await wr.write(new TextEncoder().encode('GET / HTTP/1.0\r\nHost: x\r\n\r\n'));
  let body = '';
  try {
    for (let i = 0; i < 20; i++) {
      const { value, done } = await Promise.race([rd.read(), timeout(8000)]);
      if (done) break;
      if (value) { body += new TextDecoder().decode(value); if (body.length > 300) break; }
    }
  } catch (e) { console.log('read timeout'); }
  console.log('=== HTTP RESPONSE ===');
  console.log(body.slice(0, 300));
  const ok = body.includes('mock-ok');
  console.log(ok ? '\nTEST PASSED' : '\nTEST FAILED');
  mock.close().catch(() => {});
  setTimeout(() => process.exit(ok ? 0 : 1), 500);
})().catch(async (e) => { console.error('FAILED:', e.message); console.error(e.stack && e.stack.split('\n').slice(0, 8).join('\n')); process.exit(1); });

function timeout(ms) { return new Promise((_, rej) => setTimeout(() => rej(new Error('T')), ms)); }