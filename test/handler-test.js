// Tests the /ovpn-test route (handler.js) end-to-end against the mock server.
// The handler is importable in Node; only worker.js imports cloudflare:sockets.
import { startMockServer } from './mockserver.js';
import { route, _setOpenVpnConfig, _cfgErr } from '../src/handler.js';
import { Readable, Writable } from 'stream';
import net from 'net';

function directConnect({ hostname, port }) {
  const socket = net.connect(port, hostname);
  const opened = new Promise((res, rej) => { socket.once('connect', () => res()); socket.once('error', e => rej(e)); });
  const readable = Readable.toWeb(socket, { encoding: null });
  const writable = Writable.toWeb(socket, { decodeStrings: false });
  return { opened, readable, writable, close: () => { try { socket.destroy(); } catch { } } };
}

const cipher = process.argv[2] || 'AES-128-GCM';
const debug = process.argv.includes('--debug');
const log = debug ? (m) => console.log('[mock]', m) : () => {};

(async () => {
  const mock = await startMockServer({ cipher, auth: 'SHA1', useV2: true, log });
  console.log('mock server on 127.0.0.1:' + mock.port);
  const transport = { connect: directConnect };

  const config = `client\ndev tun\nproto tcp\nremote 127.0.0.1 ${mock.port}\ncipher ${cipher}\ndata-ciphers ${cipher}\nauth SHA1\n<ca>\n${mock.certPem}</ca>\n`;

  const req = new Request('http://x/ovpn-test?target=10.8.0.1&port=80&path=/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ config, username: 'vpn', password: 'vpn' }),
  });
  const res = await route(req, transport);
  const body = await res.text();
  console.log('status', res.status);
  console.log('body:', body.slice(0, 400));
  const j = JSON.parse(body);
  const ok = j.ok && (j.response || '').includes('mock-ok');
  console.log(ok ? 'HANDLER TEST PASSED' : 'HANDLER TEST FAILED');
  mock.close().catch(() => {});
  setTimeout(() => process.exit(ok ? 0 : 1), 400);
})().catch((e) => { console.error('ERR', e); process.exit(1); });