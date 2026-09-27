// local/wsprobe.mjs — minimal VLESS-over-WebSocket client probe (no deps).
//
//   node local/wsprobe.mjs wss://host/path hs      # handshake only: did the 101 complete?
//   node local/wsprobe.mjs wss://host/path dbg     # /dbg-ws echo (newer builds only)
//   node local/wsprobe.mjs wss://host/path vless   # default: full VLESS -> OpenVPN -> target
//
// Exit: 0 = got data, 2 = WS handshake/transport error, 3 = open but no data.
const url = process.argv[2];
const mode = (process.argv[3] || 'vless').toLowerCase();
if (!url) { console.log('usage: node local/wsprobe.mjs <wss-url> [hs|dbg|vless]'); process.exit(1); }

const UUID = '2523c510-9ff0-415b-9582-93949bfae7e3';
const TARGET = { ip: [1, 1, 1, 1], port: 80 };
const PAYLOAD = 'GET / HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n';

const uuidBytes = (u) => {
  const h = u.replace(/-/g, '');
  const o = new Uint8Array(16);
  for (let i = 0; i < 16; i++) o[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return o;
};

// [ver][uuid 16][optLen=0][cmd=1 TCP][port BE][atype=1 IPv4][4B addr][payload]
function vlessPacket() {
  const pay = new TextEncoder().encode(PAYLOAD);
  const p = new Uint8Array(1 + 16 + 1 + 1 + 2 + 1 + 4 + pay.length);
  let i = 0;
  p[i++] = 0;
  p.set(uuidBytes(UUID), i); i += 16;
  p[i++] = 0;                 // optLen
  p[i++] = 1;                 // cmd = TCP
  p[i++] = TARGET.port >> 8; p[i++] = TARGET.port & 0xff;
  p[i++] = 1;                 // addrType = IPv4
  for (const b of TARGET.ip) p[i++] = b;
  p.set(pay, i);
  return p;
}

const hex = (u, n = 48) => Array.from(u.slice(0, n), (x) => x.toString(16).padStart(2, '0')).join('');
const text = (u) => new TextDecoder().decode(u);

console.log(`mode=${mode} url=${url}`);
const t0 = Date.now();
let gotData = false, opened = false, dbgNonEmpty = 0;

const ws = new WebSocket(url);
ws.binaryType = 'arraybuffer';

const done = (code) => {
  console.log(`--- elapsed ${Date.now() - t0}ms  opened=${opened} gotData=${gotData}`);
  process.exit(code);
};

const timer = setTimeout(() => {
  console.log('TIMEOUT 20s: no terminal event');
  try { ws.close(); } catch { }
  done(3);
}, 20000);

ws.onopen = () => {
  opened = true;
  console.log(`OPEN  +${Date.now() - t0}ms  protocol=${ws.protocol || '(none)'}  ext=${ws.extensions || '(none)'}`);
  if (mode === 'hs') { console.log('HANDSHAKE OK'); clearTimeout(timer); try { ws.close(); } catch { } done(0); }
  if (mode === 'vless') { const pkt = vlessPacket(); console.log(`SEND VLESS header+payload ${pkt.length}B -> ${TARGET.ip.join('.')}:${TARGET.port}`); ws.send(pkt); }
  if (mode === 'dbg') {
    console.log('SEND ping');
    ws.send('ping');
    setTimeout(() => { try { console.log('SEND ping#2'); ws.send('ping2'); } catch { } }, 1200);
  }
};

ws.onmessage = (e) => {
  gotData = true;
  const u = new Uint8Array(e.data);
  const kind = typeof e.data === 'string' ? 'text' : 'binary';
  console.log(`MSG +${Date.now() - t0}ms  ${kind} ${u.length}B  hex[0..${Math.min(48, u.length)}]=${hex(u)}`);
  console.log('        as-text: ' + JSON.stringify(text(u).slice(0, 300)));
  if (mode === 'hs') { clearTimeout(timer); try { ws.close(); } catch { } done(0); }
  if (mode === 'dbg') {
    // A frame queued before the 101 completes can arrive empty; the echo after
    // our ping is the real client->server signal, so do not stop on frame #1.
    if (u.length > 0) dbgNonEmpty++;
    if (dbgNonEmpty >= 2 || Date.now() - t0 > 9000) { clearTimeout(timer); try { ws.close(); } catch { } done(dbgNonEmpty ? 0 : 3); }
    return;
  }
  // vless: keep reading a little, the first remote bytes prove the whole chain
  if (mode === 'vless' && u.length > 2) { clearTimeout(timer); try { ws.close(); } catch { } done(0); }
};

ws.onerror = (e) => {
  console.log(`ERROR +${Date.now() - t0}ms  opened=${opened}  message=${(e && e.message) || '(none)'}  error=${String((e && e.error) || '')}`);
};

ws.onclose = (e) => {
  console.log(`CLOSE +${Date.now() - t0}ms  code=${e.code}  reason=${JSON.stringify(e.reason || '')}  wasClean=${e.wasClean}`);
  clearTimeout(timer);
  done(gotData ? 0 : (opened ? 3 : 2));
};
