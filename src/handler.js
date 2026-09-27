// Worker request routing: VLESS-over-WebSocket tunnel entry (unchanged from the
// original project) + an /ovpn-test diagnostic endpoint. Pure Workers JS.
import { vless, addr } from './vless.js';
import { resolveIP } from './dns.js';
import { openVpnConn } from './openvpn/client.js';
import { createTcp } from './tcp.js';
import { parseOvpn } from './openvpn/config.js';
import { concat } from './openvpn/bytes.js';
import { EMBEDDED_OVPN } from './embedded-ovpn.js';

// ---- config ----
// A VPN Gate OpenVPN TCP node is embedded (see src/embedded-ovpn.js), so the
// worker works out of the box. Override at runtime with _setOpenVpnConfig()
// or by editing OPTIONS/binding OPENVPN_OVPN in the dashboard.
let OPENVPN_OVPN = EMBEDDED_OVPN || '';
let _cfg = null, _cfgErr = null;

function refreshConfig() {
  try { _cfg = OPENVPN_OVPN ? parseOvpn(OPENVPN_OVPN) : null; _cfgErr = null; }
  catch (e) { _cfg = null; _cfgErr = String(e.message || e); }
}
refreshConfig();
export function _setOpenVpnConfig(text) { OPENVPN_OVPN = text || ''; refreshConfig(); }

const UUID = '2523c510-9ff0-415b-9582-93949bfae7e3';
const idBytes = Uint8Array.from(UUID.replaceAll('-', ''), (c) => parseInt(c, 16));
const enc = (s) => new TextEncoder().encode(s);
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json' } });
const timeoutSec = (ms) => new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms));
const MAX_ED = 8192;

const relay = async (rd, send, close) => {
  try { for (;;) { const { done, value } = await rd.read(); if (done) break; value?.byteLength && send(value); } }
  catch { }
  finally { try { rd.releaseLock(); } catch { } close(); }
};

async function handleWs(req, transport) {
  const [client, server] = Object.values(new WebSocketPair());
  server.accept();
  const ed = req.headers.get('sec-websocket-protocol');
  let w = null, sock = null, chain = Promise.resolve();
  const close = () => { try { sock?.close(); } catch { } try { server.close(); } catch { } };
  const send = (d) => { try { server.send(d); } catch { } };
  const process = async (chunk) => {
    if (w) return w.write(chunk);
    const v = vless(chunk, idBytes);
    if (!v) return close();
    send(new Uint8Array([chunk[0], 0]));
    if (!_cfg) return close();
    const host = addr(v.addrType, v.addrBytes), payload = chunk.subarray(v.dataOffset);
    let targetIp;
    try { targetIp = v.addrType === 1 ? host : await resolveIP(host); } catch { }
    if (!targetIp) return close();
    let tunnel, tcp;
    try {
      tunnel = await openVpnConn(_cfg, transport); // each VLESS connection gets its own OpenVPN socket
      tcp = await createTcp(tunnel, tunnel.virtualIp, targetIp, v.port);
    } catch { return close(); }
    sock = tcp;
    w = sock.writable.getWriter();
    payload.byteLength && await w.write(payload);
    relay(sock.readable.getReader(), send, () => { try { sock.close(); } catch { } close(); });
  };
  if (ed?.length <= MAX_ED) chain = chain.then(() => process(Uint8Array.fromBase64(ed, { alphabet: 'base64url' }))).catch(close);
  server.addEventListener('message', (e) => { chain = chain.then(() => process(new Uint8Array(e.data instanceof ArrayBuffer ? e.data : e.data.buffer ?? e.data))).catch(close); });
  server.addEventListener('close', close);
  server.addEventListener('error', close);
  return new Response(null, { status: 101, webSocket: client, headers: ed ? { 'sec-websocket-protocol': ed } : {} });
}

async function ovpnTest(req, transport) {
  const url = new URL(req.url);
  const p = url.searchParams;
  let cfgText = '', username = p.get('username') || 'vpn', password = p.get('password') || 'vpn';
  const target = p.get('target') || '1.1.1.1';
  const port = +(p.get('port') || 80);
  const path = p.get('path') || '/cdn-cgi/trace';
  if (req.method === 'POST') {
    const ct = req.headers.get('content-type') || '';
    if (ct.includes('application/json')) { const j = await req.json(); cfgText = j.config || j.ovpn || ''; username = j.username || username; password = j.password || password; }
    else if (ct.includes('multipart/form-data')) {
      const form = await req.formData();
      const f = form.get('config') || form.get('file') || form.get('ovpn');
      cfgText = typeof f === 'string' ? f : (f ? await f.text() : '');
      username = form.get('username') || username; password = form.get('password') || password;
    } else cfgText = await req.text();
  } else cfgText = p.get('config') || p.get('ovpn') || OPENVPN_OVPN;
  if (!cfgText) return json({ ok: false, error: 'OPENVPN_CONFIG_MISSING' }, 400);
  let cfg;
  try { cfg = parseOvpn(cfgText); } catch (e) { return json({ ok: false, stage: 'config', error: String(e.message || e) }, 400); }
  cfg.username = username; cfg.password = password;
  // Resolve a domain target to an IPv4 for the user-space dial; keep the domain
  // as the HTTP Host so IP-echo services (e.g. api.ipify.org) see it correctly.
  let dstIp = target, host = target;
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(target)) {
    try { dstIp = await resolveIP(target); } catch { }
    if (!dstIp) return json({ ok: false, stage: 'resolve', error: 'TARGET_RESOLVE_FAILED ' + target }, 502);
  }
  let tunnel, tcp;
  try { tunnel = await openVpnConn(cfg, transport); }
  catch (e) { return json({ ok: false, stage: 'openvpn', remotes: cfg.remotes, error: String(e.message || e) }, 502); }
  if (!tunnel.virtualIp) { try { tunnel.close(); } catch { } return json({ ok: false, stage: 'openvpn', error: 'NO_VIRTUAL_IP: server connected but did not push an ifconfig', remotes: cfg.remotes }, 502); }
  try { tcp = await createTcp(tunnel, tunnel.virtualIp, dstIp, port); }
  catch (e) { try { tunnel.close(); } catch { } return json({ ok: false, stage: 'tcp', error: String(e.message || e) }, 502); }
  const wr = tcp.writable.getWriter(), rd = tcp.readable.getReader();
  let text = '';
  try {
    await wr.write(enc(`GET ${path} HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: cf-worker-openvpn\r\nConnection: close\r\n\r\n`));
    for (let i = 0; i < 200; i++) {
      const { value, done } = await Promise.race([rd.read(), timeoutSec(6000)]);
      if (done) break;
      if (value) { text += new TextDecoder().decode(value); if (text.length > 8000) break; }
    }
  } catch { }
  try { tcp.close(); } catch { }
  return json({ ok: true, virtualIp: tunnel.virtualIp, target: host, targetIp: dstIp, response: text.slice(0, 8000) });
}

// Diagnostic: raw cloudflare:sockets connect() test against any target. Use to
// confirm whether CF allows outbound TCP to a given host/port (e.g. control
// checks: tcpbin.com:4242, 1.1.1.1:80, a VPN Gate node:443).
async function sockTest(req, transport) {
  const p = new URL(req.url).searchParams;
  const host = p.get('host') || 'tcpbin.com';
  const port = +(p.get('port') || 4242);
  let s;
  try {
    s = transport.connect({ hostname: host, port });
    await Promise.race([s.opened, timeoutSec(12000)]);
    const w = s.writable.getWriter(); const r = s.readable.getReader();
    await w.write(enc('ping\n'));
    const { value } = await Promise.race([r.read(), timeoutSec(8000)]);
    try { s.close(); } catch { }
    return json({ ok: true, host, port, echo: value ? new TextDecoder().decode(value).slice(0, 200) : null });
  } catch (e) {
    try { s && s.close(); } catch { }
    return json({ ok: false, host, port, error: String(e.message || e) }, 502);
  }
}

export async function route(req, transport) {
  const url = new URL(req.url);
  if (url.pathname === '/ovpn-test') return ovpnTest(req, transport);
  if (url.pathname === '/sock-test') return sockTest(req, transport);
  if (req.headers.get('Upgrade') === 'websocket') return handleWs(req, transport);
  return new Response('ok');
}

export { _cfg, _cfgErr };