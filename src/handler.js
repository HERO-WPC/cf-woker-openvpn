// Worker request routing: VLESS-over-WebSocket tunnel entry (unchanged from the
// original project) + an /ovpn-test diagnostic endpoint. Pure Workers JS.
import { parseVlessHeader, uuidToBytes } from './vless.js';
import { resolveIP } from './dns.js';
import { openVpnConn } from './openvpn/client.js';
import { createTcp } from './tcp.js';
import { parseOvpn } from './openvpn/config.js';
import { concat, bytes } from './openvpn/bytes.js';
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
const BUILD = '8e77d8e'; // last committed hash; bump on every deploy
const idBytes = uuidToBytes(UUID); // strict 16-byte; throws if invalid
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
  const createPair = (transport && transport.createPair) || (() => Object.values(new WebSocketPair()));
  const [client, server] = createPair();
  server.accept();
  const ed = req.headers.get('sec-websocket-protocol');

  // VLESS front-end state machine (aligned with cfnew's data flow).
  let hdrBuf = new Uint8Array(0);
  let hdr = null;
  let tcp = null, tcpW = null, tcpR = null;
  let buffered = [];                 // bytes arriving while the backend connects
  let headSent = false;              // response header [version,0] sent once
  let state = 'READING_VLESS_HEADER'; // READING_VLESS_HEADER | CONNECTING | RELAY | CLOSED
  let chain = Promise.resolve();

  const vlessErr = (code, message) => { const e = new Error(message); e.code = code; return e; };
  const logErr = (stage, err) => { try { console.error('[VLESS/OpenVPN] ' + stage, (err && err.code) || '', (err && err.message) || String(err)); } catch { } };
  const closeWs = () => { try { tcp && tcp.close && tcp.close(); } catch { } try { server.close(); } catch { } state = 'CLOSED'; };
  const send = (d) => { try { server.send(d); } catch { } };

  // remote (user-space TCP) -> client: prepend [version,0] exactly once
  const relayRemote = async (rd) => {
    try {
      for (;;) {
        const { value, done } = await rd.read();
        if (done) break;
        if (!value || !value.byteLength) continue;
        if (!headSent) { send(concat(bytes([hdr.version]), bytes([0]), value)); headSent = true; }
        else send(value);
      }
      if (!headSent) { send(bytes([hdr.version, 0])); headSent = true; } // ensure header even with no remote data
      closeWs();
    } catch (err) { logErr('VLESS_RELAY_READ', err); closeWs(); }
  };

  // Backend connect (OpenVPN + user-space TCP) + flush initial payload.
  const connectBackend = async (port, initialPayload) => {
    state = 'CONNECTING';
    try {
      let targetIp;
      try { targetIp = hdr.addrType === 1 ? hdr.host : await resolveIP(hdr.host); } catch { }
      if (!targetIp) throw vlessErr('VLESS_ADDRESS_INVALID', 'target resolve failed: ' + hdr.host);
      if (!_cfg) throw vlessErr('OPENVPN_CONFIG_MISSING', 'no VPN config loaded');
      const tunnel = await openVpnConn(_cfg, transport);
      if (!tunnel.virtualIp) throw vlessErr('OPENVPN_CONNECT_FAILED', 'server connected but no virtual IP');
      tcp = await createTcp(tunnel, tunnel.virtualIp, targetIp, port);
    } catch (err) { logErr('OPENVPN_CONNECT_FAILED', err); closeWs(); return; }
    tcpW = tcp.writable.getWriter();
    tcpR = tcp.readable.getReader();
    state = 'RELAY';
    try {
      if (initialPayload && initialPayload.length) await tcpW.write(initialPayload);
      while (buffered.length) await tcpW.write(buffered.shift());
    } catch (err) { logErr('TCP_WRITE_FAILED', err); closeWs(); return; }
    relayRemote(tcpR);
  };

  const pushBytes = async (chunk) => {
    if (state === 'CLOSED' || !chunk) return;
    if (state === 'RELAY') { if (tcpW) { try { await tcpW.write(chunk); } catch (err) { logErr('TCP_WRITE_FAILED', err); closeWs(); } } return; }
    if (state === 'CONNECTING') { buffered.push(chunk); return; }
    // READING_VLESS_HEADER: accumulate, never assume a WS message == a full header
    hdrBuf = concat(hdrBuf, chunk);
    if (!hdr) {
      const p = parseVlessHeader(hdrBuf, idBytes);
      if (p === null) return; // wait for more bytes
      if (p.error) { logErr(p.error, new Error(p.message)); try { server.send('VLESS_REJECT'); } catch { } closeWs(); return; }
      hdr = p;
      const rest = hdrBuf.subarray(p.headerLen);
      hdrBuf = null;
      await connectBackend(p.port, rest);
      return;
    }
    // header parsed but bytes still arriving while connecting are buffered above
  };

  // early data (sec-websocket-protocol) feeds the SAME byte stream as messages.
  if (ed && ed.length <= MAX_ED) {
    try {
      const bin = atob(String(ed).replace(/-/g, '+').replace(/_/g, '/'));
      const early = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      if (early.length) chain = chain.then(() => pushBytes(early)).catch((e) => logErr('VLESS_EARLY_DATA', e));
    } catch { /* a subprotocol value or bad base64: ignore */ }
  }
  server.addEventListener('message', (e) => {
    const d = new Uint8Array(e.data instanceof ArrayBuffer ? e.data : (e.data && e.data.buffer) ?? e.data);
    if (d.length) chain = chain.then(() => pushBytes(d)).catch((err) => logErr('VLESS_MESSAGE', err));
  });
  server.addEventListener('close', closeWs);
  server.addEventListener('error', (e) => { logErr('WS_ERROR', e); closeWs(); });
  return new Response(null, { status: 101, webSocket: client, headers: { 'Sec-WebSocket-Extensions': '' } });
}

async function ovpnTest(req, transport) {
  const url = new URL(req.url);
  const p = url.searchParams;
  let cfgText = '', username = p.get('username') || 'vpn', password = p.get('password') || 'vpn';
  const target = p.get('target') || 'ip-api.com';
  const port = +(p.get('port') || 80);
  const path = p.get('path') || '/json/';
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
  if (url.pathname === '/version') return json({ name: 'cf-worker-openvpn', version: BUILD, uuid: UUID, routes: ['/ovpn-test', '/sock-test', '/version'] });
  if (req.headers.get('Upgrade') === 'websocket') return handleWs(req, transport);
  return new Response('ok');
}

export { _cfg, _cfgErr };