// Worker request routing: VLESS-over-WebSocket tunnel entry (unchanged from the
// original project) + an /ovpn-test diagnostic endpoint. Pure Workers JS.
import { parseVlessHeader, uuidToBytes } from './vless.js';
import { resolveIP } from './dns.js';
import { candidatesFor, markBad, isBad, listInfo, nodeList, rankByConnect } from './nodes.js';
import { openVpnConn } from './openvpn/client.js';
import { createTcp, getMux } from './tcp.js';
import { parseOvpn } from './openvpn/config.js';
import { concat, bytes, u16 } from './openvpn/bytes.js';
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
const BUILD = 'v2.11-nodes'; // live VPN Gate node source + slot rotation (fanout-style)
const idBytes = uuidToBytes(UUID); // strict 16-byte; throws if invalid
const enc = (s) => new TextEncoder().encode(s);
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json' } });
const timeoutSec = (ms) => new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms));
const MAX_ED = 8192;

// ---- trace ring buffer ----
// Every front-end stage is recorded here AND written to console.error, so a
// failed VLESS handshake can be diagnosed from inside the worker (GET /trace)
// without Logpush or Workers Logs permissions. Module scope => survives between
// requests for as long as the isolate is warm.
const TRACE = [];
function trace(line) {
  try {
    TRACE.push(new Date().toISOString().slice(11, 23) + ' ' + line);
    if (TRACE.length > 80) TRACE.shift();
  } catch { }
  try { console.error('[VLESS/OpenVPN] ' + line); } catch { }
}

const relay = async (rd, send, close) => {
  try { for (;;) { const { done, value } = await rd.read(); if (done) break; value?.byteLength && send(value); } }
  catch { }
  finally { try { rd.releaseLock(); } catch { } close(); }
};

// ---- OpenVPN exits (one pinned tunnel per client node) ----
// A VLESS node can be pinned to its OWN OpenVPN exit: the WebSocket path selects
// it (/e1 -> embedded remote #1, /e2 -> #2, ...), so importing several vless://
// links gives several nodes that each leave through a different VPN Gate server.
// Any other path joins the auto pool.
//
// Why pool at all: the control/TLS handshake with a VPN Gate node costs 3-7s
// (20s+ when a remote is dead). A real VPN client pays that once and then runs
// every TCP connection through the same layer-3 interface; so do we. A tunnel is
// reused while recently used, recycled after MAX_AGE, dropped the moment it dies.
const POOL_MAX = 3;                // distinct exits the AUTO pool may open
const BUSY_FLOWS = 2;              // open another exit once every warm one carries this many flows
const TUNNEL_TTL_MS = 120000;      // idle timeout per tunnel
const TUNNEL_MAX_AGE_MS = 600000;  // absolute lifetime per tunnel
const EXITS = new Map();           // key (e1.. | auto..) -> { mux, tunnel, vip, remoteKey, createdAt, usedAt }
const DIALING = new Map();         // remoteKey -> in-flight handshake promise
const remoteKeyOf = (r) => r.host + ':' + r.port;
const remotes = () => (_cfg && _cfg.remotes) || [];

function pruneExits() {
  const now = Date.now();
  for (const [k, t] of [...EXITS]) {
    const bad = !t.mux.alive
      || now - t.usedAt > TUNNEL_TTL_MS
      || now - t.createdAt > TUNNEL_MAX_AGE_MS
      || now > (t.keepaliveUntil || 0);   // nothing is holding the socket open any more
    if (bad) { EXITS.delete(k); trace('EXIT_DROP ' + k + ' ' + t.remoteKey + ' vip=' + t.vip + ' alive=' + t.mux.alive); try { t.mux.close(); } catch { } }
  }
}
function dropExitByMux(mux) {
  for (const [k, t] of [...EXITS]) {
    if (t.mux === mux) { EXITS.delete(k); trace('EXIT_DROP ' + k + ' ' + t.remoteKey + ' vip=' + t.vip + ' (unusable)'); try { t.mux.close(); } catch { } }
  }
}
// Pick among the emptiest warm exits in turn (round-robin on ties), so sequential
// connections leave through DIFFERENT VPN Gate servers instead of always #1.
let POOL_RR = 0;
function pickWarm() {
  const all = [...EXITS.values()].filter((t) => t.mux.alive);
  if (!all.length) return null;
  let min = Infinity;
  for (const t of all) if (t.mux.flows.size < min) min = t.mux.flows.size;
  const cands = all.filter((t) => t.mux.flows.size === min);
  POOL_RR = (POOL_RR + 1) % cands.length;
  return cands[POOL_RR];
}

// Dial ONE specific remote (cfg is shallow-copied with a single remote so
// openVpnConn can never silently fall through to a different node).
function dialRemote(remote, key, transport) {
  const rk = remoteKeyOf(remote);
  const inflight = DIALING.get(rk);
  if (inflight) { trace('EXIT_DIAL_JOIN ' + rk); return inflight; }
  trace('EXIT_DIAL ' + key + ' ' + rk);
  const p = (async () => {
    const one = Object.assign({}, _cfg, { remotes: [remote] });
    // Phase timings from the OpenVPN client land in /trace: with a ~100ms RTT to
    // the node the whole handshake should take well under 1s, so any phase that
    // reports seconds is a bug in our stack (not the network).
    const tunnel = await openVpnConn(one, transport, { log: (m) => trace('OVPN ' + m), controlTimeout: 5000 });
    if (!tunnel.virtualIp) throw new Error('OPENVPN_NO_VIRTUAL_IP');
    const entry = { mux: getMux(tunnel), tunnel, vip: tunnel.virtualIp, remoteKey: rk, key, createdAt: Date.now(), usedAt: Date.now(), keepaliveUntil: Date.now() + KEEPALIVE_MS };
    EXITS.set(key, entry);
    trace('EXIT_UP ' + key + ' ' + rk + ' vip=' + entry.vip + ' exits=' + EXITS.size);
    return entry;
  })().finally(() => { DIALING.delete(rk); });
  DIALING.set(rk, p);
  return p;
}

// Pinned slot for /e<N>. Which node it uses may CHANGE (fanout's "换一个节点，
// 端口不变"): a dead or blacklisted remote is swapped for a newly fetched one
// while the slot key -- and therefore the client's share link -- stays the same.
// The slot's own node is tried first, then up to 6 live candidates, same country
// first, then the embedded bootstrap list.
async function acquirePinned(n, transport) {
  pruneExits();
  const key = 'e' + n;
  const cur = EXITS.get(key);
  if (cur && cur.mux.alive && Date.now() < (cur.keepaliveUntil || 0) && (Date.now() - cur.usedAt) < WARM_REUSE_MS) {
    cur.usedAt = Date.now();
    trace('EXIT_REUSE ' + key + ' vip=' + cur.vip + ' flows=' + cur.mux.flows.size);
    return { mux: cur.mux, fresh: false };
  }
  if (cur) { trace('EXIT_STALE ' + key + ' ' + cur.remoteKey + ' -> rotate'); dropExitByMux(cur.mux); }
  const avoid = new Set([...EXITS.entries()].filter(([k]) => k !== key).map(([, t]) => t.remoteKey));
  const wanted = (cur && cur.cc) || null;
  const seen = new Set(); const list = [];
  const addOne = (r) => {
    if (!r || !r.host || !r.port) return;
    const rk = r.host + ':' + r.port;
    if (seen.has(rk) || isBad(rk)) return;
    seen.add(rk); list.push({ host: r.host, port: r.port, cc: r.cc || 'boot', rk });
  };
  addOne(remotes()[n - 1]);                                   // this slot's configured node first
  // Only if that node is gone do we consult the live list: probe a few candidates
  // in small batches (1 RTT each) and dial the fastest first. The first entry
  // stays the slot's own node, so the common case is a single dial.
  const cands = await candidatesFor(wanted, avoid, remotes(), 6);
  const ranked = await rankByConnect(transport, cands, 3);
  for (const c of ranked) addOne(c);
  if (!list.length) { const e = new Error('EXIT_NO_CANDIDATES e' + n); e.code = 'EXIT_NO_CANDIDATES'; throw e; }
  let lastErr = null;
  for (const c of list) {
    try {
      const entry = await dialRemote(c, key, transport);
      entry.cc = c.cc;
      EXITS.set(key, entry);                                  // slot key never changes
      return { mux: entry.mux, fresh: true };
    } catch (err) {
      lastErr = err; markBad(c.rk);
      trace('EXIT_DIAL_FAIL ' + c.rk + ' ' + ((err && err.message) || err));
    }
  }
  throw lastErr || new Error('EXIT_ALL_CANDIDATES_FAILED e' + n);
}

// AUTO: share a warm exit that is not yet busy, otherwise open a NEW exit with an
// unused remote (different outbound IP), otherwise share the emptiest one.
async function acquireAuto(transport) {
  pruneExits();
  const best = pickWarm();
  if (best && best.mux.flows.size < BUSY_FLOWS && (Date.now() - best.usedAt) < WARM_REUSE_MS) {
    best.usedAt = Date.now();
    trace('EXIT_REUSE ' + best.key + ' vip=' + best.vip + ' flows=' + best.mux.flows.size + ' exits=' + EXITS.size);
    return { mux: best.mux, fresh: false };
  }
  if (EXITS.size + DIALING.size < POOL_MAX) {
    const avoid = new Set([...EXITS.values()].map((t) => t.remoteKey));
    const cands = await candidatesFor(null, avoid, remotes(), 4);
    for (const c of cands) {
      try {
        const e = await dialRemote(c, 'auto' + (EXITS.size + 1), transport);
        e.cc = c.cc; EXITS.set(e.key, e);
        return { mux: e.mux, fresh: true };
      } catch (err) { markBad(c.rk); trace('EXIT_DIAL_FAIL ' + c.rk + ' ' + ((err && err.message) || err)); }
    }
  }
  if (best) { best.usedAt = Date.now(); trace('EXIT_SHARE ' + best.key + ' flows=' + best.mux.flows.size); return { mux: best.mux, fresh: false }; }
  // Nothing warm at all: let openVpnConn walk the whole remote list.
  trace('EXIT_COLD_DIAL');
  const tunnel = await openVpnConn(_cfg, transport, { log: (m) => trace('OVPN ' + m) });
  if (!tunnel.virtualIp) throw new Error('OPENVPN_NO_VIRTUAL_IP');
  const entry = { mux: getMux(tunnel), tunnel, vip: tunnel.virtualIp, remoteKey: 'auto', key: 'auto', createdAt: Date.now(), usedAt: Date.now() };
  EXITS.set('auto', entry);
  trace('EXIT_UP auto vip=' + entry.vip + ' exits=' + EXITS.size);
  return { mux: entry.mux, fresh: true };
}

const KEEPALIVE_MS = 25000;        // how long ctx.waitUntil holds the tunnel's socket open
// VPN Gate pushes "ping 3,ping-restart 10": the SERVER restarts a session that
// stays silent for 10s. A tunnel that has not been touched for ~7s is therefore
// almost certainly dead -- reusing it used to burn the full SYN deadline and THEN
// dial a fresh one, which is exactly the "first test 100ms, second test times
// out" pattern. Treat anything older than this as stale and dial straight away.
const WARM_REUSE_MS = 7000;

// Cloudflare closes (or freezes) sockets opened inside a request once that request
// finishes, so a cached tunnel is only really usable while some execution context
// is still alive. A pending ctx.waitUntil keeps this isolate's context -- and the
// tunnel's pings -- running, so mark WHEN the tunnel stops being trustworthy and
// never hand out an expired one (that is what made "reuse" cost 10s per request).
function markKeepalive(mux) {
  const until = Date.now() + KEEPALIVE_MS;
  for (const t of EXITS.values()) if (t.mux === mux) t.keepaliveUntil = until;
}
function holdWake() {
  const ctx = PREWARM_CTX;
  if (!ctx || typeof ctx.waitUntil !== 'function') return;
  try { ctx.waitUntil(new Promise((r) => setTimeout(r, KEEPALIVE_MS - 3000))); } catch { }
}

// /e<N> (or ?exit=N) pins the node to exit #N; every other path uses the auto pool.
function exitIndexOf(req) {
  const url = new URL(req.url);
  const m = /^\/e(\d{1,2})\/?$/.exec(url.pathname || '');
  if (m) return +m[1];
  const q = url.searchParams.get('exit');
  return q && /^\d{1,2}$/.test(q) ? +q : 0;
}
async function acquireMux(transport, exitIndex) {
  return exitIndex ? acquirePinned(exitIndex, transport) : acquireAuto(transport);
}

// VPN Gate pushes "ping 3,ping-restart 10": the server restarts a session that
// stays silent for 10s, so an idle pooled tunnel dies within seconds and the next
// connection pays the full handshake again. Keep it warm in the background for as
// long as this isolate lives (the mux also pings every 2.5s while it has no flow).
let PREWARM_CTX = null, PREWARM_TRANSPORT = null;
export function setExecContext(ctx, transport) { PREWARM_CTX = ctx || null; PREWARM_TRANSPORT = transport || null; }

async function handleWs(req, transport) {
  const createPair = (transport && transport.createPair) || (() => Object.values(new WebSocketPair()));
  const [client, server] = createPair();
  server.accept();
  try { server.binaryType = 'arraybuffer'; } catch { /* not settable in this runtime; toBytes() covers it */ }
  const ed = req.headers.get('sec-websocket-protocol');
  // /e1../eN pins this VLESS node to its own OpenVPN exit; anything else is auto.
  const exitIndex = exitIndexOf(req);
  trace('WS_UPGRADE path=' + new URL(req.url).pathname + ' from=' + (req.headers.get('cf-connecting-ip') || '?') + ' proto=' + (ed || '-') + ' exit=' + (exitIndex || 'auto'));

  // VLESS front-end state machine (aligned with cfnew's data flow).
  let hdrBuf = new Uint8Array(0);
  let hdr = null;
  let hostname = '';
  let tcp = null, tcpW = null, tcpR = null;
  let buffered = [];                 // bytes arriving while the backend connects
  let headSent = false;              // response header [version,0] sent once
  let state = 'READING_VLESS_HEADER'; // READING_VLESS_HEADER | CONNECTING | RELAY | CLOSED
  let chain = Promise.resolve();

  const vlessErr = (code, message) => { const e = new Error(message); e.code = code; return e; };
  const logErr = (stage, err) => trace(stage + ' ' + ((err && err.code) || '') + ' ' + ((err && err.message) || String(err)));
  const closeWs = () => { try { tcp && tcp.close && tcp.close(); } catch { } try { server.close(); } catch { } state = 'CLOSED'; trace('WS_CLOSED'); };
  // A failing server.send() used to be swallowed; log it instead so a broken
  // outbound pipe is never invisible.
  const send = (d) => { try { server.send(d); } catch (e) { logErr('WS_SEND_FAILED', e); } };

  // remote (user-space TCP) -> client: prepend [version,0] exactly once
  const relayRemote = async (rd) => {
    trace('RELAY_START');
    try {
      for (;;) {
        const { value, done } = await rd.read();
        if (done) break;
        if (!value || !value.byteLength) continue;
        if (!headSent) {
          trace('FIRST_REMOTE n=' + value.byteLength + ' -> sending response header');
          send(concat(bytes([hdr.version]), bytes([0]), value)); headSent = true;
        } else send(value);
      }
      if (!headSent) { trace('REMOTE_EOF_EMPTY -> sending bare response header'); send(bytes([hdr.version, 0])); headSent = true; }
      closeWs();
    } catch (err) { logErr('VLESS_RELAY_READ', err); closeWs(); }
  };

  // Backend connect (cached OpenVPN tunnel + user-space TCP) + flush initial payload.
  const connectBackend = async (port, initialPayload) => {
    state = 'CONNECTING';
    try {
      let targetIp;
      try { targetIp = hdr.addrType === 1 ? hdr.host : await resolveIP(hdr.host); } catch { }
      if (!targetIp) throw vlessErr('VLESS_ADDRESS_INVALID', 'target resolve failed: ' + hdr.host);
      if (!_cfg) throw vlessErr('OPENVPN_CONFIG_MISSING', 'no VPN config loaded' + (_cfgErr ? ' (' + _cfgErr + ')' : ''));
      let vip = '', pickedMux = null;
      trace('CONNECT exit=' + (exitIndex || 'auto') + ' target=' + targetIp + ':' + port + ' remotes=' + ((_cfg.remotes || []).length));
      for (let attempt = 0; ; attempt++) {
        const pick = await acquireMux(transport, exitIndex);
        try {
          // A WARM (pooled) tunnel gets a shorter SYN deadline: a silently dead
          // tunnel must not cost the full 15s before we dial a fresh one.
          tcp = await createTcp(pick.mux, pick.mux.tunnel.virtualIp, targetIp, port, attempt === 0 && !pick.fresh ? 1500 : 15000);
          vip = pick.mux.tunnel.virtualIp;
          pickedMux = pick.mux;
          break;
        } catch (e) {
          if (attempt === 0 && (!pick.fresh || !pick.mux.alive)) { trace('EXIT_UNUSABLE ' + ((e && e.code) || '') + ' ' + ((e && e.message) || '')); dropExitByMux(pick.mux); continue; }
          throw e;
        }
      }
      trace('TCP_OPEN ' + targetIp + ':' + port + ' vip=' + vip);
      // Hold this isolate -- and therefore the tunnel's socket -- open for the
      // next connection. Without a pending context CF tears the idle socket down
      // after the response, which is why "reuse" used to time out after 10s.
      if (pickedMux) { markKeepalive(pickedMux); holdWake(); }
    } catch (err) { logErr('OPENVPN_CONNECT_FAILED', err); closeWs(); return; }
    tcpW = tcp.writable.getWriter();
    tcpR = tcp.readable.getReader();
    state = 'RELAY';
    try {
      if (initialPayload && initialPayload.length) { await tcpW.write(initialPayload); trace('PAYLOAD_WRITTEN n=' + initialPayload.length); }
      while (buffered.length) await tcpW.write(buffered.shift());
    } catch (err) { logErr('TCP_WRITE_FAILED', err); closeWs(); return; }
    relayRemote(tcpR);
  };

  // ---- mux.cool (VLESS command 3) ----
  // Xray/v2rayN keep ONE WebSocket open and multiplex every client TCP connection
  // through it as mux frames. Rejecting command 3 (the old behaviour) meant the
  // DEFAULT v2rayN setup could never connect at all, and it also forced a fresh
  // OpenVPN handshake per connection. With mux the WS stays open, so the OpenVPN
  // tunnel stays warm and every new client connection costs ~1 tunnel RTT.
  const MUX_NEW = 1, MUX_KEEP = 2, MUX_END = 3, MUX_KA = 4, MUX_OPT_DATA = 1;
  const muxSessions = new Map();   // sessionID -> { sid, tcp, writer, queue, closed }
  let muxBuf = new Uint8Array(0);

  // Response frame: [2B metaLen=4][2B sessionID][1B status][1B option][2B dataLen][data]
  const muxFrame = (sid, status, data) => {
    const dl = data ? data.byteLength : 0;
    // End/KeepAlive frames carry NO length field at all (Xray common/mux/writer.go).
    // Writing one there desynchronises the client's frame reader and kills the
    // whole mux session -- which is why muxed connections showed up as dead.
    const bare = (status === MUX_END || status === MUX_KA);
    const out = new Uint8Array((bare ? 6 : 8) + dl);
    out[1] = 4;
    out[2] = (sid >> 8) & 0xFF; out[3] = sid & 0xFF;
    out[4] = status; out[5] = dl ? MUX_OPT_DATA : 0;
    if (!bare) { out[6] = (dl >> 8) & 0xFF; out[7] = dl & 0xFF; if (dl) out.set(data, 8); }
    return out;
  };
  const sendMux = (sid, status, data) => {
    if (!headSent) { send(concat(bytes([hdr.version]), bytes([0]), muxFrame(sid, status, data))); headSent = true; }
    else send(muxFrame(sid, status, data));
  };

  // Request frame: [2B metaLen][meta][2B dataLen][data]
  // meta = [2B sessionID][1B status][1B option] (+ [1B network][2B port][address] on New)
  const parseMux = (b) => {
    if (b.length < 4) return null;
    const metaLen = u16(b, 0);
    if (metaLen > 512) return { error: 'MUX_META_TOO_LONG ' + metaLen };
    if (b.length < 2 + metaLen) return null;
    const meta = b.subarray(2, 2 + metaLen);
    const status = meta[2];
    const f = { sid: u16(meta, 0), status, option: meta[3], target: null, data: null, len: 2 + metaLen };
    if (status === MUX_KA || status === MUX_END) return f;   // meta only: no length field
    if (b.length < 2 + metaLen + 2) return null;
    const dataLen = u16(b, 2 + metaLen);
    const total = 2 + metaLen + 2 + dataLen;
    if (b.length < total) return null;
    f.data = b.subarray(2 + metaLen + 2, total);
    f.len = total;
    if (status === MUX_NEW && metaLen > 5) {
      let o = 5;                                   // meta[4] = network (1 tcp / 2 udp)
      const atype = meta[o++];
      const port = u16(meta, o); o += 2;           // PortThenAddress
      let host = null;
      if (atype === 1) { host = meta[o] + '.' + meta[o + 1] + '.' + meta[o + 2] + '.' + meta[o + 3]; o += 4; }
      else if (atype === 2) { const l = meta[o++]; host = new TextDecoder().decode(meta.subarray(o, o + l)); o += l; }
      else if (atype === 3) { const g = []; for (let i = 0; i < 8; i++) g.push(u16(meta, o + i * 2).toString(16)); host = g.join(':'); o += 16; }
      else return { error: 'MUX_ADDR_TYPE ' + atype };
      f.target = { net: meta[4], atype, host, port };
    }
    return f;
  };

  const muxOpen = async (f) => {
    const sess = { sid: f.sid, tcp: null, writer: null, queue: [], closed: false };
    muxSessions.set(f.sid, sess);
    try {
      let dstIp = f.target.host;
      if (f.target.atype !== 1) {
        try { dstIp = await resolveIP(f.target.host); } catch { }
        if (!dstIp) throw vlessErr('MUX_RESOLVE_FAILED', 'cannot resolve ' + f.target.host);
      }
      // One retry on a fresh exit: a pooled tunnel that died between sessions must
      // not kill the client's long-lived mux connection.
      let pick, t;
      for (let attempt = 0; ; attempt++) {
        pick = await acquireMux(transport, exitIndex);
        try { t = await createTcp(pick.mux, pick.mux.tunnel.virtualIp, dstIp, f.target.port, pick.fresh ? 15000 : 1500); break; }
        catch (e) {
          if (attempt === 0 && (!pick.fresh || !pick.mux.alive)) { trace('MUX_EXIT_UNUSABLE ' + ((e && e.code) || '')); dropExitByMux(pick.mux); continue; }
          throw e;
        }
      }
      if (sess.closed) { try { t.close(); } catch { } return; }
      sess.tcp = t; sess.writer = t.writable.getWriter();
      markKeepalive(pick.mux); holdWake();
      trace('MUX_OPEN sid=' + f.sid + ' ' + f.target.host + ':' + f.target.port + ' vip=' + pick.mux.tunnel.virtualIp + ' fresh=' + pick.fresh);
      if (f.data && f.data.byteLength) await sess.writer.write(f.data);
      while (sess.queue.length) await sess.writer.write(sess.queue.shift());
      (async () => {
        const rd = t.readable.getReader();
        try { for (;;) { const { value, done } = await rd.read(); if (done) break; if (value && value.byteLength) sendMux(f.sid, MUX_KEEP, value); } }
        catch (err) { logErr('MUX_RELAY_READ', err); }
        muxSessions.delete(f.sid);
        sendMux(f.sid, MUX_END, null);
        try { t.close(); } catch { }
      })();
    } catch (err) {
      logErr('MUX_OPEN_FAILED', err);
      muxSessions.delete(f.sid);
      sendMux(f.sid, MUX_END, null);
    }
  };

  const muxInput = (chunk) => {
    muxBuf = concat(muxBuf, chunk);
    for (;;) {
      const f = parseMux(muxBuf);
      if (!f) return;                              // need more bytes
      if (f.error) { logErr(f.error, new Error(f.error)); closeWs(); return; }
      muxBuf = muxBuf.subarray(f.len);
      const sess = muxSessions.get(f.sid);
      if (f.status === MUX_NEW) { muxOpen(f); continue; }
      if (f.status === MUX_END) { if (sess) { sess.closed = true; muxSessions.delete(f.sid); try { sess.tcp && sess.tcp.close(); } catch { } } continue; }
      if (f.status === MUX_KA) continue;
      if (!sess) continue;                         // stream already finished
      if (f.data && f.data.byteLength) {
        if (sess.writer) sess.writer.write(f.data).catch((e) => logErr('MUX_WRITE_FAILED', e));
        else sess.queue.push(f.data);              // still dialling its exit
      }
    }
  };

  const pushBytes = async (chunk) => {
    if (state === 'CLOSED' || !chunk) return;
    if (state === 'MUX') { muxInput(chunk); return; }
    if (state === 'RELAY') { if (tcpW) { try { await tcpW.write(chunk); } catch (err) { logErr('TCP_WRITE_FAILED', err); closeWs(); } } return; }
    if (state === 'CONNECTING') { buffered.push(chunk); trace('BUFFERED_WHILE_CONNECTING n=' + chunk.length); return; }
    // READING_VLESS_HEADER: accumulate, never assume a WS message == a full header
    hdrBuf = concat(hdrBuf, chunk);
    if (!hdr) {
      const p = parseVlessHeader(hdrBuf, idBytes);
      if (p === null) { trace('HDR_PARTIAL have=' + hdrBuf.length); return; } // wait for more bytes
      if (p.error) { logErr(p.error, new Error(p.message)); try { server.send('VLESS_REJECT'); } catch { } closeWs(); return; }
      hdr = p;
      hostname = p.host;
      trace('VLESS_HEADER_OK host=' + p.host + ' port=' + p.port + ' type=' + p.addrType + ' cmd=' + p.cmd + ' headerLen=' + p.headerLen + ' buffered=' + hdrBuf.length);
      const rest = hdrBuf.subarray(p.headerLen);
      hdrBuf = null;
      // command 3 = mux.cool: the payload is a stream of mux frames, each opening
      // its own TCP flow through a shared (warm) OpenVPN tunnel.
      if (p.cmd === 3) { state = 'MUX'; trace('VLESS_MUX_START rest=' + rest.length); if (rest.length) muxInput(rest); return; }
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
      if (early.length) { trace('EARLY_DATA n=' + early.length); chain = chain.then(() => pushBytes(early)).catch((e) => logErr('VLESS_EARLY_DATA', e)); }
    } catch { /* a subprotocol value or bad base64: ignore */ }
  }
  // WS message payloads are not uniformly an ArrayBuffer across runtimes: they
  // can also be a typed-array view, a Blob, or a string. The original code only
  // handled ArrayBuffer, so a Blob/other frame silently degraded to 0 bytes and
  // the VLESS header was never parsed (client saw a dead tunnel / "-1").
  const toBytes = async (data) => {
    if (typeof data === 'string') return enc(data);
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    if (data && typeof data.arrayBuffer === 'function') return new Uint8Array(await data.arrayBuffer());
    return new Uint8Array(0);
  };
  server.addEventListener('message', (e) => {
    const raw = e.data;
    const ctorName = (raw && raw.constructor && raw.constructor.name) || typeof raw;
    chain = chain.then(async () => {
      const d = await toBytes(raw);
      // Trace every inbound frame: length + runtime type + first bytes tell apart
      // "never delivered" / "delivered but garbled" / "delivered intact".
      try {
        let hx = ''; for (let i = 0; i < d.length && i < 64; i++) hx += d[i].toString(16).padStart(2, '0');
        trace('WS_MSG len=' + d.length + ' ctor=' + ctorName + ' bt=' + (server.binaryType) + ' state=' + state + ' first=' + hx);
      } catch { }
      if (d.length) await pushBytes(d);
    }).catch((err) => logErr('VLESS_MESSAGE', err));
  });
  server.addEventListener('close', closeWs);
  server.addEventListener('error', (e) => { logErr('WS_ERROR', e); closeWs(); });
  // Match the canonical Cloudflare / cfnew 101 exactly: no extra headers. An
  // empty `Sec-WebSocket-Extensions` value is not a valid RFC6455 extension list
  // and can leave the upgraded socket without a working message pipe.
  return new Response(null, { status: 101, webSocket: client });
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
  // Collect OpenVPN phase timings and return them in the JSON: with a ~100ms RTT
  // to the node the whole handshake must be well under 1s, so a phase reporting
  // seconds pinpoints a bug in our stack instead of guessing.
  const t0 = Date.now();
  const phases = [];
  const logPhase = (m) => { phases.push((Date.now() - t0) + 'ms ' + m); try { trace('OVPN ' + m); } catch { } };
  try { tunnel = await openVpnConn(cfg, transport, { log: logPhase }); }
  catch (e) { return json({ ok: false, stage: 'openvpn', remotes: cfg.remotes, phases, error: String(e.message || e) }, 502); }
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
  // This diagnostic deliberately uses a private tunnel, so close it here (a
  // flow no longer owns its tunnel -- shared tunnels must stay up).
  try { tunnel.close(); } catch { }
  return json({ ok: true, virtualIp: tunnel.virtualIp, target: host, targetIp: dstIp, totalMs: Date.now() - t0, phases, response: text.slice(0, 8000) });
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

// WS diagnostic endpoint (proves both WS directions independently of VLESS):
//  1. on connect it immediately SENDS a greeting frame  -> tests server->client
//  2. every client message is echoed back               -> tests client->server
// Text frames are handled too (ByteLength is undefined on a string), so a plain
// "ping" still yields a meaningful echo.
async function handleDbg(req, transport) {
  const createPair = (transport && transport.createPair) || (() => Object.values(new WebSocketPair()));
  const [client, server] = createPair();
  server.accept();
  let greetingSent = false;
  const sendGreeting = () => {
    if (greetingSent) return;
    greetingSent = true;
    try { server.send('DBG_HELLO ' + BUILD); } catch { }
  };
  // send right away AND (belt and braces) on the first inbound message, so a lost
  // pre-listener frame still cannot hide a working outbound pipe.
  sendGreeting();
  server.addEventListener('message', (e) => {
    try {
      sendGreeting();
      const d = e.data;
      const u = typeof d === 'string' ? enc(d)
        : d instanceof ArrayBuffer ? new Uint8Array(d)
          : (d && d.buffer) ? new Uint8Array(d.buffer)
            : new Uint8Array(0);
      trace('DBG_MSG len=' + u.length + ' type=' + (typeof d));
      let hex = ''; for (let i = 0; i < u.length && i < 64; i++) hex += u[i].toString(16).padStart(2, '0');
      server.send('DBG_ECHO:' + u.length + ':' + hex);
    } catch (err) { try { server.send('DBG_ERR:' + ((err && err.message) || 'x')); } catch { } }
  });
  server.addEventListener('close', () => { });
  server.addEventListener('error', () => { });
  return new Response(null, { status: 101, webSocket: client });
}

// Diagnostic: run ONE plain-HTTP request through a POOLED exit (the warm path a
// real VLESS connection takes) and report phase timings, so "why is a reused
// connection still slow" is measured instead of guessed.
async function exitTest(req, transport) {
  const p = new URL(req.url).searchParams;
  const n = +(p.get('exit') || 0);
  const target = p.get('target') || 'cp.cloudflare.com';
  const port = +(p.get('port') || 80);
  const path = p.get('path') || '/generate_204';
  const t0 = Date.now(); const ph = [];
  const mark = (m) => ph.push((Date.now() - t0) + 'ms ' + m);
  let dstIp = target;
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(target)) { try { dstIp = await resolveIP(target); } catch { } }
  mark('resolved ' + dstIp);
  const pick = await acquireMux(transport, n);
  mark('acquire exit=' + (n || 'auto') + ' fresh=' + pick.fresh + ' vip=' + pick.mux.tunnel.virtualIp);
  let tcp;
  try { tcp = await createTcp(pick.mux, pick.mux.tunnel.virtualIp, dstIp, port, 10000); }
  catch (e) { mark('tcp FAILED ' + ((e && e.code) || e)); return json({ ok: false, exit: n || 'auto', fresh: pick.fresh, phases: ph, error: String((e && e.message) || e) }, 502); }
  mark('tcp established (1 tunnel RTT)');
  const wr = tcp.writable.getWriter(), rd = tcp.readable.getReader();
  const t1 = Date.now();
  await wr.write(enc(`GET ${path} HTTP/1.0\r\nHost: ${target}\r\nConnection: close\r\n\r\n`));
  mark('request written');
  let text = '', first = 0;
  try {
    for (let i = 0; i < 200; i++) {
      const { value, done } = await Promise.race([rd.read(), timeoutSec(6000)]);
      if (done) break;
      if (value && value.byteLength) { if (!first) { first = Date.now() - t1; mark('first byte +' + first + 'ms (1 tunnel RTT)'); } text += new TextDecoder().decode(value); if (text.length > 2000) break; }
    }
  } catch { }
  mark('done');
  try { tcp.close(); } catch { }
  return json({ ok: true, exit: n || 'auto', fresh: pick.fresh, vip: pick.mux.tunnel.virtualIp, target, totalMs: Date.now() - t0, phases: ph, response: text.slice(0, 300) });
}

// Diagnostic: raw TCP connect latency (exactly 1 RTT, no write/read) to any
// host:port, N samples. This isolates "the node/route is slow" (a property of
// the free VPN Gate exit) from "our stack is slow" (a bug we can fix).
async function pingTest(req, transport) {
  const p = new URL(req.url).searchParams;
  const host = p.get('host');
  const port = +(p.get('port') || 80);
  const n = Math.max(1, Math.min(+(p.get('n') || 3), 8));
  if (!host) return json({ ok: false, error: 'host required' }, 400);
  const samples = [];
  for (let i = 0; i < n; i++) {
    const t0 = Date.now();
    let s;
    try {
      s = transport.connect({ hostname: host, port });
      await Promise.race([s.opened, timeoutSec(8000)]);
      samples.push(Date.now() - t0);
    } catch { samples.push(-1); }
    finally { try { s && s.close(); } catch { } }
  }
  const ok = samples.filter((x) => x >= 0);
  return json({
    ok: ok.length > 0, host, port, samples,
    min: ok.length ? Math.min(...ok) : -1,
    avg: ok.length ? Math.round(ok.reduce((a, b) => a + b, 0) / ok.length) : -1,
    failed: samples.length - ok.length,
  });
}

export async function route(req, transport, ctx) {
  setExecContext(ctx, transport);
  const url = new URL(req.url);
  // WS upgrades take priority: a VLESS client may use ANY path (but never keep
  // /ovpn-test|/sock-test|/version as plain HTTP workers from a client's path).
  if (req.headers.get('Upgrade') === 'websocket') {
    if (url.pathname === '/dbg-ws') return handleDbg(req, transport);
    return handleWs(req, transport);
  }
  if (url.pathname === '/ovpn-test') return ovpnTest(req, transport);
  if (url.pathname === '/ping') return pingTest(req, transport);
  if (url.pathname === '/exit-test') return exitTest(req, transport);
  if (url.pathname === '/sock-test') return sockTest(req, transport);
  // Subscription: one URL that gives the client one node PER OpenVPN exit (/e1../eN)
  // plus an auto node. Import it in v2rayN/mihomo and every node leaves through a
  // different VPN Gate server, so the client can latency-test and pick the best.
  if (url.pathname === '/sub') {
    const host = url.hostname;
    const link = (path, name) => {
      const q = new URLSearchParams({ type: 'ws', encryption: 'none', host, path, security: 'tls', sni: host, fp: 'chrome' });
      return 'vless://' + UUID + '@' + host + ':443?' + q.toString() + '#' + encodeURIComponent(name);
    };
    // Node names carry only the SLOT number: the node behind a slot rotates
    // automatically (fanout-style) when one dies, so the name must stay stable.
    const lines = remotes().map((r, i) => link('/e' + (i + 1), 'OGate-' + String(i + 1).padStart(2, '0')));
    lines.push(link('/auto', 'OGate-auto'));
    return new Response(btoa(lines.join('\n')), { headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } });
  }
  // Live node source + slot -> node mapping (fanout-style rotation view).
  if (url.pathname === '/nodes') {
    pruneExits();
    await nodeList(url.searchParams.has('refresh'));   // fetch (and cache) the live list
    return json({
      list: listInfo(),
      slots: [...EXITS.entries()].map(([k, t]) => ({ slot: k, node: t.remoteKey, cc: t.cc || '', vip: t.vip, flows: t.mux.flows.size, alive: t.mux.alive, ageSec: Math.round((Date.now() - t.createdAt) / 1000) })),
      configured: remotes().map(remoteKeyOf),
    });
  }
  if (url.pathname === '/trace') return json({ name: 'cf-worker-openvpn', version: BUILD, count: TRACE.length, trace: TRACE });
  // Which OpenVPN exits are warm in this isolate? Every entry is one VPN Gate
  // node with its own tunnel (and its own outbound IP); /e<N> pins node #N.
  if (url.pathname === '/tunnel') {
    pruneExits();
    return json({
      exits: [...EXITS.entries()].map(([k, t]) => ({ exit: k, node: t.remoteKey, vip: t.vip, flows: t.mux.flows.size, alive: t.mux.alive, ageSec: Math.round((Date.now() - t.createdAt) / 1000), idleSec: Math.round((Date.now() - t.usedAt) / 1000) })),
      dialing: [...DIALING.keys()], remotes: remotes().map(remoteKeyOf), autoPoolMax: POOL_MAX, busyFlows: BUSY_FLOWS,
    });
  }
  if (url.pathname === '/version') return json({ name: 'cf-worker-openvpn', version: BUILD, uuid: UUID, routes: ['/ovpn-test', '/sock-test', '/version', '/trace', '/tunnel', '/sub', '/e1../eN', '/auto'] });
  return new Response('ok');
}

export { _cfg, _cfgErr, TRACE };
