// OpenVPN TCP client: orchestrates TCP connect -> reset -> TLS handshake ->
// key_method 2 (peer-info + key_source + user/pass) -> PUSH_REPLY -> data
// channel. Exposes a tunnel { readable, writable, close(), virtualIp } that the
// user-space TCP stack drives (createTcp). Pure Cloudflare Workers JS.
import { concat, bytes, u16, u32, w16, w32, rng, TcpPacketStream } from './bytes.js';
import { parseStaticKey, buildControl, ControlParser, OP, parseDataHeader, tlsAuthKeyIndices } from './packet.js';
import { ReliableChannel } from './control.js';
import { TlsClient } from './tls.js';
import { DataChannel } from './data.js';
import { keyExpansion } from './crypto.js';
import { parseOvpn } from './config.js';

const OP_ACK_ARRAY = OP;
const MSS = 1400; // not used here; kept for reference

// ---- key_method 2 helpers ----
function writeStr(s) {
  const b = bytes(s);
  const out = new Uint8Array(2 + b.length + 1);
  w16(out, 0, b.length + 1);
  out.set(b, 2);
  out[2 + b.length] = 0;
  return out;
}
function readStr(buf, off) { const len = u16(buf, off); const s = new TextDecoder().decode(buf.subarray(off + 2, off + 2 + len - 1)); return { s, off: off + 2 + len }; }

function localOptionsString(cfg) {
  const cipher = (cfg.cipher || 'AES-256-GCM');
  const auth = (cfg.auth || 'SHA1');
  return `V4,dev-type tun,link-mtu 1558,tun-mtu 1500,proto TCPv4_CLIENT,cipher ${cipher},auth ${auth},keysize 256,key-method 2,tls-client`;
}
function peerInfoString(cfg) {
  const ciphers = cfg.dataCiphers || 'AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC';
  return `IV_VER=2.4.11\nIV_PLAT=linux\nIV_PROTO=2\nIV_NCP=2\nIV_CIPHERS=${ciphers}\nIV_LZO=0\nIV_COMP_STUB=1\nIV_AUTO_SESS=1\nIV_GUI_VER=cf-worker\n`;
}

function buildKeyMethod2(cfg, keySource) {
  const msg = concat(
    bytes([0, 0, 0, 0]), bytes([2]),
    keySource.client.pre_master, keySource.client.random1, keySource.client.random2,
    writeStr(localOptionsString(cfg)),
    writeStr(cfg.username || 'vpn'),
    writeStr(cfg.password || 'vpn'),
    writeStr(peerInfoString(cfg))
  );
  return msg;
}

function parseKeyMethod2(buf) {
  // The server's key_method_2 response carries only random1 + random2 (the
  // pre_master is client-only and omitted on the server write side).
  if (buf.length < 1 + 4 + 64) return null;
  if (buf[0] !== 0) return null;
  const flags = buf[4];
  if ((flags & 0x0F) !== 2) return null;
  const server = {
    pre_master: new Uint8Array(0), // not sent by the server
    random1: buf.subarray(5, 37),
    random2: buf.subarray(37, 69),
  };
  let off = 69;
  let r;
  r = readStr(buf, off); const options = r.s; off = r.off;
  r = readStr(buf, off); const username = r.s; off = r.off;
  r = readStr(buf, off); const password = r.s; off = r.off;
  r = readStr(buf, off); const peerInfo = r.s; off = r.off;
  return { keySourceServer: server, options, username, password, peerInfo, off };
}

// ---- state machine ----
export async function openVpnConn(cfg, transport, opts = {}) {
  const log = opts.log || (() => {});
  const attempts = [];
  let lastErr;
  for (const remote of cfg.remotes) {
    try {
      log('trying remote ' + remote.host + ':' + remote.port);
      const tunnel = await tryRemote(remote, cfg, transport, log);
      return tunnel;
    } catch (e) {
      const msg = String((e && e.message) || e);
      log('remote ' + remote.host + ' failed: ' + msg);
      attempts.push(remote.host + ':' + remote.port + ' -> ' + msg);
      lastErr = e;
    }
  }
  const e = new Error('OPENVPN_ALL_REMOTES_FAILED [' + attempts.join(' | ') + ']');
  e.code = 'OPENVPN_ALL_REMOTES_FAILED';
  throw e;
}

async function tryRemote(remote, cfg, transport, log) {
  const connect = transport.connect;
  const sock = connect({ hostname: remote.host, port: remote.port });
  await sock.opened;
  log('TCP connected');
  const rd = sock.readable.getReader();
  const wr = sock.writable.getWriter();
  const tcpStream = new TcpPacketStream();
  const tlsAuthKey = cfg.tlsAuth ? parseStaticKey(cfg.tlsAuth) : null;

  // readable stream of decrypted IPv4 packets
  let readableCtrl = null, readableClosed = false;
  const readable = new ReadableStream({
    start: c => { readableCtrl = c; },
    cancel: () => { readableClosed = true; },
  });

  const ctrl = new ReliableChannel({
    write: (pkt) => { const f = new Uint8Array(2 + pkt.length); w16(f, 0, pkt.length); f.set(pkt, 2); wr.write(f).catch(() => { }); },
    tlsAuthKey, keyDirection: cfg.keyDirection || 0, hmacHash: normalizeAuth(cfg.auth), log,
  });

  // outbound TLS record bytes queue (flushed by state machine)
  const tlsOut = [];
  let tlsSending = false;
  const tls = new TlsClient({
    onSend: (rec) => tlsOut.push(rec),
    verifyCaPem: cfg.ca, sni: /^[0-9.]+$/.test(remote.host) ? null : remote.host,
    clientCertPem: cfg.cert, clientKeyPem: cfg.key,
    log, log2: log,
  });

  let data = null;
  let closeDone = false;
  const close = () => {
    if (closeDone) return; closeDone = true;
    try { rd.cancel().catch(() => {}); } catch { }
    try { wr.close().catch(() => {}); } catch { }
    try { sock.close(); } catch { }
    try { readableCtrl?.close(); } catch { }
    clearInterval(retransTimer);
  };
  const retransTimer = setInterval(() => { if (!closeDone && ctrl.pendingCount) ctrl.retransmit().catch(() => {}); }, 3000);

  // read loop
  const logx = log;
  const readLoop = (async () => {
    for (;;) {
      const { value, done } = await rd.read();
      if (done) throw new Error('VPN_REMOTE_CLOSED');
      for (const pkt of tcpStream.push(value)) {
        const h = parseDataHeader(pkt);
        if (h.opcode === OP.P_DATA_V1 || h.opcode === OP.P_DATA_V2) {
          if (data) {
            const ip = await data.decrypt(pkt);
            if (isPingPacket(ip)) { /* OpenVPN data-channel keepalive: ignore */ }
            else if (ip && readableCtrl) { try { readableCtrl.enqueue(ip); } catch { } }
            else if (logx) logx('data in decrypt(null) len=' + pkt.length);
          }
        } else {
          try {
            const parsed = await ctrl.parser.parse(pkt);
            await ctrl.handle(parsed);
          }
          catch (e) { throw e; }
        }
      }
    }
  })().catch(e => { log('readLoop error ' + (e.message || e)); close(); });

  const flushTls = async () => {
    while (tlsOut.length) {
      const rec = tlsOut.shift();
      await ctrl.sendControl(OP.P_CONTROL_V1, rec);
    }
  };
  // Persistent pump: feeds every incoming P_CONTROL_V1 (TLS record) to the TLS
  // client for the WHOLE session (handshake + application data), flushes any
  // outbound records, and ACKs. Runs until the socket is closed.
  const tlsDone = new Promise((r) => { tls.onDone = () => r(); });
  const controlPump = (async () => {
    for (;;) {
      const c = await ctrl.nextControl();
      try { await tls.feed(c.message); } catch (e) { log('tls feed error: ' + (e.message || e)); tls.err2 = e; break; }
      await flushTls();
      await ctrl.flushAcks();
    }
  })();
  controlPump.catch(() => { });

  let virtualIp = null;
  let peerId = 0, useV2 = false;
  let wrapped = false;

  try {
    // Reset
    await ctrl.sendControl(OP.P_CONTROL_HARD_RESET_CLIENT_V2);
    await Promise.race([ctrl.waitServerReset(), timeout(15000, 'CONTROL_TIMEOUT')]);
    log('server reset received');
    await flushAck(ctrl);
    // TLS handshake
    await tls.start();
    await flushTls();
    await Promise.race([tlsDone, timeout(20000, 'TLS_HANDSHAKE_FAILED')]);
    if (!tls.done) throw new Error('TLS_HANDSHAKE_FAILED');
    log('TLS handshake complete');

    // key_method 2
    const keySource = randomKeySource();
    const km2 = buildKeyMethod2(cfg, keySource);
    await tls.write(km2);
    await flushTls();
    await ctrl.flushAcks();
    // read server app data until we get key_method_2 response
    const serverKm2 = await waitForAppData(tls, 'key_method');
    const parsedKm = parseKeyMethod2(serverKm2);
    if (!parsedKm) {
      if (startsWith(serverKm2, 'AUTH_FAILED')) throw new Error('AUTH_FAILED');
      throw new Error('AUTH_FAILED');
    }
    log('server key_method_2 received');
    // push request
    await tls.write(bytes('PUSH_REQUEST\0'));
    await flushTls();
    await ctrl.flushAcks();
    const pushBuf = await waitForAppData(tls, 'push');
    const pushText = stripNull(pushBuf);
    const pushOptions = parsePushReply(pushText);
    log('PUSH: ' + pushText);
    // cipher
    const cipherName = pushOptions['cipher'] || cfg.cipher || 'AES-256-GCM';
    if (pushOptions['peer-id'] != null) { peerId = parseInt(pushOptions['peer-id'], 10); useV2 = true; }
    virtualIp = parseVirtualIP(pushOptions, pushText);

    // key expansion using client + server key source
    const keyBlock = await keyExpansion({
      client: { pre_master: keySource.client.pre_master, random1: keySource.client.random1, random2: keySource.client.random2 },
      server: parsedKm.keySourceServer,
    }, ctrl.sessionId, ctrl.remoteSid);
    data = new DataChannel(keyBlock, cipherName, cfg.auth || 'SHA1', useV2, peerId);
    log('data channel ready, cipher=' + cipherName + ' useV2=' + useV2 + ' peerId=' + peerId + ' virtualIp=' + virtualIp);
    wrapped = true;

    const writable = new WritableStream({
      async write(chunk) {
        const d = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
        const pkt = await data.encrypt(d);
        const f = new Uint8Array(2 + pkt.length); w16(f, 0, pkt.length); f.set(pkt, 2);
        await wr.write(f);
      },
      close: () => { },
      abort: close,
    });
    return { readable, writable, close, virtualIp };
  } catch (e) {
    close();
    throw e;
  }
}

function normalizeAuth(a) {
  const s = (a || 'SHA1').toUpperCase();
  if (!s.startsWith('SHA') && s !== 'MD5' && s !== 'NONE') return 'SHA1';
  return s;
}
function randomKeySource() {
  return {
    client: { pre_master: rng(48), random1: rng(32), random2: rng(32) },
  };
}
async function flushAck(ctrl) { try { await ctrl.flushAcks(); } catch { } }
function timeout(ms, code) { return new Promise((_, rej) => setTimeout(() => rej(new Error(code)), ms)); }

async function nextAppData(tls) {
  for (;;) {
    let c = tls.readAppData();
    if (c.length) return concat(...c);
    const w = tls.waitAppData();
    c = tls.readAppData(); // re-check after registering to close the race
    if (c.length) { tls.clearAppDataWaiter(); return concat(...c); }
    await w;
  }
}

// wait for the next app-data message from the server
async function waitForAppData(tls, kind) {
  for (let i = 0; i < 120; i++) {
    try {
      const chunk = await Promise.race([nextAppData(tls), timeout(500, 'T')]);
      if (chunk && chunk.length) return chunk;
    } catch { /* poll timeout: keep waiting for the server */ }
  }
  throw new Error(kind === 'push' ? 'PUSH_REPLY_FAILED' : 'AUTH_FAILED');
}

function startsWith(b, s) { const t = bytes(s); if (b.length < t.length) return false; for (let i = 0; i < t.length; i++) if (b[i] !== t[i]) return false; return true; }
// OpenVPN data-channel keepalive signature (SoftEther ping_signature)
const PING_SIG = [0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48];
function isPingPacket(ip) {
  if (!ip || ip.length !== PING_SIG.length) return false;
  for (let i = 0; i < PING_SIG.length; i++) if (ip[i] !== PING_SIG[i]) return false;
  return true;
}
function stripNull(b) { let i = 0; while (i < b.length && b[i] !== 0) i++; return new TextDecoder().decode(b.subarray(0, i)); }

function parsePushReply(text) {
  const opts = {};
  const m = /^PUSH_REPLY,(.*)$/s.exec(text.trim());
  const body = m ? m[1] : text;
  for (const part of body.split(',')) {
    const kv = part.split(' ');
    if (kv.length >= 2) opts[kv[0]] = kv.slice(1).join(' ');
  }
  return opts;
}

function parseVirtualIP(pushOptions, text) {
  let ip = null;
  if (pushOptions['ifconfig']) { const [a] = pushOptions['ifconfig'].split(' '); ip = a; }
  return ip;
}

export { parseOvpn };
