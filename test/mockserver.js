// Local mock OpenVPN TCP server for validating the client. Uses Node's real
// TLS stack for the control-channel TLS (independent validation of our TLS
// client), implements key_method 2, PUSH_REPLY and a minimal TCP peer over
// the data channel (AES-GCM or AES-CBC).
import net from 'net';
import tls from 'tls';
import { Duplex } from 'stream';
import fs from 'fs';
import { buildControl, ControlParser, OP, parseDataHeader } from '../src/openvpn/packet.js';
import { concat, bytes, u16, u32, rng32, w16, hex } from '../src/openvpn/bytes.js';
import { DataChannel } from '../src/openvpn/data.js';
import { keyExpansion, aesCbcEncrypt } from '../src/openvpn/crypto.js';
import { root } from './root.js';
import { makeSelfSigned } from './mockcert.js';

function writeStr(s) { const b = bytes(s); const out = new Uint8Array(2 + b.length + 1); w16(out, 0, b.length + 1); out.set(b, 2); out[2 + b.length] = 0; return out; }
function tryParseKm2(b) {
  if (b.length < 1 + 4 + 112 + 2) return null;
  if (b[0] !== 0 || b[1] !== 0 || b[2] !== 0 || b[3] !== 0) return null;
  if ((b[4] & 0x0F) !== 2) return null;
  const ks = { pre_master: b.subarray(5, 53), random1: b.subarray(53, 85), random2: b.subarray(85, 117) };
  let off = 117;
  for (let i = 0; i < 4; i++) { if (off + 2 > b.length) return null; const l = u16(b, off); if (l < 1 || off + 2 + l > b.length) return null; off += 2 + l; }
  return { keySource: ks, off };
}

function ipChecksum(d, o, n) { let s = 0; for (let i = o; i < o + n - 1; i += 2) s += u16(d, i); if (n & 1) s += d[o + n - 1] << 8; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); return (~s) & 0xFFFF; }

export async function startMockServer(opts = {}) {
  const cipher = opts.cipher || 'AES-128-GCM';
  const auth = opts.auth || 'SHA1';
  const useV2 = opts.useV2 !== false;
  const peerId = opts.peerId || 7;
  const log = opts.log || (() => {});
  const disableEms = !!opts.disableEms;
  const { certPem, keyPem } = await makeSelfSigned();
  const secureCtx = tls.createSecureContext({ key: keyPem, cert: certPem, secureOptions: disableEms ? 0x00000010 : 0 });
  let dataChan = null;
  let clientSid = null, serverSid = null, keySourceClient = null, keySourceServer = null;

  function handleConn(socket) {
    serverSid = crypto.getRandomValues(new Uint8Array(8));
    let nextRel = 1, pendingAcks = [];
    let buf = new Uint8Array(0);
    let closed = false;
    const frame = (pkt) => { const f = new Uint8Array(2 + pkt.length); f[0] = pkt.length >> 8; f[1] = pkt.length & 0xFF; f.set(pkt, 2); return f; };
    const send = (pkt) => { if (!closed) socket.write(frame(pkt)); };
    const sendCtrl = async (opcode, msg = new Uint8Array(0)) => {
      const pkt = await buildControl({ opcode, keyId: 0, sessionId: serverSid, reliableId: nextRel++, ackSid: clientSid, ackIds: pendingAcks, message: msg, tlsAuthKey: null });
      pendingAcks = [];
      send(pkt);
    };

    // TLS over the control channel
    const tlsOut = [];
    const TLSDUMP = root('test/tlsdump.log');
    const tlslog = (dir, b) => { if (opts.recordTls) { try { fs.appendFileSync(TLSDUMP, dir + ': ' + hex(new Uint8Array(b)) + '\n'); } catch { } } };
    const vd = new Duplex({ read() { }, write(chunk, enc, cb) { tlsOut.push(Buffer.from(chunk)); tlslog('SRV_TX', chunk); cb(); } });
    const tlsSock = new tls.TLSSocket(vd, { isServer: true, secureContext: secureCtx });
    tlsSock.on('keylog', (line) => log('KEYLOG: ' + line.toString('utf8')));
    let appBuf = new Uint8Array(0), tlsUp = false, kmSent = false, pushSent = false;
    const flushTls = () => { while (tlsOut.length) { const b = tlsOut.shift(); sendCtrl(OP.P_CONTROL_V1, new Uint8Array(b)); } };
    tlsSock.on('secure', () => { tlsUp = true; log('mock: TLS handshake complete'); });
    tlsSock.on('error', (e) => log('mock: tls error ' + e.message));
    tlsSock.on('data', async (dd) => {
      appBuf = concat(appBuf, new Uint8Array(dd));
      if (!kmSent) {
        const km = tryParseKm2(appBuf);
        if (km) {
          keySourceClient = km.keySource;
          appBuf = appBuf.subarray(km.off);
          kmSent = true;
          // send our key_method 2 (server writes random1 + random2 only)
          keySourceServer = { pre_master: new Uint8Array(0), random1: crypto.getRandomValues(new Uint8Array(32)), random2: crypto.getRandomValues(new Uint8Array(32)) };
          const msg = concat(bytes([0, 0, 0, 0]), bytes([2]), keySourceServer.random1, keySourceServer.random2,
            writeStr('V4,dev-type tun,link-mtu 1558,tun-mtu 1500,proto TCPv4_SERVER,cipher ' + cipher + ',auth ' + auth + ',keysize 256,key-method 2,tls-server'),
            writeStr(''), writeStr(''), writeStr('IV_VER=2.4.11\nIV_PROTO=2\n'));
          log('mock: sent server key_method_2');
          tlsSock.write(Buffer.from(msg));
          setImmediate(flushTls);
        }
      } else if (!pushSent && appBuf.length) {
        const s = new TextDecoder().decode(appBuf);
        if (s.includes('PUSH_REQUEST')) {
          appBuf = new Uint8Array(0);
          pushSent = true;
          const push = 'PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,route-gateway 10.8.0.1,topology subnet,peer-id ' + peerId + ',cipher ' + cipher + '\0';
          log('mock: sent PUSH_REPLY cipher=' + cipher);
          tlsSock.write(Buffer.from(push));
          setImmediate(async () => {
            flushTls();
            const keyBlock = await keyExpansion({ client: keySourceClient, server: keySourceServer }, clientSid, serverSid);
            dataChan = new DataChannel(keyBlock, cipher, auth, useV2, peerId, true);
            log('mock: data channel ready');
          });
        }
      }
    });

    // minimal TCP peer state
    const conns = new Map();
    const sendTcp = async (srcIp, dstIp, sport, dport, seq, ackv, flags, payload) => {
      if (!dataChan) return;
      const tl = 20 + payload.length, il = 20 + tl;
      const f = new Uint8Array(il), v = new DataView(f.buffer);
      f.set([0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6]); f.set(srcIp, 12); f.set(dstIp, 16);
      v.setUint16(2, il); v.setUint16(4, Math.floor(Math.random() * 65535)); v.setUint16(10, ipChecksum(f, 0, 20));
      v.setUint16(20, sport); v.setUint16(22, dport); v.setUint32(24, seq); v.setUint32(28, ackv);
      f[32] = 0x50; f[33] = flags; v.setUint16(34, 1400);
      if (payload.length) f.set(payload, 40);
      const pseudo = new Uint8Array(12 + tl);
      pseudo.set(srcIp, 0); pseudo.set(dstIp, 4); pseudo[9] = 6; v2(pseudo, 10, tl);
      pseudo.set(f.subarray(20, 20 + tl), 12);
      v.setUint16(36, ipChecksum(pseudo, 0, 12 + tl));
      const pkt = await dataChan.encrypt(f);
      send(pkt);
    };
    function v2(b, o, vv) { b[o] = vv >> 8 & 0xFF; b[o + 1] = vv & 0xFF; }

    const handleIp = async (ip) => {
      if (ip.length < 40 || ip[9] !== 6) return;
      const ihl = (ip[0] & 0xF) * 4;
      const srcIp = ip.subarray(12, 16), dstIp = ip.subarray(16, 20);
      const sport = u16(ip, ihl), dport = u16(ip, ihl + 2);
      const seq = u32(ip, ihl + 4), flags = ip[ihl + 13];
      const doff = (ip[ihl + 12] >> 4) * 4;
      const payload = ip.subarray(ihl + doff);
      const key = srcIp.join('.') + ':' + sport + ':' + dport;
      if ((flags & 0x02) && !(flags & 0x10)) {
        const s = rng32();
        conns.set(key, { s, ack: (seq + 1) >>> 0 });
        log('mock: TCP SYN -> SYN-ACK');
        await sendTcp(dstIp, srcIp, dport, sport, s, (seq + 1) >>> 0, 0x12, new Uint8Array(0));
      } else if (flags & 0x18 && payload.length) {
        const c = conns.get(key);
        const a = c ? c.ack : (seq + payload.length) >>> 0;
        const sSeq = c ? (c.s + 1) >>> 0 : rng32();
        const resp = bytes('HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nConnection: close\r\n\r\nmock-ok\n');
        log('mock: TCP data -> HTTP 200 + FIN');
        await sendTcp(dstIp, srcIp, dport, sport, sSeq, a, 0x18, resp);
        await sendTcp(dstIp, srcIp, dport, sport, (sSeq + resp.length) >>> 0, a, 0x11, new Uint8Array(0));
      }
    };

    const parser = new ControlParser(null, 0, 'SHA-1');
    const process = async () => {
      for (;;) {
        if (buf.length < 2) break;
        const plen = u16(buf, 0);
        if (plen < 1 || plen > 20000) { buf = new Uint8Array(0); break; }
        if (buf.length < 2 + plen) break;
        const pkt = buf.subarray(2, 2 + plen);
        buf = buf.subarray(2 + plen);
        const h = parseDataHeader(pkt);
        if (h.opcode === OP.P_DATA_V1 || h.opcode === OP.P_DATA_V2) {
          if (dataChan) { const ip = await dataChan.decrypt(pkt); if (ip) { log('mock: data ip len=' + ip.length + ' proto=' + ip[9]); await handleIp(ip); } else log('mock: data decrypt -> null'); }
        } else {
          const parsed = await parser.parse(pkt);
          if (parsed.opcode === OP.P_CONTROL_HARD_RESET_CLIENT_V2) {
            clientSid = parsed.sessionId;
            pendingAcks.push(parsed.reliableId);
            log('mock: client reset received');
            await sendCtrl(OP.P_CONTROL_HARD_RESET_SERVER_V2);
          } else if (parsed.opcode === OP.P_CONTROL_V1) {
            pendingAcks.push(parsed.reliableId);
            tlslog('SRV_RX', parsed.message);
            vd.push(Buffer.from(parsed.message));
            setImmediate(flushTls);
          }
        }
      }
    };
    socket.on('data', (d) => { buf = concat(buf, new Uint8Array(d)); process(); });
    socket.on('close', () => { closed = true; try { tlsSock.destroy(); } catch { } });
    socket.on('error', () => { closed = true; });
  }

  const srv = net.createServer(handleConn);
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const port = srv.address().port;
  return { port, certPem, keyPem, close: () => new Promise(r => srv.close(r)) };
}