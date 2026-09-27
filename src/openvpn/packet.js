// OpenVPN packet framing: control packets (with optional tls-auth) and the
// P_DATA_V1 / P_DATA_V2 headers. Over TCP each packet is length-prefixed by
// 2 bytes (handled in bytes.js TcpPacketStream).
import { concat, bytes, u16, u32, w16, w32, hex } from './bytes.js';
import { hmac } from './crypto.js';

export const OP = {
  P_CONTROL_HARD_RESET_CLIENT_V1: 1,
  P_CONTROL_HARD_RESET_SERVER_V1: 2,
  P_CONTROL_SOFT_RESET_V1: 3,
  P_CONTROL_V1: 4,
  P_ACK_V1: 5,
  P_DATA_V1: 6,
  P_CONTROL_HARD_RESET_CLIENT_V2: 7,
  P_CONTROL_HARD_RESET_SERVER_V2: 8,
  P_DATA_V2: 9,
};
export const OPCODE_SHIFT = 3;
export const KEY_ID_MASK = 0x07;
const SID_SIZE = 8;

// ---------- static key ----------
export function parseStaticKey(pem) {
  const b64 = String(pem).replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (out.length !== 256) throw new Error('OPENVPN_STATIC_KEY_LEN ' + out.length);
  return out;
}
// key[0] = first 128 bytes, key[1] = second 128 bytes.
function keyHalf(staticKey, idx) { return staticKey.subarray(idx * 128, idx * 128 + 128); }

// key-direction -> (outIndex, inIndex). 0 = NORMAL(out0,in1), 1 = INVERSE(out1,in0), default bidirectional? no -> treat no-direction as NORMAL(0,1)? 
// OpenVPN: key-direction 0 -> NORMAL (encrypt keys[0], decrypt keys[1]); 1 -> INVERSE (encrypt keys[1], decrypt keys[0]); absent -> bidirectional (both 0).
export function tlsAuthKeyIndices(keyDirection) {
  if (keyDirection === 1) return { out: 1, in: 0 };
  if (keyDirection === 0) return { out: 0, in: 1 };
  return { out: 0, in: 0 }; // bidirectional
}

// ---------- control packet -------------
// Build a control packet (the OpenVPN packet, without the 2-byte TCP length).
// opts: { opcode, keyId, sessionId(Uint8Array8), reliableId, ackSid(Uint8Array8|null),
//         ackIds (uint array), message, tlsAuthKey (256-byte|null), outIndex, hmacHash('SHA-1'...) }
export async function buildControl(opts) {
  const { opcode, keyId = 0, sessionId, reliableId, ackSid, ackIds = [], message = new Uint8Array(0), tlsAuthKey = null, outIndex = 0, hmacHash = 'SHA-1' } = opts;
  // payload: ack-array + reliableId(4) + message
  // ACK array layout: [count(1)][id(4)*count][peer-session-id(8)] (session-id LAST)
  const ackIdsArr = ackIds.filter(id => id != null);
  let payload;
  if (ackIdsArr.length && ackSid) {
    payload = concat(bytes([ackIdsArr.length]), ...ackIdsArr.map(id => { const b = new Uint8Array(4); w32(b, 0, id >>> 0); return b; }), ackSid);
  } else {
    payload = bytes([0]);
  }
  const relBuf = new Uint8Array(4); w32(relBuf, 0, reliableId >>> 0);
  // For P_ACK_V1 there is no reliableId in the payload.
  let body;
  if (opcode === OP.P_ACK_V1) body = payload;
  else body = concat(payload, relBuf, message);
  const header = (() => { const b = new Uint8Array(1); b[0] = (opcode << OPCODE_SHIFT) | (keyId & KEY_ID_MASK); return b; })();
  let packet = concat(header, sessionId, body);
  if (tlsAuthKey) {
    // long-form packet-id: time(4) + id(4) prepended before the hmac
    const time = Math.floor(Date.now() / 1000) >>> 0;
    const pidBuf = new Uint8Array(8); w32(pidBuf, 0, time); w32(pidBuf, 4, opts.tlsAuthId >>> 0);
    // hmac input: pidBuf || header || sessionId || body  (the whole packet with pid at front)
    const keyHalfBuf = keyHalf(tlsAuthKey, outIndex);
    const mac = await hmac(hmacHash, keyHalfBuf, concat(pidBuf, header, sessionId, body));
    const macBuf = new Uint8Array(20); macBuf.set(mac.subarray(0, 20));
    packet = concat(header, sessionId, macBuf, pidBuf, body);
  }
  return packet;
}

export class ControlParser {
  constructor(tlsAuthKey, keyDirection, hmacHash = 'SHA-1') {
    this.tlsAuthKey = tlsAuthKey;
    const idx = tlsAuthKeyIndices(keyDirection);
    this.inIndex = idx.in;
    this.hmacHash = hmacHash;
    this.lastId = 0; // received tls-auth wrap packet-id (high)
  }
  // returns { opcode, keyId, sessionId, ackSid, ackIds, reliableId, message, packetId }
  async parse(packet) {
    const p = packet;
    const first = p[0];
    const opcode = first >> OPCODE_SHIFT;
    const keyId = first & KEY_ID_MASK;
    const sessionId = p.subarray(1, 1 + SID_SIZE);
    let off = 1 + SID_SIZE;
    let time = -1, id = -1;
    if (this.tlsAuthKey) {
      const macLen = 20;
      if (p.length < off + macLen + 8) throw new Error('OPENVPN_PACKET_PARSE_FAILED');
      const mac = p.subarray(off, off + macLen); off += macLen;
      time = u32(p, off); id = u32(p, off + 4); off += 8;
      // verify hmac over time||id||first||sessionId||rest
      const keyHalfBuf = keyHalf(this.tlsAuthKey, this.inIndex);
      const expect = await hmac(this.hmacHash, keyHalfBuf, concat(p.subarray(off - 8, off), p.subarray(0, 1), p.subarray(1, 9), p.subarray(off)));
      if (!stableEq(mac.subarray(0, 20), expect.subarray(0, 20))) throw new Error('TLS_AUTH_FAILED');
      this.lastId = id;
    }
    const body = p.subarray(off);
    let ackCount = body[0], ackSid = null, ackIds = [], o = 1;
    for (let i = 0; i < ackCount; i++) { ackIds.push(u32(body, o)); o += 4; }
    if (ackCount > 0 && o + 8 <= body.length) { ackSid = body.subarray(o, o + 8); o += 8; }
    let reliableId = 0, message = new Uint8Array(0);
    if (opcode !== OP.P_ACK_V1) { reliableId = u32(body, o); o += 4; message = body.subarray(o); }
    return { opcode, keyId, sessionId, ackSid, ackIds, reliableId, message, time, id };
  }
}
function stableEq(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }

// ---------- data header ----------
export function dataHeaderV1(opcode, keyId) { const b = new Uint8Array(1); b[0] = (opcode << OPCODE_SHIFT) | (keyId & KEY_ID_MASK); return b; }
export function dataHeaderV2(opcode, keyId, peerId) {
  const b = new Uint8Array(4);
  b[0] = (opcode << OPCODE_SHIFT) | (keyId & KEY_ID_MASK);
  b[1] = (peerId >> 16) & 0xFF; b[2] = (peerId >> 8) & 0xFF; b[3] = peerId & 0xFF;
  return b;
}
export function parseDataHeader(packet) {
  const first = packet[0];
  const opcode = first >> OPCODE_SHIFT;
  const keyId = first & KEY_ID_MASK;
  if (opcode === OP.P_DATA_V2) {
    let peerId = 0;
    if (packet.length >= 4) peerId = (packet[1] << 16) | (packet[2] << 8) | packet[3];
    return { opcode, keyId, peerId, headerLen: 4 };
  }
  return { opcode, keyId, peerId: 0, headerLen: 1 };
}
