// OpenVPN data channel: AES-GCM (AEAD, P_DATA_V2/V1) and AES-CBC + HMAC.
// Uses the key block from keyExpansion. For a client, key_direction = NORMAL:
// encrypt uses keys[0], decrypt uses keys[1].
import { concat, bytes, u32, w32 } from './bytes.js';
import { aesGcmEncrypt, aesGcmDecrypt, aesCbcEncrypt, aesCbcDecrypt, hmac } from './crypto.js';
import { dataHeaderV1, dataHeaderV2, parseDataHeader, OP } from './packet.js';

const CIPHER_INFO = {
  'AES-256-GCM': { key: 32, gcm: true, iv: 12 },
  'AES-128-GCM': { key: 16, gcm: true, iv: 12 },
  'AES-256-CBC': { key: 32, gcm: false, iv: 16, block: 16 },
  'AES-128-CBC': { key: 16, gcm: false, iv: 16, block: 16 },
};

export class DataChannel {
  // keyBlock: 256 bytes; cipherName: e.g. 'AES-256-CBC'; auth: 'SHA1'|'SHA256'...
  // peerId: 0 if not using P_DATA_V2; useV2 decides header shape.
  // server: server half uses keys[1] to encrypt (KEY_DIRECTION_INVERSE).
  constructor(keyBlock, cipherName, auth = 'SHA1', useV2 = true, peerId = 0, server = false) {
    const info = CIPHER_INFO[cipherName];
    if (!info) throw new Error('CIPHER_NOT_SUPPORTED ' + cipherName);
    this.gcm = info.gcm;
    this.key = info.key;
    this.ivLen = info.iv;
    const macLen = auth.toUpperCase().startsWith('SHA512') ? 64 : auth.toUpperCase().startsWith('SHA384') ? 48 : auth.toUpperCase().startsWith('SHA256') ? 32 : 20;
    this.auth = auth.toUpperCase();
    this.macLen = this.gcm ? 0 : macLen;
    this.useV2 = useV2;
    this.peerId = peerId;
    // client: encrypt keys[0], decrypt keys[1]; server: the reverse
    const encIdx = server ? 1 : 0, decIdx = server ? 0 : 1;
    const encCipher = keyBlock.subarray(encIdx * 128, encIdx * 128 + this.key);
    const decCipher = keyBlock.subarray(decIdx * 128, decIdx * 128 + this.key);
    const encHmac = keyBlock.subarray(encIdx * 128 + 64, encIdx * 128 + 128);
    const decHmac = keyBlock.subarray(decIdx * 128 + 64, decIdx * 128 + 128);
    this.enc = info.gcm
      ? { key: encCipher, implicitIv: encHmac.subarray(0, this.ivLen - 4) }
      : { key: encCipher, hmacKey: encHmac.subarray(0, this.macLen) };
    this.dec = info.gcm
      ? { key: decCipher, implicitIv: decHmac.subarray(0, this.ivLen - 4) }
      : { key: decCipher, hmacKey: decHmac.subarray(0, this.macLen) };
    this.sendId = 1;
    this.recvId = 0;
    this.lastRecvId = 0;
  }
  header(opcode) {
    return this.useV2 ? dataHeaderV2(OP.P_DATA_V2, 0, this.peerId) : dataHeaderV1(OP.P_DATA_V1, 0);
  }
  // encrypt an IPv4 packet -> full P_DATA packet (without TCP length prefix)
  async encrypt(ipPacket) {
    const header = this.header();
    if (this.gcm) {
      const explicit = new Uint8Array(4); w32(explicit, 0, this.sendId++);
      const iv = concat(explicit, this.enc.implicitIv);
      const aad = concat(header, explicit);
      const ct = await aesGcmEncrypt(this.enc.key, iv, ipPacket, aad);
      return concat(header, explicit, ct);
    } else {
      const iv = crypto.getRandomValues(new Uint8Array(this.ivLen));
      const pid = new Uint8Array(4); w32(pid, 0, this.sendId++);
      const plaintext = concat(pid, ipPacket);
      const ct = await aesCbcEncrypt(this.enc.key, iv, plaintext);
      const mac = await hmac(this.auth, this.enc.hmacKey, concat(iv, ct));
      return concat(header, mac.subarray(0, this.macLen), iv, ct);
    }
  }
  // parse + decrypt a P_DATA packet -> IPv4 packet or null
  async decrypt(packet) {
    const h = parseDataHeader(packet);
    if (h.opcode !== OP.P_DATA_V1 && h.opcode !== OP.P_DATA_V2) return null;
    const headerLen = h.headerLen;
    const header = packet.subarray(0, headerLen);
    if (this.gcm) {
      if (packet.length < headerLen + 4 + 16) return null;
      const explicit = packet.subarray(headerLen, headerLen + 4);
      const id = u32(explicit, 0);
      if (id <= this.lastRecvId) return null; // replay
      this.lastRecvId = id;
      const iv = concat(explicit, this.dec.implicitIv);
      const aad = concat(header, explicit);
      const ct = packet.subarray(headerLen + 4);
      return aesGcmDecrypt(this.dec.key, iv, ct, aad);
    } else {
      if (packet.length < headerLen + this.macLen + this.ivLen + 1) return null;
      const mac = packet.subarray(headerLen, headerLen + this.macLen);
      const iv = packet.subarray(headerLen + this.macLen, headerLen + this.macLen + this.ivLen);
      const ct = packet.subarray(headerLen + this.macLen + this.ivLen);
      const expect = await hmac(this.auth, this.dec.hmacKey, concat(iv, ct));
      if (!stableEq(mac, expect.subarray(0, this.macLen))) return null;
      const pt = await aesCbcDecrypt(this.dec.key, iv, ct);
      if (!pt) return null;
      const pid = u32(pt, 0);
      if (pid <= this.lastRecvId) return null;
      this.lastRecvId = pid;
      return pt.subarray(4);
    }
  }
}
function stableEq(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
