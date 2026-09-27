// Crypto helpers for the OpenVPN client: pure-JS MD5/HMAC-MD5 (Web Crypto has
// no MD5 but OpenVPN's data-channel PRF needs the TLS1.0 MD5^SHA1 PRF),
// Web-Crypto AES-GCM / AES-CBC, HMAC-SHA1/SHA256/..., ECDH, RSA/ECDSA verify.
import { concat, bytes, u32, w32 } from './bytes.js';

// ---------- pure JS MD5 (RFC 1321) ----------
const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0);

export function md5(msg) {
  const bitLenHi = Math.floor(msg.length / 0x20000000); // msg.length*8 in 32-bit halves
  const bitLenLo = (msg.length * 8) >>> 0;
  const total = (((msg.length + 8) >> 6) + 1) << 6;
  const padded = new Uint8Array(total);
  padded.set(msg);
  padded[msg.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(total - 8, bitLenLo, true);
  dv.setUint32(total - 4, bitLenHi, true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Uint32Array(16);
  for (let i = 0; i < total; i += 64) {
    for (let j = 0; j < 16; j++) M[j] = dv.getUint32(i + j * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let j = 0; j < 64; j++) {
      let F, g;
      if (j < 16) { F = (B & C) | (~B & D); g = j; }
      else if (j < 32) { F = (D & B) | (~D & C); g = (5 * j + 1) % 16; }
      else if (j < 48) { F = B ^ C ^ D; g = (3 * j + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * j) % 16; }
      F = (F + A + MD5_K[j] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + ((F << MD5_S[j]) | (F >>> (32 - MD5_S[j])))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16);
  // MD5 digest is little-endian per word
  out[0] = a0 & 0xFF; out[1] = (a0 >>> 8) & 0xFF; out[2] = (a0 >>> 16) & 0xFF; out[3] = (a0 >>> 24) & 0xFF;
  out[4] = b0 & 0xFF; out[5] = (b0 >>> 8) & 0xFF; out[6] = (b0 >>> 16) & 0xFF; out[7] = (b0 >>> 24) & 0xFF;
  out[8] = c0 & 0xFF; out[9] = (c0 >>> 8) & 0xFF; out[10] = (c0 >>> 16) & 0xFF; out[11] = (c0 >>> 24) & 0xFF;
  out[12] = d0 & 0xFF; out[13] = (d0 >>> 8) & 0xFF; out[14] = (d0 >>> 16) & 0xFF; out[15] = (d0 >>> 24) & 0xFF;
  return out;
}

export function hmacMd5(key, msg) {
  let k = key;
  if (k.length > 64) k = md5(k);
  const kp = new Uint8Array(64); kp.set(k);
  const ipad = new Uint8Array(64), opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) { ipad[i] = kp[i] ^ 0x36; opad[i] = kp[i] ^ 0x5c; }
  return md5(concat(opad, md5(concat(ipad, msg))));
}

// ---------- Web Crypto wrappers ----------
const subtle = globalThis.crypto?.subtle;
const HASH_TO_NAME = { 'SHA-1': 'SHA-1', 'SHA1': 'SHA-1', 'SHA-256': 'SHA-256', 'SHA256': 'SHA-256', 'SHA-384': 'SHA-384', 'SHA384': 'SHA-384', 'SHA-512': 'SHA-512', 'SHA512': 'SHA-512' };

export async function hmac(name, key, data) {
  if (name === 'MD5' || name === 'MD4') throw new Error('MD5 HMAC must use hmacMd5');
  const algo = { name: 'HMAC', hash: HASH_TO_NAME[name] || name };
  const k = await subtle.importKey('raw', key, algo, false, ['sign']);
  return new Uint8Array(await subtle.sign(algo, k, data));
}

// P_hash(hash, secret, seed) from TLS PRF. MD5 uses the pure-JS path.
export async function pHash(name, secret, seed, outLen) {
  const hmacFn = name === 'MD5' ? hmacMd5 : ((k, d) => hmac(name, k, d));
  let A1 = await hmacFn(secret, seed);
  const out = new Uint8Array(outLen);
  let o = 0;
  while (o < outLen) {
    const block = await hmacFn(secret, concat(A1, seed));
    const need = Math.min(block.length, outLen - o);
    out.set(block.subarray(0, need), o);
    o += need;
    A1 = await hmacFn(secret, A1);
  }
  return out;
}

// OpenVPN's tls1_PRF: TLS1.0-style PRF (MD5 half XOR SHA1 half).
export async function openvpnPRF(secret, seed, outLen) {
  const slen = secret.length;
  const half = slen >> 1;
  const len = half + (slen & 1);
  const S1 = secret.subarray(0, len);
  const S2 = secret.subarray(half, half + len);
  const out1 = await pHash('MD5', S1, seed, outLen);
  const out2 = await pHash('SHA1', S2, seed, outLen);
  const out = new Uint8Array(outLen);
  for (let i = 0; i < outLen; i++) out[i] = out1[i] ^ out2[i];
  return out;
}

// TLS 1.2 PRF: P_hash(secret, label || seed) with the suite hash.
export async function tlsPRF12(secret, label, seed, hash, outLen) {
  return pHash(HASH_TO_NAME[hash] || hash, secret, concat(bytes(label), seed), outLen);
}

// OpenVPN data-channel key expansion (see ssl.c generate_key_expansion).
// key_src client/server = { pre_master[48], random1[32], random2[32] }
// clientSid/serverSid = 8-byte session ids.
// Returns the 256-byte key2.keys block.
export async function keyExpansion(keySrc, clientSid, serverSid) {
  const { client, server } = keySrc;
  const master = await openvpnPRF(client.pre_master, concat(bytes('OpenVPN master secret'), client.random1, server.random1), 48);
  const block = await openvpnPRF(master, concat(bytes('OpenVPN key expansion'), client.random2, server.random2, clientSid, serverSid), 256);
  return block;
}

// ---------- AES ----------
export async function aesGcmEncrypt(keyBytes, iv, plaintext, aad) {
  const key = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, plaintext));
}
export async function aesGcmDecrypt(keyBytes, iv, data /*ciphertext+tag*/, aad) {
  try {
    const key = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, data));
  } catch { return null; }
}
export async function aesCbcEncrypt(keyBytes, iv, plaintext) {
  const key = await subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['encrypt']);
  // WebCrypto AES-CBC encrypt adds PKCS#7 padding itself; do NOT pre-pad.
  return new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, key, plaintext));
}
export async function aesCbcDecrypt(keyBytes, iv, ciphertext) {
  try {
    const key = await subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
    // WebCrypto AES-CBC decrypt strips PKCS#7 padding itself; do NOT re-unpad.
    return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv }, key, ciphertext));
  } catch { return null; }
}

// ---------- RSA PKCS#1 v1.5 signing (client-certificate auth) ----------
// WebCrypto has no raw RSA private-key op, so TLS 1.2 ClientCertificateVerify
// is done in pure JS: EM ^ d mod n over the SHA-256 DigestInfo block.
const _b2i = (b) => { let v = 0n; for (const c of b) v = (v << 8n) | BigInt(c); return v; };
function _i2b(v, len) { const out = new Uint8Array(len); let i = len; while (i-- > 0) { out[i] = Number(v & 0xffn); v >>= 8n; } return out; }
function _modPow(base, exp, mod) { let r = 1n; base %= mod; while (exp > 0n) { if (exp & 1n) r = (r * base) % mod; base = (base * base) % mod; exp >>= 1n; } return r; }
const SHA256_DIGESTINFO = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

// sign `data` (the handshake transcript hash input) with an RSA private key
export async function rsaSignPkcs1v15(priv, data) {
  const digest = new Uint8Array(await subtle.digest('SHA-256', data));
  const di = new Uint8Array(SHA256_DIGESTINFO.length + 32);
  di.set(SHA256_DIGESTINFO); di.set(digest, SHA256_DIGESTINFO.length);
  let k = 0; for (let t = priv.n; t > 0n; t >>= 8n) k++;
  if (k < 2 + di.length + 1) throw new Error('RSA_KEY_TOO_SMALL');
  const sb = new Uint8Array(k);
  sb[0] = 0x00; sb[1] = 0x01;
  let o = 2;
  const padLen = k - 2 - di.length - 1;
  for (let i = 0; i < padLen; i++) sb[o++] = 0xff;
  sb[o++] = 0x00;
  sb.set(di, o);
  const sig = _modPow(_b2i(sb), priv.d, priv.n);
  return _i2b(sig, k);
}

export { u32 };