// Quick unit tests for config parser and crypto primitives.
import { parseOvpn } from '../src/openvpn/config.js';
import { md5, hmacMd5, openvpnPRF, keyExpansion, aesGcmEncrypt, aesGcmDecrypt } from '../src/openvpn/crypto.js';
import { readFileSync } from 'fs';
import { hex, concat, bytes, u32, TcpPacketStream } from '../src/openvpn/bytes.js';
import { uuidToBytes } from '../src/vless.js';
import { root } from './root.js';

let fail = 0;
function eq(name, a, b) { const ok = a === b; if (!ok) { fail++; console.log('FAIL', name, '\n  expected', b, '\n  got     ', a); } else console.log('ok', name); }
function hexeq(name, a, b) { eq(name, hex(a), b); }

// MD5 vectors
hexeq('md5("")', md5(bytes('')), 'd41d8cd98f00b204e9800998ecf8427e');
hexeq('md5("abc")', md5(bytes('abc')), '900150983cd24fb0d6963f7d28e17f72');
hexeq('md5("The quick brown fox jumps over the lazy dog")', md5(bytes('The quick brown fox jumps over the lazy dog')), '9e107d9d372bb6826bd81d3542a419d6');
hexeq('md5("message digest")', md5(bytes('message digest')), 'f96b697d7cb7938d525a2f31aaf161d0');

// HMAC-MD5 RFC 2202 test 1: key=0x0b*16, data="Hi There"
const k = new Uint8Array(16).fill(0x0b);
hexeq('hmacMd5 rfc2202-1', hmacMd5(k, bytes('Hi There')), '9294727a3638bb1c13f48ef8158bfc9d');

// parse sample VPN Gate config
const ovpn = readFileSync(root('test/configs/sample0.ovpn'), 'utf8');
let cfg;
try { cfg = parseOvpn(ovpn); console.log('parsed ok: remote=', JSON.stringify(cfg.remotes), 'cipher=', cfg.cipher, 'hasCert=', cfg.hasCert, 'tlsAuth?', !!cfg.tlsAuth); }
catch (e) { fail++; console.log('FAIL parseOvpn', e.message); }

// AES-GCM roundtrip
(async () => {
  const key = new Uint8Array(32).fill(7);
  const iv = new Uint8Array(12).fill(1);
  const pt = bytes('hello openvpn');
  const ct = await aesGcmEncrypt(key, iv, pt, bytes('aad'));
  const back = await aesGcmDecrypt(key, iv, ct, bytes('aad'));
  eq('aes-gcm roundtrip', String.fromCharCode(...back), String.fromCharCode(...pt));
  const bad = await aesGcmDecrypt(key, iv, ct, bytes('bad'));
  eq('aes-gcm wrong aad -> null', bad, null);

  // keyExpansion deterministic
  const ks = {
    client: { pre_master: new Uint8Array(48).fill(3), random1: new Uint8Array(32).fill(5), random2: new Uint8Array(32).fill(7) },
    server: { pre_master: new Uint8Array(48).fill(9), random1: new Uint8Array(32).fill(11), random2: new Uint8Array(32).fill(13) },
  };
  const c = new Uint8Array(8).fill(1), s = new Uint8Array(8).fill(2);
  const b1 = await keyExpansion(ks, c, s);
  const b2 = await keyExpansion(ks, c, s);
  eq('keyExpansion deterministic', hex(b1), hex(b2));
  eq('keyExpansion length', b1.length, 256);

  // ---- UUID -> 16 bytes (strict) ----
  const UUID = '2523c510-9ff0-415b-9582-93949bfae7e3';
  hexeq('uuidToBytes correct', uuidToBytes(UUID), '2523c5109ff0415b958293949bfae7e3');
  hexeq('uuidToBytes accepts uppercase', uuidToBytes('2523C510-9FF0-415B-9582-93949BFAE7E3'), '2523c5109ff0415b958293949bfae7e3');
  hexeq('uuidToBytes strips multiple dashes', uuidToBytes('2523c5109ff0415b958293949bfae7e3'), '2523c5109ff0415b958293949bfae7e3');
  let uuidErr = '';
  try { uuidToBytes('not-a-uuid'); } catch (e) { uuidErr = e.code || e.message; }
  eq('uuidToBytes invalid -> INVALID_UUID', uuidErr, 'INVALID_UUID');
  let uuidErr2 = '';
  try { uuidToBytes('2523c5109ff0415b958293949bfae7e'); } catch (e) { uuidErr2 = e.code || e.message; } // 31 hex chars
  eq('uuidToBytes 31 hex chars -> INVALID_UUID', uuidErr2, 'INVALID_UUID');

  // ---- OpenVPN TCP framing (TcpPacketStream) ----
  // helper: build a length-prefixed packet
  const frame = (pkt) => { const f = new Uint8Array(2 + pkt.length); f[0] = pkt.length >> 8; f[1] = pkt.length & 0xFF; f.set(pkt, 2); return f; };
  const stream = new TcpPacketStream();
  // packet A split into 3 reads
  let r1 = stream.push(frame(bytes('AAA')).subarray(0, 2));
  eq('framing: partial read1 empty', r1.length, 0);
  r1 = stream.push(concat(bytes('AAA'), frame(bytes('BBB'))));
  eq('framing: coalesced read yields two packets', r1.length, 2);
  eq('framing: packet A', String.fromCharCode(...bytes(r1[0])), 'AAA');
  eq('framing: packet B', String.fromCharCode(...bytes(r1[1])), 'BBB');
  // invalid length -> throws labeled error
  const frameStream = new TcpPacketStream();
  let frameErr = '';
  try { frameStream.push(new Uint8Array([0, 0])); } catch (e) { frameErr = e.code; }
  eq('framing: zero length -> OPENVPN_TCP_FRAME_INVALID', frameErr, 'OPENVPN_TCP_FRAME_INVALID');

  console.log(fail ? ('\n' + fail + ' failures') : '\nALL PASS');
  process.exit(fail ? 1 : 0);
})();
