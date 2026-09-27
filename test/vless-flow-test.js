// Tests for the VLESS front-end: parseVlessHeader with split/complete header,
// initial payload preservation, UUID rejection, early-data base64, and the
// Cloudflare timer (setInterval/setTimeout return numbers) safety in createTcp.
import { parseVlessHeader, uuidToBytes } from '../src/vless.js';
import { TcpFlow, createTcp } from '../src/tcp.js';

let fail = 0;
function ok(name, cond) { if (!cond) { fail++; console.log('FAIL', name); } else console.log('ok', name); }

const UUID = '2523c510-9ff0-415b-9582-93949bfae7e3';
const id = uuidToBytes(UUID);

function buildVless({ uuid = UUID, cmd = 1, port = 443, addrType = 2, host = 'example.com', payload = new Uint8Array(0) }) {
  const idb = uuidToBytes(uuid);
  const dom = typeof host === 'string' ? new TextEncoder().encode(host) : host;
  const parts = [0]; for (const x of idb) parts.push(x);
  parts.push(0, cmd, port >> 8, port & 0xff, addrType);
  if (addrType === 2) parts.push(dom.length);
  if (addrType === 1) for (const x of host.split('.').map(Number)) parts.push(x);
  else if (addrType === 2) for (const x of dom) parts.push(x);
  else { for (let i = 0; i < 16; i++) parts.push(host[i]); }
  for (const x of payload) parts.push(x);
  return Uint8Array.from(parts);
}

// 1. complete header, one chunk
{
  const pkt = buildVless({ cmd: 1, addrType: 2, host: 'example.com', port: 443, payload: Uint8Array.from([1, 2, 3]) });
  const r = parseVlessHeader(pkt, id);
  ok('complete header parsed', r && r.port === 443 && r.host === 'example.com' && r.addrType === 2 && r.headerLen === 34);
}

// 2. header split in two chunks: first half, then rest -> same result
{
  const pkt = buildVless({ cmd: 1, addrType: 2, host: 'example.com', port: 443, payload: Uint8Array.from([1, 2, 3]) });
  const half = Math.floor(pkt.length / 2);
  const r1 = parseVlessHeader(pkt.subarray(0, half), id);
  ok('split header: partial returns null (not an error)', r1 === null);
  const r2 = parseVlessHeader(pkt.subarray(half), id);
  ok('split header: partial still null', r2 === null);
  const r3 = parseVlessHeader(pkt, id);
  ok('split header: full buffer gives the same header', r3 && r3.host === 'example.com' && r3.port === 443);
}

// 3. header + initial payload: offset preserved
{
  const pkt = buildVless({ addrType: 2, host: 'example.com', port: 443, payload: Uint8Array.from([0x16, 0x03, 0x01, 0xaa]) });
  const r = parseVlessHeader(pkt, id);
  ok('header+payload: headerLen correct', r && r.headerLen === 34);
  ok('header+payload: payload preserved', r && pkt.subarray(r.headerLen)[3] === 0xaa);
}

// 4. IPv4 + IPv6 address types
{
  const ip4 = buildVless({ addrType: 1, host: '1.1.1.1', port: 80 });
  const r4 = parseVlessHeader(ip4, id);
  ok('IPv4 target', r4 && r4.host === '1.1.1.1' && r4.addrType === 1 && r4.headerLen === 26);
  const v6addr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
  const ip6 = buildVless({ addrType: 3, host: v6addr, port: 53 });
  const r6 = parseVlessHeader(ip6, id);
  ok('IPv6 target', r6 && r6.addrType === 3 && r6.host === '102:304:506:708:90a:b0c:d0e:f10');
}

// 5. UUID wrong -> reject
{
  const bad = buildVless({ uuid: '00000000-0000-4000-8000-000000000000' });
  const r = parseVlessHeader(bad, id);
  ok('wrong UUID rejected', r && r.error === 'VLESS_UUID_INVALID');
}

// 6. command unsupported (udp=2)
{
  const udp = buildVless({ cmd: 2, addrType: 2, host: 'example.com', port: 53 });
  const r = parseVlessHeader(udp, id);
  ok('udp command rejected', r && r.error === 'VLESS_COMMAND_UNSUPPORTED');
}

// 7. early-data: the same base64url decode used by handleWs
{
  const pkt = buildVless({ cmd: 1, addrType: 2, host: 'example.com', port: 443, payload: Uint8Array.from([7, 8]) });
  const b64 = Buffer.from(pkt).toString('base64url');
  const clean = b64.replace(/-/g, '+').replace(/_/g, '/');
  const early = Uint8Array.from(Buffer.from(clean, 'base64'));
  const r = parseVlessHeader(early, id);
  ok('early data decodes to a valid header', r && r.host === 'example.com');
}

// 8. Cloudflare timers: setInterval/setTimeout return NUMBERS; createTcp must not
//    try to attach properties to those handles (would TypeError on CF).
{
  const realSI = globalThis.setInterval, realST = globalThis.setTimeout, realCI = globalThis.clearInterval, realCT = globalThis.clearTimeout;
  globalThis.setInterval = () => 111;  // CF returns a number
  globalThis.setTimeout = () => 222;   // CF returns a number
  globalThis.clearInterval = () => {}; globalThis.clearTimeout = () => {};
  function cksum(d, o, n) { let s = 0; for (let i = o; i < o + n - 1; i += 2) s += (d[i] << 8 | d[i + 1]); if (n & 1) s += d[o + n - 1] << 8; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); return (~s) & 0xFFFF; }
  let feed = null;
  const readable = new ReadableStream({ start: (c) => { feed = c; } });
  let captured = 0;
  const tunnel = {
    writable: { getWriter: () => ({ write: (syn) => { captured++;
      // answer the SYN immediately from its own fields (ports + iss + MSS option)
      const srcPort = (syn[20] << 8) | syn[21];
      const iss = ((syn[24] << 24) | (syn[25] << 16) | (syn[26] << 8) | syn[27]) >>> 0;
      const f = new Uint8Array(40); const v = new DataView(f.buffer);
      f[0] = 0x45; v.setUint16(2, 40); f[8] = 64; f[9] = 6;
      f.set([10, 8, 0, 1], 12); f.set([10, 8, 0, 2], 16);
      v.setUint16(20, 80); v.setUint16(22, srcPort); v.setUint32(24, 0x12340000 >>> 0); v.setUint32(28, (iss + 1) >>> 0);
      f[32] = 0x50; f[33] = 0x12; v.setUint16(34, 65535);
      v.setUint16(10, cksum(f, 0, 20));
      const tl = 20, pseudo = new Uint8Array(12 + tl);
      pseudo.set([10, 8, 0, 1], 0); pseudo.set([10, 8, 0, 2], 4); pseudo[9] = 6; pseudo[11] = tl;
      pseudo.set(f.subarray(20, 40), 12);
      v.setUint16(36, cksum(pseudo, 0, 12 + tl));
      feed.enqueue(f);
      return Promise.resolve(); } }) },
    readable, close: () => {},
  };
  let threw = null, tcp = null;
  try { tcp = await createTcp(tunnel, '10.8.0.2', '10.8.0.1', 80); }
  catch (e) { threw = e; }
  finally { globalThis.setInterval = realSI; globalThis.setTimeout = realST; globalThis.clearInterval = realCI; globalThis.clearTimeout = realCT; }
  ok('createTcp works when timers return plain numbers', !threw && !!tcp && !!tcp.writable);
  if (threw) console.log('   threw:', threw.message);
}

console.log(fail ? ('\n' + fail + ' failures') : '\nALL VLESS-FLOW PASS');
process.exit(fail ? 1 : 0);