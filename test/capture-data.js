// Live capture + brute-force of the real VPN Gate data channel.
// Self-contained (inline proxy connect) so importing it does not run vpngate's main.
import { readFileSync, writeFileSync } from 'fs';
import net from 'net';
import { Readable, PassThrough } from 'stream';
import { parseOvpn } from '../src/openvpn/config.js';
import { openVpnConn } from '../src/openvpn/client.js';
import crypto from 'crypto';
import { root } from './root.js';

globalThis.__KX = {};
globalThis.__DPKT = [];

function cfConnect({ hostname, port }) {
  const socket = net.connect(10808, '127.0.0.1');
  const pass = new PassThrough();
  socket.pause();
  let bridging = false;
  const opened = new Promise((res, rej) => {
    socket.once('connect', () => { socket.write(`CONNECT ${hostname}:${port} HTTP/1.1\r\nHost: ${hostname}:${port}\r\n\r\n`); });
    let buf = Buffer.alloc(0);
    const pump = () => {
      for (;;) {
        const c = socket.read();
        if (c === null) return;
        buf = Buffer.concat([buf, c]);
        const i = buf.indexOf('\r\n\r\n');
        if (i >= 0) {
          const head = buf.slice(0, i).toString('latin1');
          const excess = buf.slice(i + 4);
          if (!/ 200 /.test(head)) { socket.destroy(); rej(new Error('proxy CONNECT failed')); return; }
          if (excess.length) pass.write(excess);
          bridging = true; socket.removeAllListeners('readable'); socket.pipe(pass);
          res();
          return;
        }
      }
    };
    socket.on('readable', pump);
    socket.on('error', rej);
  });
  return {
    opened,
    readable: Readable.toWeb(pass, { encoding: null }),
    writable: new WritableStream({
      write(c) { return new Promise((r, j) => socket.write(c, (e) => e ? j(e) : r())); },
      close() { socket.end(); },
      abort() { socket.destroy(); },
    }),
    close: () => { try { socket.destroy(); } catch { } },
  };
}

const ovpnFile = process.argv[2] || root('test/configs/sample0.ovpn');
const cfg = parseOvpn(readFileSync(ovpnFile, 'utf8'));
const log = (m) => console.log('[ovpn]', m);

const t0 = Date.now();
const tunnel = await openVpnConn(cfg, { connect: cfConnect }, { log });
console.log('CONNECTED virtualIp=', tunnel.virtualIp, 'in', Date.now() - t0, 'ms');
await new Promise((r) => setTimeout(r, 5000));

const { master, block, client, server, sidC, sidS } = globalThis.__KX;
const pkts = globalThis.__DPKT;
console.log('=== capture ===');
console.log('sidC', Buffer.from(sidC).toString('hex'), 'sidS', Buffer.from(sidS).toString('hex'));
console.log('client.r1', Buffer.from(client.random1).toString('hex'));
console.log('client.r2', Buffer.from(client.random2).toString('hex'));
console.log('server.r1', Buffer.from(server.random1).toString('hex'));
console.log('server.r2', Buffer.from(server.random2).toString('hex'));
console.log('master', Buffer.from(master).toString('hex'));
console.log('block', Buffer.from(block).toString('hex'));
console.log('packets', pkts.length);
writeFileSync(root('test/cap_keys.json'), JSON.stringify({
  master: Buffer.from(master).toString('hex'),
  block: Buffer.from(block).toString('hex'),
  sidC: Buffer.from(sidC).toString('hex'), sidS: Buffer.from(sidS).toString('hex'),
  cr1: Buffer.from(client.random1).toString('hex'), cr2: Buffer.from(client.random2).toString('hex'),
  sr1: Buffer.from(server.random1).toString('hex'), sr2: Buffer.from(server.random2).toString('hex'),
  pkts: pkts.map((p) => Buffer.from(p).toString('hex')),
}));

const kb = Buffer.from(block);
function hmac(key, data, alg) { return crypto.createHmac(alg, key).update(data).digest(); }
function cbcDec(key, iv, ct) { try { const d = crypto.createDecipheriv('aes-128-cbc', key, iv); return Buffer.concat([d.update(ct), d.final()]); } catch { return null; } }
const cands = {
  cipherKeys: { 'kb0': kb.subarray(0, 16), 'kb128': kb.subarray(128, 144) },
  hmacKeys: { 'kb64': kb.subarray(64, 84), 'kb192': kb.subarray(192, 212), 'kb64full': kb.subarray(64, 128), 'kb192full': kb.subarray(192, 256) },
};
function addr(b) { return [...b].join('.'); }

for (let pi = 0; pi < Math.min(pkts.length, 3); pi++) {
  const pkt = Buffer.from(pkts[pi]);
  console.log('\n--- packet', pi, 'len', pkt.length, 'head', pkt.subarray(0, 8).toString('hex'), '---');
  const headerLen = (pkt[0] & 0x07) === 0 ? 1 : 1;
  const mac = pkt.subarray(headerLen, headerLen + 20);
  const iv = pkt.subarray(headerLen + 20, headerLen + 36);
  const ct = pkt.subarray(headerLen + 36);
  for (const [hkName, hk] of Object.entries(cands.hmacKeys)) {
    const exp = hmac(hk.subarray(0, 20), Buffer.concat([iv, ct]), 'sha1');
    const m0 = exp.subarray(0, 20).equals(mac);
    console.log(`CBC-HMAC ${hkName} over [iv||ct] match=${m0}`);
    if (m0) {
      for (const [ckName, ck] of Object.entries(cands.cipherKeys)) {
        const pt = cbcDec(ck, iv, ct);
        if (pt) {
          console.log(`  -> CBC decrypt ${ckName} OK plaintext`, pt.toString('hex'));
          if (pt.length > 20) console.log('  -> ip proto', pt[4 + 9], 'src', addr(pt.subarray(16, 20)), 'dst', addr(pt.subarray(20, 24)));
        }
      }
    }
  }
  // GCM interpretations
  for (const [ckName, ck] of Object.entries(cands.cipherKeys)) {
    for (const [ivBaseName, ivBase] of Object.entries({ 'kb64imp': kb.subarray(64, 72), 'kb192imp': kb.subarray(192, 200) })) {
      for (const order of ['exp|imp', 'imp|exp']) {
        if (pkt.length < headerLen + 4 + 16 + 1) continue;
        const explicit = pkt.subarray(headerLen, headerLen + 4);
        const ctg = pkt.subarray(headerLen + 4, pkt.length - 16);
        const tag = pkt.subarray(pkt.length - 16);
        const ivv = order === 'exp|imp' ? Buffer.concat([explicit, ivBase]) : Buffer.concat([ivBase, explicit]);
        for (const aadSel of ['headerExp', 'headerExp4']) {
          const aad = aadSel === 'headerExp' ? Buffer.concat([pkt.subarray(0, headerLen), explicit]) : Buffer.concat([pkt.subarray(0, headerLen), explicit, Buffer.from([0, 0, 0, 0])]);
          try {
            const d = crypto.createDecipheriv('aes-128-gcm', ck, ivv);
            d.setAuthTag(tag); d.setAAD(aad);
            const pt = Buffer.concat([d.update(ctg), d.final()]);
            console.log(`  -> GCM ${ckName} iv=${order} aad=${aadSel} OK:`, pt.toString('hex'));
          } catch { }
        }
      }
    }
  }
}
process.exit(0);
