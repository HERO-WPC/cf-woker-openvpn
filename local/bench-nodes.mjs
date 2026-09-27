// Benchmark VPN Gate candidates end-to-end through the deployed Worker:
// POST each node's own .ovpn to /ovpn-test (OpenVPN handshake + user-space TCP
// + HTTP round trip) and rank by wall-clock time. The API's own "ping" column is
// measured from Japan and says nothing about the path CF-edge -> node.
import fs from 'node:fs';

const CSV = 'D:/桌面/worker-openvpn-tcp/local/vpngate.csv';
const WORKER = process.env.WORKER || 'test33333.wang.dpdns.org';
const N_PUB = +(process.env.N_PUB || 6);
const N_VOL = +(process.env.N_VOL || 8);

const rows = [];
for (const line of fs.readFileSync(CSV, 'utf8').split(/\r?\n/)) {
  if (!line || line[0] === '*' || line[0] === '#') continue;
  const f = line.split(',');
  if (f.length < 15) continue;
  rows.push({
    host: f[0], ip: f[1], score: +f[2] || 0, ping: +f[3] || 0, speed: +f[4] || 0,
    cc: f[6], sess: +f[7] || 0, b64: f[f.length - 1],
  });
}

const dedupe = (a) => { const s = new Set(); return a.filter((r) => (s.has(r.ip) ? false : (s.add(r.ip), true))); };
// A: the API's own top public relays (heavily loaded but well peered).
const pub = dedupe([...rows].sort((a, b) => b.score - a.score)).slice(0, N_PUB);
// B: volunteer nodes -- rank by quality per active session so an idle node wins.
const vol = dedupe(rows.filter((r) => !/^public-vpn-/.test(r.host))
  .sort((a, b) => (b.score / Math.max(1, b.sess)) - (a.score / Math.max(1, a.sess)))).slice(0, N_VOL);

const cands = [...pub, ...vol].filter((r) => r.b64 && r.b64.length > 100);
console.log(`candidates: ${cands.length} (public ${pub.length} + volunteer ${vol.length})\n`);

// Sanity: every VPN Gate client config shares one CA/cert/key pair, so the
// embedded config only needs its `remote` lines swapped.
const cfgOf = (r) => Buffer.from(r.b64, 'base64').toString('utf8');
const certBlock = (t) => (t.match(/<ca>[\s\S]*?<\/ca>/) || [''])[0] + (t.match(/<cert>[\s\S]*?<\/cert>/) || [''])[0];
if (cands.length > 1) {
  const a = certBlock(cfgOf(cands[0])), b = certBlock(cfgOf(cands[1]));
  console.log(`cert/ca identical across nodes: ${a === b ? 'YES (shared pair -> only remote lines differ)' : 'NO'}\n`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
for (const c of cands) {
  const cfg = cfgOf(c);
  const t0 = Date.now();
  let ok = false, err = '', code = '', vip = '';
  try {
    const res = await fetch(`https://${WORKER}/ovpn-test?target=cp.cloudflare.com&port=80&path=/generate_204`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ config: cfg }),
    });
    const j = await res.json();
    ok = !!j.ok; err = j.error || ''; vip = j.virtualIp || '';
    code = ((j.response || '').match(/^HTTP\/1\.[01] (\d+)/) || [])[1] || '';
  } catch (e) { err = String(e.message || e); }
  const ms = Date.now() - t0;
  results.push({ ...c, ms, ok, err, code, vip });
  console.log(`${ok ? 'OK  ' : 'FAIL'} ${c.ip.padEnd(16)} ${c.cc} sess=${String(c.sess).padStart(4)} score=${String(c.score).padStart(8)} ${String(ms).padStart(6)}ms http=${code || '-'} vip=${vip || '-'} ${err.slice(0, 60)}`);
  await sleep(300);
}

const good = results.filter((r) => r.ok).sort((a, b) => a.ms - b.ms);
console.log(`\n===== usable ${good.length}/${results.length} (fastest first) =====`);
for (const r of good) console.log(`  ${String(r.ms).padStart(6)}ms  ${r.ip.padEnd(16)} ${r.cc} sess=${String(r.sess).padStart(4)}  ${r.host}`);
fs.writeFileSync('D:/桌面/worker-openvpn-tcp/local/node-bench.json', JSON.stringify(results, null, 2));
