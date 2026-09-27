// Probe VPN Gate US nodes from the Worker itself: decode each node's own config
// (its real TCP port), then measure the CF-edge -> node RTT with /ping (1 RTT,
// no read/write). US exits matter because CF often serves us from a US West colo.
import fs from 'node:fs';
const CSV = 'D:/桌面/worker-openvpn-tcp/local/vpngate.csv';
const WORKER = process.env.WORKER || 'test33333.wang.dpdns.org';
const WANT = (process.env.CC || 'US').split(',');

const rows = [];
for (const line of fs.readFileSync(CSV, 'utf8').split(/\r?\n/)) {
  if (!line || line[0] === '*' || line[0] === '#') continue;
  const f = line.split(',');
  if (f.length < 15) continue;
  const b64 = f[f.length - 1];
  if (!b64 || b64.length < 100) continue;
  let cfg = '';
  try { cfg = Buffer.from(b64, 'base64').toString('utf8'); } catch { continue; }
  if (!/^proto\s+tcp/m.test(cfg)) continue;
  const m = /^remote\s+(\S+)\s+(\d+)/m.exec(cfg);
  if (!m) continue;
  rows.push({ ip: m[1], port: +m[2], cc: f[6], sess: +f[7] || 0, score: +f[2] || 0, ping: +f[3] || 0, host: f[0], cfg });
}
const counts = {};
for (const r of rows) counts[r.cc] = (counts[r.cc] || 0) + 1;
console.log('TCP-capable nodes by country:', Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, v]) => k + '=' + v).join(' '));

const pick = rows.filter((r) => WANT.includes(r.cc)).sort((a, b) => (a.ping - b.ping) || (a.sess - b.sess)).slice(0, 14);
console.log(`\nprobing ${pick.length} ${WANT.join('/')} nodes (connect RTT from the CF edge + full handshake test)\n`);
const out = [];
for (const n of pick) {
  let rtt = -1, err = '';
  try {
    const r = await fetch(`https://${WORKER}/ping?host=${n.ip}&port=${n.port}&n=2`);
    const j = await r.json();
    rtt = j.min;
  } catch (e) { err = String(e.message || e); }
  // full handshake + HTTP through this node (the real usability test)
  let e2e = -1, ok = false;
  try {
    const t0 = Date.now();
    const r = await fetch(`https://${WORKER}/ovpn-test?target=cp.cloudflare.com&port=80&path=/generate_204`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ config: n.cfg }),
    });
    const j = await r.json();
    e2e = Date.now() - t0; ok = !!j.ok && / 204 /.test(j.response || '');
  } catch (e) { err = String(e.message || e); }
  out.push({ ...n, rtt, e2e, ok, err });
  console.log(`  ${n.ip.padEnd(16)}:${String(n.port).padEnd(6)} ${n.cc} sess=${String(n.sess).padStart(4)} rtt=${String(rtt).padStart(5)}ms  e2e=${ok ? String(e2e).padStart(6) + 'ms OK' : 'FAIL ' + err.slice(0, 40)}`);
}
const good = out.filter((r) => r.ok).sort((a, b) => a.e2e - b.e2e);
console.log('\nusable US exits (fastest handshake first):');
for (const g of good) console.log(`  remote ${g.ip} ${g.port}   rtt=${g.rtt}ms e2e=${g.e2e}ms`);
fs.writeFileSync('D:/桌面/worker-openvpn-tcp/local/us-picks.json', JSON.stringify(out, null, 2));
