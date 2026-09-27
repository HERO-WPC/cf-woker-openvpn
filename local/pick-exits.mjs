// Pick the embedded REMOTE list (one OpenVPN exit per client node) from the live
// VPN Gate list, ranked by REAL end-to-end handshake time through the deployed
// Worker. Each candidate is tested with ITS OWN config (VPN Gate nodes listen on
// different TCP ports -- forcing 443 makes working nodes look dead) and twice, so
// a flaky server cannot become "node /e3 is broken" for the user.
import fs from 'node:fs';

const WORKER = process.env.WORKER || 'test33333.wang.dpdns.org';
const CSV = 'D:/桌面/worker-openvpn-tcp/local/vpngate.csv';
const EMB = 'D:/桌面/worker-openvpn-tcp/src/embedded-ovpn.js';
const ROUNDS = +(process.env.ROUNDS || 2);
const N_PUB = +(process.env.N_PUB || 8);
const N_VOL = +(process.env.N_VOL || 12);

const embSrc = fs.readFileSync(EMB, 'utf8');
const mm = /export const EMBEDDED_OVPN = "([\s\S]*?)";\s*$/.exec(embSrc);
if (!mm) { console.error('cannot parse embedded-ovpn.js'); process.exit(1); }
const embCfg = JSON.parse('"' + mm[1] + '"');
const curRemotes = [...embCfg.matchAll(/^remote (\S+) (\d+)$/gm)].map((x) => ({ ip: x[1], port: +x[2] }));

const rows = [];
for (const line of fs.readFileSync(CSV, 'utf8').split(/\r?\n/)) {
  if (!line || line[0] === '*' || line[0] === '#') continue;
  const f = line.split(',');
  if (f.length < 15) continue;
  const b64 = f[f.length - 1];
  if (!b64 || b64.length < 100) continue;
  const cfg = Buffer.from(b64, 'base64').toString('utf8');
  const rm = [...cfg.matchAll(/^remote (\S+) (\d+)$/gm)].map((x) => ({ ip: x[1], port: +x[2] }));
  const tcp = /^proto\s+tcp/m.test(cfg) && /tcp-client|^proto\s+tcp/m.test(cfg);
  rows.push({ host: f[0], ip: f[1], score: +f[2] || 0, ping: +f[3] || 0, cc: f[6], sess: +f[7] || 0, cfg, rm, tcp });
}

const seen = new Set(); const cands = [];
const add = (r) => { if (r && r.tcp && r.rm.length && !seen.has(r.ip)) { seen.add(r.ip); cands.push(r); } };
for (const c of curRemotes) add(rows.find((r) => r.ip === c.ip) || { ip: c.ip, tcp: true, rm: [c], cc: '??', score: 0, sess: 0, cfg: null });
for (const r of [...rows].sort((a, b) => b.score - a.score).slice(0, N_PUB)) add(r);
for (const r of rows.filter((r) => !/^public-vpn-/.test(r.host)).sort((a, b) => (b.score / Math.max(1, b.sess)) - (a.score / Math.max(1, a.sess))).slice(0, N_VOL)) add(r);

console.log(`candidates: ${cands.length} (tcp-capable), rounds: ${ROUNDS}\n`);
const test = async (c) => {
  if (!c.cfg) return { ok: false, ms: 0, err: 'no config in CSV' };
  const t0 = Date.now();
  try {
    const res = await fetch(`https://${WORKER}/ovpn-test?target=cp.cloudflare.com&port=80&path=/generate_204`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ config: c.cfg }),
    });
    const j = await res.json();
    return { ok: !!j.ok && / 204 /.test(j.response || ''), ms: Date.now() - t0, err: j.error || '' };
  } catch (e) { return { ok: false, ms: Date.now() - t0, err: String(e.message || e) }; }
};

const stat = new Map();
for (let r = 1; r <= ROUNDS; r++) {
  for (const c of cands) {
    const res = await test(c);
    const s = stat.get(c.ip) || { wins: 0, times: [] };
    if (res.ok) { s.wins++; s.times.push(res.ms); } else { s.lastErr = res.err.slice(0, 60); }
    stat.set(c.ip, s);
    console.log(`  r${r} ${res.ok ? 'OK  ' : 'FAIL'} ${c.ip.padEnd(16)}:${String(c.rm[0].port).padEnd(5)} ${String(res.ms).padStart(6)}ms ${c.cc} sess=${String(c.sess).padStart(4)} ${res.ok ? '' : res.err.slice(0, 55)}`);
  }
}

const ranked = cands.map((c) => {
  const s = stat.get(c.ip);
  return { ip: c.ip, port: c.rm[0].port, cc: c.cc, sess: c.sess, score: c.score, wins: s.wins, avg: s.times.length ? Math.round(s.times.reduce((a, b) => a + b, 0) / s.times.length) : 0 };
}).sort((a, b) => (b.wins - a.wins) || (a.avg - b.avg));

console.log('\n===== ranked (wins desc, then fastest) =====');
for (const r of ranked) console.log(`  ${r.wins}/${ROUNDS} ok  ${String(r.avg).padStart(6)}ms  ${r.ip.padEnd(16)}:${String(r.port).padEnd(5)} ${r.cc} sess=${String(r.sess).padStart(4)}`);
fs.writeFileSync('D:/桌面/worker-openvpn-tcp/local/exit-picks.json', JSON.stringify(ranked, null, 2));

const pick = ranked.filter((r) => r.wins >= 1).slice(0, 8);
if (pick.length) {
  console.log('\n===== new remote block for src/embedded-ovpn.js =====');
  console.log(pick.map((p) => `remote ${p.ip} ${p.port}`).join('\\n') + '\\n');
  console.log('\n' + pick.map((p, i) => `e${i + 1}=${p.ip}:${p.port}(${p.avg}ms,${p.wins}/${ROUNDS})`).join('  '));
}
