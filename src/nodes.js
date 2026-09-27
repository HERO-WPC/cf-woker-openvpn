// Live VPN Gate node source -- fanout's principle applied to a Worker.
//
// fanout does not trust a static node list: volunteer nodes disappear and public
// relays fill up (AUTH_FAILED), so it fetches the live list, tries up to 6
// candidates in the same region, and swaps a dead node while keeping the slot
// (and therefore the client's share link) stable. We do the same:
//   * keep a fresh list of TCP-capable nodes (10 min TTL), cached in the isolate
//   * remember which remotes just failed, so the next attempt skips them
//   * hand out ordered candidates (same country first, embedded list last)
const API = 'https://www.vpngate.net/api/iphone/';
const LIST_TTL_MS = 10 * 60 * 1000;
const BAD_TTL_MS = 5 * 60 * 1000;
const MAX_NODES = 60;

let cache = { at: 0, list: [], err: '' };
const bad = new Map();          // remoteKey -> timestamp until which it is avoided

export function markBad(rk) { try { bad.set(rk, Date.now() + BAD_TTL_MS); } catch { } }
export function clearBad(rk) { bad.delete(rk); }
export function isBad(rk) {
  const until = bad.get(rk) || 0;
  if (until < Date.now()) { bad.delete(rk); return false; }
  return true;
}
export function listInfo() {
  return { at: cache.at, ageSec: cache.at ? Math.round((Date.now() - cache.at) / 1000) : -1, size: cache.list.length, err: cache.err, bad: [...bad.keys()] };
}

// VPN Gate CSV row: #HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,
// NumVpnSessions,...,OpenVPN_ConfigData_Base64 (last field). The base64 config
// carries the node's OWN TCP port -- forcing 443 makes live nodes look dead.
function parseList(text) {
  const out = [];
  for (const line of text.split('\n')) {
    if (!line || line[0] === '*' || line[0] === '#') continue;
    const f = line.split(',');
    if (f.length < 15) continue;
    const b64 = f[f.length - 1];
    if (!b64 || b64.length < 100) continue;
    let cfg = '';
    try { cfg = atob(b64); } catch { continue; }
    if (!/^proto\s+tcp/m.test(cfg)) continue;               // TCP only: Workers have no UDP
    const m = /^remote\s+(\S+)\s+(\d+)/m.exec(cfg);
    if (!m) continue;
    out.push({ host: m[1], port: +m[2], cc: f[6] || '??', score: +f[2] || 0, ping: +f[3] || 0, sess: +f[7] || 0 });
  }
  // Prefer what actually predicts usable latency from an edge: low API ping,
  // few sessions, then score.
  out.sort((a, b) => (a.ping - b.ping) || (a.sess - b.sess) || (b.score - a.score));
  return out.slice(0, MAX_NODES);
}

export async function nodeList(force) {
  if (!force && cache.list.length && Date.now() - cache.at < LIST_TTL_MS) return cache.list;
  try {
    const r = await fetch(API, { headers: { 'user-agent': 'cf-worker-openvpn' } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const list = parseList(await r.text());
    if (list.length) cache = { at: Date.now(), list, err: '' };
    else cache.err = 'empty list';
    return cache.list;
  } catch (e) {
    cache.err = String((e && e.message) || e);              // keep the last good list
    return cache.list;
  }
}

// Ordered candidates for one slot: same country first (fanout tries up to 6 in
// the same region), then the rest, then the embedded bootstrap list. Remotes that
// recently failed are skipped; `avoid` drops remotes another slot already owns.
export async function candidatesFor(cc, avoid, extra, limit) {
  const live = await nodeList();
  const seen = new Set();
  const out = [];
  const push = (n) => {
    if (!n || !n.host || !n.port) return;
    const rk = n.host + ':' + n.port;
    if (seen.has(rk) || isBad(rk) || (avoid && avoid.has(rk))) return;
    seen.add(rk);
    out.push({ host: n.host, port: n.port, cc: n.cc || '??', rk });
  };
  if (cc) for (const n of live) if (n.cc === cc) push(n);
  for (const n of live) push(n);
  for (const n of (extra || [])) push({ host: n.host, port: n.port, cc: 'boot' });
  return out.slice(0, limit || 6);
}

// Health check before dialling (the cheap half of fanout's "健康检查每 10 秒跑一次"):
// one TCP connect == one RTT, so the whole candidate set can be measured in
// parallel for ~1 RTT and the dead/blackholed nodes never cost an OpenVPN
// handshake timeout. Results are cached so repeated picks stay cheap.
const rtt = new Map();               // remoteKey -> { ms, at }
const RTT_TTL_MS = 3 * 60 * 1000;

export async function rankByConnect(transport, cands, limit, budgetMs) {
  const now = Date.now();
  const fresh = [];
  const stale = [];
  for (const c of cands) {
    const hit = rtt.get(c.rk);
    if (hit && now - hit.at < RTT_TTL_MS) fresh.push({ ...c, ms: hit.ms });
    else stale.push(c);
  }
  const budget = budgetMs || 2000;
  // IMPORTANT: a Worker request may only hold a handful of outbound connections
  // at once, so probe in SMALL batches. Probing too many in parallel makes the
  // extra connects fail, and treating those failures as "bad nodes" blacklists
  // healthy servers -- which is exactly what made every node time out.
  for (let i = 0; i < stale.length && fresh.length < 3; i += 3) {
    const batch = stale.slice(i, i + 3);
    await Promise.all(batch.map(async (c) => {
      const t0 = Date.now();
      let s;
      try {
        s = transport.connect({ hostname: c.host, port: c.port });
        await Promise.race([s.opened, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), budget))]);
        const ms = Date.now() - t0;
        rtt.set(c.rk, { ms, at: now });
        fresh.push({ ...c, ms });
      } catch { /* not reachable right now: just skip it for this pick */ }
      finally { try { s && s.close(); } catch { } }
    }));
  }
  fresh.sort((a, b) => a.ms - b.ms);
  return fresh.slice(0, limit || 3);
}
