// local/cflogs.cjs — read persisted Workers Logs (observability) for a script.
//   node local/cflogs.cjs [script] [minutesBack]
//
// Uses the Workers Observability telemetry query API. Prints the raw response
// when the shape is unexpected so the request can be corrected.
const fs = require('fs');
const os = require('os');
const path = require('path');

const API = 'https://api.cloudflare.com/client/v4';
const acct = process.env.CF_ACCOUNT_ID || '37de7ffcd288d95dcfd76646368b9e91';
const token = (process.env.CF_API_TOKEN || fs.readFileSync(path.join(os.tmpdir(), 'cf_oauth.txt'), 'utf8')).trim();
const service = process.argv[2] || 'cf-ogate';
const minutes = +(process.argv[3] || 20);

const now = Date.now();
const from = now - minutes * 60 * 1000;

const bodies = [
  {
    label: 'queryId+parameters(datasets,filters,limit)',
    body: {
      queryId: 'diag-' + now,
      timeframe: { from, to: now },
      parameters: {
        datasets: ['cloudflare-workers'],
        filters: [{ key: '$metadata.service', operation: 'eq', value: service }],
        limit: 100,
      },
    },
  },
  {
    label: 'parameters(no datasets) + orderBy',
    body: {
      queryId: 'diag2-' + now,
      timeframe: { from, to: now },
      parameters: {
        datasets: ['cloudflare-workers'],
        filters: [{ key: '$metadata.service', operation: 'eq', value: service }],
        orderBy: [{ key: '$metadata.timestamp', order: 'desc' }],
        limit: 100,
      },
    },
  },
];

function flatten(events) {
  const lines = [];
  for (const ev of events) {
    const ts = ev.timestamp || ev.$metadata?.timestamp || '';
    const src = ev.source || ev.$metadata?.message || '';
    const msg = ev.message ?? ev.$cloudflare?.event?.message ?? ev.$message ?? ev;
    const text = typeof msg === 'string' ? msg : JSON.stringify(msg);
    lines.push(`${ts}  ${src}  ${text}`.slice(0, 500));
  }
  return lines;
}

(async () => {
  for (const { label, body } of bodies) {
    const res = await fetch(`${API}/accounts/${acct}/workers/observability/telemetry/query`, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const t = await res.text();
    console.log(`\n===== ${label} -> HTTP ${res.status}`);
    let j = null; try { j = JSON.parse(t); } catch { }
    if (!j) { console.log(t.slice(0, 800)); continue; }
    if (!j.success) { console.log('FAIL ' + JSON.stringify(j.errors)); continue; }
    const r = j.result || {};
    const events = r.events?.events || r.events || r.rows || [];
    console.log(`events: ${Array.isArray(events) ? events.length : 'n/a'}   keys=${Object.keys(r).join(',')}`);
    if (Array.isArray(events) && events.length) {
      console.log('--- sample event ---');
      console.log(JSON.stringify(events[0]).slice(0, 1200));
      console.log('--- flattened ---');
      for (const l of flatten(events).slice(0, 120)) console.log(l);
    } else {
      console.log('raw: ' + JSON.stringify(r).slice(0, 1200));
    }
    return;
  }
})();
