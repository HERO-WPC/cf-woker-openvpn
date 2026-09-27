// local/cfver.cjs — inspect and promote Worker versions/deployments.
//   node local/cfver.cjs list [script]
//   node local/cfver.cjs promote <script> [versionId|latest]
const fs = require('fs');
const os = require('os');
const path = require('path');

const API = 'https://api.cloudflare.com/client/v4';
const acct = process.env.CF_ACCOUNT_ID || '37de7ffcd288d95dcfd76646368b9e91';
const token = (process.env.CF_API_TOKEN || fs.readFileSync(path.join(os.tmpdir(), 'cf_oauth.txt'), 'utf8')).trim();
const [cmd, a1, a2] = process.argv.slice(2);
const name = cmd === 'list' ? (a1 || 'cf-ogate') : a1;

async function cf(method, p, body) {
  const res = await fetch(API + p, {
    method,
    headers: { Authorization: 'Bearer ' + token, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let j = null; try { j = JSON.parse(text); } catch { }
  if (!j) { console.log(`HTTP ${res.status} non-JSON: ${text.slice(0, 300)}`); return null; }
  if (!j.success) { console.log(`HTTP ${res.status} FAIL: ${(j.errors || []).map((e) => `[${e.code}] ${e.message}`).join('; ')}`); return null; }
  return j.result;
}

const list = async () => {
  const vs = await cf('GET', `/accounts/${acct}/workers/scripts/${name}/versions`);
  console.log(`versions (${vs ? vs.length : 0}):`);
  if (vs) for (const v of vs) {
    console.log(`   #${v.number ?? '?'}  id=${v.id}  created=${v.metadata?.created_on || v.created_on || '?'}  tag=${String(v.metadata?.etag || '').slice(0, 8)}  by=${v.annotations?.['workers/triggered_by'] || v.metadata?.annotations?.['workers/triggered_by'] || '?'}`);
  }
  const ds = await cf('GET', `/accounts/${acct}/workers/scripts/${name}/deployments`);
  console.log(`\ndeployments (${ds ? ds.length : 0}):`);
  if (ds) for (const d of ds) {
    const parts = (d.versions || []).map((x) => `${x.version_id}@${x.percentage}%`).join(', ');
    console.log(`   id=${d.id}  created=${d.created_on}  strategy=${d.strategy || '-'}  versions=[${parts}]  author=${(d.author_email || '-')}`);
  }
};

const promote = async () => {
  let versionId = a2;
  if (!versionId || versionId === 'latest') {
    const vs = await cf('GET', `/accounts/${acct}/workers/scripts/${name}/versions`);
    if (!vs || !vs.length) return console.log('no versions found');
    vs.sort((x, y) => (x.number || 0) - (y.number || 0));
    versionId = vs[vs.length - 1].id;
    console.log(`latest version = ${versionId} (#${vs[vs.length - 1].number})`);
  }
  const r = await cf('POST', `/accounts/${acct}/workers/scripts/${name}/deployments`, {
    strategy: 'percentage',
    versions: [{ version_id: versionId, percentage: 100 }],
  });
  console.log(r ? `deployment created: id=${r.id} versions=${JSON.stringify((r.versions || []).map((v) => [v.version_id, v.percentage]))}` : 'promote FAILED');
};

(async () => {
  if (cmd === 'list') return list();
  if (cmd === 'promote') return promote();
  console.log('usage: node local/cfver.cjs list [script] | promote <script> [versionId|latest]');
})();
