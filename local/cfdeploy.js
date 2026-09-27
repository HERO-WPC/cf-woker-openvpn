// Cloudflare Workers deploy/诊断工具（仅使用 Node 内置能力，无第三方依赖）
//
//   $env:CF_API_TOKEN  = "..."      # Account > Workers Scripts > Edit
//   $env:CF_ACCOUNT_ID = "..."      # 32 位 hex
//
//   node local/cfdeploy.js whoami
//   node local/cfdeploy.js discover test33333.wang.dpdns.org
//   node local/cfdeploy.js scripts
//   node local/cfdeploy.js settings bitter-star-c6cd
//   node local/cfdeploy.js deploy   bitter-star-c6cd [file]
//   node local/cfdeploy.js verify   test33333.wang.dpdns.org
import { readFileSync } from 'node:fs';

const API = 'https://api.cloudflare.com/client/v4';
const TOKEN = process.env.CF_API_TOKEN || '';
const ACCT = process.env.CF_ACCOUNT_ID || '';
const [cmd, arg1, arg2] = process.argv.slice(2);

function die(msg) { console.error('ERROR: ' + msg); process.exit(1); }

async function cf(method, path, body, raw) {
  const headers = { Authorization: 'Bearer ' + TOKEN };
  if (body && !raw) headers['Content-Type'] = 'application/json';
  const res = await fetch(API + path, { method, headers, body: raw ? body : (body ? JSON.stringify(body) : undefined) });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { }
  if (!json) return { ok: res.ok, status: res.status, text };
  if (!json.success) {
    const errs = (json.errors || []).map(e => `[${e.code}] ${e.message}`).join('; ');
    return { ok: false, status: res.status, errors: errs, json };
  }
  return { ok: true, status: res.status, result: json.result };
}

function needToken() { if (!TOKEN) die('缺少 CF_API_TOKEN 环境变量'); }
function needAcct() { needToken(); if (!ACCT) die('缺少 CF_ACCOUNT_ID 环境变量'); }

// ---------- whoami ----------
async function whoami() {
  needToken();
  const v = await cf('GET', '/user/tokens/verify');
  console.log('token verify : ' + (v.ok ? 'OK (status=' + (v.result && v.result.status) + ')' : 'FAIL ' + v.errors));
  const a = await cf('GET', '/accounts');
  if (!a.ok) { console.log('accounts     : FAIL ' + a.errors); return; }
  console.log('accounts     :');
  for (const x of a.result) console.log('   ' + x.id + '  ' + x.name);
}

// ---------- scripts ----------
async function scripts() {
  needAcct();
  const r = await cf('GET', `/accounts/${ACCT}/workers/scripts`);
  if (!r.ok) return die('list scripts: ' + r.errors);
  console.log('scripts (' + r.result.length + '):');
  for (const s of r.result) {
    console.log('   ' + (s.id || s.name).padEnd(34) + ' modified=' + (s.modified_on || '?') + '  tag=' + (s.etag || '').slice(0, 8));
  }
}

// ---------- discover：哪个脚本在服务这个域名 ----------
async function discover(host) {
  needAcct();
  if (!host) die('用法: discover <hostname>');

  // 1) Workers 自定义域
  try {
    const d = await cf('GET', `/accounts/${ACCT}/workers/domains`);
    if (d.ok) {
      const hit = d.result.filter(x => (x.hostname || '') === host);
      console.log('custom domains on this account: ' + d.result.length);
      for (const x of d.result) console.log('   ' + (x.hostname || '').padEnd(40) + ' -> service=' + (x.service || '?') + ' env=' + (x.environment || '?') + (x.hostname === host ? '   <<< MATCH' : ''));
      if (hit.length) console.log('\n==> ' + host + ' 由脚本 "' + hit[0].service + '" (' + hit[0].environment + ') 通过 Custom Domain 提供');
      if (!hit.length) console.log('\n(该 hostname 不是本账号的 Workers Custom Domain，继续查 zone route)');
    } else { console.log('custom domains: FAIL ' + d.errors); }
  } catch (e) { console.log('custom domains: ERR ' + e.message); }

  // 2) Zone workers routes
  const parts = host.split('.');
  for (let i = 1; i < parts.length; i++) {
    const zoneName = parts.slice(i).join('.');
    const z = await cf('GET', `/zones?name=${encodeURIComponent(zoneName)}`);
    if (!z.ok) { console.log(`zone ${zoneName}: FAIL ${z.errors}`); continue; }
    if (!z.result.length) { console.log(`zone ${zoneName}: not in this account`); continue; }
    const zid = z.result[0].id;
    console.log(`zone ${zoneName} (${zid}):`);
    const rt = await cf('GET', `/zones/${zid}/workers/routes`);
    if (!rt.ok) { console.log('   routes: FAIL ' + rt.errors); continue; }
    for (const r of rt.result) console.log('   ' + (r.pattern || '').padEnd(40) + ' -> script=' + (r.script || '(none)'));
    const hit = rt.result.filter(r => {
      const p = (r.pattern || '').replace(/\*$/, '');
      return host.startsWith(p.replace(/\/$/, ''));
    });
    if (hit.length) console.log('==> ' + host + ' 命中 route "' + hit[0].pattern + '" -> 脚本 "' + hit[0].script + '"');
  }
}

// ---------- settings ----------
async function settings(name) {
  needAcct();
  if (!name) die('用法: settings <script>');
  const r = await cf('GET', `/accounts/${ACCT}/workers/scripts/${name}/settings`);
  if (!r.ok) return die('settings: ' + r.errors);
  const b = r.result.bindings || [];
  console.log('compatibility_date : ' + r.result.compatibility_date);
  console.log('compatibility_flags: ' + JSON.stringify(r.result.compatibility_flags || []));
  console.log('usage_model        : ' + (r.result.usage_model || '-'));
  console.log('logpush            : ' + (r.result.logpush !== undefined ? r.result.logpush : '-'));
  console.log('observability      : ' + JSON.stringify(r.result.observability || null));
  console.log('bindings (' + b.length + '):');
  for (const x of b) {
    if (x.type === 'secret_text') console.log('   [secret_text]  ' + x.name + '  (值不可读)');
    else if (x.type === 'plain_text') console.log('   [plain_text]   ' + x.name + ' = ' + JSON.stringify(String(x.text).slice(0, 120)));
    else console.log('   [' + x.type + '] ' + JSON.stringify(x).slice(0, 160));
  }
  console.log('\n--- 原始 settings JSON（供 deploy 复用） ---');
  console.log(JSON.stringify(r.result, null, 1).slice(0, 4000));
}

// ---------- deploy ----------
async function deploy(name, file) {
  needAcct();
  if (!name) die('用法: deploy <script> [file]');
  file = file || '_worker.js';
  const src = readFileSync(file);
  console.log(`uploading ${file} (${src.length} bytes) -> script "${name}"`);

  // 先读现有 settings，尽量原样保留 bindings / compat 设置
  const st = await cf('GET', `/accounts/${ACCT}/workers/scripts/${name}/settings`);
  const meta = { main_module: '_worker.js' };
  if (st.ok) {
    if (st.result.compatibility_date) meta.compatibility_date = st.result.compatibility_date;
    if (st.result.compatibility_flags && st.result.compatibility_flags.length) meta.compatibility_flags = st.result.compatibility_flags;
    if (st.result.usage_model) meta.usage_model = st.result.usage_model;
    if (st.result.observability) meta.observability = st.result.observability;
    const b = st.result.bindings || [];
    const secrets = b.filter(x => x.type === 'secret_text');
    const keep = b.filter(x => x.type !== 'secret_text');
    if (keep.length) meta.bindings = keep;
    if (secrets.length) console.log('保留 secret bindings（不带值）: ' + secrets.map(s => s.name).join(', '));
  } else {
    console.log('（读不到原 settings，使用默认 metadata）: ' + st.errors);
  }

  const fd = new FormData();
  fd.append('metadata', new Blob([JSON.stringify(meta)], { type: 'application/json' }));
  fd.append('_worker.js', new Blob([src], { type: 'application/javascript+module' }), '_worker.js');

  const r = await cf('PUT', `/accounts/${ACCT}/workers/scripts/${name}`, fd, true);
  if (!r.ok) return die('deploy FAILED: ' + r.errors);
  console.log('deploy OK. id=' + r.result.id + ' etag=' + String(r.result.etag).slice(0, 8) + ' modified=' + r.result.modified_on);
}

// ---------- verify ----------
async function verify(host) {
  if (!host) die('用法: verify <hostname>');
  const url = 'https://' + host + '/version?x=' + Date.now();
  const res = await fetch(url, { headers: { 'User-Agent': 'cfdeploy-verify' } });
  const t = await res.text();
  console.log('GET ' + url);
  console.log('HTTP ' + res.status + '  cf-ray=' + res.headers.get('cf-ray'));
  console.log(t.slice(0, 400));
}

// ---------- caps：这个 token 到底能碰什么 ----------
async function caps() {
  needAcct();
  const probes = [
    ['GET', '/user', 'User Details'],
    ['GET', `/accounts/${ACCT}/workers/scripts`, 'Workers Scripts'],
    ['GET', `/accounts/${ACCT}/workers/domains`, 'Workers Custom Domains'],
    ['GET', `/accounts/${ACCT}/workers/subdomain`, 'Workers Subdomain'],
    ['GET', `/accounts/${ACCT}/workers/account-settings`, 'Workers Account Settings'],
    ['GET', `/accounts/${ACCT}/pages/projects`, 'Pages Projects'],
    ['GET', `/accounts/${ACCT}/storage/kv/namespaces`, 'Workers KV'],
    ['GET', `/accounts/${ACCT}/d1/database`, 'D1'],
    ['GET', `/accounts/${ACCT}/r2/buckets`, 'R2'],
  ];
  for (const [m, p, label] of probes) {
    const r = await cf(m, p);
    let extra = '';
    if (r.ok && Array.isArray(r.result)) extra = '  (n=' + r.result.length + ')';
    console.log(label.padEnd(26) + (r.ok ? 'OK  ' : 'FAIL ') + (r.ok ? '' : r.errors) + extra);
  }
  // 每个 zone 的 route 权限（本 token 可见的 zone）
  const zs = await cf('GET', '/zones');
  if (zs.ok) for (const z of zs.result) {
    const rt = await cf('GET', `/zones/${z.id}/workers/routes`);
    console.log(('route@' + z.name).padEnd(26) + (rt.ok ? 'OK  (n=' + rt.result.length + ')' : 'FAIL ' + rt.errors));
  }
}

// ---------- pages：Pages 项目 ----------
async function pages() {
  needAcct();
  const r = await cf('GET', `/accounts/${ACCT}/pages/projects`);
  if (!r.ok) return die('pages: ' + r.errors);
  console.log('pages projects (' + r.result.length + '):');
  for (const p of r.result) {
    console.log('   ' + p.name.padEnd(28) + ' sub=' + (p.subdomain || '-'));
    console.log('      domains: ' + ((p.domains || []).join(', ') || '(none)'));
    console.log('      created=' + (p.created_on || '?') + '  prod_branch=' + (p.production_branch || '-'));
  }
}

// ---------- dns：看哪些记录是 Workers/Pages 自定义域（100::）----------
async function dns(zoneName) {
  needToken();
  if (!zoneName) die('用法: dns <zoneName>');
  const z = await cf('GET', `/zones?name=${encodeURIComponent(zoneName)}`);
  if (!z.ok) return die('zone: ' + z.errors);
  if (!z.result.length) return die('zone 不属于本账号: ' + zoneName);
  const zid = z.result[0].id;
  console.log(`zone ${zoneName} (${zid})`);
  const r = await cf('GET', `/zones/${zid}/dns_records?per_page=100`);
  if (!r.ok) return die('dns_records: ' + r.errors);
  for (const x of r.result) {
    const worker = x.meta && x.meta.origin_worker_id ? '  origin_worker_id=' + x.meta.origin_worker_id : '';
    const managed = x.meta && x.meta.read_only ? ' [managed]' : '';
    console.log('   ' + String(x.type).padEnd(6) + x.name.padEnd(42) + ' -> ' + String(x.content).padEnd(30) + (x.proxied ? 'proxied' : 'dns-only') + worker + managed);
  }
}

// ---------- api：通用探测 ----------
async function api(method, path) {
  needToken();
  method = (method || 'GET').toUpperCase();
  if (!path) die('用法: api <METHOD> <path>');
  const r = await fetch(API + path, { method, headers: { Authorization: 'Bearer ' + TOKEN } });
  const t = await r.text();
  console.log(method + ' ' + path + '  ->  HTTP ' + r.status);
  console.log(t.length > 3000 ? t.slice(0, 3000) + ' ...[truncated]' : t);
}

const cmds = { whoami, discover, scripts, settings, deploy, verify, api, caps, pages, dns };
if (!cmds[cmd]) { console.log('用法: node local/cfdeploy.js <whoami|caps|scripts|pages|dns <zone>|discover <host>|settings <script>|deploy <script> [file]|verify <host>|api <METHOD> <path>>'); process.exit(1); }
await cmds[cmd](arg1, arg2);
