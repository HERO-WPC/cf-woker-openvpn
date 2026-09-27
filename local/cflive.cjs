// Download a deployed Worker script verbatim (no truncation) so it can be diffed
// against the local build. CommonJS on purpose: no deps, works on any node >= 18.
//
//   node local/cflive.cjs <scriptName> [outFile]
//
// Auth: CF_API_TOKEN (+ CF_ACCOUNT_ID); falls back to the wrangler OAuth token
// saved by earlier steps in %TEMP%\cf_oauth.txt.
const fs = require('fs');
const os = require('os');
const path = require('path');

const acct = process.env.CF_ACCOUNT_ID || '37de7ffcd288d95dcfd76646368b9e91';
const name = process.argv[2] || 'cf-ogate';
const out = process.argv[3] || path.join('local', `live_${name}.js`);

function token() {
  if (process.env.CF_API_TOKEN) return process.env.CF_API_TOKEN.trim();
  const p = path.join(os.tmpdir(), 'cf_oauth.txt');
  if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8').trim();
  throw new Error('no token: set CF_API_TOKEN or %TEMP%\\cf_oauth.txt');
}

// Pull the single part out of a multipart/form-data body.
function partFromMultipart(text) {
  const first = text.indexOf('\r\n\r\n');
  if (first < 0) return null;
  const rest = text.slice(first + 4);
  const end = rest.lastIndexOf('\r\n--');
  return end < 0 ? rest : rest.slice(0, end);
}

(async () => {
  const t = token();
  const headers = { Authorization: 'Bearer ' + t };
  const paths = [
    `/accounts/${acct}/workers/scripts/${name}/content`,
    `/accounts/${acct}/workers/scripts/${name}`,
  ];
  for (const p of paths) {
    const url = 'https://api.cloudflare.com/client/v4' + p;
    const r = await fetch(url, { headers });
    const ct = (r.headers.get('content-type') || '').toLowerCase();
    if (!r.ok) {
      const body = await r.text();
      console.log(`${p} -> HTTP ${r.status} (${ct.split(';')[0]}) ${body.slice(0, 200).replace(/\s+/g, ' ')}`);
      continue;
    }
    let text = await r.text();
    if (ct.includes('multipart')) {
      const part = partFromMultipart(text);
      if (part === null) { console.log(`${p} -> HTTP ${r.status} multipart parse failed`); continue; }
      text = part;
    }
    fs.writeFileSync(out, text);
    console.log(`${p} -> HTTP ${r.status} ok`);
    console.log(`saved ${out}  bytes=${Buffer.byteLength(text)}  lines=${text.split('\n').length}`);
    const head = text.split('\n').slice(0, 3).join(' | ');
    console.log('head: ' + head.slice(0, 160));
    return;
  }
  console.log('FAILED: no variant returned the script body');
  process.exitCode = 1;
})();
