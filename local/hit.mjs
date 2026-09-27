// local/hit.mjs — fetch one or more URLs and print status/timing/body.
//   node local/hit.mjs <url> [url...]        (TIMEOUT_MS env overrides 150s)
const urls = process.argv.slice(2);
if (!urls.length) { console.log('usage: node local/hit.mjs <url> [url...]'); process.exit(1); }
const limit = +(process.env.TIMEOUT_MS || 150000);
for (const u of urls) {
  const t0 = Date.now();
  try {
    const r = await fetch(u, { signal: AbortSignal.timeout(limit), headers: { 'User-Agent': 'cfprobe' } });
    const b = await r.text();
    console.log(`\n### ${u}\nHTTP ${r.status}  ${Date.now() - t0}ms  cf-ray=${r.headers.get('cf-ray') || '-'}\n${b.slice(0, 2000)}`);
  } catch (e) {
    console.log(`\n### ${u}\nFAIL ${Date.now() - t0}ms  ${e.name}: ${e.message}`);
  }
}
