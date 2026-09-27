// Build an Xray config with one SOCKS inbound per node from the Worker's
// subscription, so every node can be tested independently (exit IP + latency).
import fs from 'node:fs';

const SUB = process.env.SUB || 'https://test33333.wang.dpdns.org/sub';
const BASE_PORT = +(process.env.BASE_PORT || 12100);

const b64 = await (await fetch(SUB)).text();
const links = Buffer.from(b64, 'base64').toString('utf8').split('\n').filter(Boolean).map((l) => {
  const u = new URL(l);
  return {
    name: decodeURIComponent(u.hash.slice(1)),
    id: u.username,
    host: u.hostname,
    port: +u.port,
    path: u.searchParams.get('path'),
    host_hdr: u.searchParams.get('host'),
    sni: u.searchParams.get('sni'),
    fp: u.searchParams.get('fp') || 'chrome',
  };
});

const inbounds = [], outbounds = [], rules = [];
links.forEach((n, i) => {
  const tag = 'n' + (i + 1);
  inbounds.push({ tag: 'in' + tag, listen: '127.0.0.1', port: BASE_PORT + i, protocol: 'socks', settings: { auth: 'noauth', udp: false }, sniffing: { enabled: false } });
  outbounds.push({
    tag: 'out' + tag, protocol: 'vless',
    settings: { vnext: [{ address: n.host, port: n.port, users: [{ id: n.id, encryption: 'none', flow: '' }] }] },
    streamSettings: {
      network: 'ws', security: 'tls',
      tlsSettings: { serverName: n.sni, fingerprint: n.fp },
      wsSettings: { path: n.path, host: n.host_hdr },
    },
  });
  rules.push({ type: 'field', inboundTag: ['in' + tag], outboundTag: 'out' + tag });
});

const cfg = { log: { loglevel: 'warning' }, inbounds, outbounds, routing: { rules } };
const out = 'D:/桌面/worker-openvpn-tcp/local/xray/config-sub.json';
fs.writeFileSync(out, JSON.stringify(cfg, null, 2));
fs.writeFileSync('D:/桌面/worker-openvpn-tcp/local/xray/sub-nodes.json', JSON.stringify(links.map((n, i) => ({ ...n, port: BASE_PORT + i })), null, 2));
console.log(`nodes: ${links.length} -> ${out}  (socks ports ${BASE_PORT}..${BASE_PORT + links.length - 1})`);
for (const n of links) console.log(`  ${n.name.padEnd(28)} path=${n.path}`);
