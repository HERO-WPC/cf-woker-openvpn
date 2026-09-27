// One-time generator: reads test/configs/sample0.ovpn, expands the remote list
// with a few proven VPN Gate alternates, and emits src/embedded-ovpn.js so the
// shipped worker has a working node built in (no env var needed).
import { readFileSync, writeFileSync } from 'fs';

const text = readFileSync('D:/桌面/worker-openvpn-tcp/test/configs/sample0.ovpn', 'utf8');
const remotes = ['219.100.37.224 443', '219.100.37.205 443', '219.100.37.114 443', '219.100.37.192 443', '219.100.37.17 443', '219.100.37.81 443', '219.100.37.4 443'];
// line-based replace: strip CR, find the single `remote host port` directive,
// and splice in the full remote list (deterministic, no escaping surprises).
const lines = text.split(/\r?\n/).map((l) => l.replace(/\r$/, ''));
const idx = lines.findIndex((l) => /^remote\s+\S+\s+\d+\s*$/.test(l.trim()));
if (idx < 0) throw new Error('no remote directive found');
lines.splice(idx, 1, ...remotes.map((r) => `remote ${r}`));
const out = lines.join('\n');
// JSON.stringify gives a safe, escaping-free JS string literal.
const js = `// Auto-generated from test/configs/sample0.ovpn by test/_embed.js. Do not edit.\n` +
  `// A built-in VPN Gate OpenVPN TCP node (primary + alternates) so the worker\n` +
  `// works out of the box. Override at runtime via _setOpenVpnConfig()/OPENVPN_OVPN.\n` +
  `export const EMBEDDED_OVPN = ${JSON.stringify(out)};\n`;
writeFileSync('D:/桌面/worker-openvpn-tcp/src/embedded-ovpn.js', js);
console.log('wrote src/embedded-ovpn.js', (js.length / 1024).toFixed(1) + 'KB');
