// Orchestrates the test suite: unit, mock server (GCM + CBC), handler route.
// Run with: node test/run.js  (or npm test)
import { spawnSync } from 'child_process';
import { root } from './root.js';

const T = root();
const steps = [
  { name: 'unit', cmd: ['node', 'test/unit.js'] },
  { name: 'tcp stack', cmd: ['node', 'test/tcp-test.js'] },
  { name: 'tls trust/EKU', cmd: ['node', 'test/tls-test.js'] },
  { name: 'mock GCM', cmd: ['node', 'test/mocktest.js', 'AES-128-GCM'] },
  { name: 'mock CBC', cmd: ['node', 'test/mocktest.js', 'AES-128-CBC'] },
  { name: 'handler /ovpn-test', cmd: ['node', 'test/handler-test.js'] },
];

let fail = 0;
for (const s of steps) {
  // stdio: 'inherit' — the confined sandbox forbids piped stdio (EPERM).
  const r = spawnSync(s.cmd[0], s.cmd.slice(1), { cwd: T, stdio: 'inherit' });
  const ok = r.status === 0;
  console.log(`\n===== ${s.name}: ${ok ? 'PASS' : 'FAIL'} =====`);
  if (!ok) fail++;
}
console.log(`\n${fail === 0 ? 'ALL TESTS PASSED' : fail + ' TEST(S) FAILED'}`);
process.exit(fail === 0 ? 0 : 1);
