// TLS trust-chain + remote-cert-tls EKU tests:
//  - leaf signed by the configured CA -> pass
//  - server-presented self-signed root (not the configured CA) -> reject
//  - remote-cert-tls server: leaf must carry serverAuth EKU
import { makeSelfSigned } from './mockcert.js';
import { TlsClient } from '../src/openvpn/tls.js';
import { parseX509, pemToDer } from '../src/openvpn/x509.js';

let fail = 0;
function ok(name, cond) { if (!cond) { fail++; console.log('FAIL', name); } else console.log('ok', name); }

function mkTls(verifyCaPem, opts = {}) {
  const t = new TlsClient({ onSend: () => {}, verifyCaPem, log: () => {}, ...opts });
  return t;
}
async function verifyChain(t, leafDer) {
  t.serverChain = [leafDer];
  t.serverCert = parseX509(leafDer);
  await t._verifyChain();
}

(async () => {
  // (1) configured CA == server leaf (self-signed) -> pass
  {
    const ca = await makeSelfSigned();
    const t = mkTls(ca.certPem);
    try { await verifyChain(t, ca.certDer); ok('configured CA accepts its own leaf', true); }
    catch (e) { ok('configured CA accepts its own leaf', false); }
  }

  // (2) attacker self-signed leaf, configured CA is a DIFFERENT cert -> reject
  {
    const ca = await makeSelfSigned();
    const attacker = await makeSelfSigned();
    const t = mkTls(ca.certPem);
    let threw = false, code = '';
    try { await verifyChain(t, attacker.certDer); } catch (e) { threw = true; code = e.code; }
    ok('attacker self-signed root is NOT trusted', threw && code === 'OPENVPN_TLS_CA_VERIFY_FAILED');
  }

  // (3) remote-cert-tls: serverAuth EKU present -> pass
  {
    const ca = await makeSelfSigned();
    const t = mkTls(ca.certPem, { remoteCertTls: true });
    try { await verifyChain(t, ca.certDer); ok('remote-cert-tls: serverAuth cert accepted', true); }
    catch (e) { ok('remote-cert-tls: serverAuth cert accepted', false); }
  }

  // (4) remote-cert-tls: clientAuth-only cert -> reject with EKU error
  {
    const ca = await makeSelfSigned({ serverAuth: false }); // clientAuth only
    const leafInfo = parseX509(ca.certDer);
    ok('clientAuth-only cert parsed (serverAuth=false, clientAuth=true)', leafInfo.ext.serverAuth === false && leafInfo.ext.clientAuth === true);
    const t = mkTls(ca.certPem, { remoteCertTls: true });
    let threw = false, code = '';
    try { await verifyChain(t, ca.certDer); } catch (e) { threw = true; code = e.code; }
    ok('remote-cert-tls: clientAuth-only cert rejected', threw && code === 'OPENVPN_TLS_EKU_INVALID');
  }

  // (5) no remote-cert-tls -> EKU not enforced (clientAuth-only cert still works)
  {
    const ca = await makeSelfSigned({ serverAuth: false });
    const t = mkTls(ca.certPem, { remoteCertTls: false });
    try { await verifyChain(t, ca.certDer); ok('no remote-cert-tls: EKU not enforced (compat)', true); }
    catch (e) { ok('no remote-cert-tls: EKU not enforced (compat)', false); }
  }

  // (6) leaf + intermediate + configured CA chain -> pass
  // The intermediate is "signed by the CA" is hard to fabricate here without an
  // issuer-signing helper; approximate with a 2-cert chain where the last cert
  // equals the configured CA (leaf signed by CA directly) -> step 2 chain walk.
  {
    const root = await makeSelfSigned();
    const leafInfo = parseX509(root.certDer);
    const t = mkTls(root.certPem);
    t.serverChain = [root.certDer, root.certDer]; // leaf + "intermediate" both self-signed-by-root
    t.serverCert = leafInfo;
    try { await t._verifyChain(); ok('chain walk: last signed by configured CA -> pass', true); }
    catch (e) { ok('chain walk: last signed by configured CA -> pass', false); }
  }

  console.log(fail ? ('\n' + fail + ' failures') : '\nALL TLS PASS');
  process.exit(fail ? 1 : 0);
})();