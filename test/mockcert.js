// Generates a self-signed RSA certificate (DER writer + WebCrypto) for the
// mock OpenVPN server. The client test config uses this cert as its <ca>.
// opts: { serverAuth:boolean (default true), clientAuth:boolean (default true) }
export async function makeSelfSigned(opts = {}) {
  const kp = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));

  // ---- DER helpers ----
  const len = (n) => { if (n < 0x80) return [n]; const b = []; let v = n; while (v) { b.unshift(v & 0xFF); v = Math.floor(v / 256); } return [0x80 | b.length, ...b]; };
  const tlv = (tag, content) => [tag, ...len(content.length), ...content];
  const seq = (...p) => tlv(0x30, p.flat());
  const set = (...p) => tlv(0x31, p.flat());
  const intBytes = (b) => { const a = [...b]; while (a.length > 1 && a[0] === 0) a.shift(); if (a[0] & 0x80) a.unshift(0); return tlv(0x02, a); };
  const oid = (s) => {
    const parts = s.split('.').map(Number);
    const bytes = [parts[0] * 40 + parts[1]];
    for (const p of parts.slice(2)) { let v = p; const b = []; b.unshift(v & 0x7F); v = Math.floor(v / 128); while (v) { b.unshift((v & 0x7F) | 0x80); v = Math.floor(v / 128); } bytes.push(...b); }
    return tlv(0x06, bytes);
  };
  const null0 = () => tlv(0x05, []);
  const bitString = (content) => tlv(0x03, [0, ...content]);
  const printable = (s) => tlv(0x13, [...Buffer.from(s, 'ascii')]);
  const p2 = (n) => String(n).padStart(2, '0');
  const utc = (d) => {
    const s = p2(d.getUTCFullYear() % 100) + p2(d.getUTCMonth() + 1) + p2(d.getUTCDate()) + p2(d.getUTCHours()) + p2(d.getUTCMinutes()) + p2(d.getUTCSeconds()) + 'Z';
    return tlv(0x17, [...Buffer.from(s, 'ascii')]);
  };
  const octet = (content) => tlv(0x04, content);
  const boolTrue = () => tlv(0x01, [0xFF]);
  const explicit = (tag, content) => tlv(0xA0 | tag, content);

  const name = (cn) => seq(set(seq(oid('2.5.4.3'), printable(cn))));
  const sigAlg = seq(oid('1.2.840.113549.1.1.11'), null0());
  const now = new Date();
  const nb = new Date(now.getTime() - 86400000);
  const na = new Date(now.getTime() + 86400000 * 3650);

  const extBasic = seq(oid('2.5.29.19'), octet(seq(boolTrue())));
  const extKu = seq(oid('2.5.29.15'), octet(bitString([0x05, 0, 0])));
  const ekus = [];
  if (opts.serverAuth !== false) ekus.push(oid('1.3.6.1.5.5.7.3.1'));
  if (opts.clientAuth !== false) ekus.push(oid('1.3.6.1.5.5.7.3.2'));
  const extEku = seq(oid('2.5.29.37'), octet(seq(...ekus)));
  const extensions = seq(extBasic, extKu, extEku);

  const tbs = seq(
    explicit(0, intBytes([2])),             // version v3
    intBytes([0x01, 0x23, 0x45, 0x67]),     // serial
    sigAlg,
    name('MockVPNGate'),                    // issuer
    seq(utc(nb), utc(na)),                  // validity
    name('MockVPNGate'),                    // subject
    [...spki],                              // subjectPublicKeyInfo (full SPKI der)
    explicit(3, extensions)
  );

  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, kp.privateKey, Uint8Array.from(tbs)));
  const certDer = seq(tbs, sigAlg, bitString(sig));

  const pem = (label, der) => '-----BEGIN ' + label + '-----\n' + Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n') + '\n-----END ' + label + '-----\n';
  return { certPem: pem('CERTIFICATE', certDer), keyPem: pem('PRIVATE KEY', pkcs8), certDer: Uint8Array.from(certDer) };
}