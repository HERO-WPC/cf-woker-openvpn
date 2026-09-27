// Minimal X.509 (DER) parser + signature verification for TLS / CA checks.
import { derParse, concat } from './bytes.js';

// PEM block -> DER bytes (takes either a PEM string or DER Uint8Array)
export function pemToDer(input) {
  if (input instanceof Uint8Array) return input;
  const pem = String(input).trim();
  if (!/-----BEGIN/.test(pem)) {
    // maybe raw base64
    const bin = atob(pem.replace(/\s+/g, ''));
    return new Uint8Array(bin.length).map((_, i) => bin.charCodeAt(i));
  }
  const b64 = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const OID = {
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.10045.2.1': 'ecPublicKey',
  '1.2.840.113549.1.1.11': 'sha256WithRSA',
  '1.2.840.113549.1.1.12': 'sha384WithRSA',
  '1.2.840.113549.1.1.13': 'sha512WithRSA',
  '1.2.840.113549.1.1.5': 'sha1WithRSA',
  '1.2.840.10045.4.3.2': 'ecdsaWithSHA256',
  '1.2.840.10045.4.3.3': 'ecdsaWithSHA384',
  '1.2.840.10045.4.3.4': 'ecdsaWithSHA512',
  '1.2.840.10045.4.1': 'ecdsaWithSHA1',
  '2.5.29.15': 'keyUsage',
  '2.5.29.19': 'basicConstraints',
  '2.5.29.37': 'extendedKeyUsage',
  '1.3.6.1.5.5.7.3.1': 'serverAuth',
  '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '2.5.29.17': 'subjectAltName',
  '2.5.29.14': 'subjectKeyIdentifier',
  '2.5.29.35': 'authorityKeyIdentifier',
};

export function oidBytes(v) {
  // DER OBJECT IDENTIFIER value -> dotted string. First byte encodes the first two arcs.
  const first = v[0];
  let a, b;
  if (first < 40) { a = 0; b = first; }
  else if (first < 80) { a = 1; b = first - 40; }
  else { a = 2; b = first - 80; }
  let s = a + '.' + b;
  let i = 1;
  while (i < v.length) {
    let num = 0;
    while (v[i] & 0x80) { num = num * 128 + (v[i] & 0x7f); i++; }
    num = num * 128 + v[i]; i++;
    s += '.' + num;
  }
  return s;
}
export const oidName = (v) => OID[oidBytes(v)] || oidBytes(v);

function cnFromName(nameEl) {
  if (!nameEl || !nameEl.children) return '?';
  for (const set of nameEl.children) {
    if (!set.children) continue;
    for (const ava of set.children) {
      const pair = ava.children || [];
      if (pair.length >= 2 && oidBytes(pair[0].value) === '2.5.4.3') {
        try { return new TextDecoder().decode(pair[1].value).replace(/\0.*$/, ''); } catch { return '?'; }
      }
    }
  }
  return '?';
}

function asn1Time(der) {
  const tag = der[0];
  const str = new TextDecoder().decode(der.subarray(2));
  if (tag === 0x17) { // UTCTime YYMMDDHHMMSSZ
    const yy = +str.slice(0, 2);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return Date.UTC(year, +str.slice(2, 4) - 1, +str.slice(4, 6), +str.slice(6, 8), +str.slice(8, 10), +str.slice(10, 12));
  }
  if (tag === 0x18) { // GeneralizedTime YYYYMMDDHHMMSSZ
    return Date.UTC(+str.slice(0, 4), +str.slice(4, 6) - 1, +str.slice(6, 8), +str.slice(8, 10), +str.slice(10, 12), +str.slice(12, 14));
  }
  return NaN;
}

// Parse an X.509 certificate DER. Returns:
// { tbs:Uint8Array (raw TBS bytes used for signature verify),
//   validity:{notBefore,notAfter}, publicKey:{alg,spkiDer,rsa?{n,e},ec?{curve,point}},
//   signatureAlgorithm ('sha256WithRSA' etc), signature:Uint8Array,
//   ext:{serverAuth:bool,clientAuth:bool,ca:bool} }
export function parseX509(der) {
  const root = derParse(der);
  if (root.tag !== 0x30) throw new Error('X509_NOT_SEQUENCE');
  const cert = root.children;
  const tbs = cert[0];
  const sigAlg = cert[1];
  const sigValue = cert[2];
  const tbsChildren = tbs.children;
  // tbs: [0] version [1] serial [2] signature [3] issuer [4] validity [5] subject [6] spki [7] issuerUnique [8] subjectUnique [9] extensions
  const validity = tbsChildren[4].children;
  const spki = tbsChildren[6];
  const spkiChildren = spki.children;
  const algOid = spkiChildren[0].children[0].value;
  const alg = oidName(algOid);
  const keyBits = spkiChildren[1]; // BIT STRING
  const keyDer = keyBits.value.subarray(1); // skip unused-bits byte
  let rsa = null, ec = null;
  if (alg === 'rsaEncryption') {
    const ek = derParse(keyDer);
    const n = ek.children[0].value;
    const e = ek.children[1].value;
    rsa = { n, e };
  } else if (alg === 'ecPublicKey') {
    const curveOid = oidBytes(spkiChildren[0].children[1].value);
    const point = keyDer; // BIT STRING content = uncompressed point
    ec = { curve: curveOid, point };
  }
  const saOid = sigAlg.children[0].value;
  const signatureAlgorithm = oidName(saOid) || oidBytes(saOid);
  const signature = sigValue.value.subarray(1); // skip unused bits
  const s = {};
  // tbsCertificate element (cert[0]) exactly: element start .. element end
  const tbsElemStart = tbs.start - (tbs.total - tbs.len);
  s.tbs = der.subarray(tbsElemStart, tbsElemStart + tbs.total);
  s.validity = { notBefore: asn1Time(validity[0].value), notAfter: asn1Time(validity[1].value) };
  s.publicKey = { alg, spkiDer: der.subarray(spki.start - (spki.total - spki.len), spki.start + spki.len), rsa, ec };
  s.subjectCN = cnFromName(tbsChildren[5]);
  s.issuerCN = cnFromName(tbsChildren[3]);
  s.signatureAlgorithm = signatureAlgorithm;
  s.signature = signature;
  s.ext = { serverAuth: false, clientAuth: false, ca: false, keyUsage: 0 };
  // extensions
  const extsNode = tbsChildren[9];
  if (extsNode) {
    for (const extSeq of extsNode.children) {
      const ext = extSeq.children;
      const oid = oidName(ext[0].value);
      const critical = ext[1] && ext[1].tag === 0x01;
      const valNode = critical ? ext[2] : ext[1];
      if (oid === 'extendedKeyUsage') {
        const ev = derParse(valNode.value);
        if (ev.tag === 0x30) for (const o of ev.children) {
          const n = oidName(o.value);
          if (n === 'serverAuth') s.ext.serverAuth = true;
          if (n === 'clientAuth') s.ext.clientAuth = true;
        }
      } else if (oid === 'basicConstraints') {
        const bv = derParse(valNode.value);
        if (bv.tag === 0x30 && bv.children && bv.children.length && bv.children[0].tag === 0x01) {
          s.ext.ca = bv.children[0].value[0] === 0xFF;
        }
      } else if (oid === 'keyUsage') {
        if (valNode.value.length) s.ext.keyUsage = valNode.value[0];
      }
    }
  }
  return s;
}

const SIG_HASH = {
  'sha256WithRSA': ['RSASSA-PKCS1-v1_5', 'SHA-256'],
  'sha384WithRSA': ['RSASSA-PKCS1-v1_5', 'SHA-384'],
  'sha512WithRSA': ['RSASSA-PKCS1-v1_5', 'SHA-512'],
  'sha1WithRSA': ['RSASSA-PKCS1-v1_5', 'SHA-1'],
  'ecdsaWithSHA256': ['ECDSA', 'SHA-256'],
  'ecdsaWithSHA384': ['ECDSA', 'SHA-384'],
  'ecdsaWithSHA512': ['ECDSA', 'SHA-512'],
  'ecdsaWithSHA1': ['ECDSA', 'SHA-1'],
};

// Parse a PEM/DER RSA private key (PKCS#1 "RSA PRIVATE KEY" or PKCS#8
// "PRIVATE KEY" wrapping an rsaEncryption key). Returns { n:BigInt, d:BigInt }.
export function parseRsaPrivateKey(pem) {
  const der = pemToDer(pem);
  const root = derParse(der);
  // PKCS#1: SEQUENCE{version,n,e,d,p,q,dp,dq,qi}. PKCS#8: SEQUENCE{ver,alg,octet->PKCS#1 seq}.
  let ints;
  if (root.children && root.children.length >= 4 && root.children[0].tag === 0x02) {
    ints = root.children;
  } else if (root.children && root.children.length >= 2 && root.children[1] &&
             root.children[1].children && root.children[1].children[0] &&
             root.children[1].children[0].tag === 0x06 &&
             oidBytes(root.children[1].children[0].value) === '1.2.840.113549.1.1.1') {
    // PKCS#8: unwrap the OCTET STRING (index 2) which holds the PKCS#1 sequence
    const octs = root.children[2];
    let inner;
    const oc = derParse(octs.value);
    inner = oc.children;
    ints = inner;
  } else {
    throw new Error('NOT_RSA_PRIVATE_KEY');
  }
  const b = (v) => { let x = 0n; for (const c of v) x = (x << 8n) | BigInt(c); return x; };
  return { n: b(ints[1].value), d: b(ints[3].value) };
}
export function ecdsaDerToRaw(sig, size) {
  const root = derParse(sig);
  const r = root.children[0].value, s = root.children[1].value;
  const out = new Uint8Array(size * 2);
  out.set(r.subarray(Math.max(0, r.length - size)), size - Math.min(size, r.length));
  out.set(s.subarray(Math.max(0, s.length - size)), size * 2 - Math.min(size, s.length));
  return out;
}

// Verify `signature` over `data` with the issuer's public key (SPKI DER).
export async function verifySignature(spkiDer, sigAlg, signature, data) {
  const map = SIG_HASH[sigAlg];
  if (!map) throw new Error('UNSUPPORTED_SIGNATURE_ALG ' + sigAlg);
  const [algo, hash] = map;
  const key = await crypto.subtle.importKey('spki', spkiDer, { name: algo, hash }, false, ['verify']);
  let sig = signature;
  if (algo === 'ECDSA') {
    // figure curve size from the key
    const jwk = await crypto.subtle.importKey('spki', spkiDer, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    const size = (jwk.crv === 'P-384') ? 48 : (jwk.crv === 'P-521') ? 66 : 32;
    sig = ecdsaDerToRaw(signature, size);
    return crypto.subtle.verify({ name: 'ECDSA', hash }, key, sig, data);
  }
  return crypto.subtle.verify({ name: algo }, key, sig, data);
}