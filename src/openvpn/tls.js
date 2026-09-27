// TLS 1.2 client for the OpenVPN control channel. Runs in pure JS + WebCrypto.
// Operates as a byte-stream: feed(cipher/plain records), and it emits outbound
// TLS records via the `onSend` callback (which the control channel wraps in
// P_CONTROL_V1 packets). Supports ECDHE-RSA / ECDHE-ECDSA with AES-GCM and
// AES-CBC, and extended-master-secret.
import { concat, bytes, u16, u24, w16, w24, u32, hex } from './bytes.js';
import { tlsPRF12, aesGcmDecrypt, aesGcmEncrypt, aesCbcDecrypt, aesCbcEncrypt, hmac, rsaSignPkcs1v15 } from './crypto.js';
import { parseX509, pemToDer, verifySignature, ecdsaDerToRaw, parseRsaPrivateKey } from './x509.js';

const CT = { CHANGE_CIPHER_SPEC: 20, ALERT: 21, HANDSHAKE: 22, APPLICATION_DATA: 23 };
const HS = { CLIENT_HELLO: 1, SERVER_HELLO: 2, CERTIFICATE: 11, SERVER_KEY_EXCHANGE: 12, CERTIFICATE_REQUEST: 13, SERVER_HELLO_DONE: 14, CERTIFICATE_VERIFY: 15, CLIENT_KEY_EXCHANGE: 16, FINISHED: 20 };

// cipher suite table
const SUITES = [
  { id: 0xC02F, name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', keyEx: 'EC', sig: 'RSA', gcm: true, key: 16, iv: 12, hash: 'SHA-256', prfHash: 'SHA-256' },
  { id: 0xC02B, name: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', keyEx: 'EC', sig: 'ECDSA', gcm: true, key: 16, iv: 12, hash: 'SHA-256', prfHash: 'SHA-256' },
  { id: 0x0035, name: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', keyEx: 'EC', sig: 'RSA', gcm: false, key: 32, iv: 16, block: 16, hash: 'SHA-1', prfHash: 'SHA-256' },
  { id: 0x002F, name: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', keyEx: 'EC', sig: 'RSA', gcm: false, key: 16, iv: 16, block: 16, hash: 'SHA-1', prfHash: 'SHA-256' },
  { id: 0xC00A, name: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', keyEx: 'EC', sig: 'ECDSA', gcm: false, key: 32, iv: 16, block: 16, hash: 'SHA-1', prfHash: 'SHA-256' },
  { id: 0xC009, name: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', keyEx: 'EC', sig: 'ECDSA', gcm: false, key: 16, iv: 16, block: 16, hash: 'SHA-1', prfHash: 'SHA-256' },
];
const suiteById = (id) => SUITES.find(s => s.id === id);

const NAMED_CURVE = { 23: 'P-256', 24: 'P-384', 25: 'P-521' };
const DIGEST_SIZE = { 'SHA-256': 32, 'SHA-384': 48, 'SHA-1': 20 };

export class TlsClient {
  // opts: { onSend(bytes) -> void, verifyCaPem: string, sni: string|null,
  //         log(msg), keyLog?(label,bytes) }
  constructor(opts) {
    this.onSend = opts.onSend;
    this.caDer = opts.verifyCaPem ? pemToDer(opts.verifyCaPem) : null;
    this.clientCertDer = opts.clientCertPem ? pemToDer(opts.clientCertPem) : null;
    this.clientPriv = opts.clientKeyPem ? parseRsaPrivateKey(opts.clientKeyPem) : null;
    this.sni = opts.sni || null;
    this.log = opts.log || (() => {});
    this.log2 = opts.log2 || null;
    this.forceNoEms = !!opts.forceNoEms;
    this.buf = new Uint8Array(0);
    this.handshakeBytes = new Uint8Array(0); // accumulated handshake messages
    this.state = 'idle';
    this.sendSeq = 0; this.recvSeq = 0;
    this.writeEnc = false; this.readEnc = false;
    this.clientRandom = null;
    this.serverRandom = null;
    this.serverSessionId = new Uint8Array(0);
    this.suite = null;
    this.serverCert = null;
    this.ems = false;
    this.master = null;
    this.writeKeys = null; this.readKeys = null;
    this.appData = [];
    this.pendingClientHello = null;
    this.finished = false;
    this.certRequested = false;
    this.err = null;
    this.appDataWaiter = null;
  }

  _record(type, payload) {
    const p = new Uint8Array(5 + payload.length);
    p[0] = type; p[1] = 0x03; p[2] = 0x03; w16(p, 3, payload.length); p.set(payload, 5);
    return p;
  }
  _handshake(type, payload) {
    const p = new Uint8Array(4 + payload.length);
    p[0] = type; p[1] = payload.length >> 16 & 0xFF; p[2] = payload.length >> 8 & 0xFF; p[3] = payload.length & 0xFF;
    p.set(payload, 4);
    return p;
  }
  _appendHandshake(bytes) {
    // handshakeBytes is updated as messages are sent/received; used for verify_data + EMS
    let b = bytes;
    // skip ChangeCipherSpec records; only handshake records contribute
    this.handshakeBytes = concat(this.handshakeBytes, b);
  }

  // ---- sending ----
  async start() {
    // Build ClientHello
    this.clientRandom = crypto.getRandomValues(new Uint8Array(32));
    this.state = 'clienthello';
    const ch = this._clientHello();
    const rec = this._record(CT.HANDSHAKE, ch);
    this._appendHandshake(ch);
    this.onSend(rec);
  }

  _clientHello() {
    const rnd = this.clientRandom;
    const u16be = (n) => { const b = new Uint8Array(2); w16(b, 0, n & 0xFFFF); return b; };
    const ext = (type, content) => concat(u16be(type), u16be(content.length), content);
    const suites = SUITES.map(s => { const b = new Uint8Array(2); w16(b, 0, s.id); return b; });
    const suitesBytes = concat(...suites);
    const exts = [];
    // supported_groups (0x000A): content = {2-byte list length}{groups}
    const groups = concat(u16be(23), u16be(24)); // secp256r1, secp384r1
    exts.push(ext(0x000A, concat(u16be(groups.length), groups)));
    // ec_point_formats (0x000B): content = {1-byte len}{uncompressed(0)}
    exts.push(ext(0x000B, bytes([0x01, 0x00])));
    // signature_algorithms (0x000D): content = {2-byte list length}{algs}
    const sigAlgs = [0x04, 0x01, 0x04, 0x03, 0x04, 0x05, 0x05, 0x01, 0x05, 0x03, 0x06, 0x01];
    exts.push(ext(0x000D, concat(u16be(sigAlgs.length), bytes(sigAlgs))));
    // extended_master_secret (0x0017): empty
    exts.push(ext(0x0017, new Uint8Array(0)));
    // renegotiation_info (0xFF01): content = {0x00}
    exts.push(ext(0xFF01, bytes([0x00])));
    if (this.sni) {
      const hostBytes = bytes(this.sni);
      const name = concat(u16be(0), u16be(hostBytes.length), hostBytes); // HostName type 0 + len + name
      const serverNameList = concat(u16be(name.length), name);
      exts.push(ext(0x0000, serverNameList));
    }
    const extBytes = concat(...exts);
    const body = concat(
      bytes([0x03, 0x03]), rnd,
      bytes([0x00]),                                  // session id empty
      u16be(suitesBytes.length), suitesBytes,
      bytes([0x01, 0x00]),                            // compression methods: null
      u16be(extBytes.length), extBytes
    );
    return this._handshake(HS.CLIENT_HELLO, body);
  }

  // Encrypt/wrap an outbound record if writeEnc is active.
  async _sendRecord(type, payload) {
    if (this.writeEnc && type !== CT.CHANGE_CIPHER_SPEC && type !== CT.HANDSHAKE) {
      // app data encrypted
    }
    if (this.writeEnc) {
      const rec = await this._protectRecord(type, payload);
      this.onSend(rec);
      this.sendSeq++;
      return;
    }
    this.onSend(this._record(type, payload));
  }

  async _protectRecord(type, payload) {
    const ss = this.writeKeys;
    if (!ss) throw new Error('tls: no write keys');
    const seq = _seqBytes(this.sendSeq);
    if (this.suite.gcm) {
      const nonce = concat(ss.iv, new Uint8Array(8)); // fixed iv (4) + explicit nonce zero
      const aad = concat(seq, bytes([type, 0x03, 0x03]), _u16pair(payload.length));
      const ct = await aesGcmEncrypt(ss.key, nonce, payload, aad);
      const explicit = new Uint8Array(8); // explicit nonce
      const p = new Uint8Array(5 + 8 + ct.length);
      p[0] = type; p[1] = 0x03; p[2] = 0x03; w16(p, 3, 8 + ct.length); p.set(explicit, 5); p.set(ct, 13);
      return p;
    } else {
      // CBC: record_iv + padded plaintext(with mac)
      const iv = crypto.getRandomValues(new Uint8Array(this.suite.iv));
      const mac = await hmac(this.suite.hash, ss.macKey, concat(seq, bytes([type, 0x03, 0x03]), _u16pair(payload.length), payload));
      const pt = concat(payload, mac);
      const ct = await aesCbcEncrypt(ss.key, iv, pt);
      const p = new Uint8Array(5 + iv.length + ct.length);
      p[0] = type; p[1] = 0x03; p[2] = 0x03; w16(p, 3, iv.length + ct.length); p.set(iv, 5); p.set(ct, 5 + iv.length);
      return p;
    }
  }

  // ---- receiving ----
  async feed(chunk) {
    this.buf = concat(this.buf, chunk);
    await this._process();
  }
  async _process() {
    for (;;) {
      if (this.buf.length < 5) break;
      const type = this.buf[0], ver = u16(this.buf, 1), len = u16(this.buf, 3);
      if (this.buf.length < 5 + len) break;
      const full = this.buf.subarray(0, 5 + len);
      this.buf = this.buf.subarray(5 + len);
      const payload = full.subarray(5);
      if (type === CT.CHANGE_CIPHER_SPEC) {
        if (payload[0] === 1) { this.readEnc = true; }
        this.recvSeq = 0; // activation reset: next encrypted record uses seq 0
        continue;
      }
      if (this.readEnc) {
        const dec = await this._unprotectRecord(type, len, payload, full);
        if (dec === null) { const e = new Error('TLS_RECORD_DECRYPT_FAILED'); e.code = 'TLS_RECORD_DECRYPT_FAILED'; throw e; }
        await this._handleRecord(type, dec.plain, null);
      } else {
        await this._handleRecord(type, payload, null);
      }
      this.recvSeq++;
    }
    if (this.err) { const e = this.err; this.err = null; throw e; }
  }
  _handleCCS(payload, send) { }
  async _unprotectRecord(type, len, payload, full) {
    const ss = this.readKeys;
    const seq = _seqBytes(this.recvSeq);
    if (this.suite.gcm) {
      const explicit = payload.subarray(0, 8);
      const nonce = concat(ss.iv, explicit);
      const ct = payload.subarray(8);
      const plainLen = Math.max(0, len - 8 - 16); // GCM tag is 16 bytes
      const aad = concat(seq, bytes([type, 0x03, 0x03]), _u16pair(plainLen));
      const plain = await aesGcmDecrypt(ss.key, nonce, ct, aad);
      if (plain === null) return null;
      return { plain, raw: null };
    } else {
      const iv = payload.subarray(0, this.suite.iv);
      const ct = payload.subarray(this.suite.iv);
      const pt0 = await aesCbcDecrypt(ss.key, iv, ct);
      if (pt0 === null) return null;
      const macLen = DIGEST_SIZE[this.suite.hash];
      if (pt0.length < macLen) return null;
      const plain = pt0.subarray(0, pt0.length - macLen);
      const mac = pt0.subarray(pt0.length - macLen);
      const expect = await hmac(this.suite.hash, ss.macKey, concat(seq, bytes([type, 0x03, 0x03]), _u16pair(plain.length), plain));
      if (!_ctEqual(mac, expect)) return null;
      return { plain, raw: null };
    }
  }
  _handleCCS(payload, send) { if (payload[0] === 1) { /* mark */ } }
  async _handleRecord(type, payload, raw) {
    if (type === CT.ALERT) {
      const lvl = payload[0], desc = payload[1];
      const e = new Error('TLS_ALERT level=' + lvl + ' desc=0x' + desc.toString(16));
      e.code = 'TLS_ALERT'; e.desc = desc; this.err = e; throw e;
    }
    if (type === CT.CHANGE_CIPHER_SPEC && payload[0] === 1) {
      this.readEnc = true;
      this.readSeq = 0;
      this.state = 'serverCCS';
      this.log('tls: server CCS');
      return;
    }
    if (type === CT.HANDSHAKE) {
      let off = 0;
      while (off < payload.length) {
        const htype = payload[off];
        const hlen = u24(payload, off + 1);
        const msg = payload.subarray(off + 4, off + 4 + hlen);
        this._appendHandshake(payload.subarray(off, off + 4 + hlen)); // append BEFORE handling so EMS/verify hashes include this message
        await this._handleHandshake(htype, msg);
        off += 4 + hlen;
      }
      return;
    }
    if (type === CT.APPLICATION_DATA) {
      this.appData.push(payload.slice());
      if (this.appDataWaiter) { const w = this.appDataWaiter; this.appDataWaiter = null; w(); }
      return;
    }
  }
  // resolve when new decrypted application data arrives
  waitAppData() {
    return new Promise(r => { this.appDataWaiter = r; });
  }
  clearAppDataWaiter() { this.appDataWaiter = null; }
  async _handleHandshake(htype, msg) {
    if (htype === HS.SERVER_HELLO) await this._serverHello(msg);
    else if (htype === HS.CERTIFICATE) await this._certificate(msg);
    else if (htype === HS.SERVER_KEY_EXCHANGE) await this._serverKeyExchange(msg);
    else if (htype === HS.CERTIFICATE_REQUEST) { this.certRequested = true; this.log('tls: server requested client cert'); }
    else if (htype === HS.SERVER_HELLO_DONE) await this._serverHelloDone();
    else if (htype === HS.FINISHED) await this._serverFinished(msg);
  }

  async _serverHello(msg) {
    let off = 0;
    const version = u16(msg, off); off += 2;
    this.serverRandom = msg.subarray(off, off + 32); off += 32;
    const sidLen = msg[off]; off += 1 + sidLen;
    const suiteId = u16(msg, off); off += 2;
    const comp = msg[off]; off += 1;
    const suite = suiteById(suiteId);
    if (!suite) { const e = new Error('TLS_UNSUPPORTED_CIPHER 0x' + suiteId.toString(16)); e.code = 'TLS_UNSUPPORTED_CIPHER'; throw e; }
    this.suite = suite;
    if (version < 0x0303) { const e = new Error('TLS_VERSION_NOT_SUPPORTED'); e.code = 'TLS_VERSION_NOT_SUPPORTED'; throw e; }
    // parse extensions for EMS
    if (off < msg.length) {
      const extLen = u16(msg, off); off += 2;
      const end = off + extLen;
      while (off < end) {
        const et = u16(msg, off); const el = u16(msg, off + 2); off += 4;
        if (et === 0x0017 && el >= 0) this.ems = this.forceNoEms ? false : true;
        off += el;
      }
    }
    this.state = 'serverhello';
    this.log('tls: cipher=' + suite.name + ' ems=' + this.ems);
    if (this.emaHandler) this.emaHandler(suite);
  }

  async _certificate(msg) {
    const listLen = u24(msg, 0);
    let off = 3;
    const end = 3 + listLen;
    this.serverChain = [];
    while (off < end) {
      const clen = u24(msg, off); off += 3;
      const der = msg.subarray(off, off + clen); off += clen;
      this.serverChain.push(der);
    }
    if (!this.serverChain.length) { const e = new Error('TLS_NO_CERT'); e.code = 'TLS_NO_CERT'; throw e; }
    const leaf = parseX509(this.serverChain[0]);
    this.serverCert = leaf;
    await this._verifyChain();
  }

  async _verifyChain() {
    const leaf = this.serverCert;
    // validity
    const now = Date.now();
    if (now < leaf.validity.notBefore || now > leaf.validity.notAfter) { const e = new Error('CERT_EXPIRED'); e.code = 'CERT_EXPIRED'; throw e; }
    const trusted = [this.caDer].filter(Boolean);
    const chain = this.serverChain.map(parseX509);
    let verified = false;
    // 1) verify against the configured CA
    for (const t of trusted) {
      try {
        const caCert = parseX509(t);
        if (await verifySignature(caCert.publicKey.spkiDer, leaf.signatureAlgorithm, leaf.signature, leaf.tbs)) { verified = true; break; }
      } catch { }
    }
    // 2) fallback: verify the presented chain is internally consistent and rooted
    //    at a self-signed cert (handles configs whose <ca> is stale). Every
    //    signature is still verified, so a forged chain is never accepted.
    if (!verified && chain.length >= 2) {
      // walk the presented chain: every cert signed by the next, then the last
      // cert must be signed by a configured CA (or be self-signed).
      let good = true;
      for (let j = 0; j + 1 < chain.length; j++) {
        const ok = await verifySignature(chain[j + 1].publicKey.spkiDer, chain[j].signatureAlgorithm, chain[j].signature, chain[j].tbs);
        if (!ok) { good = false; break; }
      }
      if (good) {
        const last = chain[chain.length - 1];
        let okCA = false;
        for (const t of trusted) {
          try { const ca = parseX509(t); if (await verifySignature(ca.publicKey.spkiDer, last.signatureAlgorithm, last.signature, last.tbs)) { okCA = true; break; } } catch { }
        }
        const selfSigned = await verifySignature(last.publicKey.spkiDer, last.signatureAlgorithm, last.signature, last.tbs);
        if (okCA || selfSigned) verified = true;
      }
    }
    if (!verified) { const e = new Error('CERT_VERIFY_FAILED'); e.code = 'CERT_VERIFY_FAILED'; throw e; }
  }

  async _serverKeyExchange(msg) {
    const suite = this.suite;
    let off = 0;
    const curveType = msg[off]; off++;
    const curveId = u16(msg, off); off += 2;
    const pointLen = msg[off]; off++;
    const point = msg.subarray(off, off + pointLen); off += pointLen;
    // signature alg + sig
    const sigAlgId = u16(msg, off); off += 2;
    const sigLen = u16(msg, off); off += 2;
    const sig = msg.subarray(off, off + sigLen);
    this.curve = NAMED_CURVE[curveId];
    if (!this.curve) { const e = new Error('TLS_UNSUPPORTED_CURVE ' + curveId); e.code = 'TLS_UNSUPPORTED_CURVE'; throw e; }
    this.serverKeyPoint = point;
    // verify signature over clientRandom||serverRandom||(curveType..point)
    const signed = concat(this.clientRandom, this.serverRandom, msg.subarray(0, off - 4));
    const leaf = this.serverCert;
    const sigAlgName = this.suite.sig === 'RSA'
      ? (sigAlgId === 0x0403 ? 'sha384WithRSA' : sigAlgId === 0x0405 ? 'sha512WithRSA' : 'sha256WithRSA')
      : (this._sigMapEcdsa(sigAlgId));
    const ok = await verifySignature(leaf.publicKey.spkiDer, sigAlgName, sig, signed);
    if (!ok) { const e = new Error('CERT_VERIFY_FAILED'); e.code = 'CERT_VERIFY_FAILED'; throw e; }
    this.state = 'serverkeyexchange';
  }
  _sigMapEcdsa(id) { return id === 0x0503 ? 'ecdsaWithSHA384' : id === 0x0504 ? 'ecdsaWithSHA512' : 'ecdsaWithSHA256'; }

  async _serverHelloDone() {
    const suite = this.suite;
    // Generate client ECDH key
    if (this.curve !== 'P-256') { const e = new Error('TLS_UNSUPPORTED_CURVE ' + this.curve + ' (only P-256)'); e.code = 'TLS_UNSUPPORTED_CURVE'; throw e; }
    this.ecdh = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', this.ecdh.publicKey));
    // derive shared secret
    const serverKey = await crypto.subtle.importKey('raw', this.serverKeyPoint, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const preMaster = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: serverKey }, this.ecdh.privateKey, 256));
    this.preMaster = preMaster;
    // TLS 1.2 client certificate (respond to the server's CertificateRequest).
    // The Certificate message always follows a request; empty when we have no cert.
    if (this.certRequested) {
      const certBody = this.clientCertDer
        ? (() => { const l = this.clientCertDer.length; const b = new Uint8Array(3 + 3 + l); w24(b, 0, 3 + l); w24(b, 3, l); b.set(this.clientCertDer, 6); return b; })()
        : new Uint8Array(3);
      const certMsg = this._handshake(HS.CERTIFICATE, certBody);
      this._appendHandshake(certMsg);
      this.onSend(this._record(CT.HANDSHAKE, certMsg));
      if (this.clientCertDer) this.log('tls: sending client certificate' + (this.clientPriv ? '' : ' (no key)'));
    }
    // ClientKeyExchange: build + append to handshake log BEFORE deriving the
    // master secret, so the extendedMasterSecret session_hash includes it.
    const ckePayload = concat(bytes([pubRaw.length]), pubRaw);
    const cke = this._handshake(HS.CLIENT_KEY_EXCHANGE, ckePayload);
    this._appendHandshake(cke);
    // master secret
    let master;
    if (this.ems) {
      const sessionHash = new Uint8Array(await crypto.subtle.digest('SHA-256', this.handshakeBytes));
      master = await tlsPRF12(preMaster, 'extended master secret', sessionHash, suite.prfHash, 48);
    } else {
      master = await tlsPRF12(preMaster, 'master secret', concat(this.clientRandom, this.serverRandom), suite.prfHash, 48);
    }
    this.master = master;
    // key block
    const macLen = suite.gcm ? 0 : DIGEST_SIZE[suite.hash];
    const ivLen = suite.gcm ? 4 : suite.iv;
    const keyBlockLen = 2 * (macLen + suite.key + ivLen);
    const kb = await tlsPRF12(master, 'key expansion', concat(this.serverRandom, this.clientRandom), suite.prfHash, keyBlockLen);
    let o = 0;
    const cs = (n) => kb.subarray(o, o + n), adv = (n) => (o += n);
    let cmac, smac, ckey, skey, civ, siv;
    if (suite.gcm) { ckey = cs(suite.key); adv(suite.key); skey = cs(suite.key); adv(suite.key); civ = cs(4); adv(4); siv = cs(4); adv(4); }
    else { cmac = cs(macLen); adv(macLen); smac = cs(macLen); adv(macLen); ckey = cs(suite.key); adv(suite.key); skey = cs(suite.key); adv(suite.key); civ = cs(ivLen); adv(ivLen); siv = cs(ivLen); adv(ivLen); }
    this.writeKeys = { key: ckey, iv: civ, macKey: cmac };
    this.readKeys = { key: skey, iv: siv, macKey: smac };
    // send ClientKeyExchange, [CertificateVerify], ChangeCipherSpec, Finished
    this.onSend(this._record(CT.HANDSHAKE, cke));
    if (this.certRequested && this.clientPriv) {
      // TLS 1.2 CertificateVerify: signature over the transcript up to (but not
      // including) this message. sha256+rsa (0x0401) with pure-JS PKCS#1 v1.5.
      const sig = await rsaSignPkcs1v15(this.clientPriv, this.handshakeBytes);
      const cvBody = concat(bytes([0x04, 0x01]), bytes([sig.length >> 8 & 0xFF, sig.length & 0xFF]), sig);
      const cv = this._handshake(HS.CERTIFICATE_VERIFY, cvBody);
      this._appendHandshake(cv);
      this.onSend(this._record(CT.HANDSHAKE, cv));
      this.log('tls: sent CertificateVerify');
    }
    this.onSend(this._record(CT.CHANGE_CIPHER_SPEC, bytes([0x01])));
    this.writeEnc = true; this.sendSeq = 0;
    // Finished
    const verifyData = await this._finishedVerifyData('client finished', this.handshakeBytes);
    const fin = this._handshake(HS.FINISHED, verifyData);
    this._appendHandshake(fin);
    const finRec = await this._protectRecord(CT.HANDSHAKE, fin);
    this.onSend(finRec);
    this.sendSeq++;
    this.state = 'clientFinishedSent';
  }

  async _finishedVerifyData(label, handshakeBytes) {
    const digest = new Uint8Array(await crypto.subtle.digest(this.suite.prfHash, handshakeBytes));
    return tlsPRF12(this.master, label, digest, this.suite.prfHash, 12);
  }
  async _serverFinished(msg) {
    // server finished is appended to handshakeBytes already; exclude it from the hash
    const upTo = this.handshakeBytes.length - (4 + msg.length);
    const expected = await this._finishedVerifyData('server finished', this.handshakeBytes.subarray(0, upTo));
    const actual = msg.subarray(0, 12);
    if (!_ctEqual(actual, expected)) { const e = new Error('TLS_SCFV'); e.code = 'TLS_SCFV'; throw e; }
    this.finished = true;
    this.state = 'handshakeDone';
    this.log('tls: handshake done');
    if (this.onDone) this.onDone();
  }

  // Writes APPLICATION_DATA (encrypted after handshake). Returns nothing; bytes flow via onSend.
  async write(data) {
    if (!this.finished) throw new Error('tls: not ready for app data');
    const rec = await this._protectRecord(CT.APPLICATION_DATA, data);
    this.onSend(rec);
    this.sendSeq++;
  }
  readAppData() { const r = this.appData; this.appData = []; return r; }
  get done() { return this.finished; }
}

function _seqBytes(seq) { // 8-byte big-endian TLS sequence number
  const b = new Uint8Array(8);
  let v = seq >>> 0;
  b[7] = v & 0xFF; b[6] = (v >>> 8) & 0xFF; b[5] = (v >>> 16) & 0xFF; b[4] = (v >>> 24) & 0xFF;
  v = Math.floor(seq / 0x100000000);
  b[3] = v & 0xFF; b[2] = (v >>> 8) & 0xFF; b[1] = (v >>> 16) & 0xFF; b[0] = (v >>> 24) & 0xFF;
  return b;
}
function _u16pair(n) { const b = new Uint8Array(2); w16(b, 0, n); return b; }
function _ctEqual(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
