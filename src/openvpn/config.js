// OpenVPN .ovpn config parser. First version only supports the directives
// needed for VPN Gate TCP nodes; unknown/unwanted directives produce errors.
const UNSUPPORTED = {
  'proto': (v) => {
    const tok = String(v).trim().toLowerCase();
    if (tok.startsWith('udp')) return `OPENVPN_UDP_NOT_SUPPORTED: proto ${v}`;
    if (!tok.startsWith('tcp')) return `OPENVPN_UNSUPPORTED: proto ${v}`;
    return null;
  },
  'dev': (v) => {
    const tok = String(v).trim().toLowerCase();
    if (tok.startsWith('tap')) return `OPENVPN_TAP_NOT_SUPPORTED: dev ${v}`;
    if (!tok.startsWith('tun')) return `OPENVPN_UNSUPPORTED: dev ${v}`;
    return null;
  },
};

export function parseOvpn(text) {
  const cfg = {
    client: false, dev: 'tun', proto: 'tcp', remotes: [], ca: '', tlsAuth: '', keyDirection: 0,
    cipher: '', dataCiphers: '', auth: 'SHA1', username: 'vpn', password: 'vpn',
    userPassInline: false, remoteCertTls: false, hasCert: false, hasKey: false,
  };
  const lines = text.split(/\r?\n/);
  let i = 0;
  const error = [];
  function blockTag(name) {
    // collect a <name>...</name> block starting at lines[i] (the <name> line)
    const start = i + 1;
    let end = -1;
    const closeRe = new RegExp(`^</\\s*${name}\\s*>`);
    for (let j = start; j < lines.length; j++) {
      if (closeRe.test(lines[j].trim())) { end = j; break; }
    }
    if (end < 0) error.push(`OPENVPN_PARSE_FAILED: unmatched <${name}>`);
    const body = lines.slice(start, end).join('\n');
    i = end >= 0 ? end : lines.length;
    return body;
  }
  for (i = 0; i < lines.length; i++) {
    let line = lines[i];
    const t = line.trim();
    if (!t || t.startsWith('#') || t.startsWith(';')) continue;
    // block
    let m = /^<([a-zA-Z0-9\-_]+)>$/.exec(t);
    if (m) {
      const name = m[1].toLowerCase();
      const body = blockTag(name);
      if (name === 'ca') cfg.ca = body.trim();
      else if (name === 'tls-auth') cfg.tlsAuth = body.trim();
      else if (name === 'cert') { cfg.hasCert = true; cfg.cert = body.trim(); }
      else if (name === 'key') { cfg.hasKey = true; cfg.key = body.trim(); }
      else if (name === 'auth-user-pass') { /* inline handled as block */ }
      else error.push(`OPENVPN_UNSUPPORTED_BLOCK: <${name}>`);
      continue;
    }
    // key/val
    const sp = t.indexOf(' ');
    const key = (sp < 0 ? t : t.slice(0, sp)).toLowerCase();
    const val = (sp < 0 ? '' : t.slice(sp + 1).trim());
    switch (key) {
      case 'client': cfg.client = true; break;
      case 'dev': { const e = UNSUPPORTED.dev(val); if (e) error.push(e); const dv = val.split(' ')[0].toLowerCase(); if (dv === 'tun') cfg.dev = 'tun'; break; }
      case 'proto': { const e = UNSUPPORTED.proto(val); if (e) error.push(e); const pv = val.split(' ')[0].toLowerCase(); if (pv === 'tcp' || pv === 'tcp-client') cfg.proto = 'tcp'; break; }
      case 'remote': { const [h, p] = val.split(' '); if (h && p) cfg.remotes.push({ host: h, port: +p }); break; }
      case 'cipher': cfg.cipher = val.toUpperCase(); break;
      case 'data-ciphers': cfg.dataCiphers = val.toUpperCase(); break;
      case 'auth': cfg.auth = val.toUpperCase(); break;
      case 'key-direction': cfg.keyDirection = parseInt(val, 10) || 0; break;
      case 'remote-cert-tls': cfg.remoteCertTls = true; break;
      case 'auth-user-pass': cfg.userPassInline = true; break;
      case 'username': cfg.username = val; break;
      case 'user': cfg.username = val; break;
      case 'password': cfg.password = val; break;
      // accept & ignore benign directives
      case 'resolv-retry': case 'nobind': case 'persist-key': case 'persist-tun':
      case 'verb': case 'mute': case 'block-outside-dns': case 'auth-nocache':
      case 'setenv': case 'pull': case 'float': case 'connect-retry': case 'connect-timeout':
      case 'server-poll-timeout': case 'tls-timeout': case 'reneg-sec': case 'ping':
      case 'ping-restart': case 'ping-exit': case 'route-nopull': case 'ncp-ciphers':
      case 'tls-version-min': case 'tls-cipher': case 'tls-ciphersuites': case 'sndbuf':
      case 'rcvbuf': case 'keepalive': case 'mssfix': case 'fragment': case 'explicit-exit-notify':
        break;
      default:
        error.push(`OPENVPN_UNSUPPORTED_OPTION: ${key}`);
    }
  }
  if (error.length) throw new Error(error[0]);
  if (!cfg.remotes.length) throw new Error('OPENVPN_NO_REMOTE');
  // <cert>/<key> (client cert) are parsed but ignored for v1: VPN Gate configs
  // ship a default gate client cert that the server does not verify. If the
  // server actually requests a client cert at TLS level, client.js will fail
  // with CLIENT_CERT_NOT_SUPPORTED.
  return cfg;
}
