// VLESS request header parsing (preserved from the original project).
import { u16 } from './openvpn/bytes.js';

const idB = null; // uuid bytes are injected by the worker to keep this module pure

// Strict UUID string -> 16 raw bytes. A VLESS UUID is a standard UUID whose
// 32 hex chars (after stripping '-') encode 16 bytes — two hex chars per byte.
export function uuidToBytes(uuid) {
  const h = String(uuid).replace(/-/g, '');
  if (!/^[0-9a-fA-F]{32}$/.test(h)) { const e = new Error('INVALID_UUID ' + uuid); e.code = 'INVALID_UUID'; throw e; }
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function vless(c, uuidBytes) {
  if (c.length < 23) return null;
  for (let i = 0; i < 16; i++) if (c[i + 1] !== uuidBytes[i]) return null;
  const o = 19 + c[17];
  if (o + 3 > c.length) return null;
  const p = u16(c, o);
  const t = c[o + 2] === 1 ? 1 : c[o + 2] + 1;
  const l = t === 3 ? c[o + 3] : t === 1 ? 4 : t === 4 ? 16 : 0;
  // Standard VLESS: domain has a 1-byte length right after the type byte;
  // IPv4/IPv6 do NOT. So the address bytes start at o+3 for IP, o+4 for domain.
  const addrStart = t === 3 ? o + 4 : o + 3;
  if (!l || addrStart + l > c.length) return null;
  return {
    addrType: t,
    addrBytes: c.subarray(addrStart, addrStart + l),
    dataOffset: addrStart + l,
    port: p,
  };
}

// Parse a VLESS request header from a byte buffer that may arrive across
// multiple WebSocket messages. Returns:
//   null   -> need more bytes (keep buffering; never treat a partial message as
//             an error)
//   { error: CODE, message } -> invalid (UUID / command / address)
//   { version, port, addrType, host, headerLen } -> ready
// Address types are standard VLESS: 1=IPv4, 2=domain, 3=IPv6.
export function parseVlessHeader(buf, uuidBytes) {
  if (buf.length < 18) return null; // ver+uuid+optLen
  const optLen = buf[17];
  const cmdIndex = 18 + optLen;
  if (buf.length < cmdIndex + 1) return null;
  const cmd = buf[cmdIndex];
  if (cmd !== 1 && cmd !== 3) return { error: 'VLESS_COMMAND_UNSUPPORTED', message: 'command ' + cmd + ' (only tcp=1 and mux=3)' };
  for (let i = 0; i < 16; i++) if (buf[1 + i] !== uuidBytes[i]) return { error: 'VLESS_UUID_INVALID', message: 'uuid mismatch' };
  // Command 3 (mux.cool): the destination lives inside the mux frames, so the
  // request carries NO port and NO address -- it ends right after the command
  // byte. Xray really sends this (15-byte-shorter header), which is why the old
  // parser read the first mux byte as "address type 0" and rejected every muxed
  // connection, i.e. every default v2rayN setup.
  if (cmd === 3) return { version: buf[0], port: 0, addrType: 0, host: '', headerLen: cmdIndex + 1, cmd };
  if (buf.length < cmdIndex + 4) return null;
  const port = (buf[cmdIndex + 1] << 8) | buf[cmdIndex + 2];
  const addrType = buf[cmdIndex + 3];
  let addrLen;
  if (addrType === 1) addrLen = 4;
  else if (addrType === 2) { if (buf.length < cmdIndex + 5) return null; addrLen = buf[cmdIndex + 4]; }
  else if (addrType === 3) addrLen = 16;
  else return { error: 'VLESS_ADDRESS_INVALID', message: 'address type ' + addrType + ' is not supported' };
  const addrStart = addrType === 2 ? cmdIndex + 5 : cmdIndex + 4;
  const headerLen = addrStart + addrLen;
  if (buf.length < headerLen) return null; // still a partial header
  let host;
  if (addrType === 1) host = `${buf[addrStart]}.${buf[addrStart + 1]}.${buf[addrStart + 2]}.${buf[addrStart + 3]}`;
  else if (addrType === 2) host = new TextDecoder().decode(buf.subarray(addrStart, addrStart + addrLen));
  else { const g = []; for (let i = 0; i < 8; i++) g.push(((buf[addrStart + i * 2] << 8) | buf[addrStart + i * 2 + 1]).toString(16)); host = g.join(':'); }
  if (!host) return { error: 'VLESS_ADDRESS_INVALID', message: 'empty address' };
  return { version: buf[0], port, addrType, host, headerLen, cmd };
}

export const addr = (t, b) => t === 3
  ? new TextDecoder().decode(b)
  : t === 1
    ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}`
    : `[${Array.from({ length: 8 }, (_, i) => u16(b, i * 2).toString(16)).join(':')}]`;