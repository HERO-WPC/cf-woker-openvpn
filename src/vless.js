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

export const addr = (t, b) => t === 3
  ? new TextDecoder().decode(b)
  : t === 1
    ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}`
    : `[${Array.from({ length: 8 }, (_, i) => u16(b, i * 2).toString(16)).join(':')}]`;