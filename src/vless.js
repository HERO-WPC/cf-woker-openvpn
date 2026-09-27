// VLESS request header parsing (preserved from the original project, unchanged).
import { u16 } from './openvpn/bytes.js';

const idB = null; // uuid bytes are injected by the worker to keep this module pure

export function vless(c, uuidBytes) {
  if (c.length < 23) return null;
  for (let i = 0; i < 16; i++) if (c[i + 1] !== uuidBytes[i]) return null;
  const o = 19 + c[17];
  if (o + 3 > c.length) return null;
  const p = u16(c, o);
  const t = c[o + 2] === 1 ? 1 : c[o + 2] + 1;
  const l = t === 3 ? c[o + 3] : t === 1 ? 4 : t === 4 ? 16 : 0;
  if (!l || o + 4 + l > c.length) return null;
  return {
    addrType: t,
    addrBytes: c.subarray(o + 4, o + 4 + l),
    dataOffset: o + 4 + l,
    port: p,
  };
}

export const addr = (t, b) => t === 3
  ? new TextDecoder().decode(b)
  : t === 1
    ? `${b[0]}.${b[1]}.${b[2]}.${b[3]}`
    : `[${Array.from({ length: 8 }, (_, i) => u16(b, i * 2).toString(16)).join(':')}]`;