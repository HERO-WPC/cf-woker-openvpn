// DNS resolution via Cloudflare DoH (preserved from the original project).
export const resolveIP = async (h) => {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return h;
  const j = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=A`, {
    headers: { Accept: 'application/dns-json' },
  }).then((r) => r.json()).catch(() => ({}));
  return j.Answer?.find((a) => a.type === 1)?.data ?? null;
};