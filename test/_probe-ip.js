// Proper CONNECT+HTTP/1.0 probe: does the target serve over plain TCP?
import net from 'net';

function probe(host, port, path) {
  return new Promise((resolve) => {
    const socket = net.connect(10808, '127.0.0.1');
    let buf = Buffer.alloc(0); let sent = false; let done = false;
    const finish = (v) => { if (!done) { done = true; socket.destroy(); resolve(v); } };
    socket.once('connect', () => socket.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`));
    socket.on('error', (e) => finish('ERR ' + e.message));
    const pump = () => {
      for (;;) {
        const c = socket.read(); if (c === null) return;
        buf = Buffer.concat([buf, c]);
        if (!sent) {
          const i = buf.indexOf('\r\n\r\n');
          if (i >= 0) {
            const head = buf.slice(0, i).toString('latin1');
            const excess = buf.slice(i + 4);
            buf = excess;
            if (/\b200\b/.test(head)) {
              sent = true;
              socket.write(`GET ${path} HTTP/1.0\r\nHost: ${host}\r\nUser-Agent: probe\r\nConnection: close\r\n\r\n`);
            } else { finish('proxy ' + head.slice(0, 40)); return; }
          }
        }
      }
    };
    socket.on('readable', pump);
    socket.on('data', (d) => { buf = Buffer.concat([buf, d]); if (sent && !done && buf.length > 6) finish(buf.slice(0, 500).toString('latin1')); });
    setTimeout(() => finish('TIMEOUT'), 9000);
  });
}

for (const [h, p, path] of [['www.iplocate.io', 80, '/'], ['www.iplocate.io', 443, '/'], ['ip-api.com', 80, '/json/'], ['ifconfig.me', 80, '/']]) {
  console.log(`\n=== ${h}:${p}${path} ===`);
  const r = await probe(h, p, path);
  console.log(String(r).split('\r\n').slice(0, 10).join('\n'));
}
process.exit(0);