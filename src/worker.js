// Cloudflare Worker entry point. Bundled to `_worker.js` by build.js.
// The execution context is forwarded so the handler can keep an OpenVPN tunnel
// warm in the background (ctx.waitUntil): a cold handshake costs ~2s, which is
// the dominant part of "every new connection is slow", and VPN Gate restarts an
// idle session after 10s (ping-restart 10).
import { connect } from 'cloudflare:sockets';
import { route } from './handler.js';

export default {
  fetch: (req, env, ctx) => route(req, { connect }, ctx),
};
