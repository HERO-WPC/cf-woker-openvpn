// Cloudflare Worker entry point. Bundled to `_worker.js` by build.js.
import { connect } from 'cloudflare:sockets';
import { route } from './handler.js';

export default {
  fetch: (req) => route(req, { connect }),
};