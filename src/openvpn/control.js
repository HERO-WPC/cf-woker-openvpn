// OpenVPN control channel: reliability layer (session-id, reliable packet-ids,
// ACKs, retransmission) and the on-wire control packet builder. The client
// (state machine) drives this; TLS records flow through here as P_CONTROL_V1.
import { buildControl, ControlParser, OP, tlsAuthKeyIndices } from './packet.js';
import { concat, hex } from './bytes.js';

export class ReliableChannel {
  // opts: { write(packetBytes)->void, tlsAuthKey, keyDirection, hmacHash }
  constructor(opts) {
    this.write = opts.write;
    this.sessionId = crypto.getRandomValues(new Uint8Array(8));
    this.remoteSid = null;
    this.tlsAuthKey = opts.tlsAuthKey || null;
    this.hmacHash = opts.hmacHash || 'SHA-1';
    this.outIndex = this.tlsAuthKey ? tlsAuthKeyIndices(opts.keyDirection || 0).out : 0;
    this.parser = new ControlParser(this.tlsAuthKey, opts.keyDirection || 0, this.hmacHash);
    this.nextRel = 1;
    this.tlsAuthCounter = 1;
    this.pending = [];       // [{id, opcode, message}]
    this.recvAck = [];       // reliable ids to acknowledge
    this.lastSeenRel = 0;
    this.queue = [];         // delivered control messages (P_CONTROL_V1)
    this.waiter = null;
    this.onData = null;
    this.log = opts.log || (() => {});
    this.sidResolve = null;
    this.sidReady = new Promise(r => { this.sidResolve = r; });
  }
  waitServerReset() { return this.sidReady; }
  resetSidWait() { this.sidReady = new Promise(r => { this.sidResolve = r; }); }

  _build(opcode, message, reliableId, tlsAuthId) {
    return buildControl({
      opcode, keyId: 0, sessionId: this.sessionId, reliableId,
      ackSid: this.remoteSid, ackIds: this.recvAck, message,
      tlsAuthKey: this.tlsAuthKey, outIndex: this.outIndex, hmacHash: this.hmacHash,
      tlsAuthId,
    });
  }

  async sendControl(opcode, message = new Uint8Array(0)) {
    const id = this.nextRel++;
    const pkt = await this._build(opcode, message, id, this.tlsAuthCounter++);
    this.recvAck = [];
    this.pending.push({ id, opcode, message });
    this.log('ctrl send op=' + opcode + ' rel=' + id + ' len=' + message.length);
    this.write(pkt);
  }

  async sendAckOnly() {
    if (!this.recvAck.length) return;
    const pkt = await this._build(OP.P_ACK_V1, new Uint8Array(0), 0, this.tlsAuthCounter++);
    this.recvAck = [];
    this.write(pkt);
  }
  flushAcks() { return this.recvAck.length ? this.sendAckOnly() : Promise.resolve(); }

  async handle(parsed) {
    // clear acked pending
    if (parsed.ackIds && parsed.ackIds.length) {
      this.pending = this.pending.filter(p => !parsed.ackIds.includes(p.id));
      this.log('ctrl recv acks for ' + parsed.ackIds.join(','));
    }
    if (parsed.opcode === OP.P_CONTROL_HARD_RESET_SERVER_V2 || parsed.opcode === OP.P_CONTROL_HARD_RESET_SERVER_V1) {
      if (!this.remoteSid) { this.remoteSid = parsed.sessionId; if (this.sidResolve) { this.sidResolve(); } }
      this._ack(parsed.reliableId);
      this.log('ctrl server reset rel=' + parsed.reliableId + ' sid=' + hex(parsed.sessionId));
      return;
    }
    if (parsed.opcode === OP.P_CONTROL_V1 || parsed.opcode === OP.P_CONTROL_SOFT_RESET_V1) {
      // Always ACK (including duplicates) so the peer stops retransmitting; only
      // deliver a packet when its reliable-id is strictly newer than what we saw.
      this._ack(parsed.reliableId);
      if (parsed.reliableId > this.lastSeenRel) {
        this.lastSeenRel = parsed.reliableId;
        this.queue.push(parsed);
        if (this.waiter) { const w = this.waiter; this.waiter = null; w(this.queue.shift()); }
      }
    }
  }
  _ack(id) { if (id != null && !this.recvAck.includes(id)) this.recvAck.push(id); }

  nextControl() {
    return new Promise((res) => {
      if (this.queue.length) res(this.queue.shift());
      else this.waiter = res;
    });
  }

  // resend any outstanding control packets not yet acked
  async retransmit() {
    const up = this.pending.slice();
    for (const p of up) {
      const pkt = await this._build(p.opcode, p.message, p.id, this.tlsAuthCounter++);
      this.log('ctrl retransmit op=' + p.opcode + ' rel=' + p.id);
      this.write(pkt);
    }
  }
  get pendingCount() { return this.pending.length; }
}
