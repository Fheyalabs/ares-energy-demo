// End-to-end auction over the real WebSocket protocol with real WASM.
//
// The crypto smoke test proved the FHE primitives work. It could not catch
// the class of bug this exercises: the relay never sent the seller the bid
// ciphertexts, so it had nothing to open once it knew the winner. Only
// driving the actual message flow, with one WASM Session per simulated
// tab, finds that.
//
//   node examples/energy_auction/e2e/auction_e2e.js [ws://host:port/ws]
const path = require('path');
const WASM = path.resolve(__dirname, '../static/wasm/pool_wasm.js');
const PoolWasm = require(WASM);

const URL = process.argv[2] || 'ws://localhost:8477/ws';
const RING = 16384, DEPTH = 3, SCALE_MOD = 50, FIRST_MOD = 60, BATCH = 8;
const SHARPEN = [0.5, 0.5];
const SPAN = 16.0;
const BIDS = [6.25, 7.50, 5.00, 9.75, 8.00]; // seat 3 must win

const b64 = u8 => Buffer.from(u8).toString('base64');
const unb64 = s => new Uint8Array(Buffer.from(s, 'base64'));

let M;
const why = e => {
  try { return M.getExceptionMessage(e).filter(Boolean).join(': '); } catch (_) { return String(e); }
};

// One simulated tab: its own WASM Session and its own socket.
class Tab {
  constructor(name) {
    this.name = name;
    this.S = new M.Session(RING, DEPTH, SCALE_MOD, FIRST_MOD, BATCH);
    this.pubKey = null;
    this.state = null;
    this.ws = new WebSocket(URL);
    this.ws.onmessage = ev => this.onMessage(JSON.parse(ev.data));
  }
  ready() {
    return new Promise(r => {
      if (this.ws.readyState === 1) return r();
      this.ws.onopen = () => r();
    });
  }
  send(o) { this.ws.send(JSON.stringify(o)); }
  get role() { return (this.state?.peers || []).find(p => p.id === this.me)?.role || ''; }
  get seat() { return (this.state?.peers || []).find(p => p.id === this.me)?.seat ?? -1; }

  onMessage(m) {
    try {
      if (m.type === 'state') { this.me = m.you; this.state = m.state; return; }

      if (m.type === 'pubkey') { this.pubKey = unb64(m.blob); return; }

      if (m.type === 'evalkey') {
        this.S.importEvalKey(unb64(m.blob));
        this.isEvaluator = true;
        return;
      }

      if (m.type === 'evaluate') {
        const cts = m.blobs.map(unb64);
        const masks = cts.length < 2
          ? [this.S.encrypt(this.pubKey, new Array(BATCH).fill(1.0))]
          : this.S.argmax(cts, SHARPEN);
        this.send({ type: 'masks', blobs: masks.map(b64), note: m.note });
        return;
      }

      if (m.type === 'masks') {
        const vals = m.blobs.map(b => this.S.fuse([this.S.partialDecrypt(unb64(b))], 1)[0]);
        const win = vals.indexOf(Math.max(...vals));
        const seats = JSON.parse(m.note || '[]');
        const bids = (m.bids || []).map(unb64);
        if (!bids[win]) throw new Error('relay sent no ciphertext for the winning seat');
        const price = this.S.fuse([this.S.partialDecrypt(bids[win])], 1)[0] * SPAN;
        this.masks = vals;
        this.send({ type: 'offer', seat: seats[win] ?? win, price_ct: price });
        return;
      }
    } catch (e) {
      console.error(`${this.name}: ${why(e)}`);
      process.exitCode = 1;
    }
  }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, label, ms = 40000) {
  const t0 = Date.now();
  while (!fn()) {
    if (Date.now() - t0 > ms) throw new Error(`timeout waiting for ${label}`);
    await sleep(60);
  }
}

(async () => {
  M = await PoolWasm();
  console.log(`connecting to ${URL}`);

  const seller = new Tab('seller');
  await seller.ready();
  await until(() => seller.role === 'seller', 'seller seated');
  console.log('seller seated');

  const buyers = [];
  for (let i = 0; i < BIDS.length; i++) {
    const b = new Tab(`buyer${i}`);
    await b.ready();
    await until(() => b.role === 'buyer', `buyer ${i} seated`);
    buyers.push(b);
  }
  console.log(`${buyers.length} buyers seated (seats ${buyers.map(b => b.seat).join(',')})`);

  // Seller opens the auction: keypair generated in its own tab.
  let t = Date.now();
  const { pk, evalKey } = seller.S.singleKeyGen();
  seller.send({ type: 'keys', blob: b64(pk), note: b64(evalKey) });
  await until(() => buyers.every(b => b.pubKey), 'public key delivered');
  console.log(`keys published ${Date.now() - t}ms`);

  // Each buyer encrypts its own bid.
  t = Date.now();
  for (const b of buyers) {
    const ct = b.S.encrypt(b.pubKey, new Array(BATCH).fill(BIDS[b.seat] / SPAN));
    b.send({ type: 'bid', blob: b64(ct) });
    await sleep(40);
  }
  console.log(`all bids sealed ${Date.now() - t}ms`);

  // Argmax runs on a blind buyer, masks go to the seller, seller offers.
  t = Date.now();
  await until(() => seller.state?.winner_seat >= 0, 'seller to receive an offer');
  console.log(`argmax + open ${Date.now() - t}ms`);

  const gotSeat = seller.state.winner_seat;
  const gotPrice = seller.state.price_ct;
  const wantSeat = BIDS.indexOf(Math.max(...BIDS));
  console.log(`bids   ${BIDS.map(b => b.toFixed(2)).join('  ')}`);
  console.log(`masks  ${(seller.masks || []).map(v => v.toFixed(4)).join('  ')}`);
  console.log(`winner seat ${gotSeat} (want ${wantSeat}) at ${gotPrice.toFixed(2)} ct (want ${BIDS[wantSeat].toFixed(2)})`);

  // Seller accepts; the trade must land in the log for everyone.
  seller.send({ type: 'settle', ok: true });
  await until(() => (seller.state?.trades || []).length > 0, 'trade logged');
  const tr = seller.state.trades[0];
  console.log(`logged: seat ${tr.seat} ${tr.price_ct.toFixed(2)}ct ${tr.accepted ? 'CLEARED' : 'DECLINED'} (${tr.bidders} bids)`);

  const ok = gotSeat === wantSeat
    && Math.abs(gotPrice - BIDS[wantSeat]) < 0.01
    && tr.accepted && tr.seat === wantSeat;
  console.log(ok ? 'E2E_OK' : 'E2E_FAIL');
  process.exit(ok ? 0 : 1);
})().catch(e => { console.error('ERROR:', why(e) || e); process.exit(1); });
