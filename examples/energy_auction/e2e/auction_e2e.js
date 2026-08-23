// End-to-end auction over the real WebSocket protocol with real WASM.
//
// One WASM Session per simulated tab. This exercises what a crypto smoke
// test cannot: the message flow, the anonymity of the settled log, and the
// aggregate epoch audit.
//
//   node examples/energy_auction/e2e/auction_e2e.js [ws://host:port/ws] [--tamper]
//
// --tamper makes one buyer understate what it paid, so the epoch audit
// must fail to balance. A check that only ever passes proves nothing.
const path = require('path');
const PoolWasm = require(path.resolve(__dirname, '../static/wasm/pool_wasm.js'));

const URL = process.argv.find(a => a.startsWith('ws://')) || 'ws://localhost:8477/ws';
const TAMPER = process.argv.includes('--tamper');
const RING = 16384, DEPTH = 3, SCALE_MOD = 50, FIRST_MOD = 60, BATCH = 8;
const SHARPEN = [0.5, 0.5];
const SPAN = 16.0;
const BIDS = [6.25, 7.50, 5.00, 9.75, 8.00]; // seat 3 must win
const EPOCH = 5;

const b64 = u8 => Buffer.from(u8).toString('base64');
const unb64 = s => new Uint8Array(Buffer.from(s, 'base64'));

let M;
const why = e => {
  try { return M.getExceptionMessage(e).filter(Boolean).join(': '); } catch (_) { return String(e); }
};

class Tab {
  constructor(name) {
    this.name = name;
    this.S = new M.Session(RING, DEPTH, SCALE_MOD, FIRST_MOD, BATCH);
    this.pubKey = null;
    this.state = null;
    this.net = 0;   // this tab's own epoch position, nobody else's
    this.wins = 0;
    this.epochS = null;   // separate context + share for the epoch audit
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
  epoch() {
    if (!this.epochS) this.epochS = new M.Session(RING, DEPTH, SCALE_MOD, FIRST_MOD, BATCH);
    return this.epochS;
  }
  get role() { return (this.state?.peers || []).find(p => p.id === this.me)?.role || ''; }
  get seat() { return (this.state?.peers || []).find(p => p.id === this.me)?.seat ?? -1; }

  onMessage(m) {
    try {
      if (m.type === 'state') { this.me = m.you; this.state = m.state; return; }
      if (m.type === 'pubkey') { this.pubKey = unb64(m.blob); return; }

      // Sent to exactly one tab.
      if (m.type === 'won') { this.net += m.price_ct; this.wins++; return; }

      if (m.type === 'evalkey') { this.S.importEvalKey(unb64(m.blob)); return; }

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
        this.send({ type: 'offer', seat: seats[win] ?? win, price_ct: price });
        return;
      }

      // ---- epoch audit: N-of-N across every tab ----
      if (m.type === 'epochchain') {
        const S = this.epoch();
        const pk = m.blob ? S.keyGenNext(unb64(m.blob)) : S.keyGenFirst();
        this.send({ type: 'epochchained', blob: b64(pk) });
        return;
      }
      if (m.type === 'epochkey') {
        const sign = this.role === 'seller' ? -1 : 1;
        let net = this.net;
        if (TAMPER && this.name === 'buyer3') net -= 3.0;
        const ct = this.epoch().encrypt(unb64(m.blob), new Array(BATCH).fill(sign * net / SPAN));
        this.send({ type: 'epochtotal', blob: b64(ct) });
        return;
      }
      if (m.type === 'epochsum') {
        let acc = unb64(m.blobs[0]);
        for (let i = 1; i < m.blobs.length; i++) acc = this.epoch().evalAdd(acc, unb64(m.blobs[i]));
        this.summed = acc;                       // kept for the one-share probe
        this.send({ type: 'epochsummed', blob: b64(acc) });
        return;
      }
      if (m.type === 'epochdecrypt') {
        this.summed = unb64(m.blob);
        this.send({ type: 'epochpartial', blob: b64(this.epoch().partialDecrypt(unb64(m.blob))) });
        return;
      }
      if (m.type === 'epochfuse') {
        const net = this.epoch().fuse(m.blobs.map(unb64), 1)[0] * SPAN;
        this.verified = net;                     // every tab checks for itself
        if (this.role === 'seller') {
          this.send({ type: 'epochresult', price_ct: net, ok: Math.abs(net) < 0.05 });
        }
        return;
      }
    } catch (e) {
      console.error(`${this.name}: ${why(e)}`);
      process.exitCode = 1;
    }
  }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, label, ms = 60000) {
  const t0 = Date.now();
  while (!fn()) {
    if (Date.now() - t0 > ms) throw new Error(`timeout waiting for ${label}`);
    await sleep(60);
  }
}

(async () => {
  M = await PoolWasm();
  console.log(`connecting to ${URL}${TAMPER ? '   [TAMPER]' : ''}`);

  const seller = new Tab('seller');
  await seller.ready();
  await until(() => seller.role === 'seller', 'seller seated');

  const buyers = [];
  for (let i = 0; i < BIDS.length; i++) {
    const b = new Tab(`buyer${i}`);
    await b.ready();
    await until(() => b.role === 'buyer', `buyer ${i} seated`);
    buyers.push(b);
  }
  console.log(`seated: 1 seller + ${buyers.length} buyers`);

  for (let round = 1; round <= EPOCH; round++) {
    if (round > 1) {
      await until(() => seller.state?.phase === 'settled', 'settled');
      for (const b of buyers) b.pubKey = null;
    }
    const { pk, evalKey } = seller.S.singleKeyGen();
    seller.send({ type: 'keys', blob: b64(pk), note: b64(evalKey) });
    await until(() => buyers.every(b => b.pubKey), 'public key delivered');

    for (const b of buyers) {
      const ct = b.S.encrypt(b.pubKey, new Array(BATCH).fill(BIDS[b.seat] / SPAN));
      b.send({ type: 'bid', blob: b64(ct) });
      await sleep(40);
    }
    await until(() => seller.state?.winner_seat >= 0, 'offer');

    const price = seller.state.price_ct;
    seller.net += price;
    const before = (seller.state?.trades || []).length;
    seller.send({ type: 'settle', ok: true, price_ct: price });
    await until(() => (seller.state?.trades || []).length > before, 'trade logged');
    console.log(`round ${round}: cleared ${price.toFixed(2)} ct at slot ${seller.state.trades[0].slot}`);
  }

  // The log must name nobody.
  const log = seller.state.trades;
  const named = log.some(t => 'seat' in t);
  const slots = log.map(t => t.slot).reverse();
  console.log(`\nlog rows ${log.length}, slots ${slots.join(',')}`);
  console.log(`log names a winner:      ${named ? 'YES (bad)' : 'no'}`);
  const winner = buyers[BIDS.indexOf(Math.max(...BIDS))];
  console.log(`winner knows privately:  ${winner.wins} wins, net ${winner.net.toFixed(2)} ct`);
  const othersBlind = buyers.filter(b => b !== winner).every(b => b.wins === 0);
  console.log(`other buyers told:       ${othersBlind ? 'nothing' : 'SOMETHING (bad)'}`);

  // Aggregate audit: no individual total opened, no trade replayed.
  await until(() => seller.state?.epoch === 'ready', 'epoch ready');
  console.log(`\nepoch ready after ${log.length} trades, auditing in aggregate`);
  const t = Date.now();
  seller.send({ type: 'epochstart' });
  await until(() => seller.state?.epoch === 'done', 'epoch audited');
  const net = seller.state.epoch_net, ok = seller.state.epoch_ok;
  console.log(`epoch audited in ${Date.now() - t}ms: net ${net.toFixed(3)} ct, balanced=${ok}`);

  // The seller must NOT be able to open a total on its own. Its single
  // share is one of six; fusing with it alone has to fail or return
  // something that is not the aggregate.
  let sellerAlone = 'blocked';
  try {
    const solo = seller.epoch().fuse([seller.epoch().partialDecrypt(seller.summed)], 1)[0] * SPAN;
    sellerAlone = Math.abs(solo - net) < 0.05 ? 'OPENED (bad)' : 'garbage';
  } catch (_) { sellerAlone = 'blocked'; }
  console.log(`seller opening alone:    ${sellerAlone}`);

  // Every tab reached the same figure independently.
  const allAgree = [seller, ...buyers].every(x =>
    x.verified !== undefined && Math.abs(x.verified - net) < 0.05);
  console.log(`all ${1 + buyers.length} tabs verified independently: ${allAgree ? 'yes' : 'NO (bad)'}`);

  const expectBalanced = !TAMPER;
  const pass = !named && othersBlind && winner.wins === EPOCH
    && slots.length === EPOCH && new Set(slots).size === EPOCH
    && ok === expectBalanced && sellerAlone !== 'OPENED (bad)' && allAgree;
  console.log(pass ? 'E2E_OK' : 'E2E_FAIL');
  process.exit(pass ? 0 : 1);
})().catch(e => { console.error('ERROR:', why(e) || e); process.exit(1); });
