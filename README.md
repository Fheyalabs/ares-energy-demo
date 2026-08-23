# ARES Energy Demo

A browser demo of peer-to-peer energy trading in which nobody, including the
party running the market, ever sees a bid.

One solar seller and five buyers clear a sealed-bid auction under fully
homomorphic encryption. Each buyer encrypts its bid inside its own browser tab.
The winning bid is selected without any bid being decrypted, and the seller
learns the clearing price without learning who offered it. After five settled
trades the books are checked in aggregate, so a supervisor can confirm that
everything balances without reopening a single trade.

Every tab runs real OpenFHE compiled to WebAssembly. There is no server-side
cryptography: the Go process in this repository is a message relay that holds
no keys and can decrypt nothing.

## What the demo shows

| Property | How it is enforced |
|---|---|
| Bids stay sealed during clearing | Buyers encrypt under the seller's public key; ciphertext is all that leaves the tab |
| The ranking runs blind | One buyer acts as evaluator with the relinearisation key only, so it can compute on ciphertexts but cannot read them |
| The seller learns only the price | It decrypts exactly one ciphertext, the winning bid, and nothing else |
| Only the winner learns it won | The relay sends a private message to the winning seat; the public log carries no name |
| The books are still auditable | An N-of-N threshold key opens the sum of everyone's net position, never an individual total |
| Tampering is detectable | A falsified ledger makes the audited sum non-zero |

## Requirements

| Tool | Version | Needed for |
|---|---|---|
| Go | 1.23 or newer | the relay |
| Emscripten SDK | any recent release | building the WASM module |
| Python | 3.10 or newer | required by emsdk |
| OpenFHE source | 1.5.1 | built once into the WASM module |
| Node.js | 18 or newer | the end-to-end test only |
| Browser | any current version | running the demo |

The relay is pure Go. It needs no cgo, no build tags and no OpenFHE install.
Only the browser module requires the Emscripten toolchain.

## Build

### 1. The WASM module

Get the OpenFHE source at the pinned version:

```bash
git clone --branch v1.5.1 --depth 1 \
  https://github.com/openfheorg/openfhe-development.git ~/openfhe-development
```

Then build:

```bash
bash examples/energy_auction/wasm/build.sh
```

This compiles OpenFHE to WebAssembly, then the C wrapper and the embind veneer
in `examples/energy_auction/wasm/pool_wasm.cpp`. The first run also builds
OpenFHE itself and takes a while; later runs reuse it and finish in under a
minute.

Output is `examples/energy_auction/static/wasm/pool_wasm.js` and
`pool_wasm.wasm`, roughly 2.9 MB. Both are gitignored build artifacts, so
rerun the script after cloning.

Every path the script uses can be overridden:

| Variable | Default |
|---|---|
| `EMSDK_ROOT` | `$HOME/emsdk` |
| `OPENFHE_SRC` | `$HOME/openfhe-development` |
| `OPENFHE_WASM_BUILD` | `$HOME/openfhe-wasm-build` |
| `OPENFHE_WASM_PREFIX` | `$HOME/openfhe-wasm` |

On macOS two extra exports are usually needed before running the script,
because Xcode ships Python 3.9 and recent macOS releases report an empty
version string that emsdk cannot parse:

```bash
export EMSDK_PYTHON=/opt/homebrew/bin/python3
export EMSDK_OS=macos
```

### 2. The relay

```bash
go build -o energy-auction ./examples/energy_auction/
```

## Run

```bash
./energy-auction -addr localhost:8477
```

Then open `http://localhost:8477` in **six browser tabs**.

| Flag | Default | Meaning |
|---|---|---|
| `-addr` | `localhost:8080` | listen address |
| `-wasm` | `examples/energy_auction/static/wasm` | directory holding the built module |

Each tab loads the WASM module on open, which takes a few seconds. Wait for the
display to stop showing `LOADING` before acting.

## Driving a trade

Roles are assigned in connection order: the first tab becomes the seller, the
next five become buyers, and any tab after that can only watch.

1. In the seller tab, press **START ROUND**. It generates a fresh keypair for
   this round and publishes the public key.
2. In each buyer tab, set a price with **BID +** and **BID −**, then press
   **SEAL BID**. The bid is encrypted in that tab before it is sent.
3. Once all five have sealed, the evaluator ranks the bids blind and the seller
   is shown a single price with no seat attached.
4. In the seller tab, press **ACCEPT** or **DECLINE**.
5. On accept, the trade appears in every tab's log with a slot and a price and
   no identity. Only the winning buyer is told privately that it won.
6. Press **NEW ROUND** to run another.

After five settled trades a **CLEAR EPOCH** button appears. Pressing it runs the
aggregate audit: every tab folds a share into a joint key, encrypts its own net
position, a blind peer sums the ciphertexts, and every tab contributes a partial
decryption. Only the total is revealed, and it should be zero. **NEW EPOCH**
resets the ledger and starts the next block of trades.

A fresh key is generated for every round, so a bid sealed under a previous
round's key is refused and re-sealed automatically. That is expected behaviour,
not an error.

## End-to-end test

The test drives the real WebSocket protocol with a real WASM instance per
simulated tab, and runs two complete epochs.

```bash
./energy-auction -addr localhost:8477 &
node examples/energy_auction/e2e/auction_e2e.js ws://localhost:8477/ws
```

It prints `E2E_OK` on success and asserts that the settled log names no winner,
that only the winning buyer knows it won, that the seller cannot open the epoch
total alone, and that the audit balances.

To check that the audit can actually fail, run it again with one buyer
understating what it paid:

```bash
node examples/energy_auction/e2e/auction_e2e.js ws://localhost:8477/ws --tamper
```

The audited sum should come out non-zero. A check that only ever passes proves
nothing.

## Layout

| Path | What it is |
|---|---|
| `examples/energy_auction/main.go` | the relay; message routing only, zero crypto |
| `examples/energy_auction/auction.go` | round and epoch state machine |
| `examples/energy_auction/market.go` | generation and price data behind the meter display |
| `examples/energy_auction/static/index.html` | the UI and all client-side protocol logic |
| `examples/energy_auction/wasm/pool_wasm.cpp` | embind surface over the OpenFHE C wrapper |
| `examples/energy_auction/wasm/build.sh` | WASM build, including OpenFHE |
| `examples/energy_auction/e2e/auction_e2e.js` | end-to-end protocol test |

## Parameters

The demo uses CKKS with ring dimension 2^14, multiplicative depth 3, a 50 bit
scaling modulus and a 60 bit first modulus. The comparator is the degree one
polynomial `p(x) = x/2 + 1/2`, applied over a 16 ct span. These are set at the
top of `static/index.html` and mirrored in the end-to-end test.

## Scope

This is a demonstration of the clearing and audit mechanism, not a product.
It does not settle against a real balancing group, has no metering integration,
and runs a single seller. The relay is trusted for liveness, that is, to pass
messages along, but never for confidentiality: it holds no key material at any
point.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
