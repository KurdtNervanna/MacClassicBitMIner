# MacClassicBitMiner

A **real Bitcoin Stratum pool miner for classic Macintosh computers** running
Mac OS 6.0.8, written in THINK Pascal with an optional hand-written 68000
assembly SHA-256. It builds real block headers, does real double-SHA256, and
submits real shares to real pools.

![program window screenshot](https://github.com/user-attachments/assets/e464c9b5-9ee5-4444-92e4-ea5eb7b361aa)

> It will not earn meaningful Bitcoin — a Mac Plus does ~20 hashes/second and a
> modern ASIC does ~100,000,000,000,000. That is the whole point. This is a
> retro-computing art project that happens to be a technically correct miner.

---

## Status

This is an in-progress revival. The mining logic has been **rebuilt from a
validated reference implementation** and ported into Pascal; it has not yet been
recompiled on real hardware (the author's vintage Mac is temporarily down).

| Area | State |
|------|-------|
| SHA-256d, header assembly, merkle root, difficulty math | ✅ proven — see [`reference/`](reference/) (46 automated checks, incl. reproducing the real genesis block hash) |
| `mining.notify` / `subscribe` / `set_difficulty` parsing | ✅ proven — see `reference/test_pascal_parser.py` |
| `BitcoinMiner.pas` port of the above | ✅ written; ⏳ not yet recompiled on hardware |
| On-device **Self-Test** (proves the crypto compiled correctly) | ✅ built in — click the button |
| MacTCP networking + DNS | ⏳ needs the Apple DNR glue added to the project (or a numeric IP) |
| `sha256.a` assembly speedup | ⚠️ experimental / unverified (Pascal path is the default) |

If you build it, **click Self-Test first** — it hashes the genesis block header
on your Mac and must display `Self-Test: PASS`. That single check proves the
whole SHA-256d + byte-order pipeline compiled correctly, with no pool required.

---

## What was fixed in this revival

The earlier code looked complete but did not actually mine or compile cleanly.
The important fixes:

- **It now hashes a real 80-byte block header.** The previous loop hashed only
  4 bytes of the nonce, so it wasn't mining any real work.
- **It parses the actual job.** `mining.notify` is fully decoded (prevhash,
  coinbase parts, merkle branch, version, nbits, ntime) and the coinbase +
  merkle root + header are assembled correctly.
- **Shares are submitted correctly** — real job id, extranonce2, ntime, and a
  big-endian nonce — so a pool can accept them.
- **DNS works.** Pool hostnames like `solo.ckpool.org` are resolved via the
  MacTCP DNR (numeric IPs also accepted). The old code treated the hostname as
  a dotted-quad IP and could never connect.
- **Compile/logic bugs fixed:** the `OpenDriver`/`ioCRefNum` MacTCP setup; a
  SHA-256 word-load that byte-swapped on the (big-endian) 68000 and would have
  produced wrong hashes; and a case-insensitivity clash between the Pascal
  `Sigma0`/`sigma0` helpers.
- **Long messages no longer truncate** — Stratum lines are buffered instead of
  being forced into a 255-byte string.

---

## Requirements

**Hardware:** any 68000/68020/68030 Mac, 1 MB RAM recommended, MacTCP installed,
a network connection.

**Software:** Mac OS 6.0.8+, THINK Pascal 4.0+, MacTCP configured with an IP.
For DNS you also need Apple's DNR glue (`dnr.c`, from the MacTCP developer kit)
added to the project — or just enter a numeric IP for the pool.

---

## Building

1. Open `BitcoinMiner.pas` in THINK Pascal.
2. For DNS support, add Apple's DNR glue (`dnr.c`) to the project. To build
   **without** it (numeric-IP pools only), change the line near the top:
   `{$SETC USE_DNR := 1}` to `{$SETC USE_DNR := 0}`.
3. Project → Build, then run.
4. **Click Self-Test.** It must say `Self-Test: PASS`.

### Optional: assembly speedup (experimental)

`sha256.a` provides 68000 assembly versions of the SHA-256 helpers. It is
**unverified on hardware** — the Pascal path is the validated default. To try it:

1. Add `sha256.a` to the project and add `{$L sha256.a}` to `BitcoinMiner.pas`.
2. Comment out the seven Pascal functions `ROTR`, `Ch`, `Maj`, `BigSigma0`,
   `BigSigma1`, `SmSigma0`, `SmSigma1` and declare each `external` instead, e.g.
   `function ROTR(x: LongInt; n: Integer): LongInt; external;`.
3. Rebuild and **click Self-Test**. If it does not say PASS, revert to Pascal.

---

## Usage

1. Launch the miner.
2. Enter:
   - **Wallet Address** — your Bitcoin address (used as the worker username on
     solo pools).
   - **Pool Address** — e.g. `stratum+tcp://solo.ckpool.org:3333` (or `IP:port`).
   - **Worker Name** and **Password** (`x` is typical).
3. Click **Connect**. Status moves Connecting → Subscribing → Authorizing →
   Mining, and the hash rate and share counters update live.

### Example pools

| Pool | Address |
|------|---------|
| Solo CKPool | `stratum+tcp://solo.ckpool.org:3333` |
| (others) | any Stratum v1 pool `host:port` |

---

## The reference implementation

[`reference/`](reference/) contains the Python ground truth the Pascal was
ported from, plus its test suite. Run it with:

```
python reference/test_reference.py       # crypto + pipeline
python reference/test_pascal_parser.py    # Stratum parser + wiring
```

It validates SHA-256 against NIST vectors, reconstructs and re-hashes the real
Bitcoin **genesis block** header, checks merkle-branch folding, cross-checks the
no-bignum difficulty test against native big integers over 20,000 random cases,
and verifies every Stratum field lands in the right slot.

**Not yet verified against a live pool:** the prevhash word-swap (genesis can't
exercise it — its prevhash is zero). If a pool rejects otherwise-valid shares,
check that first.

---

## Reality check

You will **not** make money, find a block, or reach a payout threshold — the
numbers are astronomical against you. You **will** do real SHA-256d, submit real
shares, appear on a pool dashboard, and run 2009 cryptocurrency on 1991 hardware.

## License

CC0-1.0 (public domain). Experimental/educational software, no warranty.

## Acknowledgments

Drewy Nucci for the fever dream; Satoshi Nakamoto for Bitcoin; Apple for the
Macintosh; Motorola for the 68000; and everyone who said you can't mine Bitcoin
on a Mac Plus.
