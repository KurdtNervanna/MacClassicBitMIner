# Reference implementation & validation

This folder is the **ground truth** for the mining logic in `../BitcoinMiner.pas`.

Because the vintage Mac / THINK Pascal toolchain isn't available for
continuous testing, the entire mining pipeline was first built and proven here
on modern hardware, then ported byte-for-byte into Pascal. Every non-trivial
Pascal routine mirrors a function that is tested here.

## Files

| File | What it is |
|------|-----------|
| `stratum_reference.py` | The mining pipeline: SHA-256d, coinbase + merkle root, 80-byte header assembly, difficulty→target, share test. Mirrors the Pascal 1:1. |
| `test_reference.py` | Validates the pipeline against known-good Bitcoin data. |
| `test_pascal_parser.py` | Re-implements the Pascal *positional JSON parser* and validates field extraction from real Stratum messages. |

## Run

```
python reference/test_reference.py        # 13 checks: crypto + pipeline
python reference/test_pascal_parser.py     # 33 checks: parser + wiring
```

Both must print `N passed, 0 failed`.

## What's proven

- **SHA-256** against NIST vectors (`""`, `"abc"`).
- **Full end-to-end** by reconstructing the **Bitcoin genesis block header**
  and reproducing its real hash `000000000019d668…`. This validates header
  layout, every field's byte order, double-SHA256, and display-order reversal.
- **Merkle-branch folding** against an independently computed full merkle tree,
  including the empty-branch (coinbase-only) case.
- **Difficulty → share test** using `hash * diff <= DIFF1` (no bignum division,
  so it ports to the 68k), cross-checked against native big-integers over
  20,000 random cases.
- **The positional JSON parser** — every `mining.notify` / `mining.subscribe` /
  `mining.set_difficulty` field lands in the correct slot.

## Not yet verified against a live pool (verify on hardware first)

- The **prevhash word-swap** (`swap_words32`): genesis can't exercise it because
  its prevhash is all zeros. It follows the documented cgminer/BFGMiner
  convention. If shares are rejected, this is the first thing to check.
- `extranonce2` is fixed at all-zero (a slow miner never exhausts the 2³² nonce
  space, so it never needs to roll extranonce2).
- Fractional pool difficulty is rounded **up** (conservative): any share the
  miner submits is at least as hard as required, so accepted shares stay
  accepted — at the cost of submitting slightly fewer.
