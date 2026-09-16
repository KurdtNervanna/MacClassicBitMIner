"""
Offline validation of stratum_reference.py against known-good Bitcoin data.

Run:  python reference/test_reference.py
Every check must print PASS. A FAIL means the pipeline (and therefore the
Pascal port) would produce shares the pool rejects.
"""

import hashlib
from stratum_reference import (
    sha256, sha256d, reverse_bytes, build_header, block_hash_display,
    merkle_root_from_coinbase, target_from_difficulty, hash_meets_target,
    DIFF1_TARGET,
)

passed = 0
failed = 0


def check(name, got, expected):
    global passed, failed
    ok = got == expected
    if ok:
        passed += 1
        print(f"PASS  {name}")
    else:
        failed += 1
        print(f"FAIL  {name}\n        got:      {got}\n        expected: {expected}")


# --------------------------------------------------------------------------
# 1. SHA-256 core test vectors (NIST) -- the Pascal SHA must match these.
# --------------------------------------------------------------------------
check("sha256('')",
      sha256(b"").hex(),
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

check("sha256('abc')",
      sha256(b"abc").hex(),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

# Double SHA-256 of 'hello' (sanity for the sha256d wrapper)
check("sha256d('hello')",
      sha256d(b"hello").hex(),
      hashlib.sha256(hashlib.sha256(b"hello").digest()).hexdigest())


# --------------------------------------------------------------------------
# 2. Genesis block -- full end-to-end serialization + double-SHA256 + endianness.
#    This is the strongest single test: if the 80-byte header assembles wrong,
#    or any field's byte order is wrong, we do NOT reproduce the famous hash.
# --------------------------------------------------------------------------
genesis_version = (1).to_bytes(4, "little")
genesis_prevhash = bytes(32)  # all zeros
genesis_merkle_display = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
genesis_merkle_internal = reverse_bytes(bytes.fromhex(genesis_merkle_display))
genesis_time = (1231006505).to_bytes(4, "little")   # 2009-01-03 18:15:05 UTC
genesis_bits = (0x1d00ffff).to_bytes(4, "little")
genesis_nonce = (2083236893).to_bytes(4, "little")

genesis_header = build_header(genesis_version, genesis_prevhash,
                              genesis_merkle_internal, genesis_time,
                              genesis_bits, genesis_nonce)

check("genesis header length == 80", len(genesis_header), 80)

check("genesis block hash",
      block_hash_display(genesis_header),
      "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")


# --------------------------------------------------------------------------
# 3. Merkle branch folding -- validate the coinbase + branch method against
#    an independently computed full merkle tree.
# --------------------------------------------------------------------------
def full_merkle_root(txids_internal):
    """Standard bottom-up merkle root (duplicate last if odd)."""
    layer = list(txids_internal)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def merkle_branch_for_coinbase(txids_internal):
    """
    The branch a pool would send: the sibling hash at each level along the
    path from the coinbase (index 0) up to the root.
    """
    branch = []
    layer = list(txids_internal)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        branch.append(layer[1])  # sibling of the left-most (coinbase) node
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return branch


# Build a fake block with 5 transactions (coinbase + 4 others).
txids = [sha256d(f"tx{i}".encode()) for i in range(5)]
coinbase_txid = txids[0]

expected_root = full_merkle_root(txids)
branch = merkle_branch_for_coinbase(txids)

# The pool sends us the coinbase *bytes*; here we fake a coinbase whose sha256d
# equals coinbase_txid by feeding the preimage directly.
got_root = merkle_root_from_coinbase(b"tx0", [b.hex() for b in branch])

check("merkle root via coinbase+branch == full tree root",
      got_root, expected_root)


# --------------------------------------------------------------------------
# 4. Difficulty -> target, and share acceptance.
# --------------------------------------------------------------------------
check("diff-1 target == DIFF1_TARGET",
      target_from_difficulty(1.0), DIFF1_TARGET)

# A higher difficulty gives a smaller (harder) target.
check("diff-1024 target is DIFF1/1024",
      target_from_difficulty(1024.0), DIFF1_TARGET // 1024)

# The genesis hash (a real solved block at diff ~1) must beat the diff-1 target.
genesis_hash_internal = sha256d(genesis_header)
check("genesis hash meets diff-1 target",
      hash_meets_target(genesis_hash_internal, target_from_difficulty(1.0)),
      True)

# An all-0xFF hash must NOT meet any sane target.
check("max hash fails diff-1 target",
      hash_meets_target(b"\xff" * 32, target_from_difficulty(1.0)),
      False)


# --------------------------------------------------------------------------
# 5. Byte-level share test, mirroring EXACTLY what the Pascal will do.
#    The Mac has no bignum, so instead of target = DIFF1/diff (a 256-bit
#    division) we test  hash * diff <= DIFF1  using only 8/16/32-bit ops on
#    byte arrays. This validates that byte-frame arithmetic against Python's
#    native integers, so the Pascal port can copy it line-for-line.
# --------------------------------------------------------------------------

# DIFF1 as a 32-byte big-endian array: 00 00 00 00 FF FF 00 ... 00
DIFF1_BYTES = bytes([0, 0, 0, 0, 0xFF, 0xFF] + [0] * 26)


def mul_bytes_by_16(inp32, m16):
    """32-byte big-endian * 16-bit -> 34-byte big-endian. Pascal: MulBytesBy16."""
    out = [0] * 34
    carry = 0
    for i in range(31, -1, -1):
        t = inp32[i] * m16 + carry
        out[i + 2] = t & 0xFF
        carry = (t >> 8) & 0xFFFFFF
    out[1] = carry & 0xFF
    out[0] = (carry >> 8) & 0xFF
    return out


def share_meets_difficulty_bytewise(hash_be, diff):
    """
    Return True iff hash_be (32-byte big-endian) * diff <= DIFF1.
    Pure byte-array arithmetic, mirroring the Pascal ShareMeetsDifficulty.
    """
    if diff < 1:
        diff = 1
    dlo = diff & 0xFFFF
    dhi = (diff >> 16) & 0xFFFF

    tmp_lo = mul_bytes_by_16(hash_be, dlo)   # 34 bytes, value V*dlo
    tmp_hi = mul_bytes_by_16(hash_be, dhi)   # 34 bytes, value V*dhi

    # prod = tmp_lo + (tmp_hi << 16), in a 36-byte big-endian frame (LSB=idx35)
    A = [0, 0] + tmp_lo                       # tmp_lo occupies frame[2..35]
    B = tmp_hi + [0, 0]                        # tmp_hi<<16 occupies frame[0..33]
    prod = [0] * 36
    carry = 0
    for j in range(35, -1, -1):
        s = A[j] + B[j] + carry
        prod[j] = s & 0xFF
        carry = s >> 8

    # DIFF1 in the same 36-byte frame (LSB=idx35): 4 leading zero bytes + DIFF1_BYTES
    D36 = [0, 0, 0, 0] + list(DIFF1_BYTES)

    # big-endian compare prod <= D36
    for j in range(36):
        if prod[j] < D36[j]:
            return True
        if prod[j] > D36[j]:
            return False
    return True  # equal


# Cross-check the byte method against native big-int for many cases.
import random
DIFF1_INT = int.from_bytes(DIFF1_BYTES, "big")
rng = random.Random(1234)
mismatches = 0
for _ in range(20000):
    hb = bytes(rng.randrange(256) for _ in range(32))
    d = rng.choice([1, 2, 3, 7, 256, 1000, 65535, 65536, 70000,
                    1000000, 2 ** 20, 2 ** 24, 123456789, 2 ** 30])
    native = (int.from_bytes(hb, "big") * d) <= DIFF1_INT
    byte = share_meets_difficulty_bytewise(hb, d)
    if native != byte:
        mismatches += 1
check("bytewise share test matches native big-int (20000 random cases)",
      mismatches, 0)

# And the two anchored cases the Mac self-test will also check on-device:
genesis_hash_be = reverse_bytes(genesis_hash_internal)
check("genesis hash is a valid diff-1 share (bytewise)",
      share_meets_difficulty_bytewise(genesis_hash_be, 1), True)
check("genesis hash fails diff-2^24 share (bytewise)",
      share_meets_difficulty_bytewise(genesis_hash_be, 2 ** 24), False)


# --------------------------------------------------------------------------
print()
print(f"{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
