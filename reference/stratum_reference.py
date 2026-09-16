"""
Byte-exact reference implementation of the MacClassicBitMiner mining pipeline.

Purpose: this file is the *ground truth* the THINK Pascal code is ported from.
Every function here maps 1:1 to something the Pascal `BitcoinMiner.pas` must do,
so that when the vintage Mac is back online we are only debugging MacTCP / the
compiler, never the crypto or the byte order.

Validated offline (see test_reference.py) against:
  - the Bitcoin genesis block  -> full header serialization + double-SHA256 +
    endianness / display-order reversal,
  - synthetic merkle trees     -> coinbase + merkle-branch folding,
  - difficulty -> target math  -> share acceptance test.

Conventions (Stratum v1, as sent by ckpool / slush-style pools):
  * mining.notify sends version, nbits, ntime as BIG-ENDIAN hex strings.
    The serialized 80-byte header stores them LITTLE-ENDIAN, so we reverse the
    4 bytes of each.
  * prevhash is sent word-reversed: 32 bytes = 8 little-endian uint32 words;
    to get the internal header order we byte-swap within each 4-byte word.
    (Genesis can't test this since its prevhash is zero -- verify against a live
    pool first. See NOTE at swap_words32.)
  * The coinbase transaction is  coinb1 + extranonce1 + extranonce2 + coinb2,
    where extranonce2 is chosen by us and is `extranonce2_size` bytes.
"""

import hashlib


# --------------------------------------------------------------------------
# Core hashing
# --------------------------------------------------------------------------

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    """Bitcoin's double SHA-256. Returns 32 bytes in internal (little-endian) order."""
    return sha256(sha256(b))


# --------------------------------------------------------------------------
# Endianness helpers (each maps to a small Pascal routine)
# --------------------------------------------------------------------------

def reverse_bytes(b: bytes) -> bytes:
    """Reverse a byte string. In Pascal: manual loop swapping bytes[i] <-> bytes[n-1-i]."""
    return b[::-1]


def swap_words32(b: bytes) -> bytes:
    """
    Reverse the byte order within each 4-byte word, keeping word order.
    Used to convert a Stratum prevhash into internal header order.

    NOTE: this specific transform is the classic Stratum gotcha and is NOT
    exercised by the genesis test (genesis prevhash is all zeros). It follows
    the documented cgminer/BFGMiner convention; confirm against a real pool
    before trusting an "accepted" result.
    """
    assert len(b) % 4 == 0
    out = bytearray(len(b))
    for i in range(0, len(b), 4):
        out[i:i + 4] = b[i:i + 4][::-1]
    return bytes(out)


# --------------------------------------------------------------------------
# Block header assembly
# --------------------------------------------------------------------------

def build_header(version_le: bytes, prevhash_internal: bytes,
                 merkle_root_internal: bytes, ntime_le: bytes,
                 nbits_le: bytes, nonce_le: bytes) -> bytes:
    """
    Assemble the 80-byte block header from fields already in serialized
    (little-endian / internal) order. All merkle/prevhash inputs are 32 bytes;
    version/ntime/nbits/nonce are 4 bytes each.
    """
    assert len(version_le) == 4
    assert len(prevhash_internal) == 32
    assert len(merkle_root_internal) == 32
    assert len(ntime_le) == 4
    assert len(nbits_le) == 4
    assert len(nonce_le) == 4
    return (version_le + prevhash_internal + merkle_root_internal
            + ntime_le + nbits_le + nonce_le)


def block_hash_display(header80: bytes) -> str:
    """Double-SHA256 a header and return the hash in display order (big-endian hex)."""
    h = sha256d(header80)
    return reverse_bytes(h).hex()


# --------------------------------------------------------------------------
# Coinbase + merkle root (Stratum)
# --------------------------------------------------------------------------

def build_coinbase(coinb1_hex: str, extranonce1_hex: str,
                   extranonce2_hex: str, coinb2_hex: str) -> bytes:
    return bytes.fromhex(coinb1_hex + extranonce1_hex + extranonce2_hex + coinb2_hex)


def merkle_root_from_coinbase(coinbase: bytes, branch_hex_list) -> bytes:
    """
    Fold the coinbase hash up the merkle branch the pool provides.
    Returns 32 bytes in internal order (ready to drop into the header).
    """
    root = sha256d(coinbase)
    for branch_hex in branch_hex_list:
        root = sha256d(root + bytes.fromhex(branch_hex))
    return root


# --------------------------------------------------------------------------
# Difficulty / target
# --------------------------------------------------------------------------

# Difficulty-1 target (the "pdiff" used by pools): the target for bits 0x1d00ffff.
DIFF1_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000


def target_from_difficulty(difficulty: float) -> int:
    """Share target for a given pool difficulty. hash <= target => valid share."""
    return int(DIFF1_TARGET / difficulty)


def hash_meets_target(header_hash_internal: bytes, target: int) -> bool:
    """
    A block hash is interpreted as a little-endian 256-bit integer.
    (i.e. reverse the internal-order bytes to big-endian, then compare.)
    """
    value = int.from_bytes(header_hash_internal, "little")
    return value <= target


# --------------------------------------------------------------------------
# Full Stratum job -> mining, mirroring what the Mac will do
# --------------------------------------------------------------------------

class StratumJob:
    """Holds everything from mining.subscribe + mining.notify + set_difficulty."""

    def __init__(self, job_id, prevhash_hex, coinb1_hex, coinb2_hex,
                 merkle_branch, version_hex, nbits_hex, ntime_hex,
                 extranonce1_hex, extranonce2_size, difficulty):
        self.job_id = job_id
        self.prevhash_hex = prevhash_hex
        self.coinb1_hex = coinb1_hex
        self.coinb2_hex = coinb2_hex
        self.merkle_branch = merkle_branch
        self.version_hex = version_hex
        self.nbits_hex = nbits_hex
        self.ntime_hex = ntime_hex
        self.extranonce1_hex = extranonce1_hex
        self.extranonce2_size = extranonce2_size
        self.difficulty = difficulty

    def header_for_nonce(self, extranonce2_hex: str, nonce: int) -> bytes:
        coinbase = build_coinbase(self.coinb1_hex, self.extranonce1_hex,
                                  extranonce2_hex, self.coinb2_hex)
        merkle = merkle_root_from_coinbase(coinbase, self.merkle_branch)

        version_le = reverse_bytes(bytes.fromhex(self.version_hex))
        prevhash_internal = swap_words32(bytes.fromhex(self.prevhash_hex))
        ntime_le = reverse_bytes(bytes.fromhex(self.ntime_hex))
        nbits_le = reverse_bytes(bytes.fromhex(self.nbits_hex))
        nonce_le = nonce.to_bytes(4, "little")

        return build_header(version_le, prevhash_internal, merkle,
                            ntime_le, nbits_le, nonce_le)

    def scan(self, extranonce2_hex: str, nonce_start: int, nonce_count: int):
        """
        Scan a nonce range; yield (nonce, hash_display) for every nonce whose
        hash meets the share target. This is exactly the Mac's inner loop.
        """
        target = target_from_difficulty(self.difficulty)
        for nonce in range(nonce_start, nonce_start + nonce_count):
            header = self.header_for_nonce(extranonce2_hex, nonce)
            h = sha256d(header)
            if hash_meets_target(h, target):
                yield nonce, reverse_bytes(h).hex()
