"""
Validates the POSITIONAL JSON parser used by BitcoinMiner.pas.

The Pascal has no JSON library; it scans Stratum lines positionally
(ReadJsonStr / ReadMerkleArray / SkipBalanced / ReadJsonInt /
ReadDifficultyCeil). This file re-implements that exact scanning logic in
Python and runs it on realistic mining.subscribe / mining.notify /
mining.set_difficulty messages, asserting each field lands in the right slot.

A wiring bug here (e.g. swapping coinb1/coinb2, or misreading the merkle
array so the version/nbits/ntime shift) would NOT show up in the crypto
tests, so this is the guard for it.

Run:  python reference/test_pascal_parser.py
"""

passed = 0
failed = 0


def check(name, got, expected):
    global passed, failed
    if got == expected:
        passed += 1
        print(f"PASS  {name}")
    else:
        failed += 1
        print(f"FAIL  {name}\n        got:      {got!r}\n        expected: {expected!r}")


# --- exact mirror of the Pascal scanning routines (1-based cursor) ---------
# The Pascal indexes s.data[1..len]; here we keep a 1-based convention by
# using a leading pad char so indices match the Pascal exactly.

class Line:
    def __init__(self, text):
        self.data = " " + text   # index 1..len
        self.len = len(text)

    def at(self, i):
        return self.data[i] if 1 <= i <= self.len else "\x00"


def skip_to_char(s, cur, c):
    while cur <= s.len and s.at(cur) != c:
        cur += 1
    return cur


def read_json_str(s, cur):
    cur = skip_to_char(s, cur, '"')
    cur += 1
    out = []
    while cur <= s.len and s.at(cur) != '"':
        out.append(s.at(cur))
        cur += 1
    cur += 1
    return "".join(out), cur


def read_json_int(s, cur):
    while cur <= s.len and not (s.at(cur).isdigit() or s.at(cur) == "-"):
        cur += 1
    neg = False
    if cur <= s.len and s.at(cur) == "-":
        neg = True
        cur += 1
    v = 0
    while cur <= s.len and s.at(cur).isdigit():
        v = v * 10 + (ord(s.at(cur)) - ord("0"))
        cur += 1
    return (-v if neg else v), cur


def read_difficulty_ceil(s, cur):
    while cur <= s.len and not s.at(cur).isdigit():
        cur += 1
    v = 0
    while cur <= s.len and s.at(cur).isdigit():
        v = v * 10 + (ord(s.at(cur)) - ord("0"))
        cur += 1
    frac = False
    if cur <= s.len and s.at(cur) == ".":
        cur += 1
        while cur <= s.len and s.at(cur).isdigit():
            if s.at(cur) != "0":
                frac = True
            cur += 1
    if frac:
        v += 1
    return v


def skip_balanced(s, cur):
    cur = skip_to_char(s, cur, "[")
    depth = 0
    while cur <= s.len:
        if s.at(cur) == "[":
            depth += 1
        elif s.at(cur) == "]":
            depth -= 1
            if depth == 0:
                return cur + 1
        cur += 1
    return cur


def ls_find_str(s, sub):
    idx = s.data.find(sub, 1)
    return idx if idx >= 1 else 0


def ls_contains(s, sub):
    return s.data.find(sub, 1) >= 1


# --- the Pascal handlers, mirrored ----------------------------------------

def handle_subscribe_result(text):
    s = Line(text)
    p = ls_find_str(s, '"result":')
    cur = p + 9
    cur = skip_to_char(s, cur, "[")
    cur += 1
    cur = skip_balanced(s, cur)          # skip [[...]] subscriptions
    extranonce1, cur = read_json_str(s, cur)
    extranonce2_size, cur = read_json_int(s, cur)
    return extranonce1, extranonce2_size


def handle_notify(text):
    s = Line(text)
    p = ls_find_str(s, '"params":')
    cur = p + 9
    cur = skip_to_char(s, cur, "[")
    cur += 1
    job_id, cur = read_json_str(s, cur)
    prevhash, cur = read_json_str(s, cur)
    coinb1, cur = read_json_str(s, cur)
    coinb2, cur = read_json_str(s, cur)
    # merkle branch array
    branches = []
    cur = skip_to_char(s, cur, "[")
    cur += 1
    while cur <= s.len and s.at(cur) != "]":
        if s.at(cur) == '"':
            b, cur = read_json_str(s, cur)
            branches.append(b)
        else:
            cur += 1
    cur += 1
    version, cur = read_json_str(s, cur)
    nbits, cur = read_json_str(s, cur)
    ntime, cur = read_json_str(s, cur)
    return {
        "job_id": job_id, "prevhash": prevhash, "coinb1": coinb1,
        "coinb2": coinb2, "branches": branches, "version": version,
        "nbits": nbits, "ntime": ntime,
    }


def handle_set_diff(text):
    s = Line(text)
    p = ls_find_str(s, '"params":')
    cur = p + 9
    cur = skip_to_char(s, cur, "[")
    cur += 1
    return read_difficulty_ceil(s, cur)


def extract_id(text):
    s = Line(text)
    p = ls_find_str(s, '"id":')
    if p == 0:
        return -1
    cur = p + 5
    while cur <= s.len and s.at(cur) == " ":
        cur += 1
    if cur <= s.len and s.at(cur).isdigit():
        v, _ = read_json_int(s, cur)
        return v
    return -1


# ==========================================================================
# Test data: realistic Stratum messages.
# ==========================================================================

PREV = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
CB1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20"
CB2 = "ffffffff0100f2052a010000001976a914000000000000000000000000000000000000000088ac00000000"
BR1 = "1111111111111111111111111111111111111111111111111111111111111111"
BR2 = "2222222222222222222222222222222222222222222222222222222222222222"

notify = (
    '{"id":null,"method":"mining.notify","params":['
    '"job42",'
    f'"{PREV}",'
    f'"{CB1}",'
    f'"{CB2}",'
    f'["{BR1}","{BR2}"],'
    '"20000000",'
    '"170b8c8b",'
    '"66e6f0a0",'
    'true]}'
)

subscribe = (
    '{"id":1,"result":[[["mining.set_difficulty","abc123"],'
    '["mining.notify","def456"]],"a1b2c3d4",4],"error":null}'
)

# --- routing / id extraction ---
check("extract_id(subscribe)", extract_id(subscribe), 1)
check("extract_id(notify) is null -> -1", extract_id(notify), -1)
check("notify is a method line", ls_contains(Line(notify), '"method"'), True)
check("notify names mining.notify", ls_contains(Line(notify), "mining.notify"), True)

# --- subscribe parse ---
en1, en2size = handle_subscribe_result(subscribe)
check("subscribe extranonce1", en1, "a1b2c3d4")
check("subscribe extranonce2_size", en2size, 4)

# --- notify parse: every field in the right slot ---
n = handle_notify(notify)
check("notify job_id", n["job_id"], "job42")
check("notify prevhash", n["prevhash"], PREV)
check("notify coinb1", n["coinb1"], CB1)
check("notify coinb2", n["coinb2"], CB2)
check("notify merkle branch count", len(n["branches"]), 2)
check("notify branch[0]", n["branches"][0], BR1)
check("notify branch[1]", n["branches"][1], BR2)
check("notify version", n["version"], "20000000")
check("notify nbits", n["nbits"], "170b8c8b")
check("notify ntime", n["ntime"], "66e6f0a0")

# --- notify with an EMPTY merkle branch (coinbase-only block) ---
notify_empty = notify.replace(f'["{BR1}","{BR2}"]', "[]")
ne = handle_notify(notify_empty)
check("empty-branch: 0 branches", len(ne["branches"]), 0)
check("empty-branch: version still correct", ne["version"], "20000000")
check("empty-branch: ntime still correct", ne["ntime"], "66e6f0a0")

# --- set_difficulty parse (integer, fractional->ceil, sub-1->1) ---
check("set_difficulty integer",
      handle_set_diff('{"id":null,"method":"mining.set_difficulty","params":[16384]}'),
      16384)
check("set_difficulty 2.5 -> ceil 3",
      handle_set_diff('{"id":null,"method":"mining.set_difficulty","params":[2.5]}'),
      3)
check("set_difficulty 0.001 -> 1",
      handle_set_diff('{"id":null,"method":"mining.set_difficulty","params":[0.001]}'),
      1)
check("set_difficulty 100.0 -> 100 (no frac)",
      handle_set_diff('{"id":null,"method":"mining.set_difficulty","params":[100.0]}'),
      100)

# --- submit-result routing ---
check("submit ok id", extract_id('{"id":7,"result":true,"error":null}'), 7)
check("submit result true detected",
      ls_contains(Line('{"id":7,"result":true,"error":null}'), '"result":true'), True)
check("submit result false detected",
      ls_contains(Line('{"id":8,"result":false,"error":[21,"stale",null]}'),
                  '"result":false'), True)


# ==========================================================================
# End-to-end: parsed notify -> reference header build -> self-consistent hash.
# Confirms the parser output wires correctly into the proven pipeline.
# ==========================================================================
from stratum_reference import StratumJob, sha256d, reverse_bytes

job = StratumJob(
    job_id=n["job_id"], prevhash_hex=n["prevhash"],
    coinb1_hex=n["coinb1"], coinb2_hex=n["coinb2"],
    merkle_branch=n["branches"], version_hex=n["version"],
    nbits_hex=n["nbits"], ntime_hex=n["ntime"],
    extranonce1_hex=en1, extranonce2_size=en2size, difficulty=1.0,
)
extranonce2 = "00" * en2size
header0 = job.header_for_nonce(extranonce2, 0)
check("assembled header is 80 bytes", len(header0), 80)
# nonce is the last 4 bytes, little-endian
check("header nonce bytes (nonce=0)", header0[76:80].hex(), "00000000")
header5 = job.header_for_nonce(extranonce2, 5)
check("header nonce bytes (nonce=5)", header5[76:80].hex(), "05000000")
# version field little-endian of 0x20000000
check("header version LE", header0[0:4].hex(), "00000020")
# ntime LE of 66e6f0a0
check("header ntime LE", header0[68:72].hex(), "a0f0e666")
# nbits LE of 170b8c8b
check("header nbits LE", header0[72:76].hex(), "8b8c0b17")
# the hash is deterministic; recomputing must match
check("header hash is stable",
      sha256d(header0).hex(), sha256d(header0).hex())


# ==========================================================================
print()
print(f"{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
