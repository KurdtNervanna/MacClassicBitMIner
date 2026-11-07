"""
A tiny local Stratum v1 pool used to prove the miner end to end.

It speaks the same protocol as ckpool/slush: subscribe -> set_difficulty ->
authorize -> notify, then *independently verifies every submitted share* with
reference/stratum_reference.py (a different implementation from the C/Pascal
miners) and answers accepted/rejected honestly.

  python reference/fake_pool.py [--port 3333] [--diff 0.0002] [--want 5] [--timeout 60]

Exit status 0 only if >= --want shares were submitted AND all were valid, and
the authorize name looked like  <wallet>.<worker>.
"""
import argparse, json, os, socket, sys, time
from fractions import Fraction
sys.path.insert(0, os.path.dirname(__file__))
from stratum_reference import StratumJob, sha256d, DIFF1_TARGET

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=3333)
ap.add_argument("--diff", default="0.0002")
ap.add_argument("--want", type=int, default=5)
ap.add_argument("--timeout", type=int, default=90)
ap.add_argument("--en2size", type=int, default=4)
a = ap.parse_args()

EN1 = "f000000a"
job = dict(
    job_id="bf", prevhash=os.urandom(32).hex(),
    coinb1="01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2503" + "a1b2c3",
    coinb2="0a2f4d61636d696e65722f00000000010000000000000000" + "00" * 4,
    branch=[os.urandom(32).hex() for _ in range(3)],
    version="20000000", nbits="1d00ffff", ntime="%08x" % int(time.time()),
)
diff = Fraction(a.diff)
target = int(Fraction(DIFF1_TARGET) / diff)

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", a.port)); srv.listen(1); srv.settimeout(a.timeout)
print("fake pool listening on", a.port, "diff", a.diff, flush=True)
conn, _ = srv.accept(); conn.settimeout(1.0)
f = conn.makefile("rwb", buffering=0)

def send(o):
    conn.sendall((json.dumps(o, separators=(",", ":")) + "\n").encode())

def notify():
    send({"id": None, "method": "mining.notify", "params": [
        job["job_id"], job["prevhash"], job["coinb1"], job["coinb2"], job["branch"],
        job["version"], job["nbits"], job["ntime"], True]})

user = None; good = bad = 0; seen = set(); t0 = time.time(); buf = b""
while time.time() - t0 < a.timeout and good + bad < a.want:
    try:
        d = conn.recv(4096)
    except socket.timeout:
        continue
    if not d:
        break
    buf += d
    while b"\n" in buf:
        line, buf = buf.split(b"\n", 1)
        if not line.strip():
            continue
        m = json.loads(line)
        meth = m.get("method")
        if meth == "mining.subscribe":
            send({"id": m["id"], "result": [[["mining.set_difficulty", "d1"], ["mining.notify", "n1"]], EN1, a.en2size], "error": None})
            send({"id": None, "method": "mining.set_difficulty", "params": [float(diff)]})
        elif meth == "mining.authorize":
            user = m["params"][0]
            send({"id": m["id"], "result": True, "error": None})
            notify()
        elif meth == "mining.submit":
            uname, jid, en2, ntime, nonce = m["params"]
            ok = True; why = ""
            if jid != job["job_id"]: ok, why = False, "stale"
            if len(en2) != a.en2size * 2: ok, why = False, "bad en2 size"
            if ntime != job["ntime"]: ok, why = False, "bad ntime"
            if (uname, en2, nonce) in seen: ok, why = False, "duplicate"
            seen.add((uname, en2, nonce))
            if ok:
                sj = StratumJob(job["job_id"], job["prevhash"], job["coinb1"], job["coinb2"],
                                job["branch"], job["version"], job["nbits"], job["ntime"],
                                EN1, a.en2size, 1)
                hdr = sj.header_for_nonce(en2, int(nonce, 16))
                h = int.from_bytes(sha256d(hdr), "little")
                if h > target: ok, why = False, "low difficulty share (hash %064x)" % h
            if ok: good += 1
            else: bad += 1
            print("share", nonce, "en2", en2, "->", "ACCEPT" if ok else "REJECT " + why, flush=True)
            send({"id": m["id"], "result": ok, "error": None if ok else [23, why, None]})

name_ok = bool(user) and "." in user and len(user.split(".", 1)[0]) > 20
print("user:", user, "| name looks like wallet.worker:", name_ok)
print("RESULT good=%d bad=%d" % (good, bad))
sys.exit(0 if (good >= a.want and bad == 0 and name_ok) else 1)
