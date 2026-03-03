#!/usr/bin/env python3
import re
import socket
import time
from pathlib import Path

HOST = "chal.bearcatctf.io"
PORT = 47798
CACHE_PATH = Path(__file__).with_name("leak_cache.txt")

Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
I = pow(2, (Q - 1) // 4, Q)

TORSION_Y = 2707385501144840649318225287225658788936804267575313519463743609750303402022

UID_RE = re.compile(r"UID:\s*(\d+)")
FLAG_SIG_RE = re.compile(r"Signature:\s*(\d+)")
SIG_RE = re.compile(r"Your signature is:\s*(\d+)")


class Point:
    __slots__ = ("x", "y")

    def __init__(self, x: int, y: int):
        self.x = x % Q
        self.y = y % Q

    def is_inf(self) -> bool:
        return self.x == 0 and self.y == 1


def x_recover(y: int) -> int:
    y %= Q
    yy = (y * y) % Q
    xx = (yy - 1) * pow((D * yy + 1) % Q, Q - 2, Q) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = (x * I) % Q
    if x & 1:
        x = Q - x
    if (x * x - xx) % Q != 0:
        raise ValueError("x_recover failed")
    return x


def add(P: Point, R: Point) -> Point:
    x1, y1 = P.x, P.y
    x2, y2 = R.x, R.y
    t = (D * x1 * x2 * y1 * y2) % Q
    x3 = ((x1 * y2 + y1 * x2) * pow((1 + t) % Q, Q - 2, Q)) % Q
    y3 = ((y1 * y2 + x1 * x2) * pow((1 - t) % Q, Q - 2, Q)) % Q
    return Point(x3, y3)


def mul(k: int, P: Point) -> Point:
    k %= L
    if k == 0 or P.is_inf():
        return Point(0, 1)
    R = Point(0, 1)
    Qp = P
    while k:
        if k & 1:
            R = add(R, Qp)
        Qp = add(Qp, Qp)
        k >>= 1
    return R


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 8.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def query_torsion(uid: int, retries: int = 8):
    last_err = None
    for _ in range(retries):
        s = None
        try:
            s = socket.create_connection((HOST, PORT), timeout=8)
            banner = recv_until(s, b"3. Verify signature", timeout=8).decode(errors="ignore")
            uid_m = UID_RE.search(banner)
            fs_m = FLAG_SIG_RE.search(banner)
            if not uid_m or not fs_m:
                raise RuntimeError("failed to parse banner")
            flag_uid = int(uid_m.group(1))
            flag_sig = int(fs_m.group(1))

            s.sendall(b"2\n")
            recv_until(s, b"Enter your data:", timeout=8)
            s.sendall(str(TORSION_Y).encode() + b"\n")
            recv_until(s, b"Enter your UID:", timeout=8)
            s.sendall(str(uid).encode() + b"\n")

            s.settimeout(2.5)
            out = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
                if b"Your signature is:" in out:
                    break
            text = out.decode(errors="ignore")
            m = SIG_RE.search(text)
            if not m:
                raise RuntimeError("no signature in oracle response")
            sig = int(m.group(1))
            if sig == 1:
                return flag_uid, flag_sig, "Z"
            if sig == Q - 1:
                return flag_uid, flag_sig, "F"
            if sig == TORSION_Y:
                return flag_uid, flag_sig, "A"
            if sig == 0:
                return flag_uid, flag_sig, "B"
            if sig == (Q - TORSION_Y):
                return flag_uid, flag_sig, "C"
            raise RuntimeError(f"unexpected torsion signature: {sig}")
        except (OSError, RuntimeError, socket.timeout) as e:
            last_err = e
            time.sleep(0.25)
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
    raise RuntimeError(f"query failed for uid={uid}: {last_err}")


def classes_to_residues(symbols):
    mapping = {
        "Z": [0],
        "F": [4],
        "A": [1, 7],
        "B": [2, 6],
        "C": [3, 5],
    }
    return [mapping[s] for s in symbols]


def recover_master_candidates(symbols):
    residues = classes_to_residues(symbols)
    n = len(residues)

    prev = [dict() for _ in range(n)]
    for c0 in residues[0]:
        prev[0][c0] = [(None, None)]

    for i in range(n - 1):
        for c in prev[i]:
            for b in (0, 1):
                c2 = (2 * c - 5 * b) % 8
                if c2 in residues[i + 1]:
                    prev[i + 1].setdefault(c2, []).append((c, b))
        if not prev[i + 1]:
            raise RuntimeError(f"no valid carry transitions at step {i}")

    paths = []

    def backtrack(i, c, carries):
        if i == 0:
            paths.append((c, list(reversed(carries))))
            return
        for pc, b in prev[i][c]:
            if pc is None:
                continue
            carries.append(b)
            backtrack(i - 1, pc, carries)
            carries.pop()

    for c_last in prev[-1]:
        backtrack(n - 1, c_last, [])

    uniq = {}
    for c0, carries in paths:
        uniq[(c0, tuple(carries))] = (c0, carries)

    candidates = []
    m = n - 1
    for c0, carries in uniq.values():
        B = 0
        for bit in carries:
            B = (B << 1) | bit
        lo = (L * B + (1 << m) - 1) >> m
        hi = (L * B + (L - 1)) >> m
        if lo == hi and 1 <= lo < L:
            M = lo
            ok = True
            for i, sym in enumerate(symbols):
                c = (M * pow(2, i, L)) % L % 8
                if c not in classes_to_residues([sym])[0]:
                    ok = False
                    break
            if ok:
                candidates.append(M)

    return sorted(set(candidates))


def int_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def extract_flag_token(blob: bytes):
    needles = [b"bearcatctf{", b"BCCTF{", b"bcctf{", b"CTF{"]
    for n in needles:
        i = blob.find(n)
        if i != -1:
            j = blob.find(b"}", i)
            if j != -1:
                return blob[i : j + 1]
            return blob[i:]
    return None


def main():
    N = 320
    symbols = []
    flag_uid = None
    flag_sig = None

    if CACHE_PATH.exists():
        raw = CACHE_PATH.read_text().strip().splitlines()
        if len(raw) >= 2:
            parts = raw[0].split()
            if len(parts) == 2 and 0 < len(raw[1].strip()) <= N:
                flag_uid = int(parts[0])
                flag_sig = int(parts[1])
                symbols = list(raw[1].strip())
                print(f"[*] Loaded leakage cache from {CACHE_PATH.name}")
                print(f"[*] Target UID: {flag_uid}")
                print(f"[*] Target signature: {flag_sig}")
                print(f"[*] Cached samples: {len(symbols)}/{N}")

    if len(symbols) < N:
        if not symbols:
            flag_uid = None
            flag_sig = None
        print("[*] Collecting torsion leakage classes...")
        for i in range(len(symbols), N):
            uid = 1 << i
            fu, fs, sym = query_torsion(uid)
            if flag_uid is None:
                flag_uid = fu
                flag_sig = fs
                print(f"[*] Target UID: {flag_uid}")
                print(f"[*] Target signature: {flag_sig}")
            symbols.append(sym)
            if (i + 1) % 25 == 0 or i < 10:
                print(f"    - {i + 1:3d}/{N}: class={sym}")
            CACHE_PATH.write_text(f"{flag_uid} {flag_sig}\n{''.join(symbols)}\n")
        print(f"[*] Saved leakage cache to {CACHE_PATH.name}")

    print("[*] Reconstructing master key candidates...")
    masters = recover_master_candidates(symbols)
    if not masters:
        raise RuntimeError("failed to recover any master key candidates")
    print(f"[*] Candidate count: {len(masters)}")
    for idx, M in enumerate(masters, 1):
        print(f"    - M[{idx}] = {M}")

    Qflag = Point(x_recover(flag_sig), flag_sig)
    T = Point(x_recover(TORSION_Y), TORSION_Y)
    found = False
    for M in masters:
        kf = (M * flag_uid) % L
        if kf == 0:
            continue
        inv_kf = pow(kf, -1, L)
        Pbase = mul(inv_kf, Qflag)

        for j in range(8):
            Pcand = add(Pbase, mul(j, T))
            flag_bytes = int_to_bytes(Pcand.y)
            out = extract_flag_token(flag_bytes)
            if out is not None:
                print(f"[+] FLAG: {out.decode(errors='ignore')}")
                found = True
                break
        if found:
            break

        print(f"[*] Candidate base bytes (no obvious flag marker): {int_to_bytes(Pbase.y)!r}")

    if not found:
        print("[!] No direct flag marker found; try increasing N or refreshing the cache.")


if __name__ == "__main__":
    main()
