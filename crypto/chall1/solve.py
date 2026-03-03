#!/usr/bin/env python3
from pwn import remote, context
from Crypto.Util.number import isPrime, GCD, inverse, long_to_bytes
from Crypto.PublicKey import RSA
import re
import math

context.log_level = "error"
HOST, PORT = "chal.bearcatctf.io", 56025
E = 65537


def next_prime_ge(n: int) -> int:
    if n <= 2:
        return 2
    if n % 2 == 0:
        n += 1
    while not isPrime(n):
        n += 2
    return n


def gen_minimal_512bit_rsa():
    base = 1 << 511
    p = next_prime_ge(base)
    q = next_prime_ge(p + 2)
    phi = (p - 1) * (q - 1)
    while GCD(E, phi) != 1:
        q = next_prime_ge(q + 2)
        phi = (p - 1) * (q - 1)
    n = p * q
    d = inverse(E, phi)
    key = RSA.construct((n, E, d, p, q))
    return n, d, key.export_key("PEM")


def crt_pair(a1, n1, a2, n2):
    if math.gcd(n1, n2) != 1:
        raise ValueError("Non-coprime moduli; retry")
    k = ((a2 - a1) % n2) * pow(n1, -1, n2) % n2
    return a1 + k * n1, n1 * n2


def talk_once():
    n, d, pem = gen_minimal_512bit_rsa()
    r = remote(HOST, PORT)
    r.recvuntil(b"Enter your key in pem format:")
    r.sendline(b"")
    r.send(pem + b"\n")
    out = r.recvall(timeout=3).decode(errors="ignore")
    r.close()
    return n, d, out


def main():
    x, mod = 0, 1
    leaks = 0
    for i in range(20):
        n, d, out = talk_once()

        m = re.search(r"take a look:\s*(\d+)", out)
        if not m:
            print(f"[-] round {i + 1}: no leak. Server said:\n{out.strip()}\n")
            continue

        leaks += 1
        c = int(m.group(1))
        residue = pow(c, d, n)

        if mod == 1:
            x, mod = residue, n
        else:
            x, mod = crt_pair(x, mod, residue, n)

        cand = long_to_bytes(x)
        print(f"[+] leak #{leaks}: combined_bits={mod.bit_length()}")

        if b"bearcatctf{" in cand:
            s = cand[cand.index(b"bearcatctf{"):]
            print("[+] FLAG:", s.decode(errors="ignore"))
            return

    print("[!] Finished. If you never saw 'take a look:', then your instance never leaks ciphertext.")


if __name__ == "__main__":
    main()
