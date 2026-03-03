# chall1

## Summary

The service asks us for an RSA private key in PEM format, loads it with
`unsafe_skip_rsa_key_validation=True`, and then "tests" it by encrypting the flag and checking
whether decryption gives the original integer back.

The bug is that it compares against the full integer `FLAG`, not against `FLAG mod n`.

## Bug

The core check is:

```python
m = FLAG
c = pow(m, pub.e, pub.n)
if m != pow(c, priv.d, pub.n):
    return f"Some unknown error occurred! Maybe you should take a look: {c}"
```

For a mathematically valid RSA key, decryption gives back `m mod n`.
So if we choose a valid key with modulus `n < FLAG`, this condition fails and the server leaks:

```text
c = FLAG^e mod n
```

Because we know our own private exponent `d`, we can turn that ciphertext leak back into:

```text
c^d mod n = FLAG mod n
```

So every successful query gives one modular residue of the flag.

## Exploit

The checks on the key are strict enough that we still need a real RSA key:

- `p` and `q` must be prime
- both must be at least 512 bits
- `n = p * q`
- `e` must be prime, at least `65537`, and have Hamming weight at most `2`
- `d` must satisfy `e * d = 1 mod phi`

The clean choice is:

- use the smallest allowed 512-bit primes for `p` and `q`
- use `e = 65537`

That makes `n` as small as possible while still passing validation, which maximizes the chance that
`FLAG > n` and therefore triggers the leak.

For each round:

1. generate a valid minimal RSA key
2. submit it to the service
3. parse the leaked ciphertext `c`
4. compute `c^d mod n = FLAG mod n`
5. combine residues with CRT

Once the product of all collected moduli is larger than the flag integer, CRT reconstructs the full
flag.

## Why CRT Works

Each query gives:

```text
FLAG ≡ r_i (mod n_i)
```

If the moduli are pairwise coprime, CRT combines them into a single value modulo

```text
N = n_1 * n_2 * ... * n_k
```

When `N > FLAG`, that combined value is the actual flag integer, not just a residue class.

## Files

- `solve.py`: remote solver that keeps collecting leaks and merges them with CRT

## Local Note

There is no local `flag.txt` in the challenge folder, so I could not run the full challenge end to
end here. I did verify the underlying math locally with a toy RSA example: if the plaintext integer
is larger than `n`, then RSA decryption returns `m mod n`, which is exactly the leak the solver
uses.
