# chall3

## Summary

The service derives each user's signing scalar as:

```python
KDF(uid) = MASTER_KEY * uid mod L
```

where `L` is the Ed25519 subgroup order. The bug is that the signer accepts attacker-chosen
points, does not clear the cofactor, and returns only the `y`-coordinate of `[key]P`.

That lets us feed the signer a point of order `8`, which leaks `key mod 8`. Since we can choose
arbitrary `uid` values, we query with `uid = 2^i` and recover enough residues to reconstruct the
global `MASTER_KEY`. Once `MASTER_KEY` is known, the banner's `FLAG_UID` and `Signature` are enough
to undo the flag signature and recover the original flag bytes.

Flag:

```text
BCCTF{NOW_7h0s3_4r3_s0m3_curv35}
```

## Bug

The signing code is:

```python
def sign(y, key):
    padding = 0
    while True:
        try:
            x = E.x_recover(y + padding)
            break
        except AssertionError:
            padding += 1
    P = Point(x, y, E)
    signed_point = E.mul_point(key, P)
    return signed_point.y + (padding<<256)
```

The important issues are:

- the input is interpreted as a curve point
- there is no subgroup check
- there is no cofactor clearing
- the output only keeps the `y`-coordinate
- option `2` lets us choose any `uid`, so the key is effectively a linear oracle in `uid`

This is exactly the setting where a low-order point attack works.

## Leakage Oracle

Let `T` be an order-8 Ed25519 point. The solver uses the valid torsion point with
`y = 2707385501144840649318225287225658788936804267575313519463743609750303402022`.

If we ask the service to sign `T`, the result is `[k]T`, where:

```text
k = MASTER_KEY * uid mod L
```

Because `T` has order `8`, the output depends only on `k mod 8`. The returned `y`-coordinate falls
into five classes:

- `1` means `k mod 8 = 0`
- `q - 1` means `k mod 8 = 4`
- `TORSION_Y` means `k mod 8 in {1, 7}`
- `0` means `k mod 8 in {2, 6}`
- `q - TORSION_Y` means `k mod 8 in {3, 5}`

So a single signature query leaks the key modulo `8`, up to the sign ambiguity from using only the
`y`-coordinate.

## Recovering `MASTER_KEY`

Choose:

```text
uid_i = 2^i
k_i = MASTER_KEY * 2^i mod L
c_i = k_i mod 8
```

Doubling modulo `L` gives:

```text
k_{i+1} = 2*k_i - b_i*L,    b_i in {0, 1}
```

and since `L mod 8 = 5`:

```text
c_{i+1} = 2*c_i - 5*b_i mod 8
```

Each torsion signature tells us a small set of valid values for `c_i`. A short dynamic program over
the carry bits `b_i` keeps only transitions consistent with all observed classes. After about 320
queries, the path is unique and yields:

```text
MASTER_KEY = 4747627684408952554495055884313346755842726269957015465592140336813957778804
```

## Recovering the Flag

The server prints:

```text
UID: FLAG_UID
Signature: flag_sig
```

That signature is the `y`-coordinate of:

```text
[k_f]P_flag,    k_f = MASTER_KEY * FLAG_UID mod L
```

Once `MASTER_KEY` is known:

1. compute `k_f`
2. invert it modulo `L`
3. reconstruct a point `Q` from `flag_sig`
4. compute `[k_f^-1]Q`
5. try all 8 torsion offsets, because the message point is only defined up to an 8-torsion element

One of those candidates has a `y`-coordinate whose big-endian bytes are the flag.

## Files

- `solve.py`: full remote solver and offline recovery helper
- `leak_cache.txt`: 320 leaked torsion classes from one run, so the solver can recover the flag
  without re-querying the service

## Verification

Running the included solver against the included cache recovers the flag directly:

```text
[*] Candidate count: 1
[+] FLAG: BCCTF{NOW_7h0s3_4r3_s0m3_curv35}
```
