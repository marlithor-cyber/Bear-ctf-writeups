# chall2

`tomb`

## Summary

This challenge is easiest to solve as a staged offline reconstruction problem.

The provided binary is a large statically linked ELF with anti-analysis behavior, but the solver
shows that the flag bytes are constrained in three clean layers:

1. a 32-byte key is derived from fixed data plus runtime-dependent mutations
2. bytes `x[6..26]` are linked by a SHA-256-based chain stored in `LOCK`
3. bytes `x[26..43]` are constrained by a second-stage decrypted code stub

Combining those constraints recovers the full flag:

```text
BCCTF{Buri3d_at_sea_Ent0m3d_amm0nG_th3_w4v3S}
```

## Stage 1: Fixed Prefix and Base Key

The flag starts with the obvious prefix:

```text
x[0..5] = "BCCTF{"
```

The solver starts from a 32-byte constant:

```python
KEY0 = ...
```

and applies the same mutations the binary does at runtime:

- `proc()`-related XOR with `0x1356`
- a second XOR that only happens on the `ptrace(PTRACE_TRACEME)` success path
- the main hash-prefix check for `x[0..5]`
- a final XOR by byte `x[44]`

The important observation is that all of these transformations are reversible.

## Stage 2: Recover `x[6..26]` from `LOCK`

The 20 blocks in `LOCK` each encode a relation between adjacent flag bytes.

Let:

```text
h(c) = SHA-256([c])
```

Then each 32-byte lock block has the form:

```text
block_i = [ h(x_i)[0] xor h(x_{i+1})[0] ] || h(x_{i+1})[1:]
```

for consecutive characters in the range `x[6]..x[26]`.

That makes recovery straightforward:

- the last 31 bytes of each block identify `x[i+1]` uniquely
- the first byte then pins down `x[i]`

Working backward through the 20 blocks recovers the full chain `x[6]..x[26]`.

## Stage 3: Use the Decrypted Stage-2 Stub

The binary also contains an encrypted second-stage code blob:

```python
ENC_STAGE2
```

Decrypting it with the correct 32-byte key yields the expected code template:

```python
STAGE2_TEMPLATE
```

The solver brute-forces the only remaining small unknowns:

- whether the `ptrace`-success mutation path was taken
- the value of `x[44]`

There is exactly one pair that makes:

```text
decrypt_stage2(key) == STAGE2_TEMPLATE
```

That uniquely determines the runtime mode and the final key bytes.

The recovered stage-2 logic gives:

```text
key[i] == ((5*i + 0x40) xor x[26+i])   for i = 0..17
```

So once the key is known, this directly yields `x[26]..x[43]`.

## Final Assembly

The flag is assembled as:

- `x[0..5] = "BCCTF{"`
- `x[6..26]` from the SHA-256 lock chain
- `x[27..43]` from the decrypted stage-2 relation
- `x[44]` from the unique stage-2 brute-force hit

The solver also re-checks the stage-2 comparator logic to make sure the recovered bytes satisfy the
same success path the binary expects.

## Local Verification

Running the provided offline reconstruction solver prints:

```text
BCCTF{Buri3d_at_sea_Ent0m3d_amm0nG_th3_w4v3S}
```

That is a complete local recovery of the flag without depending on interactive execution of the
anti-analysis binary.

## Files

- `solve.py`: offline reconstruction of the flag from the extracted constants and stage relations
