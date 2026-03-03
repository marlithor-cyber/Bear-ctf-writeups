# chall2

## Summary

This challenge looks like a battleship guessing game, but the board is not random in the usual
sense. Every round starts from a known basis board whose entries are all distinct, and the shuffle
only permutes rows and columns.

That means each revealed number tells us:

- which original row the current row came from
- which original column the current column came from

So we do not need to brute-force the seed. We only need to recover the row permutation and the
column permutation, then locate the cell whose original value is `0`.

## Board Structure

Each board is built from a known tuple:

```python
Board(size, attempts, basis)
```

and if `basis` is not provided, it would just be `0..size^2-1`. The important point is that the
board entries are unique.

The shuffle repeatedly applies:

```python
self.row_round(...)
self.col_round(...)
```

So no matter how many rounds of shuffling happen, the final board is still just:

- one permutation of the rows
- one permutation of the columns

Nothing else changes.

## Key Observation

Suppose we reveal a value `v` at current coordinates `(r, c)`.

Because the basis is known, we can invert it and find the original coordinates of `v`:

```text
v -> (orig_row, orig_col)
```

That immediately gives:

```text
row_perm[r] = orig_row
col_perm[c] = orig_col
```

So one revealed cell teaches us one row mapping and one column mapping.

## Finding the Battleship

The battleship is the cell whose value is `0`, and the basis tells us the original coordinates of
that `0`.

The solver guesses the diagonal cells:

```text
(0,0), (1,1), (2,2), ..., (n-2,n-2)
```

After `n-1` such guesses:

- we have learned `n-1` distinct current rows
- we have learned `n-1` distinct current columns

That is enough because only one current row and one current column remain unresolved.

So for the target value `0`:

- if its original row is already mapped, we use that current row
- otherwise the only unseen current row must be the target row
- same for the column

Then we guess that final intersection and win.

## Why the Attempt Limits Work

For an `n x n` board, this strategy needs at most:

```text
n - 1   guesses to learn the permutations
1       final guess for the zero cell
= n     total guesses
```

The challenge limits are:

- easy: `n = 3`, attempts `= 5`
- medium: `n = 10`, attempts `= 20`
- hard: `n = 30`, attempts `= 30`

So even the hard board is solvable exactly at the limit.

## Ultimate Challenge

Option `4` requires:

- 10 easy boards
- then 10 medium boards
- then 10 hard boards

The solver automates all 30 rounds. It parses the masked board, uses each revealed number to update
the row and column mappings, and finishes each board in at most `n` guesses.

## Local Verification

I verified the strategy offline against the provided board logic on many random shuffles:

- easy: 200 random trials, max 3 guesses
- medium: 100 random trials, max 10 guesses
- hard: 50 random trials, max 30 guesses

So the permutation-recovery strategy stays within the allowed attempts for every difficulty.

## Files

- `solve.py`: remote solver for `chal.bearcatctf.io:45457`
