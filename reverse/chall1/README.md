# chall1

`pollys_key`

## Summary

The file is a real Ruby/Perl polyglot. Both interpreters accept it, both enforce different
constraints on the same input, and both decrypt the same treasure string with:

```text
MD5(key)[hex nibbles] XOR encTreasure
```

The trick is that the Ruby side fixes the **character set**, while the Perl side fixes almost the
entire **ordering**.

The recovered key is:

```text
}O;m`pHw[Gq(g1\5@W6~Uu8{v7jnE?=9yRZ|$f#],ceCbkF+Qz
```

and both interpreters print:

```text
BCCTF{Th3_P05h_9oLly61Ot_p4rr0t}
```

## Ruby Side

The active Ruby branch does four important things:

1. `key.length == 50`
2. all characters are unique
3. all characters are printable
4. after subtracting `0x10`, every character becomes a primitive root modulo `257`

That primitive-root test is:

```ruby
$arr = (2..256).map { |x| ($userArr[$i] ** x) % 257 }
if not ($arr.length.eql? $arr.uniq.length)
  ...
end
```

For printable ASCII, that leaves exactly 51 possible characters:

```text
#$(+,156789;=?@CEFGHOQRUWZ[\]^`bcefgjkmnpquvwyz{|}~
```

The Perl side forbids `^`, so the final key must use the other 50 exactly once.

Ruby also gives three useful order constraints among duplicate Perl-transform pairs:

- `O` before `p`
- `E` before `f`
- `c` before `F`

## Perl Side

The Perl branch is where the ordering comes from.

Two quirks matter:

1. `$userKey = $userKey.chomp;` is parsed as Perl, not Ruby
2. the last byte gets decremented before the main checks

So if the user enters a 50-character key, Perl effectively works on:

```text
key + "\n" + "0"
```

and then changes the trailing `"0"` into `"/"` before the rest of the logic.

That gives a 52-element array, which matches the 51-entry `@sArray` perfectly.

## Insertion-Sort Signature

Perl transforms each byte with:

```perl
$_ = ($_ - $c.hex) % 257;
```

Under Perl precedence, that is the weird numeric value of:

```text
(x - 0) . hex(x)
```

modulo `257`.

After that, the script runs an insertion-sort-like process and checks the number of swaps performed
at each step against `@sArray`.

That means `@sArray` is an inversion sequence for the transformed 52-byte array. Once we know the
multiset of transformed values, we can reconstruct the full transformed sequence.

## Reconstructing the Key

Using the 50 Ruby-valid characters plus:

- newline `10`
- final modified slash `47`

we know the exact multiset of 52 Perl-transformed values.

Rebuilding from the inversion sequence gives a transformed array with seven duplicate pairs. Those
pairs correspond to:

- `` ` `` / `8`
- `6` / `u`
- `@` / `~`
- `{` / `7`
- `c` / `F`
- `O` / `p`
- `E` / `f`

The Ruby and Perl ordering checks resolve all of them except `@` versus `~`.

Trying those two remaining possibilities gives:

- one garbage decryption
- one valid flag string

That picks the correct key unambiguously.

## Local Verification

I verified the recovered key against both interpreters locally:

```text
ruby pollys_key   -> BCCTF{Th3_P05h_9oLly61Ot_p4rr0t}
perl pollys_key   -> BCCTF{Th3_P05h_9oLly61Ot_p4rr0t}
```

## Files

- `solve.py`: reconstructs the key from the Ruby/Perl constraints and decrypts the flag offline
