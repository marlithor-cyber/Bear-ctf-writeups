# chall5

`pwn_math_playground`

## Summary

The bug is an unchecked index into a global function-pointer table:

```c
int (*operations[4])(int, int) = {add, subtract, multiply, divide};
...
res = (*operations[choice-1])(a, b);
```

Because `choice` is never bounded, negative values let us read function pointers from memory before
`operations[]`, including resolved GOT entries for `scanf`, `puts`, and `setvbuf`.

That gives a useful call primitive:

- `choice = -2` calls `__isoc99_scanf`
- `choice = -4` calls `puts`
- `choice = -3` calls `setvbuf`

With one initial arbitrary write to `printf@got`, we can loop back inside `main`, leak libc, write a
command string into `.data`, overwrite `setvbuf@got` with `system`, and finally call
`system("cat flag.txt")`.

## Memory Layout

`operations` is at `0x804c02c`, and the nearby GOT slots are:

- `printf@got = 0x804c010`
- `puts@got = 0x804c018`
- `setvbuf@got = 0x804c01c`
- `__isoc99_scanf@got = 0x804c020`

So:

- `choice = -2` indexes `scanf@got`
- `choice = -3` indexes `setvbuf@got`
- `choice = -4` indexes `puts@got`

The binary is also non-PIE, so all of those addresses are fixed.

## Stage 1: Turn `printf` into a Loop

After the indirect call, `main` ends with:

```c
printf("%d\n", res);
```

We first abuse `choice = -2` to call `scanf("%d", printf_got)` and write:

```text
printf@got = 0x8049276
```

`0x8049276` is inside `main`, right at the block that scans a fresh `choice` and then reads `a`
and `b` again. That means every later `printf("%d\n", res)` jumps back into a reusable mini-loop
instead of exiting.

## Stage 2: Leak libc

Once the loop is active, choose:

```text
choice = -4
a = puts@got
```

That calls `puts(puts_got)`, which prints the raw bytes starting at the resolved `puts` address.
The first four bytes are enough to recover `puts@libc`, so:

```text
libc_base = leak - libc.symbols["puts"]
system    = libc_base + libc.symbols["system"]
```

## Stage 3: Write the Command String

We still have the `scanf` write primitive through `choice = -2`, so we write:

```text
"cat flag.txt\x00"
```

into the writable `.data` area at `operations`.

The helper in the exploit writes 32-bit chunks as signed decimal integers, because the primitive is:

```c
scanf("%d", target);
```

## Stage 4: Redirect a Safe GOT Slot to `system`

We do **not** overwrite `puts@got`, because the loop itself uses `puts("Enter two integers:")`.
If `puts@got` becomes `system`, the loop breaks immediately.

Instead we overwrite:

```text
setvbuf@got = system
```

`setvbuf` is not used again after startup, so it is a clean call target.

## Stage 5: Call `system("cat flag.txt")`

Finally:

```text
choice = -3
a = operations
```

Since `choice = -3` resolves through `setvbuf@got`, that becomes:

```c
system("cat flag.txt");
```

and prints the flag.

## Local Verification

The challenge bundle includes a placeholder local flag. Running the exploit against the supplied
binary and bundled `flag.txt` prints:

```text
BCCTF{fake_flag}
```

So the exploit chain is verified end to end locally.

## Deployment Note

The supplied Dockerfile has an additional issue:

```dockerfile
CMD ./ynetd -p 5000 sh
```

If the challenge was deployed exactly as shipped, that would hand out a shell directly instead of
running `math_playground`. The writeup above covers the binary itself, which is still exploitable
even without that misconfiguration.

## Files

- `solve.py`: tested exploit for the bundled binary; defaults to local mode and accepts optional
  `REMOTE`, `HOST`, `PORT`, `BIN`, and `LIBC` arguments
