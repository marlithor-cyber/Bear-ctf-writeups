# chall1

## Summary

This is a straight two-stage stack exploit:

1. leak the stack canary with a format string
2. reuse that canary in a buffer overflow and return into `win()`

The binary is:

- 64-bit ELF
- no PIE
- NX enabled
- stack canary present
- partial RELRO

Because PIE is off, the `win()` address and the tiny ROP gadgets in the text segment are fixed.

## Bug 1: Format String Leak

`find_treasure()` first reads 10 bytes into a stack buffer and then calls `printf(name)` directly.

Relevant behavior from the disassembly:

```text
read(0, rbp-0x3a, 0xa)
printf("Hello ")
printf(name)
```

So our name is treated as a format string. In this binary, `%13$p` leaks the stack canary:

```text
Hello 0x??????????????00
```

The low byte is `00`, which matches the expected stack canary layout on x86-64.

## Bug 2: Stack Overflow

The second input is much worse:

```text
read(0, rbp-0x30, 0x70)
```

but the destination buffer is only 0x28 bytes away from the canary:

```text
buf @ rbp-0x30
canary @ rbp-0x8
```

So the layout to control RIP is:

- `0x28` bytes of padding
- leaked canary
- `8` bytes saved `rbp`
- ROP chain

## Reaching `win()`

`win()` is not called normally because it checks its arguments first:

```text
if ((rdi & 0xff) == 6 || (rsi & 0xff) == 7) { ... }
```

The binary also gives us exactly what we need:

- `0x40132c`: `ret`
- `0x40132d`: `pop rdi ; ret`
- `0x4011a6`: `win`

So the final payload is:

```text
'A' * 0x28
+ canary
+ 'B' * 8
+ ret
+ pop rdi ; ret
+ 6
+ win
```

The extra `ret` keeps stack alignment safe before entering `win()`.

## Exploit

The bundled solver does exactly this:

1. connect to the service
2. send `%13$p`
3. parse the leaked canary
4. send the overflow payload
5. pivot into `win()` with `rdi = 6`

With a local dummy `flag.txt`, the exploit returns:

```text
You found the treasure BCCTF{local_test_flag}
```

## Files

- `solve.py`: remote exploit for `chal.bearcatctf.io:28799`

## Notes

The challenge bundle did not include the real `flag.txt`, so local end-to-end testing was done with
a temporary dummy flag file. The control-flow and offsets were still verified directly against the
provided binary.
