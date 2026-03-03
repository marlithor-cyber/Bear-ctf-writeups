# chall4

## Summary

This challenge is a shellcode execution bug caused by two separate mistakes:

1. option `3` swaps the arguments to `handlePirate()`
2. the name validator uses `strlen()`, so an embedded NUL hides the rest of our payload

Because the binary has an executable stack, that is enough to run shellcode directly from the input
buffer and spawn a shell.

## Useful Binary Properties

`checksec` on the provided binary shows:

- PIE enabled
- canary present
- full RELRO
- executable stack
- RWX segments present

So a normal ret2win path is unattractive, but direct stack shellcode is viable.

## Core Bug

`handlePirate()` expects:

```c
handlePirate(name, action_function)
```

and does:

```c
printf("Let's find out your fate %s\n", name);
action_function();
```

For options `1`, `2`, and `4`, the arguments are passed in the right order. But option `3`
reverses them:

```text
rdi = eatCoconut
rsi = user_buffer
call handlePirate
```

So for menu choice `3`, `handlePirate()` effectively does:

```c
printf("Let's find out your fate %s\n", eatCoconut);
((void(*)())user_buffer)();
```

That means our input buffer is treated as executable code.

## Validation Bypass

Before that call, the program reads the name with `read()` and validates it like this:

```c
read(0, buf, 0x95);
...
size_t len = strlen(buf);
is_alphanum_string(buf, len);
```

The validator only checks the first `strlen(buf)` bytes. Since `read()` accepts raw bytes, we can
send:

```text
'j' + '\x00' + shellcode
```

and get:

- first byte `'j'` is alphanumeric, so validation passes
- the NUL byte makes `strlen()` stop immediately
- the rest of the buffer is unchecked shellcode

That is why the exploit payload starts with:

```python
b"\\x6a\\x00"
```

`0x6a` is ASCII `'j'`, which is alphanumeric.

## Exploit

The full attack is:

1. choose menu option `3`
2. send `b"\\x6a\\x00" + shellcode`
3. let `handlePirate()` call the buffer as a function
4. use the spawned shell to read the flag

The included solver uses standard amd64 `execve("/bin/sh", ...)` shellcode and then runs:

```sh
cat flag* 2>/dev/null; cat /flag* 2>/dev/null; cat /home/*/flag* 2>/dev/null
```

## Local Verification

I verified the exploit locally with a dummy `flag.txt`. Running the same payload against the local
binary produced:

```text
Let's find out your fate ...
BCCTF{local_test_flag}
```

The weird bytes after `Let's find out your fate` are expected: option `3` passes the address of
`eatCoconut` as the `%s` argument, so `printf()` starts printing instruction bytes until it hits a
zero byte.

## Files

- `solve.py`: remote shellcode exploit for `chal.bearcatctf.io:40385`
