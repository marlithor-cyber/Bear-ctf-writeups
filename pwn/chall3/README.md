# chall3

## Summary

This challenge is a pure logic bug. You do not need memory corruption, libc leaks, or RNG
prediction.

The game starts with `$100`, and the flag costs `$5,000,000`. The intended mechanics are:

- place one bet per day
- if your group wins, you double your bet
- crypto investments pay out the next day

The implementation breaks that model in two places:

1. an over-sized bet is rejected visually, but the amount still stays in `moneyBet`
2. the payout check only tests whether you bet at all, not whether you bet on the winning group

That lets us "bet" millions we do not own and get paid on a winning day anyway.

## Bug 1: Overbet Still Pays Later

In `gamble()`:

```c
scanf("%f", &moneyBet);

if ( moneyBet > money ) {
    printf("\nYou don't have enough money to bet that much! And you can't go into debt either.\n");
} else if ( moneyBet < 0.0 ) {
    printf("\nYou can't gamble negative money!\n");
    exit(0);
} else {
    money -= moneyBet;
}
```

If `moneyBet > money`, the program only prints an error. It does **not** reset `moneyBet`, and it
does **not** reset `betOn`.

So after choosing any valid group and entering something like `3000000`, the state becomes:

- `betOn != 0`
- `moneyBet = 3000000.0`
- `money` is still `100.0`

## Bug 2: Winning Check Ignores Which Group You Picked

At end of day:

```c
if ( betOn && isWinning(day) ) {
    money += moneyBet * 2;
}
```

This never checks whether `betOn` matches the winner. It only checks:

- did you place any valid bet?
- is the current day listed in `values`?

The hardcoded winning days are:

```c
int values[5] = {5, 2, 10, 8, 13};
```

So day `2` is already a guaranteed payout day.

## Exploit

The shortest path is:

1. on day 1, do nothing and complete the day
2. on day 2, place any valid bet, for example group `1`
3. enter an amount far larger than your balance, for example `3000000`
4. complete the day
5. on day 3, buy the flag

Why it works:

```text
start money      = 100
overbet amount   = 3000000
end-of-day payout = moneyBet * 2 = 6000000
final money      = 6000100
```

That is enough to satisfy:

```c
if ( money >= 5000000.0) {
    printFlag();
}
```

## Local Verification

The challenge folder only included source and the remote solver, not the shipped binary or real
`flag.txt`. I compiled the provided source locally and verified the exact sequence with a dummy
flag:

```text
It is day 3 and you have 6000100.00 dollars
...
BCCTF{local_test_flag}
```

So the day-2 overbet path really does reach `printFlag()`.

## Files

- `solve.py`: remote solver for `chal.bearcatctf.io:22723`

## Note on the Solver

The bundled solver works because it follows the same flow:

- complete day 1
- abuse the free payout on day 2
- buy the flag once the menu reports at least `5000000`

No brute force is needed.
