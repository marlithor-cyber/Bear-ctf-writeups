# chall1

## Summary

The challenge asks for a quine, checks it by writing our input to a random file in `/tmp`, running
that file in a subprocess, and verifying:

- no stderr
- stdout is exactly equal to the submitted source

If the check passes, the server then does:

```python
exec(code)
```

That second `exec()` happens in the challenge process, not in the `/tmp` subprocess. So the solve is
to submit a payload that:

1. behaves like a perfect quine when run from `/tmp`
2. behaves like a flag stealer when later `exec()`'d by the parent process

## Vulnerable Logic

The important code is:

```python
def is_quine(code):
    filename = f"/tmp/{uuid4()}.py"
    ...
    result = subprocess.run(
        ["sudo", "-u", "quine", "/usr/local/bin/python3", filename],
        capture_output=True,
        text=True,
        timeout=5,
    )
    ...
    return code == result.stdout

def main():
    print("Give me a quine")
    code = input("> ")
    if is_quine(code):
        print("That will do just fine.")
        exec(code)
```

The checker and the final `exec()` do **not** run our code in the same context:

- check phase: `__file__` is something like `/tmp/<uuid>.py`
- exec phase: `__file__` comes from the challenge's own script, so it is not under `/tmp`

That difference is enough to branch the payload.

## Exploit Idea

The payload is a one-line quine that always prints its own source:

```python
sys.stdout.write(s % s)
```

Then it conditionally runs the post-check payload only when it is **not** being executed from
`/tmp`:

```python
globals().get("__file__", "").startswith("/tmp/") or exec(t)
```

So:

- in the quine checker, the condition is true and `exec(t)` is skipped
- in the parent `exec()` call, the condition is false and `t` runs

## Post-Check Payload

The second-stage code is still one line. It searches for a flag in:

- common environment variables like `FLAG` and `BCCTF_FLAG`
- common file paths such as `/flag*`, `/app/flag*`, `/srv/flag*`, `/opt/flag*`, and `/home/*/flag*`

Then it prints the first `BCCTF{...}` token it finds.

Because the original input is read with `input("> ")`, the whole exploit must be a single line with
semicolon-separated statements.

## Local Verification

I verified the corrected payload locally in two ways:

1. write it to a temporary file under `/tmp` and run it directly
   Result: stdout matches the payload exactly, so it is a real quine
2. `exec()` the same string with `__file__` set to a non-`/tmp` path and `FLAG=BCCTF{local_test_flag}`
   Result: it prints the payload and then prints `BCCTF{local_test_flag}`

That matches the two execution contexts in the challenge.

## Files

- `solve.py`: builds the one-line quine/exfil payload and sends it to `chal.bearcatctf.io:31806`
